use crate::AttackChainRecord;
use dendrite_protocol::{EntityKind, MemoryGraphDto, ObjectDescriptor};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

#[derive(Debug)]
pub enum KnowledgeError {
    Database(rusqlite::Error),
    Json(serde_json::Error),
    Invalid(String),
}

impl From<rusqlite::Error> for KnowledgeError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

impl From<serde_json::Error> for KnowledgeError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationKeyRecord {
    pub object_id: String,
    pub key_type: String,
    pub value: String,
    pub confidence: u8,
    pub origin_instance_id: String,
    pub first_seen_at: u64,
    pub last_seen_at: u64,
}

impl CorrelationKeyRecord {
    pub fn display_key(&self) -> String {
        format!("{}:{}", self.key_type, self.value)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BehaviourDefinition {
    pub id: String,
    pub name: String,
    pub description: String,
    pub confidence: u8,
    pub severity: String,
    pub techniques: Vec<String>,
    pub conditions: Vec<Value>,
    pub ordered: bool,
    pub max_interval_seconds: Option<u64>,
    pub source_refs: Vec<String>,
    pub fingerprint: Option<String>,
    pub origin_instance_id: Option<String>,
    pub imported_from_instance_id: Option<String>,
    pub derived_by_instance_id: Option<String>,
    pub lineage: Vec<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackChainClassification {
    pub chain_id: String,
    pub display_name: String,
    pub original_title: String,
    pub confidence: u8,
    pub matched_cve_ids: Vec<String>,
    pub behaviour_ids: Vec<String>,
    pub behaviour_fingerprint: String,
    pub classified_at: u64,
}

pub struct KnowledgeService {
    connection: Connection,
}

impl KnowledgeService {
    pub fn open(path: &str) -> Result<Self, KnowledgeError> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        if path != ":memory:" {
            connection.pragma_update(None, "journal_mode", "WAL")?;
            connection.pragma_update(None, "synchronous", "NORMAL")?;
        }
        let service = Self { connection };
        service.initialise()?;
        Ok(service)
    }

    fn initialise(&self) -> Result<(), KnowledgeError> {
        self.connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS correlation_keys (
                object_id           TEXT NOT NULL,
                key_type            TEXT NOT NULL,
                value               TEXT NOT NULL,
                confidence          INTEGER NOT NULL,
                origin_instance_id  TEXT NOT NULL,
                first_seen_at       INTEGER NOT NULL,
                last_seen_at        INTEGER NOT NULL,
                PRIMARY KEY(object_id, key_type, value)
            );
            CREATE INDEX IF NOT EXISTS idx_correlation_keys_lookup
                ON correlation_keys(key_type, value);

            CREATE TABLE IF NOT EXISTS behaviour_knowledge (
                id                          TEXT PRIMARY KEY,
                name                        TEXT NOT NULL,
                description                 TEXT NOT NULL,
                confidence                  INTEGER NOT NULL,
                severity                    TEXT NOT NULL,
                techniques                  TEXT NOT NULL,
                conditions                  TEXT NOT NULL,
                ordered                     INTEGER NOT NULL,
                max_interval_seconds        INTEGER,
                source_refs                 TEXT NOT NULL,
                fingerprint                 TEXT,
                origin_instance_id          TEXT,
                imported_from_instance_id   TEXT,
                derived_by_instance_id      TEXT,
                lineage                     TEXT NOT NULL,
                created_at                  INTEGER NOT NULL,
                updated_at                  INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_behaviour_knowledge_fingerprint
                ON behaviour_knowledge(fingerprint);

            CREATE TABLE IF NOT EXISTS behaviour_bindings (
                behaviour_id    TEXT NOT NULL,
                subject_type    TEXT NOT NULL,
                subject_id      TEXT NOT NULL,
                confidence      INTEGER NOT NULL,
                observed_at     INTEGER NOT NULL,
                PRIMARY KEY(behaviour_id, subject_type, subject_id),
                FOREIGN KEY(behaviour_id) REFERENCES behaviour_knowledge(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_behaviour_bindings_subject
                ON behaviour_bindings(subject_type, subject_id);

            CREATE TABLE IF NOT EXISTS cve_behaviour_associations (
                cve_id          TEXT NOT NULL,
                package         TEXT NOT NULL,
                behaviour_id    TEXT NOT NULL,
                confidence      INTEGER NOT NULL DEFAULT 100,
                source          TEXT NOT NULL,
                PRIMARY KEY(cve_id, package, behaviour_id)
            );
            CREATE INDEX IF NOT EXISTS idx_cve_behaviour_id
                ON cve_behaviour_associations(behaviour_id, cve_id);

            CREATE TABLE IF NOT EXISTS cve_enrichment (
                cve_id          TEXT NOT NULL,
                package         TEXT NOT NULL,
                display_name    TEXT,
                updated_at      INTEGER NOT NULL,
                PRIMARY KEY(cve_id, package)
            );

            CREATE TABLE IF NOT EXISTS attack_chain_classifications (
                chain_id                TEXT PRIMARY KEY,
                display_name            TEXT NOT NULL,
                original_title          TEXT NOT NULL,
                confidence              INTEGER NOT NULL,
                matched_cve_ids         TEXT NOT NULL,
                behaviour_ids           TEXT NOT NULL,
                behaviour_fingerprint   TEXT NOT NULL,
                classified_at           INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS automatic_chain_exports (
                incident_id             TEXT NOT NULL,
                behaviour_fingerprint   TEXT NOT NULL,
                antiserum_id            TEXT NOT NULL,
                created_at              INTEGER NOT NULL,
                PRIMARY KEY(incident_id, behaviour_fingerprint)
            );
            ",
        )?;
        Ok(())
    }

    /// Whether an automatic Antiserum export has already been created for
    /// this incident and this structural chain shape (`behaviour_fingerprint`
    /// — stable across reinforcements of the same pattern, unlike the
    /// literal evidence/chain ID, which is fresh on every reinforcement).
    /// Used to stop reinforcement of an already-exported chain from creating
    /// an unbounded number of automatic packages.
    pub fn has_automatic_export(
        &self,
        incident_id: &str,
        behaviour_fingerprint: &str,
    ) -> Result<bool, KnowledgeError> {
        Ok(self
            .connection
            .query_row(
                "SELECT 1 FROM automatic_chain_exports
                 WHERE incident_id = ?1 AND behaviour_fingerprint = ?2",
                params![incident_id, behaviour_fingerprint],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Records that an automatic export was created for this incident and
    /// chain shape, so future reinforcements of the same shape are skipped
    /// by `has_automatic_export`. A conflicting insert (a race between two
    /// callers) is silently ignored — the first writer wins and that's fine,
    /// since the intent is just "at least one such package already exists".
    pub fn record_automatic_export(
        &self,
        incident_id: &str,
        behaviour_fingerprint: &str,
        antiserum_id: &str,
        now: u64,
    ) -> Result<(), KnowledgeError> {
        self.connection.execute(
            "INSERT INTO automatic_chain_exports
             (incident_id, behaviour_fingerprint, antiserum_id, created_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(incident_id, behaviour_fingerprint) DO NOTHING",
            params![incident_id, behaviour_fingerprint, antiserum_id, now],
        )?;
        Ok(())
    }

    pub fn record_object_correlations(
        &self,
        canonical_object_id: &str,
        object: &ObjectDescriptor,
        origin_instance_id: &str,
        now: u64,
    ) -> Result<(), KnowledgeError> {
        for (key_type, value, confidence) in derive_correlation_keys(object) {
            self.connection.execute(
                "INSERT INTO correlation_keys
                 (object_id, key_type, value, confidence, origin_instance_id, first_seen_at, last_seen_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
                 ON CONFLICT(object_id, key_type, value) DO UPDATE SET
                    confidence = MAX(correlation_keys.confidence, excluded.confidence),
                    last_seen_at = excluded.last_seen_at",
                params![
                    canonical_object_id,
                    key_type,
                    value,
                    confidence,
                    origin_instance_id,
                    now
                ],
            )?;
        }
        Ok(())
    }

    pub fn import_correlation_display_keys(
        &self,
        object_id: &str,
        keys: &[String],
        origin_instance_id: &str,
        now: u64,
    ) -> Result<usize, KnowledgeError> {
        let mut imported = 0usize;
        for key in keys {
            let Some((key_type, value)) = key.split_once(':') else {
                continue;
            };
            if key_type.trim().is_empty() || value.trim().is_empty() {
                continue;
            }
            self.connection.execute(
                "INSERT INTO correlation_keys
                 (object_id, key_type, value, confidence, origin_instance_id, first_seen_at, last_seen_at)
                 VALUES (?1, ?2, ?3, 100, ?4, ?5, ?5)
                 ON CONFLICT(object_id, key_type, value) DO UPDATE SET
                    confidence = MAX(correlation_keys.confidence, excluded.confidence),
                    last_seen_at = excluded.last_seen_at",
                params![object_id, key_type, value, origin_instance_id, now],
            )?;
            imported += 1;
        }
        Ok(imported)
    }

    pub fn correlation_keys_for_object(
        &self,
        object_id: &str,
    ) -> Result<Vec<CorrelationKeyRecord>, KnowledgeError> {
        let mut statement = self.connection.prepare(
            "SELECT object_id, key_type, value, confidence, origin_instance_id,
                    first_seen_at, last_seen_at
             FROM correlation_keys WHERE object_id = ?1
             ORDER BY confidence DESC, key_type, value",
        )?;
        let rows = statement.query_map([object_id], |row| {
            Ok(CorrelationKeyRecord {
                object_id: row.get(0)?,
                key_type: row.get(1)?,
                value: row.get(2)?,
                confidence: row.get(3)?,
                origin_instance_id: row.get(4)?,
                first_seen_at: row.get(5)?,
                last_seen_at: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn correlation_display_keys(&self, object_id: &str) -> Result<Vec<String>, KnowledgeError> {
        Ok(self
            .correlation_keys_for_object(object_id)?
            .into_iter()
            .map(|record| record.display_key())
            .collect())
    }

    pub fn upsert_behaviour(&self, behaviour: &BehaviourDefinition) -> Result<(), KnowledgeError> {
        validate_behaviour(behaviour)?;
        self.connection.execute(
            "INSERT INTO behaviour_knowledge
             (id, name, description, confidence, severity, techniques, conditions, ordered,
              max_interval_seconds, source_refs, fingerprint, origin_instance_id,
              imported_from_instance_id, derived_by_instance_id, lineage, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
             ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                confidence = MAX(behaviour_knowledge.confidence, excluded.confidence),
                severity = excluded.severity,
                techniques = excluded.techniques,
                conditions = excluded.conditions,
                ordered = excluded.ordered,
                max_interval_seconds = excluded.max_interval_seconds,
                source_refs = excluded.source_refs,
                fingerprint = COALESCE(excluded.fingerprint, behaviour_knowledge.fingerprint),
                origin_instance_id = COALESCE(behaviour_knowledge.origin_instance_id, excluded.origin_instance_id),
                imported_from_instance_id = excluded.imported_from_instance_id,
                derived_by_instance_id = excluded.derived_by_instance_id,
                lineage = excluded.lineage,
                updated_at = excluded.updated_at",
            params![
                behaviour.id,
                behaviour.name,
                behaviour.description,
                behaviour.confidence,
                behaviour.severity,
                serde_json::to_string(&behaviour.techniques)?,
                serde_json::to_string(&behaviour.conditions)?,
                i64::from(behaviour.ordered),
                behaviour.max_interval_seconds,
                serde_json::to_string(&behaviour.source_refs)?,
                behaviour.fingerprint,
                behaviour.origin_instance_id,
                behaviour.imported_from_instance_id,
                behaviour.derived_by_instance_id,
                serde_json::to_string(&behaviour.lineage)?,
                behaviour.created_at,
                behaviour.updated_at,
            ],
        )?;
        Ok(())
    }

    pub fn behaviours(&self) -> Result<Vec<BehaviourDefinition>, KnowledgeError> {
        let mut statement = self.connection.prepare(
            "SELECT id, name, description, confidence, severity, techniques, conditions, ordered,
                    max_interval_seconds, source_refs, fingerprint, origin_instance_id,
                    imported_from_instance_id, derived_by_instance_id, lineage, created_at, updated_at
             FROM behaviour_knowledge ORDER BY updated_at DESC, id",
        )?;
        let rows = statement.query_map([], behaviour_from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(decode_behaviour)
            .collect()
    }

    pub fn behaviour(&self, id: &str) -> Result<Option<BehaviourDefinition>, KnowledgeError> {
        let row = self.connection.query_row(
            "SELECT id, name, description, confidence, severity, techniques, conditions, ordered,
                    max_interval_seconds, source_refs, fingerprint, origin_instance_id,
                    imported_from_instance_id, derived_by_instance_id, lineage, created_at, updated_at
             FROM behaviour_knowledge WHERE id = ?1",
            [id],
            behaviour_from_row,
        ).optional()?;
        row.map(decode_behaviour).transpose()
    }

    pub fn selected_behaviours(
        &self,
        ids: &[String],
    ) -> Result<Vec<BehaviourDefinition>, KnowledgeError> {
        if ids.is_empty() {
            return self.behaviours();
        }
        let wanted = ids.iter().collect::<BTreeSet<_>>();
        Ok(self
            .behaviours()?
            .into_iter()
            .filter(|value| wanted.contains(&value.id))
            .collect())
    }

    pub fn behaviours_for_chain(
        &self,
        chain_id: &str,
    ) -> Result<Vec<BehaviourDefinition>, KnowledgeError> {
        let mut statement = self.connection.prepare(
            "SELECT behaviour_id FROM behaviour_bindings
             WHERE subject_type = 'attack_chain' AND subject_id = ?1
             ORDER BY behaviour_id",
        )?;
        let ids = statement
            .query_map([chain_id], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        self.selected_behaviours(&ids)
    }

    pub fn classification(
        &self,
        chain_id: &str,
    ) -> Result<Option<AttackChainClassification>, KnowledgeError> {
        let row = self
            .connection
            .query_row(
                "SELECT chain_id, display_name, original_title, confidence, matched_cve_ids,
                    behaviour_ids, behaviour_fingerprint, classified_at
             FROM attack_chain_classifications WHERE chain_id = ?1",
                [chain_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, u8>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, u64>(7)?,
                    ))
                },
            )
            .optional()?;
        row.map(|row| {
            Ok(AttackChainClassification {
                chain_id: row.0,
                display_name: row.1,
                original_title: row.2,
                confidence: row.3,
                matched_cve_ids: serde_json::from_str(&row.4)?,
                behaviour_ids: serde_json::from_str(&row.5)?,
                behaviour_fingerprint: row.6,
                classified_at: row.7,
            })
        })
        .transpose()
    }

    pub fn observe_attack_chain(
        &self,
        chain: &AttackChainRecord,
        graph: &MemoryGraphDto,
        instance_id: &str,
        now: u64,
    ) -> Result<AttackChainClassification, KnowledgeError> {
        let (fingerprint, conditions) = chain_fingerprint_and_conditions(chain, graph);
        let observed_id = format!("behaviour:graph:{}", &fingerprint[..32]);
        let observed = BehaviourDefinition {
            id: observed_id.clone(),
            name: format!("Observed attack-chain behaviour {}", &fingerprint[..12]),
            description: "Dendrite-derived structural behaviour fingerprint from an observed Memory Graph attack chain.".into(),
            confidence: chain.confidence,
            severity: normalise_severity(&chain.severity),
            techniques: Vec::new(),
            conditions: conditions.clone(),
            ordered: true,
            max_interval_seconds: None,
            source_refs: vec!["src_local_observation".into()],
            fingerprint: Some(format!("sha256:{fingerprint}")),
            origin_instance_id: Some(instance_id.into()),
            imported_from_instance_id: None,
            derived_by_instance_id: Some(instance_id.into()),
            lineage: vec![instance_id.into()],
            created_at: now,
            updated_at: now,
        };
        self.upsert_behaviour(&observed)?;

        let mut matched = vec![observed.clone()];
        for behaviour in self.behaviours()? {
            if behaviour.id == observed_id || behaviour.conditions.is_empty() {
                continue;
            }
            if behaviour_matches_chain(&behaviour, &conditions) {
                matched.push(behaviour);
            }
        }
        matched.sort_by(|left, right| left.id.cmp(&right.id));
        matched.dedup_by(|left, right| left.id == right.id);

        for behaviour in &matched {
            self.connection.execute(
                "INSERT INTO behaviour_bindings
                 (behaviour_id, subject_type, subject_id, confidence, observed_at)
                 VALUES (?1, 'attack_chain', ?2, ?3, ?4)
                 ON CONFLICT(behaviour_id, subject_type, subject_id) DO UPDATE SET
                    confidence = MAX(behaviour_bindings.confidence, excluded.confidence),
                    observed_at = excluded.observed_at",
                params![
                    behaviour.id,
                    chain.id,
                    chain.confidence.min(behaviour.confidence),
                    now
                ],
            )?;
        }

        let behaviour_ids = matched
            .iter()
            .map(|value| value.id.clone())
            .collect::<Vec<_>>();
        let placeholders = std::iter::repeat_n("?", behaviour_ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let mut cve_matches = Vec::<(String, Option<String>, u8)>::new();
        if !behaviour_ids.is_empty() {
            let sql = format!(
                "SELECT DISTINCT a.cve_id, e.display_name, a.confidence
                 FROM cve_behaviour_associations a
                 LEFT JOIN cve_enrichment e ON e.cve_id = a.cve_id AND e.package = a.package
                 WHERE a.behaviour_id IN ({placeholders})
                 ORDER BY a.confidence DESC, a.cve_id"
            );
            let mut statement = self.connection.prepare(&sql)?;
            let refs = behaviour_ids.iter().map(String::as_str).collect::<Vec<_>>();
            let rows = statement.query_map(rusqlite::params_from_iter(refs), |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?;
            cve_matches = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        }

        let matched_cve_ids = cve_matches
            .iter()
            .map(|value| value.0.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let best = cve_matches.first();
        let display_name = best
            .and_then(|(_, name, _)| name.clone())
            .filter(|value| !value.trim().is_empty())
            .or_else(|| best.map(|(cve, _, _)| cve.clone()))
            .unwrap_or_else(|| chain.title.clone());
        let confidence = best
            .map(|(_, _, association_confidence)| chain.confidence.min(*association_confidence))
            .unwrap_or(chain.confidence);

        let classification = AttackChainClassification {
            chain_id: chain.id.clone(),
            display_name,
            original_title: chain.title.clone(),
            confidence,
            matched_cve_ids,
            behaviour_ids,
            behaviour_fingerprint: format!("sha256:{fingerprint}"),
            classified_at: now,
        };
        self.connection.execute(
            "INSERT INTO attack_chain_classifications
             (chain_id, display_name, original_title, confidence, matched_cve_ids,
              behaviour_ids, behaviour_fingerprint, classified_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(chain_id) DO UPDATE SET
                display_name = excluded.display_name,
                confidence = excluded.confidence,
                matched_cve_ids = excluded.matched_cve_ids,
                behaviour_ids = excluded.behaviour_ids,
                behaviour_fingerprint = excluded.behaviour_fingerprint,
                classified_at = excluded.classified_at",
            params![
                classification.chain_id,
                classification.display_name,
                classification.original_title,
                classification.confidence,
                serde_json::to_string(&classification.matched_cve_ids)?,
                serde_json::to_string(&classification.behaviour_ids)?,
                classification.behaviour_fingerprint,
                classification.classified_at,
            ],
        )?;
        Ok(classification)
    }
}

fn derive_correlation_keys(object: &ObjectDescriptor) -> Vec<(String, String, u8)> {
    let mut keys = Vec::new();
    let id = object.id.0.trim();
    let label = object.label.trim();

    if let Some(value) = id.strip_prefix("cve:") {
        keys.push(("cve".into(), value.to_ascii_uppercase(), 100));
    } else if let Some(value) = id.strip_prefix("process_identity:") {
        keys.push(("process-identity".into(), value.to_ascii_lowercase(), 90));
    } else if let Some(value) = id.strip_prefix("network:") {
        keys.push(("network-endpoint".into(), value.to_ascii_lowercase(), 90));
    } else if let Some(value) = id.strip_prefix("user:uid:") {
        keys.push(("uid".into(), value.into(), 95));
    } else if let Some(value) = id.strip_prefix("file:") {
        keys.push(("file-path".into(), normalise_path_like(value), 60));
    } else if matches!(
        object.kind,
        EntityKind::Service | EntityKind::Container | EntityKind::Host
    ) {
        keys.push(("semantic-id".into(), id.to_ascii_lowercase(), 75));
    }

    for candidate in [id, label] {
        let candidate = candidate.strip_prefix("sha256:").unwrap_or(candidate);
        if candidate.len() == 64 && candidate.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            keys.push(("sha256".into(), candidate.to_ascii_lowercase(), 100));
        }
    }

    let kind = format!("{:?}", object.kind).to_ascii_lowercase();
    let semantic = format!("{kind}|{}", label.to_ascii_lowercase());
    let mut hasher = Sha256::new();
    hasher.update(semantic.as_bytes());
    keys.push((
        "semantic-fingerprint".into(),
        hex::encode(hasher.finalize()),
        50,
    ));

    keys.sort();
    keys.dedup();
    keys
}

fn normalise_path_like(value: &str) -> String {
    let value = value.trim();
    if value == "/" {
        return "/".into();
    }
    value.trim_end_matches('/').to_string()
}

fn chain_fingerprint_and_conditions(
    chain: &AttackChainRecord,
    graph: &MemoryGraphDto,
) -> (String, Vec<Value>) {
    let relationship_by_id = graph
        .relationships
        .iter()
        .map(|value| (value.id.as_str(), value))
        .collect::<HashMap<_, _>>();
    let mut signature_parts = Vec::new();
    let mut conditions = Vec::new();
    for (index, pair) in chain.steps.windows(2).enumerate() {
        let relationship = chain
            .relationships
            .get(index)
            .and_then(|id| relationship_by_id.get(id.as_str()).copied());
        let relationship_kind = relationship.map_or("associated_with", |value| value.kind.as_str());
        let source_kind = pair[0].kind.to_ascii_lowercase();
        let target_kind = pair[1].kind.to_ascii_lowercase();
        signature_parts.push(format!("{source_kind}>{relationship_kind}>{target_kind}"));
        conditions.push(serde_json::json!({
            "kind": "graph-relation",
            "source_kind": source_kind,
            "relationship": relationship_kind,
            "target_kind": target_kind
        }));
    }
    if signature_parts.is_empty() {
        signature_parts.extend(
            chain
                .steps
                .iter()
                .map(|step| step.kind.to_ascii_lowercase()),
        );
    }
    let signature = signature_parts.join("|");
    let mut hasher = Sha256::new();
    hasher.update(signature.as_bytes());
    (hex::encode(hasher.finalize()), conditions)
}

fn behaviour_matches_chain(behaviour: &BehaviourDefinition, observed: &[Value]) -> bool {
    if behaviour.conditions.is_empty() {
        return false;
    }
    let wanted = behaviour
        .conditions
        .iter()
        .filter(|value| value.get("kind").and_then(Value::as_str) == Some("graph-relation"))
        .collect::<Vec<_>>();
    if wanted.is_empty() {
        return false;
    }
    if behaviour.ordered {
        let mut cursor = 0usize;
        for condition in wanted {
            let Some(relative) = observed[cursor..]
                .iter()
                .position(|candidate| graph_condition_matches(condition, candidate))
            else {
                return false;
            };
            cursor += relative + 1;
        }
        true
    } else {
        wanted.into_iter().all(|condition| {
            observed
                .iter()
                .any(|candidate| graph_condition_matches(condition, candidate))
        })
    }
}

fn graph_condition_matches(wanted: &Value, observed: &Value) -> bool {
    ["source_kind", "relationship", "target_kind"]
        .into_iter()
        .all(|key| {
            let wanted_value = wanted.get(key).and_then(Value::as_str);
            wanted_value.is_none() || wanted_value == observed.get(key).and_then(Value::as_str)
        })
}

fn validate_behaviour(value: &BehaviourDefinition) -> Result<(), KnowledgeError> {
    if !value.id.starts_with("behaviour:") || value.id.len() > 256 {
        return Err(KnowledgeError::Invalid(
            "behaviour id must start with behaviour:".into(),
        ));
    }
    if value.name.trim().is_empty() || value.description.trim().is_empty() {
        return Err(KnowledgeError::Invalid(
            "behaviour requires name and description".into(),
        ));
    }
    if value.confidence > 100 {
        return Err(KnowledgeError::Invalid(
            "behaviour confidence must be <= 100".into(),
        ));
    }
    Ok(())
}

fn normalise_severity(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" | "moderate" => "medium",
        "low" => "low",
        "informational" => "informational",
        _ => "unknown",
    }
    .into()
}

type BehaviourRow = (
    String,
    String,
    String,
    u8,
    String,
    String,
    String,
    i64,
    Option<u64>,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    u64,
    u64,
);

fn behaviour_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<BehaviourRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
        row.get(14)?,
        row.get(15)?,
        row.get(16)?,
    ))
}

fn decode_behaviour(row: BehaviourRow) -> Result<BehaviourDefinition, KnowledgeError> {
    Ok(BehaviourDefinition {
        id: row.0,
        name: row.1,
        description: row.2,
        confidence: row.3,
        severity: row.4,
        techniques: serde_json::from_str(&row.5)?,
        conditions: serde_json::from_str(&row.6)?,
        ordered: row.7 != 0,
        max_interval_seconds: row.8,
        source_refs: serde_json::from_str(&row.9)?,
        fingerprint: row.10,
        origin_instance_id: row.11,
        imported_from_instance_id: row.12,
        derived_by_instance_id: row.13,
        lineage: serde_json::from_str(&row.14)?,
        created_at: row.15,
        updated_at: row.16,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dendrite_protocol::{EvidenceObjectRef, MemoryRelationshipDto, ObjectId};

    #[test]
    fn identical_semantics_correlate_without_reusing_object_identity() {
        let service = KnowledgeService::open(":memory:").unwrap();
        let object = ObjectDescriptor {
            id: ObjectId("network:Example.COM:443".into()),
            kind: EntityKind::NetworkEndpoint,
            label: "Example.COM:443".into(),
        };
        service
            .record_object_correlations("host-a::network:1", &object, "host-a", 10)
            .unwrap();
        service
            .record_object_correlations("host-b::network:9", &object, "host-b", 11)
            .unwrap();
        let a = service
            .correlation_display_keys("host-a::network:1")
            .unwrap();
        let b = service
            .correlation_display_keys("host-b::network:9")
            .unwrap();
        assert_ne!("host-a::network:1", "host-b::network:9");
        assert!(
            a.iter()
                .any(|value| value == "network-endpoint:example.com:443")
        );
        assert!(
            b.iter()
                .any(|value| value == "network-endpoint:example.com:443")
        );
    }

    #[test]
    fn attack_chain_derives_stable_behaviour_fingerprint() {
        let service = KnowledgeService::open(":memory:").unwrap();
        let chain = AttackChainRecord {
            id: "chain:1".into(),
            incident_id: "inc_1".into(),
            title: "Unknown chain".into(),
            original_title: "Unknown chain".into(),
            severity: "high".into(),
            confidence: 90,
            observed_at: 10,
            steps: vec![
                EvidenceObjectRef {
                    id: "a".into(),
                    label: "a".into(),
                    kind: "process".into(),
                    origin_instance_id: None,
                    imported_from_instance_id: None,
                    derived_by_instance_id: None,
                    lineage: vec![],
                },
                EvidenceObjectRef {
                    id: "b".into(),
                    label: "b".into(),
                    kind: "network_endpoint".into(),
                    origin_instance_id: None,
                    imported_from_instance_id: None,
                    derived_by_instance_id: None,
                    lineage: vec![],
                },
            ],
            relationships: vec!["r1".into()],
            evidence_id: "e1".into(),
            matched_cve_ids: vec![],
            behaviour_ids: vec![],
            behaviour_fingerprint: None,
            classification_confidence: None,
        };
        let graph = MemoryGraphDto {
            nodes: vec![],
            relationships: vec![MemoryRelationshipDto {
                id: "r1".into(),
                kind: "connected_to".into(),
                source: "a".into(),
                target: "b".into(),
                state: "observed".into(),
                priority: "normal".into(),
                retention: "short_term".into(),
                strength: 90,
                effective_strength: 90,
                confidence: 90,
                observation_count: 1,
                created_at: 1,
                last_seen_at: 1,
                expires_at: None,
                origin_instance_id: None,
                imported_from_instance_id: None,
                derived_by_instance_id: None,
                lineage: vec![],
            }],
            truncated: false,
            total_nodes: 0,
            total_relationships: 1,
        };
        let first = service
            .observe_attack_chain(&chain, &graph, "host", 10)
            .unwrap();
        let second = service
            .observe_attack_chain(&chain, &graph, "host", 11)
            .unwrap();
        assert_eq!(first.behaviour_fingerprint, second.behaviour_fingerprint);
        assert_eq!(first.behaviour_ids, second.behaviour_ids);
    }
}
