use crate::{
    ANTISERUM_DEFAULT_STREAM, ActionService, ActionStoreError, AnalysisError, AnalysisReviewRecord,
    AntiserumAttestation, AntiserumError, AntiserumKnowledgeAcceptanceResult,
    AntiserumPackageDetail, AntiserumPackageOrigin, AntiserumPackageStore, AntiserumPackageSummary,
    AntiserumPayload, AntiserumVerificationKey, AttackChainRecord, BuiltPayloadSet,
    CreateAntiserumRequest, CveKnowledgeBundle, CveKnowledgeRecord, GuardIpcClient, GuardService,
    GuardStoreError, IncidentService, IncidentStoreError, InstanceKeyRecord, KnowledgeError,
    KnowledgeService, MagiIpcClient, SelfStore, SelfStoreError, SignedAntiserumPackage,
    VulnerabilityCandidate, VulnerabilityError, VulnerabilityService,
    automatic_attack_chain_request, build_payloads, build_signed_package,
    enforce_automatic_export_ceiling, verification_key_from_package, verify_signed_package,
};
use dendrite_memory::model::{
    DecayPolicy, DecayRate, MemoryConfidence, MemoryNode, MemoryNodeId, MemoryNodeKind,
    MemoryPriority, MemoryProvenance, MemoryRelationship, MemoryRelationshipId,
    MemoryRelationshipKind, MemoryState, MemoryStrength, RetentionClass,
};
use dendrite_memory::storage::{
    GraphReader, MemoryPath, MemoryStore, PathQuery, StorageError, ThreatPath, TraversalDirection,
    execute_node_upsert, execute_relationship_upsert,
};
use dendrite_protocol::{
    ActionDetailDto, ActionSummaryDto, Confidence, EntityKind, EvidenceCandidate, EvidenceId,
    EvidenceObjectRef, EvidenceSource, GuardStatusDto, HealthDto, IncidentDetailDto, IncidentId,
    IncidentSummaryDto, InstanceSigningKeyDto, IntegrityFindingDto, IntegrityManifestStatusDto,
    IntegrityVerificationDto, MemoryGraphDto, MemoryNodeDto, MemoryRelationshipDto,
    ObjectDescriptor, ObjectId, Observation, ObservationKind, RecoveryBeginDto,
    RecoveryCompleteDto, Severity, TelemetryEventDto, TelemetryPipelineDto, TelemetrySourceDto,
    TelemetryStatusDto, VulnerabilityExposureDto,
};
use rusqlite::Connection;
use std::collections::{BTreeMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

fn imported_lineage(mut lineage: Vec<String>, origin: &str, receiver: &str) -> Vec<String> {
    if lineage.is_empty() {
        lineage.push(origin.to_owned());
    }
    lineage.retain(|host| host != receiver);
    lineage.push(receiver.to_owned());
    if lineage.len() > dendrite_memory::model::MAX_PROVENANCE_LINEAGE {
        let drop_count = lineage.len() - dendrite_memory::model::MAX_PROVENANCE_LINEAGE;
        lineage.drain(0..drop_count);
    }
    lineage
}

fn imported_memory_provenance(
    origin: Option<String>,
    derived_by: Option<String>,
    lineage: Vec<String>,
    exporter: &str,
    receiver: &str,
) -> MemoryProvenance {
    let origin_value = origin.unwrap_or_else(|| exporter.to_owned());
    MemoryProvenance::new(
        Some(origin_value.clone()),
        Some(exporter.to_owned()),
        derived_by,
        imported_lineage(lineage, &origin_value, receiver),
    )
}

fn json_required_string(value: &serde_json::Value, key: &str) -> Result<String, DaemonError> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            DaemonError::Debug(format!("Antiserum payload is missing string field {key}"))
        })
}

fn json_optional_string(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

fn json_string_array(value: &serde_json::Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn json_optional_timestamp(value: &serde_json::Value, key: &str) -> Option<u64> {
    let text = value.get(key).and_then(serde_json::Value::as_str)?;
    time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
        .ok()
        .and_then(|value| u64::try_from(value.unix_timestamp()).ok())
}

const REINFORCED_STM_BASE_TTL_SECONDS: u64 = 900;
const REINFORCED_STM_STEP_SECONDS: u64 = 300;
const REINFORCED_STM_MAX_TTL_SECONDS: u64 = 3_600;
const REINFORCED_STM_HARD_LIFETIME_SECONDS: u64 = 21_600;
const LTM_REINFORCED_TTL_SECONDS: u64 = 604_800;
const LTM_PROMOTION_QUALIFIED_LINKS: usize = 3;

/// Caps how many relationships the threat-path search expands through at
/// any single node, at any hop of the BFS - see `PathQuery::max_relationships_per_node`'s
/// doc comment. Without this, a hub node (an "unresolvable process" bucket
/// like `host:local`, or a heavily-shared file/library) with a fan-out in
/// the thousands turns a bounded-depth search into an effectively unbounded
/// amount of work: `max_depth` limits how far the search goes, not how wide
/// it is at each step. 200 is generous relative to what a real reasoning
/// step needs (the strongest 200 edges at a node, not an arbitrary 200) and
/// was picked to comfortably clear legitimate high-degree nodes seen in
/// practice while still bounding a genuinely pathological one - not
/// benchmarked against a specific worst-case target, so revisit if a hub
/// node's fan-out ever approaches it in practice.
const MAX_RELATIONSHIPS_PER_NODE_FOR_REASONING: usize = 200;

#[derive(Debug)]
pub enum DaemonError {
    Database(rusqlite::Error),
    Memory(StorageError),
    Incidents(IncidentStoreError),
    Actions(ActionStoreError),
    Guard(GuardStoreError),
    Vulnerability(VulnerabilityError),
    SelfStore(SelfStoreError),
    Antiserum(AntiserumError),
    Analysis(AnalysisError),
    Knowledge(KnowledgeError),
    Debug(String),
}

impl From<rusqlite::Error> for DaemonError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

impl From<StorageError> for DaemonError {
    fn from(error: StorageError) -> Self {
        Self::Memory(error)
    }
}

impl From<GuardStoreError> for DaemonError {
    fn from(error: GuardStoreError) -> Self {
        Self::Guard(error)
    }
}

impl From<ActionStoreError> for DaemonError {
    fn from(error: ActionStoreError) -> Self {
        Self::Actions(error)
    }
}

impl From<IncidentStoreError> for DaemonError {
    fn from(error: IncidentStoreError) -> Self {
        Self::Incidents(error)
    }
}
impl From<VulnerabilityError> for DaemonError {
    fn from(error: VulnerabilityError) -> Self {
        Self::Vulnerability(error)
    }
}

impl From<SelfStoreError> for DaemonError {
    fn from(error: SelfStoreError) -> Self {
        Self::SelfStore(error)
    }
}

impl From<AntiserumError> for DaemonError {
    fn from(error: AntiserumError) -> Self {
        Self::Antiserum(error)
    }
}

impl From<AnalysisError> for DaemonError {
    fn from(error: AnalysisError) -> Self {
        Self::Analysis(error)
    }
}

impl From<KnowledgeError> for DaemonError {
    fn from(error: KnowledgeError) -> Self {
        Self::Knowledge(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestionOutcome {
    pub relationship_id: Option<MemoryRelationshipId>,
    pub incidents: Vec<IncidentId>,
    pub evidence: Vec<EvidenceId>,
    pub strongest_graph_score: Option<u8>,
}

pub struct DaemonCore {
    self_store: SelfStore,
    memory: MemoryStore,
    instance_id: String,
    signing_key: InstanceKeyRecord,
    antiserum_store: AntiserumPackageStore,
    knowledge: KnowledgeService,
    incidents: IncidentService,
    actions: ActionService,
    guard: GuardService,
    http_api_token: String,
    observations_ingested: u64,
    telemetry_recent: VecDeque<TelemetryEventDto>,
    telemetry_sources: Vec<TelemetrySourceDto>,
    telemetry_pipeline: TelemetryPipelineDto,
}

impl DaemonCore {
    pub fn open(memory_path: &str) -> Result<Self, DaemonError> {
        Self::open_with_stores(":memory:", memory_path, ":memory:")
    }

    pub fn open_with_incidents(
        memory_path: &str,
        incident_path: &str,
    ) -> Result<Self, DaemonError> {
        Self::open_with_stores(":memory:", memory_path, incident_path)
    }

    pub fn open_with_stores(
        self_path: &str,
        memory_path: &str,
        incident_path: &str,
    ) -> Result<Self, DaemonError> {
        Self::open_with_tiered_stores(self_path, memory_path, ":memory:", incident_path)
    }

    pub fn open_with_tiered_stores(
        self_path: &str,
        stm_path: &str,
        ltm_path: &str,
        incident_path: &str,
    ) -> Result<Self, DaemonError> {
        let memory = MemoryStore::open_tiered(stm_path, ltm_path)?;
        memory.initialise()?;
        Self::open_with_memory_store(self_path, memory, incident_path, true)
    }

    /// Opens another core around an existing tiered MemoryStore reader. The
    /// reader has its own SQLite connection while physical writes are shared
    /// with the store's per-tier writer actors. Runtime ingestion workers use
    /// this so they can remain parallel without opening competing DB writers.
    pub fn open_with_shared_memory(
        self_path: &str,
        memory: MemoryStore,
        incident_path: &str,
    ) -> Result<Self, DaemonError> {
        Self::open_with_memory_store(self_path, memory, incident_path, false)
    }

    fn open_with_memory_store(
        self_path: &str,
        memory: MemoryStore,
        incident_path: &str,
        run_memory_startup_maintenance: bool,
    ) -> Result<Self, DaemonError> {
        let mut self_store = SelfStore::open(self_path)?;
        let instance_id = self_store.instance_id()?;
        let signing_key = self_store.ensure_active_signing_key()?;
        let http_api_token = self_store.ensure_http_api_token()?;
        if run_memory_startup_maintenance {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs());
            preserve_short_term_connectors(&memory, now)?;
            memory.mark_expired(now)?;
        }
        let antiserum_store = AntiserumPackageStore::for_self_store(self_path)?;
        Ok(Self {
            self_store,
            memory,
            instance_id,
            signing_key,
            antiserum_store,
            knowledge: KnowledgeService::open(incident_path)?,
            incidents: IncidentService::open(incident_path)?,
            actions: ActionService::open(incident_path)?,
            guard: GuardService::new(),
            http_api_token,
            observations_ingested: 0,
            telemetry_recent: VecDeque::with_capacity(512),
            telemetry_sources: Vec::new(),
            telemetry_pipeline: TelemetryPipelineDto::default(),
        })
    }

    pub fn memory(&self) -> &MemoryStore {
        &self.memory
    }

    pub fn self_store(&self) -> &SelfStore {
        &self.self_store
    }

    pub fn incidents_store(&self) -> &IncidentService {
        &self.incidents
    }

    /// The bearer token gating the HTTP API/`/ws` upgrade (see `http.rs`).
    /// Exposed to `dendrite-cli http-token` over the Unix socket, which is
    /// already permission-gated the same way as the HTTP API is meant to
    /// be — see `docs/CONFIGURATION.md`'s "HTTP API authentication" section.
    pub fn http_api_token(&self) -> &str {
        &self.http_api_token
    }

    /// Placeholder timeout for the liveness probe below. Deliberately not
    /// tuned yet — see `docs/TODO.md`: this needs real benchmarking on
    /// representative hardware/load before it can be trusted as a
    /// meaningful "healthy vs degraded" threshold. 200ms is a generous
    /// guess for two local `SELECT 1` queries, nothing more.
    const HEALTH_CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(200);

    /// Real liveness check backing the `daemon` field of `HealthDto`
    /// (`memory` and `guard` were already real checks; `daemon` used to be
    /// a hardcoded `"ok"` regardless of anything). Pings the self-store and
    /// incidents databases (the latter also backs the vulnerability/CVE/
    /// behaviour-knowledge tables — see `CONFIGURATION.md` — so one ping
    /// covers all of them) and times the round trip: `"ok"` if both
    /// respond within `HEALTH_CHECK_TIMEOUT`, `"degraded"` if they respond
    /// but too slowly, `"error"` if either query fails outright.
    pub fn health_check(&self) -> Result<HealthDto, DaemonError> {
        let started = std::time::Instant::now();
        let self_store_ok = self.self_store.ping().is_ok();
        let incidents_ok = self.incidents.ping().is_ok();
        let elapsed = started.elapsed();
        let daemon = if !self_store_ok || !incidents_ok {
            "error"
        } else if elapsed > Self::HEALTH_CHECK_TIMEOUT {
            "degraded"
        } else {
            "ok"
        };
        Ok(HealthDto {
            daemon: daemon.into(),
            memory: if self.memory.ping().is_ok() {
                "ok".into()
            } else {
                "error".into()
            },
            // Deliberately `trust_state()` (infallible, safe-value fallback),
            // not `guard_status()` (genuinely fallible — see its own doc
            // comment). A health check's whole job is to stay informative
            // when something is unhealthy; if `dendrite-guard` is
            // unreachable, `trust_state()` already reports `Compromised`,
            // and that's exactly what this field should show, not a hard
            // error that makes `health`/`GET /api/v1/health` itself fail.
            guard: self.guard.trust_state().as_str().to_string(),
        })
    }

    /// Starts a batched-write transaction on the Memory Graph store — see
    /// `MemoryStore::begin_batch`'s doc comment for why this is enough to
    /// make every subsequent `ingest_observation` call in the batch part of
    /// one commit, with no changes to `ingest_observation` itself.
    ///
    /// Under tiered (STM/LTM) storage this is a no-op, same as
    /// `MemoryStore::begin_batch` itself: routine ingestion's real batching
    /// now goes through `ingest_routine_batch`/`MemoryStore::run_stm_batch`
    /// instead, which needs a single writer-owned connection to let a
    /// batch's later reads see its own earlier writes - something a
    /// caller-side `BEGIN`/`COMMIT` around per-item writer-actor dispatch
    /// could never provide. Kept for any other caller still relying on the
    /// non-tiered (`open()`) compatibility path this preserves.
    pub fn begin_memory_batch(&self) -> Result<(), DaemonError> {
        Ok(self.memory.begin_batch()?)
    }

    pub fn commit_memory_batch(&self) -> Result<(), DaemonError> {
        Ok(self.memory.commit_batch()?)
    }

    /// Best-effort: logs nothing itself, just tries — the caller is
    /// responsible for logging, since it knows why the rollback happened.
    pub fn rollback_memory_batch(&self) {
        let _ = self.memory.rollback_batch();
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub fn signing_key_status(&self) -> InstanceSigningKeyDto {
        InstanceSigningKeyDto {
            key_id: self.signing_key.key_id.clone(),
            algorithm: "ed25519".into(),
            public_key: self.signing_key.public_key.clone(),
            fingerprint: self.signing_key.fingerprint.clone(),
            created_at: self.signing_key.created_at,
        }
    }

    pub fn antiserum_attestation(&self, now: u64) -> Result<AntiserumAttestation, DaemonError> {
        let findings = self.guard.findings()?;
        Ok(AntiserumAttestation::from_guard(
            &self.instance_id,
            &self.signing_key.key_id,
            self.guard.trust_state(),
            &findings,
            now,
        )?)
    }

    pub fn build_antiserum_package(
        &mut self,
        payloads: Vec<AntiserumPayload>,
        now: u64,
        expires_at: Option<u64>,
    ) -> Result<SignedAntiserumPackage, DaemonError> {
        let attestation = self.antiserum_attestation(now)?;
        if attestation.export_safety == "blocked" {
            return Err(DaemonError::Debug(
                "Guard has blocked Antiserum export for this host".into(),
            ));
        }
        Ok(build_signed_package(
            &mut self.self_store,
            &self.signing_key,
            attestation,
            payloads,
            now,
            expires_at,
            ANTISERUM_DEFAULT_STREAM,
        )?)
    }

    pub fn verify_and_record_antiserum_sequence(
        &mut self,
        package: &SignedAntiserumPackage,
        exporter_key: &AntiserumVerificationKey,
        now: u64,
    ) -> Result<(), DaemonError> {
        verify_signed_package(package, exporter_key, now)?;
        self.self_store.accept_antiserum_sequence(
            &package.envelope.issuer.instance_id,
            &package.envelope.issuer.key_fingerprint,
            ANTISERUM_DEFAULT_STREAM,
            package.envelope.sequence,
        )?;
        Ok(())
    }

    pub fn analysis_packages(&self, now: u64) -> Result<Vec<AntiserumPackageSummary>, DaemonError> {
        let mut rows = self.antiserum_store.list(now)?;
        for row in &mut rows {
            self.apply_antiserum_knowledge_status(row)?;
        }
        Ok(rows)
    }

    pub fn analysis_package_detail(
        &self,
        antiserum_id: &str,
        now: u64,
    ) -> Result<AntiserumPackageDetail, DaemonError> {
        let mut detail = self.antiserum_store.detail(antiserum_id, now)?;
        self.apply_antiserum_knowledge_status(&mut detail.summary)?;
        Ok(detail)
    }

    pub fn analysis_package_graph(
        &self,
        antiserum_id: &str,
        now: u64,
    ) -> Result<MemoryGraphDto, DaemonError> {
        Ok(self.antiserum_store.graph(antiserum_id, now)?)
    }

    pub fn analysis_package_bytes(&self, antiserum_id: &str) -> Result<Vec<u8>, DaemonError> {
        let (_, _, bytes) = self.antiserum_store.load(antiserum_id)?;
        Ok(bytes)
    }

    pub fn import_antiserum_package(
        &mut self,
        bytes: &[u8],
        now: u64,
    ) -> Result<AntiserumPackageSummary, DaemonError> {
        let package = self.antiserum_store.parse_import(bytes, now)?;
        let key = verification_key_from_package(&package);
        self.verify_and_record_antiserum_sequence(&package, &key, now)?;
        Ok(self
            .antiserum_store
            .store(&package, AntiserumPackageOrigin::Imported)?)
    }

    pub fn accept_antiserum_knowledge(
        &mut self,
        vulnerability: &mut VulnerabilityService,
        antiserum_id: &str,
        now: u64,
    ) -> Result<AntiserumKnowledgeAcceptanceResult, DaemonError> {
        if let Some(existing) = self
            .self_store
            .antiserum_knowledge_acceptance(antiserum_id)?
        {
            return Ok(AntiserumKnowledgeAcceptanceResult {
                antiserum_id: existing.antiserum_id,
                accepted_at: existing.accepted_at,
                graph_nodes: 0,
                graph_relationships: 0,
                behaviours: 0,
                vulnerabilities: 0,
                vulnerability_candidates: 0,
                skipped_payloads: Vec::new(),
                already_accepted: true,
            });
        }

        let (package, origin, _) = self.antiserum_store.load(antiserum_id)?;
        if origin != AntiserumPackageOrigin::Imported {
            return Err(DaemonError::Debug(
                "Accept Knowledge is only valid for imported Antiserum packages".into(),
            ));
        }
        verify_signed_package(&package, &verification_key_from_package(&package), now)?;

        let exporter = package.envelope.issuer.instance_id.clone();
        if exporter == self.instance_id {
            return Err(DaemonError::Debug(
                "This Antiserum package was issued by the local Dendrite instance; its knowledge is already local".into(),
            ));
        }
        let graph = self.antiserum_store.graph(antiserum_id, now)?;
        let graph_nodes = graph.nodes.len();
        let graph_relationships = graph.relationships.len();
        self.accept_antiserum_graph(&graph, &exporter, now)?;

        let behaviours = self.accept_antiserum_behaviours(&package, &exporter, now)?;
        let (vulnerabilities, vulnerability_candidates) =
            self.accept_antiserum_vulnerabilities(vulnerability, &package, &exporter, now)?;

        let mut skipped_payloads = Vec::new();
        for declaration in &package.envelope.payloads {
            if declaration.status != crate::AntiserumPayloadStatus::Populated {
                continue;
            }
            match declaration.class.as_str() {
                "graph-fragment" | "behaviour" | "vulnerability" | "provenance" => {}
                "attack-chain" => skipped_payloads.push(
                    "attack-chain: retained in the package/review; foreign incident history is not injected as a local incident".into(),
                ),
                "indicator-hash" | "indicator-domain" | "indicator-ip" | "indicator-url" => skipped_payloads.push(format!(
                    "{}: no first-class local indicator store exists yet",
                    declaration.class
                )),
                other => skipped_payloads.push(format!("{other}: unsupported knowledge class")),
            }
        }

        let accepted =
            self.self_store
                .mark_antiserum_knowledge_accepted(antiserum_id, &exporter, now)?;

        Ok(AntiserumKnowledgeAcceptanceResult {
            antiserum_id: antiserum_id.into(),
            accepted_at: accepted.accepted_at,
            graph_nodes,
            graph_relationships,
            behaviours,
            vulnerabilities,
            vulnerability_candidates,
            skipped_payloads,
            already_accepted: false,
        })
    }

    fn apply_antiserum_knowledge_status(
        &self,
        summary: &mut AntiserumPackageSummary,
    ) -> Result<(), DaemonError> {
        if let Some(acceptance) = self
            .self_store
            .antiserum_knowledge_acceptance(&summary.antiserum_id)?
        {
            summary.knowledge_status = "accepted".into();
            summary.knowledge_accepted_at = Some(acceptance.accepted_at);
            summary.verification.local_trust = "knowledge_accepted".into();
        } else {
            summary.knowledge_status = if summary.origin != AntiserumPackageOrigin::Imported
                || summary.issuer_instance_id == self.instance_id
            {
                "source".into()
            } else {
                "not_accepted".into()
            };
            summary.knowledge_accepted_at = None;
            summary.verification.local_trust = if summary.knowledge_status == "source" {
                "source".into()
            } else {
                "unassigned".into()
            };
        }
        Ok(())
    }

    fn accept_antiserum_graph(
        &self,
        graph: &MemoryGraphDto,
        exporter: &str,
        now: u64,
    ) -> Result<(), DaemonError> {
        for node in &graph.nodes {
            let origin = node
                .origin_instance_id
                .clone()
                .unwrap_or_else(|| exporter.to_owned());
            let provenance = imported_memory_provenance(
                Some(origin.clone()),
                node.derived_by_instance_id.clone(),
                node.lineage.clone(),
                exporter,
                &self.instance_id,
            );
            let memory_node = MemoryNode {
                id: MemoryNodeId(node.id.clone()),
                kind: node.kind.parse().map_err(|_| {
                    DaemonError::Debug(format!("invalid imported Memory node kind {}", node.kind))
                })?,
                label: node.label.clone(),
                created_at: if node.created_at == 0 {
                    now
                } else {
                    node.created_at
                },
                last_seen_at: if node.last_seen_at == 0 {
                    now
                } else {
                    node.last_seen_at
                },
                expires_at: node.expires_at,
                state: node.state.parse().map_err(|_| {
                    DaemonError::Debug(format!("invalid imported Memory state {}", node.state))
                })?,
                priority: node.priority.parse().map_err(|_| {
                    DaemonError::Debug(format!(
                        "invalid imported Memory priority {}",
                        node.priority
                    ))
                })?,
                retention: node.retention.parse().map_err(|_| {
                    DaemonError::Debug(format!("invalid imported retention {}", node.retention))
                })?,
                decay_policy: DecayPolicy::None,
                provenance,
            };
            self.memory.save_node(&memory_node)?;
            self.knowledge.import_correlation_display_keys(
                &node.id,
                &node.correlation_keys,
                &origin,
                now,
            )?;
        }

        for relationship in &graph.relationships {
            let origin = relationship
                .origin_instance_id
                .clone()
                .unwrap_or_else(|| exporter.to_owned());
            let provenance = imported_memory_provenance(
                Some(origin),
                relationship.derived_by_instance_id.clone(),
                relationship.lineage.clone(),
                exporter,
                &self.instance_id,
            );
            let memory_relationship = MemoryRelationship {
                id: MemoryRelationshipId(relationship.id.clone()),
                kind: relationship.kind.parse().map_err(|_| {
                    DaemonError::Debug(format!(
                        "invalid imported Memory relationship kind {}",
                        relationship.kind
                    ))
                })?,
                source: MemoryNodeId(relationship.source.clone()),
                target: MemoryNodeId(relationship.target.clone()),
                created_at: if relationship.created_at == 0 {
                    now
                } else {
                    relationship.created_at
                },
                last_seen_at: if relationship.last_seen_at == 0 {
                    now
                } else {
                    relationship.last_seen_at
                },
                observation_count: relationship.observation_count.max(1),
                expires_at: relationship.expires_at,
                state: relationship.state.parse().map_err(|_| {
                    DaemonError::Debug(format!(
                        "invalid imported relationship state {}",
                        relationship.state
                    ))
                })?,
                priority: relationship.priority.parse().map_err(|_| {
                    DaemonError::Debug(format!(
                        "invalid imported relationship priority {}",
                        relationship.priority
                    ))
                })?,
                retention: relationship.retention.parse().map_err(|_| {
                    DaemonError::Debug(format!(
                        "invalid imported relationship retention {}",
                        relationship.retention
                    ))
                })?,
                decay_policy: DecayPolicy::None,
                strength: MemoryStrength::new(relationship.strength).ok_or_else(|| {
                    DaemonError::Debug("invalid imported relationship strength".into())
                })?,
                confidence: MemoryConfidence::new(relationship.confidence).ok_or_else(|| {
                    DaemonError::Debug("invalid imported relationship confidence".into())
                })?,
                reinforcement: None,
                provenance,
            };
            self.memory.save_relationship(&memory_relationship)?;
        }
        Ok(())
    }

    fn accept_antiserum_behaviours(
        &self,
        package: &SignedAntiserumPackage,
        exporter: &str,
        now: u64,
    ) -> Result<usize, DaemonError> {
        let Some(payload) = package
            .payloads
            .iter()
            .find(|payload| payload.class == "behaviour")
        else {
            return Ok(0);
        };
        let document: serde_json::Value =
            serde_json::from_slice(&payload.bytes).map_err(AnalysisError::from)?;
        let rows = document
            .get("behaviours")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                DaemonError::Debug("Antiserum behaviour payload has no behaviours array".into())
            })?;
        let mut imported = 0usize;
        for row in rows {
            let relationship = row
                .get("relationship")
                .and_then(serde_json::Value::as_object);
            let origin = json_optional_string(row, "origin_instance_id")
                .unwrap_or_else(|| exporter.to_owned());
            let lineage = imported_lineage(
                json_string_array(row, "lineage"),
                &origin,
                &self.instance_id,
            );
            let behaviour = crate::BehaviourDefinition {
                id: json_required_string(row, "id")?,
                name: json_required_string(row, "name")?,
                description: json_required_string(row, "description")?,
                confidence: row
                    .get("confidence")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0)
                    .min(100) as u8,
                severity: json_required_string(row, "severity")?,
                techniques: json_string_array(row, "techniques"),
                conditions: row
                    .get("conditions")
                    .and_then(serde_json::Value::as_array)
                    .cloned()
                    .unwrap_or_default(),
                ordered: relationship
                    .and_then(|value| value.get("ordered"))
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
                max_interval_seconds: relationship
                    .and_then(|value| value.get("max_interval_seconds"))
                    .and_then(serde_json::Value::as_u64),
                source_refs: json_string_array(row, "source_refs"),
                fingerprint: json_optional_string(row, "fingerprint"),
                origin_instance_id: Some(origin),
                imported_from_instance_id: Some(exporter.to_owned()),
                derived_by_instance_id: json_optional_string(row, "derived_by_instance_id"),
                lineage,
                created_at: now,
                updated_at: now,
            };
            self.knowledge.upsert_behaviour(&behaviour)?;
            imported += 1;
        }
        Ok(imported)
    }

    fn accept_antiserum_vulnerabilities(
        &self,
        vulnerability: &mut VulnerabilityService,
        package: &SignedAntiserumPackage,
        exporter: &str,
        now: u64,
    ) -> Result<(usize, usize), DaemonError> {
        let Some(payload) = package
            .payloads
            .iter()
            .find(|payload| payload.class == "vulnerability")
        else {
            return Ok((0, 0));
        };
        let document: serde_json::Value =
            serde_json::from_slice(&payload.bytes).map_err(AnalysisError::from)?;
        let rows = document
            .get("vulnerabilities")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                DaemonError::Debug(
                    "Antiserum vulnerability payload has no vulnerabilities array".into(),
                )
            })?;
        let mut cves = Vec::new();
        let mut candidates = BTreeMap::<String, VulnerabilityCandidate>::new();

        for row in rows {
            let record_type = row
                .get("record_type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("cve");
            let id = json_required_string(row, "id")?;
            let package_name = json_required_string(row, "package")?;
            let affected = row.get("affected").and_then(serde_json::Value::as_object);
            let introduced = affected
                .and_then(|value| value.get("introduced"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            let fixed = affected
                .and_then(|value| value.get("fixed"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            let behaviour_ids = json_string_array(row, "behaviour_ids");
            let title = json_optional_string(row, "title");
            let description =
                json_optional_string(row, "description").unwrap_or_else(|| id.clone());
            let severity = json_required_string(row, "severity")?;
            let cvss = row
                .get("cvss")
                .and_then(serde_json::Value::as_f64)
                .map(|value| value.to_string());

            if record_type == "candidate" {
                let entry =
                    candidates
                        .entry(id.clone())
                        .or_insert_with(|| VulnerabilityCandidate {
                            candidate_id: id.clone(),
                            title: title.clone().unwrap_or_else(|| id.clone()),
                            description: description.clone(),
                            affected_products: Vec::new(),
                            affected_versions: Vec::new(),
                            weaknesses: Vec::new(),
                            severity: severity.clone(),
                            cvss: cvss.clone(),
                            behaviour_ids: behaviour_ids.clone(),
                            attack_chain_ids: Vec::new(),
                            indicator_ids: Vec::new(),
                            evidence_ids: Vec::new(),
                            source_antiserum_ids: vec![package.envelope.antiserum_id.clone()],
                            reproduction_notes: None,
                            mitigation_notes: None,
                            discovery_origin: "imported-antiserum".into(),
                            confidence: row
                                .get("confidence")
                                .and_then(serde_json::Value::as_u64)
                                .unwrap_or(50)
                                .min(100) as u8,
                            cve_id: None,
                            status: json_optional_string(row, "candidate_status")
                                .unwrap_or_else(|| "draft".into()),
                            created_at: now,
                            updated_at: now,
                        });
                if !entry.affected_products.contains(&package_name) {
                    entry.affected_products.push(package_name);
                }
                if let Some(version) = introduced
                    && !entry.affected_versions.contains(&version)
                {
                    entry.affected_versions.push(version);
                }
            } else {
                cves.push(CveKnowledgeRecord {
                    id,
                    name: title,
                    package: package_name,
                    affected_before: introduced,
                    fixed_version: fixed,
                    severity,
                    cvss,
                    exploitability: None,
                    description,
                    published_at: json_optional_timestamp(row, "published_at"),
                    modified_at: json_optional_timestamp(row, "modified_at"),
                    provenance: format!(
                        "Antiserum {} from {}",
                        package.envelope.antiserum_id, exporter
                    ),
                    expires_at: None,
                    behaviour_ids,
                });
            }
        }

        let imported_cves = if cves.is_empty() {
            0
        } else {
            let bundle = CveKnowledgeBundle {
                schema_version: 1,
                generated_at: now,
                source: format!("antiserum:{exporter}"),
                behaviours: Vec::new(),
                records: cves,
            };
            vulnerability.import_bundle(&bundle, now)?
        };
        let imported_candidates = candidates.len();
        for candidate in candidates.values() {
            vulnerability.import_candidate(candidate)?;
        }
        Ok((imported_cves, imported_candidates))
    }

    pub fn analysis_reviews(&self) -> Result<Vec<AnalysisReviewRecord>, DaemonError> {
        Ok(self.self_store.analysis_reviews()?)
    }

    pub fn create_analysis_review(
        &self,
        antiserum_id: &str,
        label: Option<&str>,
        now: u64,
    ) -> Result<AnalysisReviewRecord, DaemonError> {
        self.antiserum_store.load(antiserum_id)?;
        Ok(self
            .self_store
            .create_analysis_review(antiserum_id, label, now)?)
    }

    pub fn touch_analysis_review(
        &self,
        review_id: &str,
        now: u64,
    ) -> Result<Option<AnalysisReviewRecord>, DaemonError> {
        Ok(self.self_store.touch_analysis_review(review_id, now)?)
    }

    pub fn unload_analysis_review(&self, review_id: &str) -> Result<bool, DaemonError> {
        Ok(self.self_store.delete_analysis_review(review_id)?)
    }

    pub fn create_antiserum_export(
        &mut self,
        vulnerability: &VulnerabilityService,
        request: &CreateAntiserumRequest,
        now: u64,
    ) -> Result<AntiserumPackageSummary, DaemonError> {
        let graph = self.memory_graph(0)?;
        let chains = self.analysis_attack_chains()?;
        let BuiltPayloadSet { payloads, .. } = build_payloads(
            &graph,
            &chains,
            &self.instance_id,
            Some(vulnerability),
            Some(&self.knowledge),
            request,
            now,
        )?;
        let package = self.build_antiserum_package(payloads, now, None)?;
        Ok(self
            .antiserum_store
            .store(&package, AntiserumPackageOrigin::ManualExport)?)
    }

    pub fn analysis_attack_chains(&self) -> Result<Vec<AttackChainRecord>, DaemonError> {
        let graph = self.memory_graph(0)?;
        let relationship_ids = graph
            .relationships
            .iter()
            .map(|relationship| {
                (
                    (relationship.source.clone(), relationship.target.clone()),
                    relationship.id.clone(),
                )
            })
            .collect::<std::collections::HashMap<_, _>>();
        let mut chains = Vec::new();
        for incident in self.list_incidents()? {
            let Some(detail) = self.incident_detail(&incident.id)? else {
                continue;
            };
            for evidence in detail.evidence {
                if evidence.source != "memory_graph" || evidence.objects.len() < 2 {
                    continue;
                }
                let relationships = evidence
                    .objects
                    .windows(2)
                    .filter_map(|pair| {
                        relationship_ids
                            .get(&(pair[0].id.clone(), pair[1].id.clone()))
                            .cloned()
                    })
                    .collect::<Vec<_>>();
                let chain_id = format!("chain:{}:{}", incident.id, evidence.id);
                let classification = self.knowledge.classification(&chain_id)?;
                chains.push(AttackChainRecord {
                    id: chain_id,
                    incident_id: incident.id.clone(),
                    title: classification.as_ref().map_or_else(
                        || incident.summary.clone(),
                        |value| value.display_name.clone(),
                    ),
                    original_title: classification.as_ref().map_or_else(
                        || incident.summary.clone(),
                        |value| value.original_title.clone(),
                    ),
                    severity: incident.severity.clone(),
                    confidence: evidence.confidence,
                    observed_at: evidence.observed_at,
                    steps: evidence.objects,
                    relationships,
                    evidence_id: evidence.id,
                    matched_cve_ids: classification
                        .as_ref()
                        .map_or_else(Vec::new, |value| value.matched_cve_ids.clone()),
                    behaviour_ids: classification
                        .as_ref()
                        .map_or_else(Vec::new, |value| value.behaviour_ids.clone()),
                    behaviour_fingerprint: classification
                        .as_ref()
                        .map(|value| value.behaviour_fingerprint.clone()),
                    classification_confidence: classification
                        .as_ref()
                        .map(|value| value.confidence),
                });
            }
        }
        chains.sort_by(|left, right| {
            right
                .observed_at
                .cmp(&left.observed_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(chains)
    }

    /// Re-runs classification for every existing attack chain against current
    /// behaviour/CVE knowledge. Attack-chain classification is otherwise only
    /// computed once, at the moment a chain's evidence is first created
    /// (see `ingest_observation`'s call to `observe_attack_chain`), so newly
    /// imported behaviour or CVE knowledge would never reach chains that
    /// already existed before the import. Callers that add knowledge capable
    /// of retroactively matching existing chains (currently: vulnerability/
    /// CVE bundle import) should call this afterwards.
    ///
    /// This mirrors the update-summary behaviour already used at chain
    /// creation: if the new classification carries a matched CVE and a
    /// display name different from the chain's original title, the
    /// incident's summary is updated to reflect it. Canonical chain/incident
    /// identity is never changed by this.
    /// Re-runs attack-chain classification against all current chains, e.g.
    /// after new behaviour/CVE knowledge is imported. Returns the number of
    /// chains reclassified and the set of CVE IDs that matched anywhere in
    /// the process — the latter is what `unignore_if_matched` on
    /// `VulnerabilityService` uses to re-raise any exposure for that CVE the
    /// operator had previously ignored ("a later attack chain/behaviour
    /// match references it" from the CVE lifecycle design).
    pub fn reclassify_all_attack_chains(
        &mut self,
        now: u64,
    ) -> Result<(usize, Vec<String>), DaemonError> {
        let graph = self.memory_graph(0)?;
        let chains = self.analysis_attack_chains()?;
        let mut matched_cve_ids = Vec::new();
        for chain in &chains {
            let classification =
                self.knowledge
                    .observe_attack_chain(chain, &graph, &self.instance_id, now)?;
            if !classification.matched_cve_ids.is_empty()
                && classification.display_name != chain.original_title
            {
                self.incidents.update_summary(
                    &chain.incident_id,
                    &classification.display_name,
                    now,
                )?;
            }
            matched_cve_ids.extend(classification.matched_cve_ids);
        }
        Ok((chains.len(), matched_cve_ids))
    }

    fn auto_export_attack_chain(
        &mut self,
        incident_id: &str,
        chain_id: &str,
        start_node: &str,
        behaviour_fingerprint: &str,
        behaviour_ids: &[String],
        now: u64,
    ) -> Result<(), DaemonError> {
        // Reinforcement of an already-exported chain must not create another
        // package: the literal chain_id is fresh on every reinforcement
        // (it embeds a fresh evidence_id), but behaviour_fingerprint is a
        // stable structural hash of the chain's shape, so it's the correct
        // key for "have we already exported something equivalent for this
        // incident".
        if self
            .knowledge
            .has_automatic_export(incident_id, behaviour_fingerprint)?
        {
            return Ok(());
        }
        let graph = self.memory_graph(0)?;
        let chains = self.analysis_attack_chains()?;
        let request = automatic_attack_chain_request(start_node, chain_id, behaviour_ids);
        let built = build_payloads(
            &graph,
            &chains,
            &self.instance_id,
            None,
            Some(&self.knowledge),
            &request,
            now,
        )?;
        enforce_automatic_export_ceiling(&built.graph)?;
        let attestation = self.antiserum_attestation(now)?;
        if attestation.export_safety == "blocked" {
            return Ok(());
        }
        let package = build_signed_package(
            &mut self.self_store,
            &self.signing_key,
            attestation,
            built.payloads,
            now,
            None,
            ANTISERUM_DEFAULT_STREAM,
        )?;
        let summary = self
            .antiserum_store
            .store(&package, AntiserumPackageOrigin::AutomaticExport)?;
        self.knowledge.record_automatic_export(
            incident_id,
            behaviour_fingerprint,
            &summary.antiserum_id,
            now,
        )?;
        Ok(())
    }

    fn local_memory_node_id(&self, local_id: &str) -> MemoryNodeId {
        local_memory_node_id(&self.instance_id, local_id)
    }

    fn display_memory_node(&self, id: &MemoryNodeId) -> Result<String, DaemonError> {
        let Some(node) = self.memory.load_node(id)? else {
            return Ok(id
                .0
                .split_once("::")
                .map_or_else(|| id.0.clone(), |(_, local_id)| local_id.to_string()));
        };

        let mut provenance = Vec::new();
        if let Some(origin) = node.provenance.origin_instance_id.as_deref()
            && origin != self.instance_id
        {
            provenance.push(format!("origin {}", short_instance_id(origin)));
        }

        if let Some(imported_from) = node.provenance.imported_from_instance_id.as_deref()
            && Some(imported_from) != node.provenance.origin_instance_id.as_deref()
        {
            provenance.push(format!("via {}", short_instance_id(imported_from)));
        }

        if let Some(derived_by) = node.provenance.derived_by_instance_id.as_deref()
            && Some(derived_by) != node.provenance.origin_instance_id.as_deref()
            && Some(derived_by) != node.provenance.imported_from_instance_id.as_deref()
        {
            provenance.push(format!("derived by {}", short_instance_id(derived_by)));
        }

        if provenance.is_empty() {
            Ok(node.label)
        } else {
            Ok(format!("{} ({})", node.label, provenance.join(", ")))
        }
    }

    fn evidence_object_ref(&self, id: &MemoryNodeId) -> Result<EvidenceObjectRef, DaemonError> {
        let Some(node) = self.memory.load_node(id)? else {
            let label =
                id.0.split_once("::")
                    .map_or_else(|| id.0.clone(), |(_, local_id)| local_id.to_string());
            return Ok(EvidenceObjectRef {
                id: id.0.clone(),
                label,
                kind: "unknown".into(),
                origin_instance_id: None,
                imported_from_instance_id: None,
                derived_by_instance_id: None,
                lineage: Vec::new(),
            });
        };

        Ok(EvidenceObjectRef {
            id: node.id.0,
            label: node.label,
            kind: node.kind.as_str().into(),
            origin_instance_id: node.provenance.origin_instance_id,
            imported_from_instance_id: node.provenance.imported_from_instance_id,
            derived_by_instance_id: node.provenance.derived_by_instance_id,
            lineage: node.provenance.lineage,
        })
    }

    fn memory_node_dto(&self, node: MemoryNode) -> Result<MemoryNodeDto, DaemonError> {
        let correlation_keys = self.knowledge.correlation_display_keys(&node.id.0)?;
        Ok(MemoryNodeDto {
            id: node.id.0,
            kind: node.kind.as_str().into(),
            label: node.label,
            state: node.state.as_str().into(),
            priority: node.priority.as_str().into(),
            retention: node.retention.as_str().into(),
            created_at: node.created_at,
            last_seen_at: node.last_seen_at,
            expires_at: node.expires_at,
            origin_instance_id: node.provenance.origin_instance_id,
            imported_from_instance_id: node.provenance.imported_from_instance_id,
            derived_by_instance_id: node.provenance.derived_by_instance_id,
            lineage: node.provenance.lineage,
            correlation_keys,
        })
    }

    pub fn behaviours(&self) -> Result<Vec<crate::BehaviourDefinition>, DaemonError> {
        Ok(self.knowledge.behaviours()?)
    }

    pub fn observations_ingested(&self) -> u64 {
        self.observations_ingested
    }

    pub fn set_observations_ingested(&mut self, value: u64) {
        self.observations_ingested = value;
    }

    /// Points MAGI evaluation at a real `dendrite-magi` process over its
    /// Unix socket, overriding `ActionService::open`'s dev default
    /// (`DEFAULT_MAGI_SOCKET_PATH`). `DaemonRuntime::open` calls this with
    /// the configured `DENDRITE_MAGI_SOCKET` path.
    pub fn set_magi_socket_path(&mut self, socket_path: std::path::PathBuf) {
        self.actions
            .set_magi_evaluator(Box::new(MagiIpcClient::new(socket_path)));
    }

    /// Points Guard evaluation at a real `dendrite-guard` process over its
    /// Unix socket, overriding `GuardService::new`'s dev default
    /// (`DEFAULT_GUARD_SOCKET_PATH`). `DaemonRuntime::open` calls this with
    /// the configured `DENDRITE_GUARD_SOCKET` path.
    pub fn set_guard_socket_path(&mut self, socket_path: std::path::PathBuf) {
        self.guard
            .set_guard_evaluator(Box::new(GuardIpcClient::new(socket_path)));
    }

    pub fn expire_memory(&self, now: u64) -> Result<(), DaemonError> {
        preserve_short_term_connectors(&self.memory, now)?;
        self.memory.mark_expired(now)?;
        Ok(())
    }

    pub fn set_telemetry_sources(&mut self, sources: Vec<TelemetrySourceDto>) {
        self.telemetry_sources = sources;
    }

    pub fn set_telemetry_pipeline(&mut self, pipeline: TelemetryPipelineDto) {
        self.telemetry_pipeline = pipeline;
    }

    pub fn record_telemetry_event(&mut self, event: TelemetryEventDto) {
        const MAX_RECENT_TELEMETRY: usize = 512;
        if self.telemetry_recent.len() >= MAX_RECENT_TELEMETRY {
            self.telemetry_recent.pop_front();
        }
        self.telemetry_recent.push_back(event);
    }

    pub fn telemetry_recent(&self, limit: usize) -> Vec<TelemetryEventDto> {
        self.telemetry_recent
            .iter()
            .rev()
            .take(limit.min(self.telemetry_recent.len()))
            .cloned()
            .collect()
    }

    pub fn telemetry_status(&self) -> TelemetryStatusDto {
        TelemetryStatusDto {
            sources: self.telemetry_sources.clone(),
            recent_events: self.telemetry_recent.len(),
            pipeline: self.telemetry_pipeline.clone(),
        }
    }

    pub fn incident_count(&self) -> Result<u64, DaemonError> {
        Ok(self.incidents.open_count()?)
    }

    pub fn list_incidents(&self) -> Result<Vec<IncidentSummaryDto>, DaemonError> {
        Ok(self.incidents.list()?)
    }

    pub fn incident_detail(&self, id: &str) -> Result<Option<IncidentDetailDto>, DaemonError> {
        Ok(self.incidents.detail(id)?)
    }

    pub fn memory_nodes(&self, kind: Option<&str>) -> Result<Vec<MemoryNodeDto>, DaemonError> {
        let kind = kind
            .map(|value| {
                value
                    .parse::<MemoryNodeKind>()
                    .map_err(|_| StorageError::InvalidNodeKind(value.into()))
            })
            .transpose()?;

        self.memory
            .nodes(kind)?
            .into_iter()
            .map(|node| self.memory_node_dto(node))
            .collect::<Result<Vec<_>, _>>()
    }

    pub fn memory_recent(&self, limit: usize) -> Result<Vec<MemoryNodeDto>, DaemonError> {
        self.memory
            .recent_nodes(limit)?
            .into_iter()
            .map(|node| self.memory_node_dto(node))
            .collect::<Result<Vec<_>, _>>()
    }

    pub fn memory_graph(&self, limit: usize) -> Result<MemoryGraphDto, DaemonError> {
        let (nodes, relationships, truncated) = if limit == 0 {
            (
                self.memory.recent_nodes(usize::MAX)?,
                self.memory.relationships()?,
                false,
            )
        } else {
            let requested = limit.max(1);
            let nodes = self.memory.recent_nodes(requested + 1)?;
            let truncated = nodes.len() > requested;
            let nodes = nodes.into_iter().take(requested).collect::<Vec<_>>();
            let relationships = self.memory.relationships_between_recent_nodes(requested)?;
            (nodes, relationships, truncated)
        };

        let nodes = nodes
            .into_iter()
            .filter(|node| node.state.is_active_for_reasoning())
            .collect::<Vec<_>>();
        let included = nodes
            .iter()
            .map(|node| node.id.0.clone())
            .collect::<std::collections::HashSet<_>>();
        let relationships = relationships
            .into_iter()
            .filter(|relationship| {
                relationship.state.is_active_for_reasoning()
                    && included.contains(&relationship.source.0)
                    && included.contains(&relationship.target.0)
            })
            .collect::<Vec<_>>();

        let total_nodes = nodes.len() as u64;
        let total_relationships = relationships.len() as u64;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());

        let relationships = relationships
            .into_iter()
            .map(|relationship| {
                let effective_strength = relationship.effective_strength(now).value();
                MemoryRelationshipDto {
                    id: relationship.id.0,
                    kind: relationship.kind.as_str().into(),
                    source: relationship.source.0,
                    target: relationship.target.0,
                    state: relationship.state.as_str().into(),
                    priority: relationship.priority.as_str().into(),
                    retention: relationship.retention.as_str().into(),
                    strength: relationship.strength.value(),
                    effective_strength,
                    confidence: relationship.confidence.value(),
                    observation_count: relationship.observation_count,
                    created_at: relationship.created_at,
                    last_seen_at: relationship.last_seen_at,
                    expires_at: relationship.expires_at,
                    origin_instance_id: relationship.provenance.origin_instance_id,
                    imported_from_instance_id: relationship.provenance.imported_from_instance_id,
                    derived_by_instance_id: relationship.provenance.derived_by_instance_id,
                    lineage: relationship.provenance.lineage,
                }
            })
            .collect();

        Ok(MemoryGraphDto {
            nodes: nodes
                .into_iter()
                .map(|node| self.memory_node_dto(node))
                .collect::<Result<Vec<_>, _>>()?,
            relationships,
            truncated,
            total_nodes,
            total_relationships,
        })
    }

    pub fn memory_neighbours(&self, id: &str) -> Result<Vec<String>, DaemonError> {
        Ok(self
            .memory
            .neighbours(&MemoryNodeId(id.into()))?
            .into_iter()
            .map(|node| node.0)
            .collect())
    }

    pub fn memory_path(
        &self,
        source: &str,
        target: &str,
    ) -> Result<Option<MemoryPath>, DaemonError> {
        let query = PathQuery::default();
        Ok(self.memory.find_path(
            &MemoryNodeId(source.into()),
            &MemoryNodeId(target.into()),
            &query,
        )?)
    }

    pub fn record_vulnerability_exposure(
        &mut self,
        exposure: &VulnerabilityExposureDto,
        now: u64,
    ) -> Result<(), DaemonError> {
        let severity = match exposure.severity.as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            _ => Severity::Low,
        };
        let confidence = Confidence::new(100).expect("100 is valid confidence");
        let package = ObjectDescriptor {
            id: ObjectId(format!(
                "package:{}:{}",
                exposure.package, exposure.architecture
            )),
            kind: EntityKind::Service,
            label: format!("{} {}", exposure.package, exposure.installed_version),
        };
        let cve = ObjectDescriptor {
            id: ObjectId(format!("cve:{}", exposure.cve_id.to_ascii_lowercase())),
            kind: EntityKind::Threat,
            label: exposure.cve_id.clone(),
        };
        let observation = Observation {
            id: dendrite_protocol::ObservationId(format!("vulnerability:{}:{}", exposure.id, now)),
            kind: ObservationKind::Associated,
            source: package,
            target: Some(cve),
            observed_at: now,
            expires_at: None,
            severity,
            confidence,
        };
        self.ingest_observation(&observation)?;
        Ok(())
    }

    /// Convenience wrapper preserving the original fixed-depth behaviour —
    /// every existing caller (including the test suite) keeps working
    /// unchanged. `spawn_routine_worker` calls `ingest_observation_with_max_depth`
    /// directly with a tighter cap instead; see that method's doc comment.
    pub fn ingest_observation(
        &mut self,
        observation: &Observation,
    ) -> Result<IngestionOutcome, DaemonError> {
        self.ingest_observation_with_max_depth(observation, 6)
    }

    /// Same as `ingest_observation`, but with the threat-path search's
    /// traversal depth as a parameter instead of the fixed default of 6.
    ///
    /// This exists specifically to make the routine ingestion lane cheaper
    /// without weakening priority-lane detection at all: priority
    /// observations are already pre-filtered to be threat-relevant and
    /// latency-sensitive, so they keep the full depth via `ingest_observation`.
    /// Routine observations are the overwhelming majority of volume with a
    /// near-zero hit rate (a Perl interpreter opening its own module tree has
    /// no realistic path to a threat node) — for those, `spawn_routine_worker`
    /// calls this directly with a much shallower cap. A shallower search can
    /// only ever find *fewer* paths than depth 6 would, never a different
    /// one — nothing here changes scoring, ranking, or what counts as
    /// significant, only how far the search is willing to look for routine
    /// traffic, on the reasoning that a threat connection routine telemetry
    /// can only reach many hops away is already a weak, speculative signal
    /// on depth 6 too.
    pub fn ingest_observation_with_max_depth(
        &mut self,
        observation: &Observation,
        max_depth: usize,
    ) -> Result<IngestionOutcome, DaemonError> {
        self.persist_object(&observation.source, observation, false)?;
        if let Some(target) = &observation.target {
            self.persist_object(target, observation, true)?;
        }
        let relationship_id = self.persist_relationship(observation)?;
        self.observations_ingested = self.observations_ingested.saturating_add(1);

        let seeds_threat_knowledge = seeds_threat_knowledge(observation);
        let mut threat_paths: Vec<(String, ThreatPath)> = Vec::new();

        if !seeds_threat_knowledge {
            let query = PathQuery {
                max_depth,
                direction: TraversalDirection::Any,
                evaluation_time: Some(observation.observed_at),
                max_relationships_per_node: Some(MAX_RELATIONSHIPS_PER_NODE_FOR_REASONING),
                ..PathQuery::default()
            };

            if observation.source.kind != EntityKind::Threat {
                let start = self.local_memory_node_id(&observation.source.id.0);
                for finding in self.memory.threat_paths_from(&start, &query)? {
                    threat_paths.push((observation.source.id.0.clone(), finding));
                }
            }

            if threat_paths.is_empty()
                && let Some(target) = &observation.target
                && target.kind != EntityKind::Threat
            {
                let start = self.local_memory_node_id(&target.id.0);
                for finding in self.memory.threat_paths_from(&start, &query)? {
                    threat_paths.push((target.id.0.clone(), finding));
                }
            }
        }

        self.finish_ingestion(
            observation,
            relationship_id,
            seeds_threat_knowledge,
            threat_paths,
        )
    }

    /// Processes a whole routine-lane batch in one pass: the memory-graph
    /// persistence and threat-path search for every job in it run inside a
    /// single transaction on the STM writer's own connection (see
    /// `MemoryStore::run_stm_batch`), instead of each job paying its own
    /// round trip to the writer actor. The rare "found a threat path" tail
    /// (incident/evidence creation, reinforcement, knowledge correlation)
    /// still runs per job afterward, unbatched, via `finish_ingestion` -
    /// exactly the code the single-item path already uses. That tail is hit
    /// on a near-zero fraction of routine traffic, so batching it too would
    /// add real complexity (it touches the incidents and knowledge stores,
    /// not just the memory graph) for a cost that isn't the one driving
    /// routine-lane load.
    pub fn ingest_routine_batch(
        &mut self,
        jobs: Vec<(Observation, usize)>,
    ) -> Vec<Result<IngestionOutcome, DaemonError>> {
        if jobs.is_empty() {
            return Vec::new();
        }

        let instance_id = self.instance_id.clone();
        let batch_input = jobs.clone();

        let batch_result = self.memory.run_stm_batch(move |connection, reader| {
            batch_input
                .iter()
                .map(|(observation, max_depth)| {
                    run_batched_job(connection, &reader, &instance_id, observation, *max_depth)
                })
                .collect::<Vec<_>>()
        });

        let per_job_results = match batch_result {
            Ok(results) => results,
            Err(_) => {
                // The batch never ran at all - e.g. the STM writer thread is
                // gone - so nothing was written or searched for any job in
                // it. Routine ingestion is best-effort (the queue already
                // drops on overflow), so this is reported per job rather
                // than propagated as one fatal error for the whole daemon.
                return jobs
                    .into_iter()
                    .map(|_| {
                        Err(DaemonError::Debug(
                            "routine ingestion batch failed - STM writer unavailable".into(),
                        ))
                    })
                    .collect();
            }
        };

        let mut outcomes = Vec::with_capacity(per_job_results.len());
        for ((observation, _max_depth), job_result) in jobs.into_iter().zip(per_job_results) {
            let outcome = (|| -> Result<IngestionOutcome, DaemonError> {
                let batch_job = job_result?;
                for deferred in batch_job.deferred_saves {
                    match deferred {
                        DeferredSave::Node(node) => self.memory.save_node(&node)?,
                        DeferredSave::Relationship(relationship) => {
                            self.memory.save_relationship(&relationship)?
                        }
                    }
                }
                self.record_object_correlations(&observation)?;
                self.observations_ingested = self.observations_ingested.saturating_add(1);
                self.finish_ingestion(
                    &observation,
                    batch_job.relationship_id,
                    batch_job.seeds_threat_knowledge,
                    batch_job.threat_paths,
                )
            })();
            outcomes.push(outcome);
        }
        outcomes
    }

    /// `dendrite-knowledge`'s correlation-key bookkeeping for one
    /// observation's source (and target, if any). Split out of
    /// `persist_object` so batched routine ingestion can call it once per
    /// object after the batch, using only deterministic inputs (the local
    /// node id is a pure function of instance id + object id; provenance
    /// for a freshly observed local object is always `MemoryProvenance::local`)
    /// rather than needing the batch's merged node state.
    fn record_object_correlations(&self, observation: &Observation) -> Result<(), DaemonError> {
        let source_id = self.local_memory_node_id(&observation.source.id.0);
        self.knowledge.record_object_correlations(
            &source_id.0,
            &observation.source,
            &self.instance_id,
            observation.observed_at,
        )?;
        if let Some(target) = &observation.target {
            let target_id = self.local_memory_node_id(&target.id.0);
            self.knowledge.record_object_correlations(
                &target_id.0,
                target,
                &self.instance_id,
                observation.observed_at,
            )?;
        }
        Ok(())
    }

    /// The shared tail of ingestion: given the relationship id and threat
    /// paths already found (whether by the single-item path above or by a
    /// batched job), decide whether a threat path is significant enough to
    /// raise an incident/evidence and reinforce the graph. Node/relationship
    /// persistence and the threat-path search itself happen before this is
    /// called; this function's job starts once that data already exists.
    fn finish_ingestion(
        &mut self,
        observation: &Observation,
        relationship_id: Option<MemoryRelationshipId>,
        seeds_threat_knowledge: bool,
        mut threat_paths: Vec<(String, ThreatPath)>,
    ) -> Result<IngestionOutcome, DaemonError> {
        if seeds_threat_knowledge {
            return Ok(IngestionOutcome {
                relationship_id,
                incidents: Vec::new(),
                evidence: Vec::new(),
                strongest_graph_score: None,
            });
        }

        threat_paths.sort_by(|left, right| {
            right
                .1
                .path
                .score()
                .cmp(&left.1.path.score())
                .then_with(|| {
                    left.1
                        .path
                        .relationships
                        .len()
                        .cmp(&right.1.path.relationships.len())
                })
                .then_with(|| left.1.threat.0.cmp(&right.1.threat.0))
        });
        let strongest_graph_score = threat_paths
            .first()
            .map(|(_, finding)| finding.path.score());
        let mut incidents = Vec::new();
        let mut evidence = Vec::new();

        if let Some((origin, finding)) = threat_paths.first() {
            let candidate = EvidenceCandidate {
                source: EvidenceSource::MemoryGraph,
                summary: "Memory Graph threat path detected".into(),
                description: format!(
                    "Threat path: {} ({} relationship(s)), score {}",
                    finding
                        .path
                        .nodes
                        .iter()
                        .map(|node| self.display_memory_node(node))
                        .collect::<Result<Vec<_>, _>>()?
                        .join(" -> "),
                    finding.path.relationships.len(),
                    finding.path.score()
                ),
                severity: observation.severity,
                confidence: Confidence::new(finding.path.weakest_confidence.value())
                    .expect("memory confidence is constrained to 0..=100"),
                related_objects: finding
                    .path
                    .nodes
                    .iter()
                    .map(|node| ObjectId(node.0.clone()))
                    .collect(),
                evidence_objects: finding
                    .path
                    .nodes
                    .iter()
                    .map(|node| self.evidence_object_ref(node))
                    .collect::<Result<Vec<_>, _>>()?,
            };
            let correlation_key = format!("{}|{}", origin, finding.threat.0);
            let (incident_id, evidence_id) = self.incidents.record_candidate(
                candidate,
                &correlation_key,
                observation.observed_at,
            )?;
            self.reinforce_significant_path(
                &finding.path,
                &incident_id,
                &evidence_id,
                observation.observed_at,
                observation.severity,
            )?;
            let chain_id = format!("chain:{}:{}", incident_id.0, evidence_id.0);
            let start_node = finding.path.nodes.first().map(|node| node.0.clone());
            incidents.push(incident_id.clone());
            evidence.push(evidence_id.clone());

            let graph = self.memory_graph(0)?;
            let chain = self
                .analysis_attack_chains()?
                .into_iter()
                .find(|chain| chain.id == chain_id);
            let mut behaviour_ids = Vec::new();
            let mut behaviour_fingerprint = None;
            if let Some(chain) = chain {
                let classification = self.knowledge.observe_attack_chain(
                    &chain,
                    &graph,
                    &self.instance_id,
                    observation.observed_at,
                )?;
                behaviour_ids = classification.behaviour_ids.clone();
                behaviour_fingerprint = Some(classification.behaviour_fingerprint.clone());
                if !classification.matched_cve_ids.is_empty()
                    && classification.display_name != chain.original_title
                {
                    self.incidents.update_summary(
                        &incident_id.0,
                        &classification.display_name,
                        observation.observed_at,
                    )?;
                }
            }

            if let (Some(start_node), Some(fingerprint)) = (start_node, behaviour_fingerprint) {
                // Antiserum export is evidence packaging, not execution authority. Guard may still
                // block export through the attestation export-safety gate.
                let _ = self.auto_export_attack_chain(
                    &incident_id.0,
                    &chain_id,
                    &start_node,
                    &fingerprint,
                    &behaviour_ids,
                    observation.observed_at,
                );
            }
        }

        Ok(IngestionOutcome {
            relationship_id,
            incidents,
            evidence,
            strongest_graph_score,
        })
    }

    fn reinforce_significant_path(
        &self,
        path: &MemoryPath,
        incident_id: &IncidentId,
        evidence_id: &EvidenceId,
        now: u64,
        severity: Severity,
    ) -> Result<(), DaemonError> {
        use dendrite_memory::model::{ReinforcementProvenance, ReinforcementReason};

        let mut qualified_links = 1usize;
        for relationship_id in &path.relationships {
            let Some(mut relationship) = self.memory.load_relationship(relationship_id)? else {
                continue;
            };
            if relationship.retention != RetentionClass::ShortTerm {
                continue;
            }

            let mut evidence_ids = relationship
                .reinforcement
                .as_ref()
                .map(|value| value.evidence_ids.clone())
                .unwrap_or_default();
            if !evidence_ids.iter().any(|existing| existing == evidence_id) {
                evidence_ids.push(evidence_id.clone());
            }
            qualified_links = qualified_links.max(evidence_ids.len());
            relationship.reinforcement = Some(ReinforcementProvenance {
                reason: ReinforcementReason::ConfirmedHighRisk,
                incident_id: Some(incident_id.clone()),
                evidence_ids,
            });
            relationship.state = MemoryState::Supported;
            relationship.priority = relationship.priority.max(MemoryPriority::High);
            relationship.strength =
                MemoryStrength::new(relationship.strength.value().saturating_add(10).min(100))
                    .expect("reinforced relationship strength remains valid");
            relationship.expires_at = Some(reinforced_expiry(
                relationship.created_at,
                now,
                qualified_links,
            ));

            if severity == Severity::Critical || qualified_links >= LTM_PROMOTION_QUALIFIED_LINKS {
                relationship.retention = RetentionClass::LongTerm;
                relationship.expires_at = Some(now.saturating_add(LTM_REINFORCED_TTL_SECONDS));
            }
            self.memory.save_relationship(&relationship)?;
        }

        for node_id in &path.nodes {
            let Some(mut node) = self.memory.load_node(node_id)? else {
                continue;
            };
            // Reinforce only the concrete STM object on this evidence path. Durable semantic
            // identities (for example process_identity:comm:mv) are intentionally not changed.
            if node.retention != RetentionClass::ShortTerm {
                continue;
            }
            node.state = MemoryState::Supported;
            node.priority = node.priority.max(MemoryPriority::High);
            node.expires_at = Some(reinforced_expiry(node.created_at, now, qualified_links));
            if severity == Severity::Critical || qualified_links >= LTM_PROMOTION_QUALIFIED_LINKS {
                node.retention = RetentionClass::LongTerm;
                node.expires_at = Some(now.saturating_add(LTM_REINFORCED_TTL_SECONDS));
            }
            self.memory.save_node(&node)?;
        }

        Ok(())
    }

    pub fn list_actions(&self) -> Result<Vec<ActionSummaryDto>, DaemonError> {
        Ok(self.actions.list()?)
    }

    pub fn action_detail(&self, id: &str) -> Result<Option<ActionDetailDto>, DaemonError> {
        Ok(self.actions.detail(id)?)
    }

    pub fn create_action(
        &mut self,
        incident_id: &str,
        action: &str,
        target: &str,
        now: u64,
    ) -> Result<ActionDetailDto, DaemonError> {
        if self.incidents.detail(incident_id)?.is_none() {
            return Err(ActionStoreError::InvalidProposal(format!(
                "incident {incident_id} does not exist"
            ))
            .into());
        }

        Ok(self.actions.create(incident_id, action, target, now)?)
    }

    pub fn execute_authorised_vulnerability_update(
        &mut self,
        exposure: &VulnerabilityExposureDto,
        now: u64,
    ) -> Result<ActionDetailDto, DaemonError> {
        if exposure.status != "authorised" || exposure.authorised_at.is_none() {
            return Err(ActionStoreError::InvalidProposal(
                "package update requires explicit user authority".into(),
            )
            .into());
        }
        if exposure.fixed_version.is_none() {
            return Err(ActionStoreError::InvalidProposal(
                "package update cannot execute without a known fixed version".into(),
            )
            .into());
        }

        let severity = match exposure.severity.as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            _ => Severity::Low,
        };
        let package_id = ObjectId(format!(
            "package:{}:{}",
            exposure.package, exposure.architecture
        ));
        let cve_id = ObjectId(format!("cve:{}", exposure.cve_id.to_ascii_lowercase()));
        let candidate = EvidenceCandidate {
            source: EvidenceSource::Rule,
            summary: format!(
                "Vulnerability exposure: {} in {}",
                exposure.cve_id, exposure.package
            ),
            description: format!(
                "{} {} is affected by {}; fixed version {} is available for authorised remediation",
                exposure.package,
                exposure.installed_version,
                exposure.cve_id,
                exposure.fixed_version.as_deref().unwrap_or("unknown")
            ),
            severity,
            confidence: Confidence::new(100).expect("100 is valid confidence"),
            related_objects: vec![package_id.clone(), cve_id],
            evidence_objects: Vec::new(),
        };
        let correlation_key = format!("vulnerability:{}", exposure.id);
        let (incident_id, _) = self
            .incidents
            .record_candidate(candidate, &correlation_key, now)?;

        let created = self.actions.create(
            &incident_id.0,
            dendrite_protocol::ActionType::UpdatePackage.as_str(),
            &package_id.0,
            now,
        )?;
        let proposal = dendrite_protocol::ActionProposal {
            id: dendrite_protocol::ActionProposalId(created.proposal.id.clone()),
            incident_id,
            action: dendrite_protocol::ActionType::UpdatePackage,
            target: package_id,
        };
        let guard_decision = self.guard.evaluate_authority(&proposal);
        let trust_state = self.guard.trust_state();
        Ok(self.actions.evaluate_and_execute_package_update(
            &created.proposal.id,
            guard_decision,
            trust_state,
            exposure.clone(),
            now,
        )?)
    }

    pub fn evaluate_action(&mut self, id: &str, now: u64) -> Result<ActionDetailDto, DaemonError> {
        let detail = self
            .actions
            .detail(id)?
            .ok_or_else(|| ActionStoreError::InvalidProposal(format!("proposal {id} not found")))?;
        let action = detail
            .proposal
            .action
            .parse()
            .map_err(|_| ActionStoreError::InvalidAction(detail.proposal.action.clone()))?;
        let proposal = dendrite_protocol::ActionProposal {
            id: dendrite_protocol::ActionProposalId(detail.proposal.id),
            incident_id: IncidentId(detail.proposal.incident_id),
            action,
            target: ObjectId(detail.proposal.target),
        };
        let guard_decision = self.guard.evaluate_authority(&proposal);
        let trust_state = self.guard.trust_state();
        Ok(self
            .actions
            .evaluate_and_execute(id, guard_decision, trust_state, now)?)
    }

    pub fn reevaluate_action(
        &mut self,
        id: &str,
        now: u64,
    ) -> Result<ActionDetailDto, DaemonError> {
        let previous = self
            .actions
            .detail(id)?
            .ok_or_else(|| ActionStoreError::InvalidProposal(format!("proposal {id} not found")))?;
        let created = self.actions.create(
            &previous.proposal.incident_id,
            &previous.proposal.action,
            &previous.proposal.target,
            now,
        )?;
        self.evaluate_action(&created.proposal.id, now)
    }

    pub fn guard_status(&self) -> Result<GuardStatusDto, DaemonError> {
        Ok(self.guard.status()?)
    }

    pub fn guard_findings(&self) -> Result<Vec<IntegrityFindingDto>, DaemonError> {
        Ok(self.guard.findings()?)
    }

    pub fn guard_establish_baseline(&self) -> Result<IntegrityManifestStatusDto, DaemonError> {
        Ok(self.guard.establish_baseline()?)
    }

    pub fn guard_verify_integrity(&self) -> Result<IntegrityVerificationDto, DaemonError> {
        Ok(self.guard.verify_integrity()?)
    }

    pub fn guard_begin_recovery(&self) -> Result<RecoveryBeginDto, DaemonError> {
        Ok(self.guard.begin_recovery()?)
    }

    pub fn guard_complete_recovery(&self, token: &str) -> Result<RecoveryCompleteDto, DaemonError> {
        Ok(self.guard.complete_recovery(token)?)
    }

    #[cfg(debug_assertions)]
    pub fn debug_set_guard_state(
        &mut self,
        state: &str,
        now: u64,
    ) -> Result<GuardStatusDto, DaemonError> {
        self.guard.debug_set_state(state, now)?;
        self.guard_status()
    }

    #[cfg(debug_assertions)]
    pub fn debug_record_guard_finding(
        &mut self,
        target: &str,
        severity: &str,
        description: &str,
        now: u64,
    ) -> Result<Vec<IntegrityFindingDto>, DaemonError> {
        self.guard
            .debug_record_finding(target, severity, description, now)?;
        self.guard_findings()
    }

    #[cfg(debug_assertions)]
    pub fn debug_seed_incident(
        &mut self,
        label: Option<&str>,
        now: u64,
    ) -> Result<IncidentDetailDto, DaemonError> {
        let seed_id = uuid::Uuid::new_v4();
        let suffix = format!("{now}:{seed_id}");
        let label = label.unwrap_or("Synthetic debug incident");

        let endpoint = ObjectDescriptor {
            id: ObjectId(format!("debug:endpoint:{suffix}")),
            kind: EntityKind::NetworkEndpoint,
            label: format!("{label} endpoint"),
        };
        let threat = ObjectDescriptor {
            id: ObjectId(format!("debug:threat:{suffix}")),
            kind: EntityKind::Threat,
            label: format!("{label} threat"),
        };
        let process = ObjectDescriptor {
            id: ObjectId(format!("debug:process:{suffix}")),
            kind: EntityKind::Process,
            label: format!("{label} process"),
        };

        let threat_seed = Observation {
            id: dendrite_protocol::ObservationId(format!("debug:threat-seed:{suffix}")),
            kind: ObservationKind::Associated,
            source: endpoint.clone(),
            target: Some(threat),
            observed_at: now,
            expires_at: None,
            severity: Severity::High,
            confidence: Confidence::new(95).expect("95 is valid confidence"),
        };
        self.ingest_observation(&threat_seed)?;

        let process_observation = Observation {
            id: dendrite_protocol::ObservationId(format!("debug:process-edge:{suffix}")),
            kind: ObservationKind::NetworkConnection,
            source: process,
            target: Some(endpoint),
            observed_at: now.saturating_add(1),
            expires_at: Some(now.saturating_add(3_600)),
            severity: Severity::High,
            confidence: Confidence::new(90).expect("90 is valid confidence"),
        };
        let outcome = self.ingest_observation(&process_observation)?;
        let incident_id = outcome
            .incidents
            .first()
            .ok_or_else(|| DaemonError::Debug("debug seed did not produce an incident".into()))?
            .0
            .clone();

        self.incident_detail(&incident_id)?.ok_or_else(|| {
            DaemonError::Debug(format!("debug incident {incident_id} could not be loaded"))
        })
    }

    fn persist_object(
        &self,
        object: &ObjectDescriptor,
        observation: &Observation,
        is_target: bool,
    ) -> Result<(), DaemonError> {
        let retention = map_retention(object, observation, is_target);
        let mut node = MemoryNode {
            id: self.local_memory_node_id(&object.id.0),
            kind: map_entity_kind(object.kind),
            label: object.label.clone(),
            created_at: observation.observed_at,
            last_seen_at: observation.observed_at,
            expires_at: object_expiry(object, observation, is_target, retention),
            state: MemoryState::Observed,
            priority: map_priority(observation.severity),
            retention,
            decay_policy: DecayPolicy::None,
            provenance: MemoryProvenance::local(self.instance_id.clone()),
        };
        if let Some(existing) = self.memory.load_node(&node.id)? {
            node.created_at = existing.created_at;
            node.last_seen_at = existing.last_seen_at.max(observation.observed_at);
            node.state = if existing.state.is_active_for_reasoning() {
                existing.state
            } else {
                MemoryState::Observed
            };
            node.priority = existing.priority.max(node.priority);
            node.retention = stronger_retention(existing.retention, node.retention);
            node.expires_at = match (existing.expires_at, node.expires_at) {
                (None, _) | (_, None) => None,
                (Some(left), Some(right)) => Some(left.max(right)),
            };
        }
        self.memory.save_node(&node)?;
        self.knowledge.record_object_correlations(
            &node.id.0,
            object,
            node.provenance
                .origin_instance_id
                .as_deref()
                .unwrap_or(&self.instance_id),
            observation.observed_at,
        )?;
        Ok(())
    }

    fn persist_relationship(
        &self,
        observation: &Observation,
    ) -> Result<Option<MemoryRelationshipId>, DaemonError> {
        let Some(target) = &observation.target else {
            return Ok(None);
        };
        let relationship = MemoryRelationship {
            id: MemoryRelationshipId(format!("{}::obs:{}", self.instance_id, observation.id.0)),
            kind: map_relationship_kind(observation.kind),
            source: self.local_memory_node_id(&observation.source.id.0),
            target: self.local_memory_node_id(&target.id.0),
            created_at: observation.observed_at,
            last_seen_at: observation.observed_at,
            observation_count: 1,
            expires_at: observation.expires_at,
            state: MemoryState::Observed,
            priority: map_priority(observation.severity),
            retention: map_relationship_retention(observation),
            decay_policy: DecayPolicy::Linear {
                rate: DecayRate::new(10).expect("10 must be a valid decay rate"),
            },
            strength: MemoryStrength::new(observation.confidence.value())
                .expect("protocol confidence is constrained to 0..=100"),
            confidence: MemoryConfidence::new(observation.confidence.value())
                .expect("protocol confidence is constrained to 0..=100"),
            reinforcement: None,
            provenance: MemoryProvenance::local(self.instance_id.clone()),
        };
        Ok(Some(self.memory.observe_relationship(&relationship)?))
    }
}

fn preserve_short_term_connectors(memory: &MemoryStore, now: u64) -> Result<(), StorageError> {
    for mut node in memory.expired_nodes(now)? {
        if node.retention != RetentionClass::ShortTerm {
            continue;
        }

        // A node is allowed to outlive its own TTL only when an active relationship that
        // explicitly references this exact node still outlives it. Merely sharing a label
        // (for example every `mv`) or being adjacent to a longer-lived node is not enough.
        // Relationship TTL is never extended here, which prevents connector cycles from
        // keeping one another alive indefinitely.
        let connector_expiry = memory
            .relationships_for(&node.id)?
            .into_iter()
            .filter(|relationship| relationship.state.is_active_for_reasoning())
            .filter_map(|relationship| relationship.expires_at)
            .filter(|expires_at| *expires_at > now)
            .max();

        let Some(connector_expiry) = connector_expiry else {
            continue;
        };

        let hard_limit = node
            .created_at
            .saturating_add(REINFORCED_STM_HARD_LIFETIME_SECONDS);
        let extended_expiry = connector_expiry.min(hard_limit);
        if extended_expiry > now {
            node.expires_at = Some(extended_expiry);
            memory.save_node(&node)?;
        }
    }
    Ok(())
}

fn reinforced_expiry(created_at: u64, now: u64, qualified_links: usize) -> u64 {
    let logarithmic_steps = usize::BITS
        .saturating_sub((qualified_links.saturating_add(1)).leading_zeros())
        .saturating_sub(1) as u64;
    let ttl = REINFORCED_STM_BASE_TTL_SECONDS
        .saturating_add(REINFORCED_STM_STEP_SECONDS.saturating_mul(logarithmic_steps))
        .min(REINFORCED_STM_MAX_TTL_SECONDS);
    now.saturating_add(ttl)
        .min(created_at.saturating_add(REINFORCED_STM_HARD_LIFETIME_SECONDS))
}

fn short_instance_id(instance_id: &str) -> &str {
    let end = instance_id
        .char_indices()
        .nth(8)
        .map_or(instance_id.len(), |(index, _)| index);
    &instance_id[..end]
}

fn local_memory_node_id(instance_id: &str, local_id: &str) -> MemoryNodeId {
    MemoryNodeId(format!("{instance_id}::{local_id}"))
}

fn seeds_threat_knowledge(observation: &Observation) -> bool {
    observation.kind == ObservationKind::Associated
        && observation
            .target
            .as_ref()
            .is_some_and(|target| target.kind == EntityKind::Threat)
}

/// One routine job's outcome from inside a batch closure: whatever this
/// batch's own connection could apply directly (STM-destined writes,
/// already durable once the batch commits) plus whatever it could not
/// (anything that resolved to LTM retention, which must go through the
/// ordinary cross-tier-aware `save_node`/`save_relationship` afterward -
/// see `DeferredSave`).
struct BatchJobResult {
    relationship_id: Option<MemoryRelationshipId>,
    seeds_threat_knowledge: bool,
    threat_paths: Vec<(String, ThreatPath)>,
    deferred_saves: Vec<DeferredSave>,
}

/// A node or relationship whose merged retention turned out to be
/// LongTerm/Persistent rather than ShortTerm. Batched routine ingestion
/// only ever writes directly to the STM writer's own connection - writing
/// an LTM-destined item there would leave it stranded in the wrong tier (or
/// worse, diverging from an existing LTM copy this same connection can only
/// read, never write, since it is attached `mode=ro`). Deferring it to the
/// caller's normal `MemoryStore::save_node`/`save_relationship` after the
/// batch reuses the exact destination-first promotion logic that already
/// handles this outside of batching.
enum DeferredSave {
    Node(MemoryNode),
    Relationship(MemoryRelationship),
}

/// The batched, connection-direct counterpart to
/// `DaemonCore::persist_object` + `persist_relationship` + the threat-path
/// search in `ingest_observation_with_max_depth`, run once per job inside
/// `DaemonCore::ingest_routine_batch`'s single `run_stm_batch` closure. Its
/// reads (`reader.load_node`, `reader.find_relationship_id`,
/// `reader.threat_paths_from`) see every earlier job's writes in the same
/// batch, because they share one connection - the correctness property
/// that ruled out a read-once-upfront batching plan.
///
/// Kept deliberately separate from `persist_object`/`persist_relationship`
/// rather than parameterising them over "how to read/write" - those two
/// also drive `record_object_correlations` and reinforcement bookkeeping
/// that this batched path intentionally defers to after the batch (see
/// `ingest_routine_batch`'s doc comment), so unifying them would either
/// drag those subsystems into the batch transaction too or leave the
/// single-item path with unused generality. Retention/priority/expiry
/// decisions themselves (`map_retention`, `object_expiry`, `stronger_retention`,
/// ...) are the same pure functions both paths call.
fn run_batched_job(
    connection: &Connection,
    reader: &GraphReader<'_>,
    instance_id: &str,
    observation: &Observation,
    max_depth: usize,
) -> Result<BatchJobResult, StorageError> {
    let mut deferred_saves = Vec::new();

    persist_object_batched(
        connection,
        reader,
        instance_id,
        &observation.source,
        observation,
        false,
        &mut deferred_saves,
    )?;
    if let Some(target) = &observation.target {
        persist_object_batched(
            connection,
            reader,
            instance_id,
            target,
            observation,
            true,
            &mut deferred_saves,
        )?;
    }
    let relationship_id = persist_relationship_batched(
        connection,
        reader,
        instance_id,
        observation,
        &mut deferred_saves,
    )?;

    let seeds = seeds_threat_knowledge(observation);
    let mut threat_paths: Vec<(String, ThreatPath)> = Vec::new();
    if !seeds {
        let query = PathQuery {
            max_depth,
            direction: TraversalDirection::Any,
            evaluation_time: Some(observation.observed_at),
            max_relationships_per_node: Some(MAX_RELATIONSHIPS_PER_NODE_FOR_REASONING),
            ..PathQuery::default()
        };
        if observation.source.kind != EntityKind::Threat {
            let start = local_memory_node_id(instance_id, &observation.source.id.0);
            for finding in reader.threat_paths_from(&start, &query)? {
                threat_paths.push((observation.source.id.0.clone(), finding));
            }
        }
        if threat_paths.is_empty()
            && let Some(target) = &observation.target
            && target.kind != EntityKind::Threat
        {
            let start = local_memory_node_id(instance_id, &target.id.0);
            for finding in reader.threat_paths_from(&start, &query)? {
                threat_paths.push((target.id.0.clone(), finding));
            }
        }
    }

    Ok(BatchJobResult {
        relationship_id,
        seeds_threat_knowledge: seeds,
        threat_paths,
        deferred_saves,
    })
}

fn persist_object_batched(
    connection: &Connection,
    reader: &GraphReader<'_>,
    instance_id: &str,
    object: &ObjectDescriptor,
    observation: &Observation,
    is_target: bool,
    deferred_saves: &mut Vec<DeferredSave>,
) -> Result<(), StorageError> {
    let retention = map_retention(object, observation, is_target);
    let mut node = MemoryNode {
        id: local_memory_node_id(instance_id, &object.id.0),
        kind: map_entity_kind(object.kind),
        label: object.label.clone(),
        created_at: observation.observed_at,
        last_seen_at: observation.observed_at,
        expires_at: object_expiry(object, observation, is_target, retention),
        state: MemoryState::Observed,
        priority: map_priority(observation.severity),
        retention,
        decay_policy: DecayPolicy::None,
        provenance: MemoryProvenance::local(instance_id.to_owned()),
    };
    if let Some(existing) = reader.load_node(&node.id)? {
        node.created_at = existing.created_at;
        node.last_seen_at = existing.last_seen_at.max(observation.observed_at);
        node.state = if existing.state.is_active_for_reasoning() {
            existing.state
        } else {
            MemoryState::Observed
        };
        node.priority = existing.priority.max(node.priority);
        node.retention = stronger_retention(existing.retention, node.retention);
        node.expires_at = match (existing.expires_at, node.expires_at) {
            (None, _) | (_, None) => None,
            (Some(left), Some(right)) => Some(left.max(right)),
        };
    }

    if node.retention == RetentionClass::ShortTerm {
        let created_at = node.created_at;
        execute_node_upsert(connection, &node, created_at).map_err(StorageError::Database)?;
    } else {
        deferred_saves.push(DeferredSave::Node(node));
    }
    Ok(())
}

fn persist_relationship_batched(
    connection: &Connection,
    reader: &GraphReader<'_>,
    instance_id: &str,
    observation: &Observation,
    deferred_saves: &mut Vec<DeferredSave>,
) -> Result<Option<MemoryRelationshipId>, StorageError> {
    let Some(target) = &observation.target else {
        return Ok(None);
    };
    let mut relationship = MemoryRelationship {
        id: MemoryRelationshipId(format!("{instance_id}::obs:{}", observation.id.0)),
        kind: map_relationship_kind(observation.kind),
        source: local_memory_node_id(instance_id, &observation.source.id.0),
        target: local_memory_node_id(instance_id, &target.id.0),
        created_at: observation.observed_at,
        last_seen_at: observation.observed_at,
        observation_count: 1,
        expires_at: observation.expires_at,
        state: MemoryState::Observed,
        priority: map_priority(observation.severity),
        retention: map_relationship_retention(observation),
        decay_policy: DecayPolicy::Linear {
            rate: DecayRate::new(10).expect("10 must be a valid decay rate"),
        },
        strength: MemoryStrength::new(observation.confidence.value())
            .expect("protocol confidence is constrained to 0..=100"),
        confidence: MemoryConfidence::new(observation.confidence.value())
            .expect("protocol confidence is constrained to 0..=100"),
        reinforcement: None,
        provenance: MemoryProvenance::local(instance_id.to_owned()),
    };

    // Mirrors `MemoryStore::observe_relationship`: consolidate onto an
    // existing active edge of the same kind/source/target rather than
    // always minting a new relationship id.
    let id = if let Some(existing_id) = reader.find_relationship_id(
        relationship.kind,
        &relationship.source,
        &relationship.target,
    )? {
        let Some(mut existing) = reader.load_relationship(&existing_id)? else {
            return Ok(Some(existing_id));
        };
        existing.record_observation(relationship.last_seen_at);
        existing.expires_at = match (existing.expires_at, relationship.expires_at) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (None, other) | (other, None) => other,
        };
        existing.priority = existing.priority.max(relationship.priority);
        existing.strength = existing.strength.max(relationship.strength);
        existing.confidence = existing.confidence.max(relationship.confidence);
        if existing.state == MemoryState::Expired {
            existing.state = MemoryState::Observed;
        }
        relationship = existing;
        existing_id
    } else {
        relationship.id.clone()
    };

    if relationship.retention == RetentionClass::ShortTerm {
        let created_at = relationship.created_at;
        execute_relationship_upsert(connection, &relationship, created_at)
            .map_err(StorageError::Database)?;
    } else {
        deferred_saves.push(DeferredSave::Relationship(relationship));
    }
    Ok(Some(id))
}

fn map_entity_kind(kind: EntityKind) -> MemoryNodeKind {
    match kind {
        EntityKind::Process => MemoryNodeKind::Process,
        EntityKind::File => MemoryNodeKind::File,
        EntityKind::User => MemoryNodeKind::User,
        EntityKind::Host => MemoryNodeKind::Host,
        EntityKind::NetworkEndpoint => MemoryNodeKind::NetworkEndpoint,
        EntityKind::Service => MemoryNodeKind::Service,
        EntityKind::Container => MemoryNodeKind::Container,
        EntityKind::Incident => MemoryNodeKind::Incident,
        EntityKind::Threat => MemoryNodeKind::Threat,
    }
}

fn map_relationship_kind(kind: ObservationKind) -> MemoryRelationshipKind {
    match kind {
        ObservationKind::ProcessStarted => MemoryRelationshipKind::Spawned,
        ObservationKind::FileExecuted => MemoryRelationshipKind::Executed,
        ObservationKind::FileRead => MemoryRelationshipKind::Read,
        ObservationKind::FileWritten => MemoryRelationshipKind::Wrote,
        ObservationKind::NetworkConnection => MemoryRelationshipKind::ConnectedTo,
        ObservationKind::ServiceInteraction | ObservationKind::Associated => {
            MemoryRelationshipKind::AssociatedWith
        }
    }
}

fn map_priority(severity: Severity) -> MemoryPriority {
    match severity {
        Severity::Low => MemoryPriority::Low,
        Severity::Medium => MemoryPriority::Normal,
        Severity::High => MemoryPriority::High,
        Severity::Critical => MemoryPriority::Critical,
    }
}

fn stronger_retention(left: RetentionClass, right: RetentionClass) -> RetentionClass {
    match (left, right) {
        (RetentionClass::Persistent, _) | (_, RetentionClass::Persistent) => {
            RetentionClass::Persistent
        }
        (RetentionClass::LongTerm, _) | (_, RetentionClass::LongTerm) => RetentionClass::LongTerm,
        _ => RetentionClass::ShortTerm,
    }
}

fn map_retention(
    object: &ObjectDescriptor,
    observation: &Observation,
    is_target: bool,
) -> RetentionClass {
    match object.kind {
        EntityKind::Threat => RetentionClass::LongTerm,
        EntityKind::Incident | EntityKind::Host => RetentionClass::Persistent,
        EntityKind::User => RetentionClass::LongTerm,
        EntityKind::Process if object.id.0.starts_with("process_identity:") => {
            RetentionClass::LongTerm
        }
        EntityKind::File if is_target && observation.kind == ObservationKind::FileExecuted => {
            RetentionClass::LongTerm
        }
        _ => RetentionClass::ShortTerm,
    }
}

fn map_relationship_retention(observation: &Observation) -> RetentionClass {
    match observation.kind {
        ObservationKind::FileExecuted
            if observation.source.id.0.starts_with("process_identity:") =>
        {
            RetentionClass::LongTerm
        }
        _ => RetentionClass::ShortTerm,
    }
}

fn object_expiry(
    object: &ObjectDescriptor,
    observation: &Observation,
    is_target: bool,
    retention: RetentionClass,
) -> Option<u64> {
    let durable_identity = matches!(object.kind, EntityKind::Host | EntityKind::User)
        || object.id.0.starts_with("process_identity:")
        || (object.kind == EntityKind::File
            && is_target
            && observation.kind == ObservationKind::FileExecuted);

    if durable_identity && retention != RetentionClass::ShortTerm {
        None
    } else {
        observation.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GuardEvaluator, GuardStoreError, MagiEvaluator};
    use dendrite_protocol::{
        ActionProposal, Evaluation, Evaluator, EvaluatorVerdict, GuardDecision, GuardStatusDto,
        IntegrityFindingDto, ObjectDescriptor, ObservationId, TrustState,
    };

    /// `DaemonCore::open` (unlike `DaemonRuntime::open`) never wires in a
    /// `magi_socket_path`, so its `ActionService` defaults to a real
    /// `MagiIpcClient` pointed at nothing — correctly fail-closed
    /// (`not_authorised`) with no `dendrite-magi` process to answer it.
    /// Tests here that exercise a full action evaluation swap in this
    /// always-decides-in-process stand-in, the same way `actions.rs`'s own
    /// tests do, rather than relying on a real socket being present.
    struct TestRuleMagiEvaluator;

    impl MagiEvaluator for TestRuleMagiEvaluator {
        fn evaluate(
            &self,
            action: dendrite_protocol::ActionType,
            user_authorised: bool,
        ) -> Vec<(Evaluation, String)> {
            let safe = action.is_safe_non_privileged();
            let package_update = action == dendrite_protocol::ActionType::UpdatePackage;

            vec![
                (
                    Evaluation {
                        evaluator: Evaluator::Host,
                        verdict: if safe || package_update {
                            EvaluatorVerdict::Approve
                        } else {
                            EvaluatorVerdict::Abstain
                        },
                    },
                    "BALTHASAR-2: test evaluator".into(),
                ),
                (
                    Evaluation {
                        evaluator: Evaluator::User,
                        verdict: if package_update && user_authorised {
                            EvaluatorVerdict::Approve
                        } else if package_update {
                            EvaluatorVerdict::Deny
                        } else {
                            EvaluatorVerdict::Abstain
                        },
                    },
                    "CASPER-3: test evaluator".into(),
                ),
                (
                    Evaluation {
                        evaluator: Evaluator::Environment,
                        verdict: if safe || package_update {
                            EvaluatorVerdict::Approve
                        } else {
                            EvaluatorVerdict::Abstain
                        },
                    },
                    "MELCHIOR-1: test evaluator".into(),
                ),
            ]
        }
    }

    /// `DaemonCore::open` also never wires in a `guard_socket_path`, so its
    /// `GuardService` defaults to a real `GuardIpcClient` pointed at
    /// nothing too — correctly fail-closed (`Compromised`/`Deny`) with no
    /// `dendrite-guard` process to answer it. Tests here that need a
    /// working (trusted) Guard swap this in instead, the same way
    /// `TestRuleMagiEvaluator` stands in for MAGI above.
    struct TrustedGuardEvaluator;

    impl GuardEvaluator for TrustedGuardEvaluator {
        fn trust_state(&self) -> TrustState {
            TrustState::Trusted
        }

        fn evaluate_authority(&self, _proposal: &ActionProposal) -> GuardDecision {
            GuardDecision::Allow
        }

        fn status(&self) -> Result<GuardStatusDto, GuardStoreError> {
            Ok(GuardStatusDto {
                trust_state: TrustState::Trusted.as_str().into(),
                authority: "available".into(),
                findings_count: 0,
            })
        }

        fn findings(&self) -> Result<Vec<IntegrityFindingDto>, GuardStoreError> {
            Ok(Vec::new())
        }

        fn establish_baseline(&self) -> Result<IntegrityManifestStatusDto, GuardStoreError> {
            Err(GuardStoreError::Protocol(
                "establish_baseline not supported by TrustedGuardEvaluator".into(),
            ))
        }

        fn verify_integrity(&self) -> Result<IntegrityVerificationDto, GuardStoreError> {
            Err(GuardStoreError::Protocol(
                "verify_integrity not supported by TrustedGuardEvaluator".into(),
            ))
        }

        fn begin_recovery(&self) -> Result<RecoveryBeginDto, GuardStoreError> {
            Err(GuardStoreError::Protocol(
                "begin_recovery not supported by TrustedGuardEvaluator".into(),
            ))
        }

        fn complete_recovery(&self, _token: &str) -> Result<RecoveryCompleteDto, GuardStoreError> {
            Err(GuardStoreError::Protocol(
                "complete_recovery not supported by TrustedGuardEvaluator".into(),
            ))
        }

        #[cfg(debug_assertions)]
        fn debug_set_state(&self, _state: &str) -> Result<(), GuardStoreError> {
            Ok(())
        }

        #[cfg(debug_assertions)]
        fn debug_record_finding(
            &self,
            _target: &str,
            _severity: &str,
            _description: &str,
        ) -> Result<(), GuardStoreError> {
            Ok(())
        }
    }

    fn object(id: &str, kind: EntityKind) -> ObjectDescriptor {
        ObjectDescriptor {
            id: ObjectId(id.into()),
            kind,
            label: id.into(),
        }
    }

    fn observation(
        id: &str,
        kind: ObservationKind,
        source: ObjectDescriptor,
        target: ObjectDescriptor,
        confidence: u8,
    ) -> Observation {
        Observation {
            id: ObservationId(id.into()),
            kind,
            source,
            target: Some(target),
            observed_at: 100,
            expires_at: Some(1_000),
            severity: Severity::High,
            confidence: Confidence::new(confidence).unwrap(),
        }
    }

    #[test]
    fn repeated_observations_consolidate_in_memory() {
        let mut core = DaemonCore::open(":memory:").unwrap();
        let first = observation(
            "one",
            ObservationKind::NetworkConnection,
            object("proc", EntityKind::Process),
            object("endpoint", EntityKind::NetworkEndpoint),
            70,
        );
        let second = Observation {
            id: dendrite_protocol::ObservationId("two".into()),
            observed_at: 200,
            confidence: Confidence::new(90).unwrap(),
            ..first.clone()
        };
        let first_outcome = core.ingest_observation(&first).unwrap();
        let second_outcome = core.ingest_observation(&second).unwrap();
        assert_eq!(
            first_outcome.relationship_id,
            second_outcome.relationship_id
        );
        let relationship = core
            .memory()
            .load_relationship(first_outcome.relationship_id.as_ref().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(relationship.observation_count, 2);
        assert_eq!(relationship.confidence.value(), 90);
    }

    #[test]
    fn routine_batch_consolidates_repeated_observations_within_one_batch() {
        // Same scenario as `repeated_observations_consolidate_in_memory`,
        // but both observations go through `ingest_routine_batch` in a
        // single call - this is exactly the correctness property that
        // ruled out a read-once-upfront batching plan: the second
        // observation's read must see the first observation's write, even
        // though both are in the same batch and neither has been through
        // the ordinary per-item `save_relationship` path.
        let mut core = DaemonCore::open(":memory:").unwrap();
        let first = observation(
            "one",
            ObservationKind::NetworkConnection,
            object("proc", EntityKind::Process),
            object("endpoint", EntityKind::NetworkEndpoint),
            70,
        );
        let second = Observation {
            id: dendrite_protocol::ObservationId("two".into()),
            observed_at: 200,
            confidence: Confidence::new(90).unwrap(),
            ..first.clone()
        };

        let mut outcomes = core.ingest_routine_batch(vec![(first, 6), (second, 6)]);
        assert_eq!(outcomes.len(), 2);
        let second_outcome = outcomes.pop().unwrap().unwrap();
        let first_outcome = outcomes.pop().unwrap().unwrap();

        assert_eq!(
            first_outcome.relationship_id, second_outcome.relationship_id,
            "both observations in the batch must consolidate onto the same relationship"
        );
        let relationship = core
            .memory()
            .load_relationship(first_outcome.relationship_id.as_ref().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(relationship.observation_count, 2);
        assert_eq!(relationship.confidence.value(), 90);
    }

    #[test]
    fn routine_batch_results_line_up_one_to_one_with_input_jobs() {
        let mut core = DaemonCore::open(":memory:").unwrap();
        let jobs: Vec<(Observation, usize)> = (0..5)
            .map(|index| {
                let id = format!("obs-{index}");
                (
                    observation(
                        &id,
                        ObservationKind::NetworkConnection,
                        object(&format!("proc-{index}"), EntityKind::Process),
                        object(&format!("endpoint-{index}"), EntityKind::NetworkEndpoint),
                        50,
                    ),
                    6,
                )
            })
            .collect();
        let expected_sources: Vec<String> = jobs
            .iter()
            .map(|(observation, _)| observation.source.id.0.clone())
            .collect();

        let outcomes = core.ingest_routine_batch(jobs);
        assert_eq!(outcomes.len(), 5);
        for (index, outcome) in outcomes.into_iter().enumerate() {
            let outcome = outcome.unwrap();
            let relationship_id = outcome.relationship_id.expect("relationship was created");
            let relationship = core
                .memory()
                .load_relationship(&relationship_id)
                .unwrap()
                .unwrap();
            let source_node = core
                .memory()
                .load_node(&relationship.source)
                .unwrap()
                .unwrap();
            assert!(
                source_node.id.0.ends_with(&expected_sources[index]),
                "job {index}'s outcome must correspond to job {index}'s own observation"
            );
        }
    }

    #[test]
    fn memory_node_display_is_clean_for_local_nodes_and_origin_aware_for_foreign_nodes() {
        let core = DaemonCore::open(":memory:").unwrap();
        let local_id = core.local_memory_node_id("proc");
        core.memory
            .save_node(&MemoryNode {
                id: local_id.clone(),
                kind: MemoryNodeKind::Process,
                label: "proc".into(),
                created_at: 1,
                last_seen_at: 1,
                expires_at: None,
                state: MemoryState::Observed,
                priority: MemoryPriority::Normal,
                retention: RetentionClass::ShortTerm,
                decay_policy: DecayPolicy::None,
                provenance: MemoryProvenance::local(core.instance_id().to_string()),
            })
            .unwrap();
        assert_eq!(core.display_memory_node(&local_id).unwrap(), "proc");

        let foreign_id = MemoryNodeId("aaaaaaaa-0000-0000-0000-000000000000::proc".into());
        core.memory
            .save_node(&MemoryNode {
                id: foreign_id.clone(),
                kind: MemoryNodeKind::Process,
                label: "proc".into(),
                created_at: 1,
                last_seen_at: 1,
                expires_at: None,
                state: MemoryState::Observed,
                priority: MemoryPriority::Normal,
                retention: RetentionClass::ShortTerm,
                decay_policy: DecayPolicy::None,
                provenance: MemoryProvenance::new(
                    Some("aaaaaaaa-0000-0000-0000-000000000000".into()),
                    Some("bbbbbbbb-0000-0000-0000-000000000000".into()),
                    Some("cccccccc-0000-0000-0000-000000000000".into()),
                    vec![
                        "aaaaaaaa-0000-0000-0000-000000000000".into(),
                        "bbbbbbbb-0000-0000-0000-000000000000".into(),
                        "cccccccc-0000-0000-0000-000000000000".into(),
                    ],
                ),
            })
            .unwrap();
        assert_eq!(
            core.display_memory_node(&foreign_id).unwrap(),
            "proc (origin aaaaaaaa, via bbbbbbbb, derived by cccccccc)"
        );
    }

    #[test]
    fn debug_seed_incident_uses_unique_graph_ids_even_at_same_timestamp() {
        let mut core = DaemonCore::open(":memory:").unwrap();

        let first = core
            .debug_seed_incident(Some("synthetic-a"), 1_000)
            .unwrap();
        let second = core
            .debug_seed_incident(Some("synthetic-b"), 1_000)
            .unwrap();

        assert_ne!(first.related_objects, second.related_objects);
        assert!(
            first
                .related_objects
                .iter()
                .all(|id| id.contains("::debug:"))
        );
        assert!(
            second
                .related_objects
                .iter()
                .all(|id| id.contains("::debug:"))
        );

        let first_ids = first
            .related_objects
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        let second_ids = second
            .related_objects
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        assert!(first_ids.is_disjoint(&second_ids));
    }

    #[test]
    fn graph_findings_correlate_into_one_persistent_incident() {
        let mut core = DaemonCore::open(":memory:").unwrap();
        core.actions
            .set_magi_evaluator(Box::new(TestRuleMagiEvaluator));
        core.guard
            .set_guard_evaluator(Box::new(TrustedGuardEvaluator));
        let instance_id = core.instance_id().to_string();
        let threat_edge = observation(
            "threat-edge",
            ObservationKind::Associated,
            object("endpoint", EntityKind::NetworkEndpoint),
            object("known-threat", EntityKind::Threat),
            95,
        );
        core.ingest_observation(&threat_edge).unwrap();

        let process_edge = observation(
            "process-edge",
            ObservationKind::NetworkConnection,
            object("proc", EntityKind::Process),
            object("endpoint", EntityKind::NetworkEndpoint),
            90,
        );
        let first = core.ingest_observation(&process_edge).unwrap();
        let mut repeated = process_edge.clone();
        repeated.id = ObservationId("process-edge-2".into());
        repeated.observed_at = 200;
        let second = core.ingest_observation(&repeated).unwrap();

        assert_eq!(first.incidents, second.incidents);
        let detail = core
            .incident_detail(&first.incidents[0].0)
            .unwrap()
            .unwrap();
        assert_eq!(detail.incident.evidence_count, 2);
        assert_eq!(
            detail.related_objects,
            vec![
                format!("{instance_id}::endpoint"),
                format!("{instance_id}::known-threat"),
                format!("{instance_id}::proc"),
            ]
        );
        assert!(detail.evidence.iter().all(|evidence| {
            evidence
                .description
                .contains("proc -> endpoint -> known-threat")
        }));

        let proposal = core
            .create_action(&first.incidents[0].0, "observe", "proc", 300)
            .unwrap();
        assert_eq!(proposal.proposal.incident_id, first.incidents[0].0);

        let evaluated = core.evaluate_action(&proposal.proposal.id, 301).unwrap();
        assert_eq!(evaluated.proposal.status, "completed");
    }

    #[test]
    fn reclassify_all_attack_chains_matches_behaviour_knowledge_added_after_chain_creation() {
        use crate::BehaviourDefinition;

        let mut core = DaemonCore::open(":memory:").unwrap();

        let threat_edge = observation(
            "threat-edge",
            ObservationKind::Associated,
            object("endpoint", EntityKind::NetworkEndpoint),
            object("known-threat", EntityKind::Threat),
            95,
        );
        core.ingest_observation(&threat_edge).unwrap();

        let process_edge = observation(
            "process-edge",
            ObservationKind::NetworkConnection,
            object("proc", EntityKind::Process),
            object("endpoint", EntityKind::NetworkEndpoint),
            90,
        );
        core.ingest_observation(&process_edge).unwrap();

        let chains_before = core.analysis_attack_chains().unwrap();
        assert_eq!(chains_before.len(), 1);
        let chain_id = chains_before[0].id.clone();
        assert!(chains_before[0].matched_cve_ids.is_empty());
        assert!(
            !chains_before[0]
                .behaviour_ids
                .contains(&"behaviour:test-imported".to_string())
        );

        // The chain's auto-derived "observed" behaviour already carries the
        // exact graph-relation conditions the classifier computed for this
        // chain's actual step order (which is an internal detail of the
        // correlation/path-finding engine, not something this test should
        // assume). Reuse that same condition shape for the custom behaviour
        // below, so this test verifies "newly added knowledge matching an
        // existing chain's real shape" without being coupled to exactly how
        // that shape is derived.
        assert_eq!(chains_before[0].behaviour_ids.len(), 1);
        let observed_conditions = core
            .knowledge
            .behaviour(&chains_before[0].behaviour_ids[0])
            .unwrap()
            .expect("auto-derived observed behaviour must exist")
            .conditions;
        assert!(
            !observed_conditions.is_empty(),
            "expected the observed chain to have derived graph-relation conditions"
        );

        // Behaviour knowledge added *after* the chain already exists —
        // mirrors a `vulnerability import` happening later. Conditions are
        // written here in their normalised form (with an explicit
        // "kind": "graph-relation" tag) since this goes straight through
        // `KnowledgeService::upsert_behaviour`, bypassing the CVE-bundle
        // import path in `vulnerability.rs`, which validates that tag is
        // present rather than injecting it for hand-authored bundles that
        // omit it (see `validate_behaviour_condition`).
        let behaviour = BehaviourDefinition {
            id: "behaviour:test-imported".into(),
            name: "Imported test behaviour".into(),
            description: "test".into(),
            confidence: 85,
            severity: "high".into(),
            techniques: Vec::new(),
            conditions: observed_conditions,
            ordered: true,
            max_interval_seconds: Some(3_600),
            source_refs: vec!["test".into()],
            fingerprint: None,
            origin_instance_id: None,
            imported_from_instance_id: None,
            derived_by_instance_id: None,
            lineage: Vec::new(),
            created_at: 1,
            updated_at: 1,
        };
        core.knowledge.upsert_behaviour(&behaviour).unwrap();

        let (reclassified_count, matched_cve_ids) = core.reclassify_all_attack_chains(200).unwrap();
        assert_eq!(reclassified_count, 1);
        assert!(
            matched_cve_ids.is_empty(),
            "this behaviour has no associated CVE"
        );

        let chains_after = core.analysis_attack_chains().unwrap();
        assert_eq!(chains_after.len(), 1);
        assert_eq!(
            chains_after[0].id, chain_id,
            "canonical chain id must not change when retroactively classified"
        );
        assert!(
            chains_after[0]
                .behaviour_ids
                .contains(&"behaviour:test-imported".to_string())
        );
    }

    #[test]
    fn reinforcing_the_same_chain_does_not_create_a_second_automatic_export() {
        let mut core = DaemonCore::open(":memory:").unwrap();
        core.guard
            .set_guard_evaluator(Box::new(TrustedGuardEvaluator));

        let threat_edge = observation(
            "threat-edge",
            ObservationKind::Associated,
            object("endpoint", EntityKind::NetworkEndpoint),
            object("known-threat", EntityKind::Threat),
            95,
        );
        core.ingest_observation(&threat_edge).unwrap();

        let process_edge = observation(
            "process-edge",
            ObservationKind::NetworkConnection,
            object("proc", EntityKind::Process),
            object("endpoint", EntityKind::NetworkEndpoint),
            90,
        );
        core.ingest_observation(&process_edge).unwrap();

        let automatic_count = |core: &DaemonCore| {
            core.analysis_packages(1_000)
                .unwrap()
                .into_iter()
                .filter(|package| package.origin == AntiserumPackageOrigin::AutomaticExport)
                .count()
        };
        assert_eq!(
            automatic_count(&core),
            1,
            "the first significant path should produce exactly one automatic export"
        );

        // Reinforce the same incident/pattern with a second observation of
        // the same shape. This creates a new evidence row (and therefore a
        // new literal chain_id) for the same incident, exactly like a
        // real ongoing attack chain being observed again.
        let mut repeated = process_edge.clone();
        repeated.id = ObservationId("process-edge-2".into());
        repeated.observed_at = 200;
        core.ingest_observation(&repeated).unwrap();

        assert_eq!(
            automatic_count(&core),
            1,
            "reinforcing the same chain shape must not create a second automatic export"
        );
    }

    #[test]
    fn health_check_reports_ok_when_every_store_responds() {
        let mut core = DaemonCore::open(":memory:").unwrap();
        core.guard
            .set_guard_evaluator(Box::new(TrustedGuardEvaluator));
        let health = core.health_check().unwrap();
        assert_eq!(health.daemon, "ok");
        assert_eq!(health.memory, "ok");
        assert_eq!(health.guard, "trusted");
    }

    /// Regression test: `health_check()` must read `guard.trust_state()`
    /// (infallible, safe-value fallback), not `guard_status()` (genuinely
    /// fallible, since it also feeds signed Antiserum attestations). A
    /// health check exists specifically to stay informative when something
    /// is unhealthy — it must not itself error out just because
    /// `dendrite-guard` is unreachable, the same way `daemon`/`memory`
    /// report `"error"` rather than failing the whole call.
    #[test]
    fn health_check_reports_compromised_rather_than_erroring_when_guard_is_unreachable() {
        // `DaemonCore::open`'s default guard is a real `GuardIpcClient`
        // pointed at nothing in this test environment — exactly the
        // "dendrite-guard isn't running" case this test targets.
        let core = DaemonCore::open(":memory:").unwrap();
        let health = core.health_check().unwrap();
        assert_eq!(health.daemon, "ok");
        assert_eq!(health.memory, "ok");
        assert_eq!(health.guard, "compromised");
    }

    #[test]
    fn executable_identity_is_long_term_while_execution_instance_is_short_term() {
        let source = ObjectDescriptor {
            id: ObjectId("process:123:1".into()),
            kind: EntityKind::Process,
            label: "git".into(),
        };
        let target = ObjectDescriptor {
            id: ObjectId("file:/usr/bin/git".into()),
            kind: EntityKind::File,
            label: "/usr/bin/git".into(),
        };
        let observation = Observation {
            id: ObservationId("exec-1".into()),
            kind: ObservationKind::FileExecuted,
            source: source.clone(),
            target: Some(target.clone()),
            observed_at: 100,
            expires_at: Some(3_700),
            severity: Severity::Low,
            confidence: Confidence::new(100).unwrap(),
        };

        assert_eq!(
            map_retention(&source, &observation, false),
            RetentionClass::ShortTerm
        );
        assert_eq!(
            map_retention(&target, &observation, true),
            RetentionClass::LongTerm
        );
        assert_eq!(
            map_relationship_retention(&observation),
            RetentionClass::ShortTerm
        );

        let unresolved_identity = ObjectDescriptor {
            id: ObjectId("process_identity:comm:123".into()),
            kind: EntityKind::Process,
            label: "git".into(),
        };
        assert_eq!(
            map_retention(&unresolved_identity, &observation, false),
            RetentionClass::LongTerm
        );
    }

    #[test]
    fn reinforced_expiry_is_bounded_and_sublinear() {
        let one = reinforced_expiry(100, 200, 1);
        let two = reinforced_expiry(100, 200, 2);
        let eight = reinforced_expiry(100, 200, 8);
        let many = reinforced_expiry(100, 20_000, 10_000);
        assert!(two >= one);
        assert!(eight >= two);
        assert!(many <= 100 + REINFORCED_STM_HARD_LIFETIME_SECONDS);
    }

    #[test]
    fn significant_path_reinforces_only_specific_short_term_instance() {
        let mut core = DaemonCore::open(":memory:").unwrap();
        let mv_identity = object("process_identity:comm:mv", EntityKind::Process);
        let mv_instance = object("process:4242:1", EntityKind::Process);
        let infected = object("file:/tmp/infected", EntityKind::File);
        let threat = object("threat:test", EntityKind::Threat);

        let identity_edge = observation(
            "identity-edge",
            ObservationKind::FileExecuted,
            mv_instance.clone(),
            mv_identity.clone(),
            90,
        );
        core.ingest_observation(&identity_edge).unwrap();

        let threat_edge = observation(
            "threat-edge-specific",
            ObservationKind::Associated,
            infected.clone(),
            threat,
            95,
        );
        core.ingest_observation(&threat_edge).unwrap();

        let move_edge = observation(
            "move-edge-specific",
            ObservationKind::FileWritten,
            mv_instance.clone(),
            infected,
            95,
        );
        let outcome = core.ingest_observation(&move_edge).unwrap();
        assert!(!outcome.incidents.is_empty());

        let instance = core
            .memory()
            .load_node(&core.local_memory_node_id(&mv_instance.id.0))
            .unwrap()
            .unwrap();
        let identity = core
            .memory()
            .load_node(&core.local_memory_node_id(&mv_identity.id.0))
            .unwrap()
            .unwrap();
        assert_eq!(instance.state, MemoryState::Supported);
        assert_eq!(identity.retention, RetentionClass::LongTerm);
        assert_ne!(identity.state, MemoryState::Supported);
    }
}
