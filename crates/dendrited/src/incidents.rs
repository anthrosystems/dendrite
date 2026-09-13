use dendrite_protocol::{
    EvidenceCandidate, EvidenceDto, EvidenceId, EvidenceObjectRef, EvidenceSource,
    IncidentDetailDto, IncidentId, IncidentSummaryDto, Severity,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::time::Duration;

#[derive(Debug)]
pub enum IncidentStoreError {
    Database(rusqlite::Error),
    InvalidSeverity(String),
    InvalidEvidenceLineage(String),
}

impl From<rusqlite::Error> for IncidentStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

fn configure_connection(connection: &Connection, path: &str) -> rusqlite::Result<()> {
    connection.busy_timeout(Duration::from_secs(5))?;
    if path != ":memory:" {
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
    }
    connection.pragma_update(None, "foreign_keys", "ON")?;
    Ok(())
}

pub struct IncidentService {
    connection: Connection,
}

impl IncidentService {
    pub fn open(path: &str) -> Result<Self, IncidentStoreError> {
        let connection = Connection::open(path)?;
        configure_connection(&connection, path)?;
        let service = Self { connection };
        service.initialise()?;
        Ok(service)
    }

    /// Cheap liveness probe for the incidents database — also the physical
    /// file backing the vulnerability/CVE/behaviour-knowledge tables (see
    /// `CONFIGURATION.md`'s note on `DENDRITE_INCIDENT_DB`), so this one
    /// check stands in for all of them.
    pub fn ping(&self) -> Result<(), IncidentStoreError> {
        self.connection.execute_batch("SELECT 1;")?;
        Ok(())
    }

    fn initialise(&self) -> Result<(), IncidentStoreError> {
        self.connection.execute_batch(
            "
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS incidents (
                id              TEXT PRIMARY KEY,
                correlation_key TEXT NOT NULL,
                severity        TEXT NOT NULL,
                summary         TEXT NOT NULL,
                status          TEXT NOT NULL,
                first_seen_at   INTEGER NOT NULL,
                last_seen_at    INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_incidents_correlation_status
                ON incidents(correlation_key, status);

            CREATE TABLE IF NOT EXISTS evidence (
                id           TEXT PRIMARY KEY,
                incident_id  TEXT NOT NULL,
                source       TEXT NOT NULL,
                description  TEXT NOT NULL,
                confidence   INTEGER NOT NULL,
                observed_at  INTEGER NOT NULL,
                FOREIGN KEY(incident_id) REFERENCES incidents(id)
            );
            CREATE INDEX IF NOT EXISTS idx_evidence_incident
                ON evidence(incident_id);

            CREATE TABLE IF NOT EXISTS evidence_objects (
                evidence_id               TEXT NOT NULL,
                position                  INTEGER NOT NULL,
                object_id                 TEXT NOT NULL,
                label                     TEXT NOT NULL,
                kind                      TEXT NOT NULL,
                origin_instance_id        TEXT,
                imported_from_instance_id TEXT,
                derived_by_instance_id    TEXT,
                lineage                   TEXT NOT NULL,
                PRIMARY KEY(evidence_id, position),
                FOREIGN KEY(evidence_id) REFERENCES evidence(id)
            );
            CREATE INDEX IF NOT EXISTS idx_evidence_objects_evidence
                ON evidence_objects(evidence_id, position);

            CREATE TABLE IF NOT EXISTS incident_objects (
                incident_id TEXT NOT NULL,
                object_id   TEXT NOT NULL,
                PRIMARY KEY(incident_id, object_id),
                FOREIGN KEY(incident_id) REFERENCES incidents(id)
            );
            ",
        )?;
        Ok(())
    }

    pub fn record_candidate(
        &mut self,
        candidate: EvidenceCandidate,
        correlation_key: &str,
        observed_at: u64,
    ) -> Result<(IncidentId, EvidenceId), IncidentStoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let existing = tx
            .query_row(
                "SELECT id, severity FROM incidents
                 WHERE correlation_key = ?1 AND status = 'open'
                 ORDER BY last_seen_at DESC LIMIT 1",
                [correlation_key],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;

        let incident_id = if let Some((id, stored_severity)) = existing {
            let severity = decode_severity(&stored_severity)?.max(candidate.severity);
            tx.execute(
                "UPDATE incidents
                 SET severity = ?1, summary = ?2, last_seen_at = ?3
                 WHERE id = ?4",
                params![
                    severity_as_str(severity),
                    &candidate.summary,
                    observed_at,
                    &id
                ],
            )?;
            IncidentId(id)
        } else {
            let next: u64 = tx.query_row(
                "SELECT COALESCE(MAX(CAST(SUBSTR(id, 5) AS INTEGER)), 0) + 1 FROM incidents",
                [],
                |row| row.get(0),
            )?;
            let id = IncidentId(format!("inc_{next:08}"));
            tx.execute(
                "INSERT INTO incidents
                 (id, correlation_key, severity, summary, status, first_seen_at, last_seen_at)
                 VALUES (?1, ?2, ?3, ?4, 'open', ?5, ?5)",
                params![
                    &id.0,
                    correlation_key,
                    severity_as_str(candidate.severity),
                    &candidate.summary,
                    observed_at,
                ],
            )?;
            id
        };

        let next_evidence: u64 = tx.query_row(
            "SELECT COALESCE(MAX(CAST(SUBSTR(id, 5) AS INTEGER)), 0) + 1 FROM evidence",
            [],
            |row| row.get(0),
        )?;
        let evidence_id = EvidenceId(format!("evi_{next_evidence:08}"));
        tx.execute(
            "INSERT INTO evidence
             (id, incident_id, source, description, confidence, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &evidence_id.0,
                &incident_id.0,
                evidence_source_as_str(candidate.source),
                &candidate.description,
                candidate.confidence.value(),
                observed_at,
            ],
        )?;

        for (position, object) in candidate.evidence_objects.iter().enumerate() {
            let lineage = serde_json::to_string(&object.lineage)
                .map_err(|error| IncidentStoreError::InvalidEvidenceLineage(error.to_string()))?;
            tx.execute(
                "INSERT INTO evidence_objects
                 (evidence_id, position, object_id, label, kind, origin_instance_id,
                  imported_from_instance_id, derived_by_instance_id, lineage)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    &evidence_id.0,
                    position as u64,
                    &object.id,
                    &object.label,
                    &object.kind,
                    object.origin_instance_id.as_deref(),
                    object.imported_from_instance_id.as_deref(),
                    object.derived_by_instance_id.as_deref(),
                    lineage,
                ],
            )?;
        }

        for object in candidate.related_objects {
            tx.execute(
                "INSERT OR IGNORE INTO incident_objects (incident_id, object_id) VALUES (?1, ?2)",
                params![&incident_id.0, object.0],
            )?;
        }

        tx.commit()?;
        Ok((incident_id, evidence_id))
    }

    pub fn list(&self) -> Result<Vec<IncidentSummaryDto>, IncidentStoreError> {
        let mut statement = self.connection.prepare(
            "SELECT i.id, i.severity, i.summary, i.status, i.first_seen_at, i.last_seen_at,
                    COUNT(e.id)
             FROM incidents i
             LEFT JOIN evidence e ON e.incident_id = i.id
             GROUP BY i.id
             ORDER BY i.last_seen_at DESC, i.id ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(IncidentSummaryDto {
                id: row.get(0)?,
                severity: row.get(1)?,
                summary: row.get(2)?,
                status: row.get(3)?,
                first_seen_at: row.get(4)?,
                last_seen_at: row.get(5)?,
                evidence_count: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn update_summary(
        &self,
        incident_id: &str,
        summary: &str,
        now: u64,
    ) -> Result<bool, IncidentStoreError> {
        let changed = self.connection.execute(
            "UPDATE incidents SET summary = ?2, last_seen_at = MAX(last_seen_at, ?3) WHERE id = ?1",
            params![incident_id, summary, now],
        )?;
        Ok(changed > 0)
    }

    pub fn detail(&self, id: &str) -> Result<Option<IncidentDetailDto>, IncidentStoreError> {
        let incident = self
            .connection
            .query_row(
                "SELECT i.id, i.severity, i.summary, i.status, i.first_seen_at, i.last_seen_at,
                        (SELECT COUNT(*) FROM evidence e WHERE e.incident_id = i.id)
                 FROM incidents i WHERE i.id = ?1",
                [id],
                |row| {
                    Ok(IncidentSummaryDto {
                        id: row.get(0)?,
                        severity: row.get(1)?,
                        summary: row.get(2)?,
                        status: row.get(3)?,
                        first_seen_at: row.get(4)?,
                        last_seen_at: row.get(5)?,
                        evidence_count: row.get(6)?,
                    })
                },
            )
            .optional()?;
        let Some(incident) = incident else {
            return Ok(None);
        };

        let mut evidence_statement = self.connection.prepare(
            "SELECT id, source, description, confidence, observed_at
             FROM evidence WHERE incident_id = ?1 ORDER BY observed_at ASC, id ASC",
        )?;
        let evidence_rows = evidence_statement
            .query_map([id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u8>(3)?,
                    row.get::<_, u64>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut evidence = Vec::with_capacity(evidence_rows.len());
        for (evidence_id, source, description, confidence, observed_at) in evidence_rows {
            let mut object_statement = self.connection.prepare(
                "SELECT object_id, label, kind, origin_instance_id, imported_from_instance_id,
                        derived_by_instance_id, lineage
                 FROM evidence_objects WHERE evidence_id = ?1 ORDER BY position ASC",
            )?;
            let stored_objects = object_statement
                .query_map([&evidence_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut objects = Vec::with_capacity(stored_objects.len());
            for (
                object_id,
                label,
                kind,
                origin_instance_id,
                imported_from_instance_id,
                derived_by_instance_id,
                lineage_json,
            ) in stored_objects
            {
                let lineage =
                    serde_json::from_str::<Vec<String>>(&lineage_json).map_err(|error| {
                        IncidentStoreError::InvalidEvidenceLineage(error.to_string())
                    })?;
                objects.push(EvidenceObjectRef {
                    id: object_id,
                    label,
                    kind,
                    origin_instance_id,
                    imported_from_instance_id,
                    derived_by_instance_id,
                    lineage,
                });
            }
            evidence.push(EvidenceDto {
                id: evidence_id,
                source,
                description,
                confidence,
                observed_at,
                objects,
            });
        }

        let mut object_statement = self.connection.prepare(
            "SELECT object_id FROM incident_objects WHERE incident_id = ?1 ORDER BY object_id ASC",
        )?;
        let related_objects = object_statement
            .query_map([id], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(Some(IncidentDetailDto {
            incident,
            evidence,
            related_objects,
        }))
    }

    pub fn open_count(&self) -> Result<u64, IncidentStoreError> {
        Ok(self.connection.query_row(
            "SELECT COUNT(*) FROM incidents WHERE status = 'open'",
            [],
            |row| row.get(0),
        )?)
    }
}

fn severity_as_str(value: Severity) -> &'static str {
    match value {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn decode_severity(value: &str) -> Result<Severity, IncidentStoreError> {
    match value {
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        _ => Err(IncidentStoreError::InvalidSeverity(value.into())),
    }
}

fn evidence_source_as_str(value: EvidenceSource) -> &'static str {
    match value {
        EvidenceSource::Rule => "rule",
        EvidenceSource::SelfModel => "self_model",
        EvidenceSource::MemoryGraph => "memory_graph",
        EvidenceSource::MachineLearning => "machine_learning",
        EvidenceSource::KernelTelemetry => "kernel_telemetry",
        EvidenceSource::FilesystemTelemetry => "filesystem_telemetry",
        EvidenceSource::NetworkTelemetry => "network_telemetry",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dendrite_protocol::{Confidence, EvidenceSource, ObjectId};

    fn candidate(severity: Severity) -> EvidenceCandidate {
        EvidenceCandidate {
            source: EvidenceSource::MemoryGraph,
            summary: "Threat path found".into(),
            description: "process -> threat".into(),
            severity,
            confidence: Confidence::new(90).unwrap(),
            related_objects: vec![ObjectId("process:test".into())],
            evidence_objects: Vec::new(),
        }
    }

    #[test]
    fn evidence_objects_are_persisted_with_the_evidence_record() {
        let mut service = IncidentService::open(":memory:").unwrap();
        let mut candidate = candidate(Severity::High);
        candidate.evidence_objects = vec![EvidenceObjectRef {
            id: "instance-a::process:test".into(),
            label: "test process".into(),
            kind: "process".into(),
            origin_instance_id: Some("instance-a".into()),
            imported_from_instance_id: None,
            derived_by_instance_id: None,
            lineage: vec!["instance-a".into()],
        }];

        let (incident_id, _) = service
            .record_candidate(candidate, "process:test|threat:test", 10)
            .unwrap();
        let detail = service.detail(&incident_id.0).unwrap().unwrap();

        assert_eq!(detail.evidence.len(), 1);
        assert_eq!(detail.evidence[0].objects.len(), 1);
        assert_eq!(detail.evidence[0].objects[0].id, "instance-a::process:test");
        assert_eq!(detail.evidence[0].objects[0].label, "test process");
        assert_eq!(
            detail.evidence[0].objects[0].origin_instance_id.as_deref(),
            Some("instance-a")
        );
        assert_eq!(detail.evidence[0].objects[0].lineage, vec!["instance-a"]);
    }

    #[test]
    fn correlated_candidates_share_incident_and_escalate_severity() {
        let mut service = IncidentService::open(":memory:").unwrap();
        let (first_incident, first_evidence) = service
            .record_candidate(candidate(Severity::Medium), "process:test|threat:test", 10)
            .unwrap();
        let (second_incident, second_evidence) = service
            .record_candidate(
                candidate(Severity::Critical),
                "process:test|threat:test",
                20,
            )
            .unwrap();

        assert_eq!(first_incident, second_incident);
        assert_ne!(first_evidence, second_evidence);
        let detail = service.detail(&first_incident.0).unwrap().unwrap();
        assert_eq!(detail.incident.severity, "critical");
        assert_eq!(detail.incident.evidence_count, 2);
        assert_eq!(detail.incident.last_seen_at, 20);
    }
}
