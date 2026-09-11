use crate::{
    ActionService, ActionStoreError, GuardService, GuardStoreError, IncidentService,
    IncidentStoreError,
};
use dendrite_memory::model::{
    DecayPolicy, DecayRate, MemoryConfidence, MemoryNode, MemoryNodeId, MemoryNodeKind,
    MemoryPriority, MemoryRelationship, MemoryRelationshipId, MemoryRelationshipKind, MemoryState,
    MemoryStrength, RetentionClass,
};
use dendrite_memory::storage::{
    MemoryPath, MemoryStore, PathQuery, StorageError, ThreatPath, TraversalDirection,
};
use dendrite_protocol::{
    ActionDetailDto, ActionSummaryDto, Confidence, EntityKind, EvidenceCandidate, EvidenceId,
    EvidenceSource, GuardStatusDto, IncidentDetailDto, IncidentId, IncidentSummaryDto,
    IntegrityFindingDto, MemoryNodeDto, ObjectDescriptor, ObjectId, Observation, ObservationKind,
    Severity, TelemetryEventDto, TelemetrySourceDto, TelemetryStatusDto,
};
use std::collections::VecDeque;

#[derive(Debug)]
pub enum DaemonError {
    Database(rusqlite::Error),
    Memory(StorageError),
    Incidents(IncidentStoreError),
    Actions(ActionStoreError),
    Guard(GuardStoreError),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestionOutcome {
    pub relationship_id: Option<MemoryRelationshipId>,
    pub incidents: Vec<IncidentId>,
    pub evidence: Vec<EvidenceId>,
    pub strongest_graph_score: Option<u8>,
}

pub struct DaemonCore {
    memory: MemoryStore,
    incidents: IncidentService,
    actions: ActionService,
    guard: GuardService,
    observations_ingested: u64,
    telemetry_recent: VecDeque<TelemetryEventDto>,
    telemetry_sources: Vec<TelemetrySourceDto>,
}

impl DaemonCore {
    pub fn open(memory_path: &str) -> Result<Self, DaemonError> {
        Self::open_with_stores(memory_path, ":memory:", ":memory:")
    }

    pub fn open_with_incidents(
        memory_path: &str,
        incident_path: &str,
    ) -> Result<Self, DaemonError> {
        Self::open_with_stores(memory_path, incident_path, ":memory:")
    }

    pub fn open_with_stores(
        memory_path: &str,
        incident_path: &str,
        guard_path: &str,
    ) -> Result<Self, DaemonError> {
        let memory = MemoryStore::open(memory_path)?;
        memory.initialise()?;
        Ok(Self {
            memory,
            incidents: IncidentService::open(incident_path)?,
            actions: ActionService::open(incident_path)?,
            guard: GuardService::open(guard_path)?,
            observations_ingested: 0,
            telemetry_recent: VecDeque::with_capacity(512),
            telemetry_sources: Vec::new(),
        })
    }

    pub fn memory(&self) -> &MemoryStore {
        &self.memory
    }

    pub fn observations_ingested(&self) -> u64 {
        self.observations_ingested
    }

    pub fn set_telemetry_sources(&mut self, sources: Vec<TelemetrySourceDto>) {
        self.telemetry_sources = sources;
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

        Ok(self
            .memory
            .nodes(kind)?
            .into_iter()
            .map(memory_node_dto)
            .collect())
    }

    pub fn memory_recent(&self, limit: usize) -> Result<Vec<MemoryNodeDto>, DaemonError> {
        Ok(self
            .memory
            .recent_nodes(limit)?
            .into_iter()
            .map(memory_node_dto)
            .collect())
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

    pub fn ingest_observation(
        &mut self,
        observation: &Observation,
    ) -> Result<IngestionOutcome, DaemonError> {
        self.persist_object(&observation.source, observation)?;
        if let Some(target) = &observation.target {
            self.persist_object(target, observation)?;
        }
        let relationship_id = self.persist_relationship(observation)?;
        self.observations_ingested = self.observations_ingested.saturating_add(1);

        let seeds_threat_knowledge = observation.kind == ObservationKind::Associated
            && observation
                .target
                .as_ref()
                .is_some_and(|target| target.kind == EntityKind::Threat);

        if seeds_threat_knowledge {
            return Ok(IngestionOutcome {
                relationship_id,
                incidents: Vec::new(),
                evidence: Vec::new(),
                strongest_graph_score: None,
            });
        }

        let query = PathQuery {
            max_depth: 6,
            direction: TraversalDirection::Any,
            evaluation_time: Some(observation.observed_at),
            ..PathQuery::default()
        };
        let mut threat_paths: Vec<(String, ThreatPath)> = Vec::new();

        if observation.source.kind != EntityKind::Threat {
            let start = MemoryNodeId(observation.source.id.0.clone());
            for finding in self.memory.threat_paths_from(&start, &query)? {
                threat_paths.push((observation.source.id.0.clone(), finding));
            }
        }

        if threat_paths.is_empty()
            && let Some(target) = &observation.target
            && target.kind != EntityKind::Threat
        {
            let start = MemoryNodeId(target.id.0.clone());
            for finding in self.memory.threat_paths_from(&start, &query)? {
                threat_paths.push((target.id.0.clone(), finding));
            }
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
                        .map(|node| node.0.as_str())
                        .collect::<Vec<_>>()
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
            };
            let correlation_key = format!("{}|{}", origin, finding.threat.0);
            let (incident_id, evidence_id) = self.incidents.record_candidate(
                candidate,
                &correlation_key,
                observation.observed_at,
            )?;
            incidents.push(incident_id);
            evidence.push(evidence_id);
        }

        Ok(IngestionOutcome {
            relationship_id,
            incidents,
            evidence,
            strongest_graph_score,
        })
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

    pub fn guard_status(&self) -> Result<GuardStatusDto, DaemonError> {
        Ok(self.guard.status()?)
    }

    pub fn guard_findings(&self) -> Result<Vec<IntegrityFindingDto>, DaemonError> {
        Ok(self.guard.findings()?)
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
        let sequence = self.observations_ingested.saturating_add(1);
        let suffix = format!("{now}:{sequence}");
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
    ) -> Result<(), DaemonError> {
        let mut node = MemoryNode {
            id: MemoryNodeId(object.id.0.clone()),
            kind: map_entity_kind(object.kind),
            label: object.label.clone(),
            created_at: observation.observed_at,
            last_seen_at: observation.observed_at,
            expires_at: observation.expires_at,
            state: MemoryState::Observed,
            priority: map_priority(observation.severity),
            retention: map_retention(object.kind),
            decay_policy: DecayPolicy::None,
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
        }
        self.memory.save_node(&node)?;
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
            id: MemoryRelationshipId(format!("obs:{}", observation.id.0)),
            kind: map_relationship_kind(observation.kind),
            source: MemoryNodeId(observation.source.id.0.clone()),
            target: MemoryNodeId(target.id.0.clone()),
            created_at: observation.observed_at,
            last_seen_at: observation.observed_at,
            observation_count: 1,
            expires_at: observation.expires_at,
            state: MemoryState::Observed,
            priority: map_priority(observation.severity),
            retention: RetentionClass::ShortTerm,
            decay_policy: DecayPolicy::Linear {
                rate: DecayRate::new(10).expect("10 must be a valid decay rate"),
            },
            strength: MemoryStrength::new(observation.confidence.value())
                .expect("protocol confidence is constrained to 0..=100"),
            confidence: MemoryConfidence::new(observation.confidence.value())
                .expect("protocol confidence is constrained to 0..=100"),
            reinforcement: None,
        };
        Ok(Some(self.memory.observe_relationship(&relationship)?))
    }
}

fn memory_node_dto(node: MemoryNode) -> MemoryNodeDto {
    MemoryNodeDto {
        id: node.id.0,
        kind: node.kind.as_str().into(),
        label: node.label,
        state: node.state.as_str().into(),
        priority: node.priority.as_str().into(),
        retention: node.retention.as_str().into(),
        created_at: node.created_at,
        last_seen_at: node.last_seen_at,
        expires_at: node.expires_at,
    }
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

fn map_retention(kind: EntityKind) -> RetentionClass {
    match kind {
        EntityKind::Threat => RetentionClass::LongTerm,
        EntityKind::Incident => RetentionClass::Persistent,
        _ => RetentionClass::ShortTerm,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dendrite_protocol::{ObjectDescriptor, ObservationId};

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
    fn graph_findings_correlate_into_one_persistent_incident() {
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
                "endpoint".to_string(),
                "known-threat".to_string(),
                "proc".to_string(),
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
}
