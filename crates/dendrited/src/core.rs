use crate::{IncidentService, ProposalService};
use dendrite_memory::model::{
    DecayPolicy, DecayRate, MemoryConfidence, MemoryNode, MemoryNodeId, MemoryNodeKind,
    MemoryPriority, MemoryRelationship, MemoryRelationshipId, MemoryRelationshipKind, MemoryState,
    MemoryStrength, RetentionClass,
};
use dendrite_memory::storage::{MemoryStore, PathQuery, StorageError, TraversalDirection};
use dendrite_protocol::{
    ActionProposal, ActionType, Confidence, EntityKind, EvidenceCandidate, EvidenceId,
    EvidenceSource, IncidentId, ObjectDescriptor, ObjectId, Observation, ObservationKind, Severity,
};

#[derive(Debug)]
pub enum DaemonError {
    Database(rusqlite::Error),
    Memory(StorageError),
    MissingObservationTarget,
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
    proposals: ProposalService,
}

impl DaemonCore {
    pub fn open(memory_path: &str) -> Result<Self, DaemonError> {
        let memory = MemoryStore::open(memory_path)?;
        memory.initialise()?;

        Ok(Self {
            memory,
            incidents: IncidentService::new(),
            proposals: ProposalService::new(),
        })
    }

    pub fn memory(&self) -> &MemoryStore {
        &self.memory
    }

    pub fn incidents(&self) -> &IncidentService {
        &self.incidents
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

        let start = MemoryNodeId(observation.source.id.0.clone());
        let query = PathQuery {
            max_depth: 6,
            direction: TraversalDirection::Any,
            evaluation_time: Some(observation.observed_at),
            ..PathQuery::default()
        };

        let threat_paths = self.memory.threat_paths_from(&start, &query)?;
        let strongest_graph_score = threat_paths.first().map(|finding| finding.path.score());

        let mut incidents = Vec::new();
        let mut evidence = Vec::new();

        if let Some(finding) = threat_paths.first() {
            let candidate = EvidenceCandidate {
                source: EvidenceSource::MemoryGraph,
                summary: "Memory Graph threat path detected".into(),
                description: format!(
                    "Object {} is connected to threat {} through {} relationship(s), score {}",
                    observation.source.id.0,
                    finding.threat.0,
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

            let (incident_id, evidence_id) = self.incidents.record_candidate(candidate);
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

    pub fn propose_action(
        &mut self,
        incident_id: IncidentId,
        action: ActionType,
        target: ObjectId,
    ) -> ActionProposal {
        self.proposals.propose(incident_id, action, target)
    }

    fn persist_object(
        &self,
        object: &ObjectDescriptor,
        observation: &Observation,
    ) -> Result<(), DaemonError> {
        let node = MemoryNode {
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
    fn graph_threat_finding_creates_incident_but_not_action() {
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
        let outcome = core.ingest_observation(&process_edge).unwrap();

        assert_eq!(outcome.incidents.len(), 1);
        assert_eq!(outcome.evidence.len(), 1);
        assert!(outcome.strongest_graph_score.is_some());

        let proposal = core.propose_action(
            outcome.incidents[0].clone(),
            ActionType::RestrictProcess,
            ObjectId("proc".into()),
        );

        assert_eq!(proposal.incident_id, outcome.incidents[0]);
        // Producing a proposal is deliberately separate from execution.
    }
}
