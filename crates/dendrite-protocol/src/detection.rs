use crate::{EvidenceId, IncidentId, ObjectId, ObservationId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Confidence(u8);

impl Confidence {
    pub fn new(value: u8) -> Option<Self> {
        if value <= 100 {
            Some(Self(value))
        } else {
            None
        }
    }

    pub fn value(self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceSource {
    Rule,
    SelfModel,
    MemoryGraph,
    MachineLearning,
    KernelTelemetry,
    FilesystemTelemetry,
    NetworkTelemetry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub id: EvidenceId,
    pub source: EvidenceSource,
    pub description: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incident {
    pub id: IncidentId,
    pub severity: Severity,
    pub summary: String,
    pub evidence: Vec<EvidenceId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityKind {
    Process,
    File,
    User,
    Host,
    NetworkEndpoint,
    Service,
    Container,
    Incident,
    Threat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectDescriptor {
    pub id: ObjectId,
    pub kind: EntityKind,
    pub label: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationKind {
    ProcessStarted,
    FileExecuted,
    FileRead,
    FileWritten,
    NetworkConnection,
    ServiceInteraction,
    Associated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub id: ObservationId,
    pub kind: ObservationKind,
    pub source: ObjectDescriptor,
    pub target: Option<ObjectDescriptor>,
    pub observed_at: u64,
    pub expires_at: Option<u64>,
    pub severity: Severity,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceCandidate {
    pub source: EvidenceSource,
    pub summary: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub related_objects: Vec<ObjectId>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_accepts_valid_values() {
        assert_eq!(Confidence::new(0).unwrap().value(), 0);
        assert_eq!(Confidence::new(100).unwrap().value(), 100);
    }

    #[test]
    fn confidence_rejects_values_above_100() {
        assert_eq!(Confidence::new(101), None);
    }
}
