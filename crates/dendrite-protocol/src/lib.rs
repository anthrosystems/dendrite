//! Shared Dendrite domain types and IPC/API protocol definitions.

pub mod action;
pub mod detection;
pub mod ids;
pub mod ipc;
pub mod trust;

pub use action::{
    ActionAuthorization, ActionExecutionStatus, ActionProposal, ActionTransactionState, ActionType,
    Evaluation, Evaluator, EvaluatorVerdict, PolicyDecision, QuorumDecision, QuorumPolicy,
};
pub use detection::{
    Confidence, EntityKind, Evidence, EvidenceCandidate, EvidenceSource, Incident,
    ObjectDescriptor, Observation, ObservationKind, Severity,
};
pub use ids::{ActionProposalId, EvidenceId, IncidentId, ObjectId, ObservationId};
pub use ipc::{RequestEnvelope, ResponseEnvelope, ResponseStatus};
pub use trust::{GuardDecision, IntegrityFinding, IntegritySeverity, TrustState};
