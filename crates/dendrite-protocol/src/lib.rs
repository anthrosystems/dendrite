//! Shared Dendrite domain types and IPC/API protocol definitions.

pub mod action;
pub mod detection;
pub mod guard_ipc;
pub mod ids;
pub mod ipc;
pub mod magi_ipc;
pub mod trust;

pub use action::{
    ActionAuthorization, ActionExecutionStatus, ActionProposal, ActionTransactionState, ActionType,
    Evaluation, Evaluator, EvaluatorVerdict, PolicyDecision, QuorumDecision, QuorumPolicy,
};
pub use detection::{
    Confidence, EntityKind, Evidence, EvidenceCandidate, EvidenceObjectRef, EvidenceSource,
    Incident, ObjectDescriptor, Observation, ObservationKind, Severity,
};
pub use guard_ipc::{GuardRequest, GuardResponse};
pub use ids::{ActionProposalId, EvidenceId, IncidentId, ObjectId, ObservationId};
pub use ipc::{
    ActionDetailDto, ActionSummaryDto, CreateActionDto, CultureCampaignDto, CveKnowledgeStatusDto,
    DaemonStatusDto, EvaluationDto, EvidenceDto, GuardStatusDto, HealthDto, HerdPeerStatusDto,
    IncidentDetailDto, IncidentSummaryDto, InstanceSigningKeyDto, IntegrityFindingDto,
    IntegrityManifestEntryDto, IntegrityManifestStatusDto, IntegrityMismatchDto,
    IntegrityVerificationDto, IpcRequest, IpcResponse, MemoryGraphDto, MemoryNodeDto,
    MemoryPathDto, MemoryRelationshipDto, PackageInventoryDto, RecoveryBeginDto,
    RecoveryCompleteDto, RequestEnvelope, ResponseEnvelope, ResponseStatus, TelemetryEventDto,
    TelemetryPipelineDto, TelemetryPipelineLaneDto, TelemetrySourceDto, TelemetryStatusDto,
    TransactionEventDto, VulnerabilityExposureDto, VulnerabilityRemediationDto,
};
pub use magi_ipc::{MagiEvaluation, MagiRequest, MagiResponse};
pub use trust::{GuardDecision, IntegrityFinding, IntegritySeverity, TrustState};
