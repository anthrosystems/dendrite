//! Core Dendrite daemon orchestration.

mod actions;
mod analysis;
mod antiserum;
mod core;
mod culture;
mod guard;
mod http;
mod incidents;
mod knowledge;
mod live;
mod runtime;
mod self_store;
mod telemetry;
mod vulnerability;

pub use actions::{
    ActionService, ActionStoreError, DEFAULT_MAGI_SOCKET_PATH, MagiEvaluator, MagiIpcClient,
};
pub use analysis::{
    AnalysisError, AntiserumKnowledgeAcceptanceResult, AntiserumPackageDetail,
    AntiserumPackageOrigin, AntiserumPackageStore, AntiserumPackageSummary,
    AntiserumPackageVerification, AttackChainRecord, BuiltPayloadSet, CreateAntiserumRequest,
    GraphExportOptions, GraphExportScope, RecordExportOptions, RecordExportScope,
    automatic_attack_chain_request, build_payloads, enforce_automatic_export_ceiling,
};
pub use antiserum::{
    ANTISERUM_ATTESTATION_PATH, ANTISERUM_DEFAULT_STREAM, ANTISERUM_ENVELOPE_SIGNATURE_CONTEXT,
    ANTISERUM_FORMAT, ANTISERUM_MAX_ATTESTATION_AGE_SECONDS, ANTISERUM_MERKLE_ALGORITHM,
    ANTISERUM_SCHEMA_VERSION, AntiserumAttestation, AntiserumAttestationRef, AntiserumContentRoot,
    AntiserumEnvelope, AntiserumError, AntiserumIntegrity, AntiserumIssuer, AntiserumPayload,
    AntiserumPayloadDeclaration, AntiserumPayloadStatus, AntiserumVerificationKey,
    SignedAntiserumPackage, build_signed_package, canonical_json_bytes, merkle_root,
    package_from_danti_bytes, package_to_danti_bytes, verification_key_from_package,
    verify_signed_package,
};
pub use core::{DaemonCore, DaemonError, IngestionOutcome};
pub use culture::{CultureCampaign, CultureError, CultureManager, CultureSources};
pub use guard::{GuardService, GuardStoreError};
pub use incidents::{IncidentService, IncidentStoreError};
pub use knowledge::{
    AttackChainClassification, BehaviourDefinition, CorrelationKeyRecord, KnowledgeError,
    KnowledgeService,
};
pub use runtime::{DaemonRuntime, RuntimeConfig, RuntimeError};
pub use self_store::{
    AnalysisReviewRecord, AntiserumKnowledgeAcceptanceRecord, InstanceKeyRecord, SelfStore,
    SelfStoreError,
};
pub use telemetry::TelemetryManager;
pub use vulnerability::{
    CveBehaviourDefinition, CveKnowledgeBundle, CveKnowledgeRecord, VulnerabilityCandidate,
    VulnerabilityCandidateRequest, VulnerabilityError, VulnerabilityService,
};
