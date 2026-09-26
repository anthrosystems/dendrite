use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEnvelope<T> {
    pub request_id: String,
    pub payload: T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseStatus {
    Ok,
    Rejected,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseEnvelope<T> {
    pub request_id: String,
    pub status: ResponseStatus,
    pub payload: Option<T>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum IpcRequest {
    Status,
    Incidents,
    Incident {
        id: String,
    },
    MemoryNodes {
        kind: Option<String>,
    },
    MemoryRecent {
        limit: usize,
    },
    MemoryNeighbours {
        node_id: String,
    },
    MemoryPath {
        source: String,
        target: String,
    },
    Actions,
    Action {
        id: String,
    },
    CreateAction {
        incident_id: String,
        action: String,
        target: String,
    },
    EvaluateAction {
        id: String,
    },
    GuardStatus,
    GuardFindings,
    TelemetryRecent {
        limit: usize,
    },
    TelemetryStatus,
    DebugSeedIncident {
        label: Option<String>,
    },
    /// Debug-only, like `DebugSeedIncident` — never available outside a
    /// debug build (see `#[cfg(debug_assertions)]` at the handler). Unlike
    /// `DebugSeedIncident`, this pushes a synthetic observation through the
    /// *real* priority ingestion channel and worker — the same path real
    /// high-severity telemetry takes — rather than seeding an incident
    /// directly. Exists because there's no safe way to deliberately trigger
    /// real priority-lane traffic otherwise: `ingestion_lane()` only routes
    /// something there for `Severity::High`/`Critical` or a `Threat`/
    /// `Incident`-kind entity, and nothing on a normal host reliably
    /// produces that on demand.
    DebugInjectPriority {
        label: Option<String>,
    },
    DebugGuardState {
        state: String,
    },
    DebugGuardFinding {
        target: String,
        severity: String,
        description: String,
    },
    VulnerabilityStatus,
    VulnerabilityInventory,
    Vulnerabilities {
        include_resolved: bool,
    },
    Vulnerability {
        id: String,
    },
    VulnerabilityRefresh,
    VulnerabilityImport {
        path: String,
    },
    VulnerabilityManual {
        id: String,
    },
    VulnerabilityAuthorise {
        id: String,
    },
    VulnerabilityUpdate {
        id: String,
    },
    VulnerabilityIgnore {
        id: String,
    },
    VulnerabilityDelete {
        id: String,
    },
    Health,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceSigningKeyDto {
    pub key_id: String,
    pub algorithm: String,
    pub public_key: String,
    pub fingerprint: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonStatusDto {
    pub version: String,
    pub instance_id: String,
    pub signing_key: InstanceSigningKeyDto,
    pub observations_ingested: u64,
    pub incidents_open: u64,
    pub memory_nodes_known: u64,
    pub socket_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentSummaryDto {
    pub id: String,
    pub severity: String,
    pub summary: String,
    pub status: String,
    pub first_seen_at: u64,
    pub last_seen_at: u64,
    pub evidence_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceDto {
    pub id: String,
    pub source: String,
    pub description: String,
    pub confidence: u8,
    pub observed_at: u64,
    pub objects: Vec<crate::EvidenceObjectRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentDetailDto {
    pub incident: IncidentSummaryDto,
    pub evidence: Vec<EvidenceDto>,
    pub related_objects: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryNodeDto {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub state: String,
    pub priority: String,
    pub retention: String,
    pub created_at: u64,
    pub last_seen_at: u64,
    pub expires_at: Option<u64>,
    pub origin_instance_id: Option<String>,
    pub imported_from_instance_id: Option<String>,
    pub derived_by_instance_id: Option<String>,
    pub lineage: Vec<String>,
    #[serde(default)]
    pub correlation_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRelationshipDto {
    pub id: String,
    pub kind: String,
    pub source: String,
    pub target: String,
    pub state: String,
    pub priority: String,
    pub retention: String,
    pub strength: u8,
    pub effective_strength: u8,
    pub confidence: u8,
    pub observation_count: u64,
    pub created_at: u64,
    pub last_seen_at: u64,
    pub expires_at: Option<u64>,
    pub origin_instance_id: Option<String>,
    pub imported_from_instance_id: Option<String>,
    pub derived_by_instance_id: Option<String>,
    pub lineage: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryGraphDto {
    pub nodes: Vec<MemoryNodeDto>,
    pub relationships: Vec<MemoryRelationshipDto>,
    pub truncated: bool,
    pub total_nodes: u64,
    pub total_relationships: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryPathDto {
    pub nodes: Vec<String>,
    pub relationships: Vec<String>,
    pub score: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationDto {
    pub evaluator: String,
    pub verdict: String,
    pub reason: String,
    pub evaluated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionEventDto {
    pub state: String,
    pub status: String,
    pub message: Option<String>,
    pub recorded_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionSummaryDto {
    pub id: String,
    pub incident_id: String,
    pub action: String,
    pub target: String,
    pub status: String,
    pub quorum: Option<String>,
    pub policy: Option<String>,
    pub guard: Option<String>,
    pub trust_state: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionDetailDto {
    pub proposal: ActionSummaryDto,
    pub evaluations: Vec<EvaluationDto>,
    pub transactions: Vec<TransactionEventDto>,
    pub guard_requirement: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateActionDto {
    pub incident_id: String,
    pub action: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardStatusDto {
    pub trust_state: String,
    pub authority: String,
    pub findings_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityFindingDto {
    pub id: u64,
    pub target: String,
    pub severity: String,
    pub description: String,
    pub recorded_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryEventDto {
    pub id: String,
    pub source: String,
    pub event: String,
    pub observation_kind: String,
    pub process_id: Option<u32>,
    pub scope: String,
    pub source_object: String,
    pub source_label: String,
    pub target_object: Option<String>,
    pub target_label: Option<String>,
    pub observed_at: u64,
    pub incident_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetrySourceDto {
    pub source: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TelemetryPipelineLaneDto {
    pub queue_depth: usize,
    pub queue_capacity: usize,
    pub peak_queue_depth: usize,
    pub events_received: u64,
    pub events_processed: u64,
    pub events_dropped: u64,
    pub last_queue_wait_ms: u64,
    pub max_queue_wait_ms: u64,
    pub last_processing_ms: u64,
    pub max_processing_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TelemetryPipelineDto {
    pub queue_depth: usize,
    pub queue_capacity: usize,
    pub peak_queue_depth: usize,
    pub events_received: u64,
    pub events_processed: u64,
    pub events_dropped: u64,
    pub security_observations_ingested: u64,
    pub last_queue_wait_ms: u64,
    pub max_queue_wait_ms: u64,
    pub last_processing_ms: u64,
    pub max_processing_ms: u64,
    pub priority: TelemetryPipelineLaneDto,
    pub routine: TelemetryPipelineLaneDto,
    pub scheduler_priority_weight: usize,
    pub scheduler_routine_weight: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryStatusDto {
    pub sources: Vec<TelemetrySourceDto>,
    pub recent_events: usize,
    pub pipeline: TelemetryPipelineDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageInventoryDto {
    pub name: String,
    pub architecture: String,
    pub version: String,
    pub source: String,
    pub first_seen_at: u64,
    pub last_seen_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulnerabilityExposureDto {
    pub id: String,
    pub cve_id: String,
    pub package: String,
    pub architecture: String,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    pub severity: String,
    pub status: String,
    pub first_seen_at: u64,
    pub last_seen_at: u64,
    pub resolution_source: Option<String>,
    pub awaiting_manual: bool,
    pub authorised_at: Option<u64>,
    /// The `installed_version` at the moment this exposure was ignored — used
    /// to detect "a package update revealed the same CVE again" (the
    /// installed version has since changed while still matching the CVE)
    /// and automatically re-raise it. `None` unless `status == "ignored"`.
    pub ignored_version: Option<String>,
    pub ignored_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CveKnowledgeStatusDto {
    pub records: u64,
    pub packages: u64,
    pub inventory_packages: u64,
    pub open_exposures: u64,
    pub source: Option<String>,
    pub generated_at: Option<u64>,
    pub last_imported_at: Option<u64>,
    pub inventory_last_refreshed_at: Option<u64>,
    pub assessment_last_run_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulnerabilityRemediationDto {
    pub exposure: VulnerabilityExposureDto,
    pub action: ActionDetailDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthDto {
    pub daemon: String,
    pub memory: String,
    pub guard: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum IpcResponse {
    Status(DaemonStatusDto),
    Incidents {
        incidents: Vec<IncidentSummaryDto>,
    },
    Incident {
        incident: IncidentDetailDto,
    },
    MemoryNodes {
        nodes: Vec<MemoryNodeDto>,
    },
    MemoryRecent {
        nodes: Vec<MemoryNodeDto>,
    },
    MemoryNeighbours {
        node_id: String,
        neighbours: Vec<String>,
    },
    MemoryPath {
        path: Option<MemoryPathDto>,
    },
    Actions {
        actions: Vec<ActionSummaryDto>,
    },
    Action {
        action: ActionDetailDto,
    },
    GuardStatus(GuardStatusDto),
    GuardFindings {
        findings: Vec<IntegrityFindingDto>,
    },
    TelemetryRecent {
        events: Vec<TelemetryEventDto>,
    },
    TelemetryStatus(TelemetryStatusDto),
    VulnerabilityStatus(CveKnowledgeStatusDto),
    VulnerabilityInventory {
        packages: Vec<PackageInventoryDto>,
    },
    Vulnerabilities {
        exposures: Vec<VulnerabilityExposureDto>,
    },
    Vulnerability {
        exposure: VulnerabilityExposureDto,
    },
    VulnerabilityImport {
        imported: usize,
        status: CveKnowledgeStatusDto,
    },
    VulnerabilityRemediation(Box<VulnerabilityRemediationDto>),
    VulnerabilityDeleted {
        deleted: bool,
    },
    /// `queued: true` means the synthetic observation was accepted onto the
    /// real priority channel; `false` means it was dropped because that
    /// channel was already full (itself a meaningful result to observe, not
    /// an error).
    DebugInjectPriority {
        queued: bool,
    },
    Health(HealthDto),
    Error {
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_through_json() {
        let request = IpcRequest::MemoryPath {
            source: "process:1".into(),
            target: "threat:test".into(),
        };
        let json = serde_json::to_string(&request).unwrap();
        let decoded: IpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn create_action_request_round_trips_through_json() {
        let request = IpcRequest::CreateAction {
            incident_id: "inc_00000001".into(),
            action: "observe".into(),
            target: "process:1".into(),
        };
        let json = serde_json::to_string(&request).unwrap();
        let decoded: IpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, request);
    }
}
