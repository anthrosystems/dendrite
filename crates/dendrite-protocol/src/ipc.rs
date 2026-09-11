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
    DebugGuardState {
        state: String,
    },
    DebugGuardFinding {
        target: String,
        severity: String,
        description: String,
    },
    Health,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonStatusDto {
    pub version: String,
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
    pub source_object: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryStatusDto {
    pub sources: Vec<TelemetrySourceDto>,
    pub recent_events: usize,
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
