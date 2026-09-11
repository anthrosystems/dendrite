export interface DaemonStatus {
  version: string
  observations_ingested: number
  incidents_open: number
  memory_nodes_known: number
  socket_path: string
}

export interface Health {
  daemon: string
  memory: string
  guard: string
}

export interface IncidentSummary {
  id: string
  severity: string
  summary: string
  status: string
  first_seen_at: number
  last_seen_at: number
  evidence_count: number
}

export interface Evidence {
  id: string
  source: string
  description: string
  confidence: number
  observed_at: number
}

export interface IncidentDetail {
  incident: IncidentSummary
  evidence: Evidence[]
  related_objects: string[]
}

export interface MemoryNode {
  id: string
  kind: string
  label: string
  state: string
  priority: string
  retention: string
  created_at: number
  last_seen_at: number
  expires_at: number | null
}

export interface MemoryNeighbours {
  node_id: string
  neighbours: string[]
}

export interface MemoryPath {
  nodes: string[]
  relationships: string[]
  score: number
}

export interface ActionSummary {
  id: string
  incident_id: string
  action: string
  target: string
  status: string
  quorum: string | null
  policy: string | null
  guard: string | null
  trust_state: string | null
  created_at: number
  updated_at: number
}

export interface Evaluation {
  evaluator: string
  verdict: string
  reason: string
  evaluated_at: number
}

export interface TransactionEvent {
  state: string
  status: string
  message: string | null
  recorded_at: number
}

export interface ActionDetail {
  proposal: ActionSummary
  evaluations: Evaluation[]
  transactions: TransactionEvent[]
  guard_requirement: string
}

export interface CreateAction {
  incident_id: string
  action: string
  target: string
}

export interface GuardStatus {
  trust_state: string
  authority: string
  findings_count: number
}

export interface IntegrityFinding {
  id: number
  target: string
  severity: string
  description: string
  recorded_at: number
}


export interface TelemetryEvent {
  id: string
  source: string
  event: string
  observation_kind: string
  process_id: number | null
  source_object: string
  target_object: string | null
  target_label: string | null
  observed_at: number
  incident_ids: string[]
}

export interface TelemetrySource {
  source: string
  status: string
  detail: string
}

export interface TelemetryStatus {
  sources: TelemetrySource[]
  recent_events: number
}
