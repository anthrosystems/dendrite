export interface DaemonStatus {
  version: string
  instance_id: string
  signing_key: {
    key_id: string
    algorithm: string
    public_key: string
    fingerprint: string
    created_at: number
  }
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

export interface EvidenceObject {
  id: string
  label: string
  kind: string
  origin_instance_id: string | null
  imported_from_instance_id: string | null
  derived_by_instance_id: string | null
  lineage: string[]
}

export interface Evidence {
  id: string
  source: string
  description: string
  confidence: number
  observed_at: number
  objects: EvidenceObject[]
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
  origin_instance_id: string | null
  imported_from_instance_id: string | null
  derived_by_instance_id: string | null
  lineage: string[]
  correlation_keys: string[]
}


export interface MemoryRelationship {
  id: string
  kind: string
  source: string
  target: string
  state: string
  priority: string
  retention: string
  strength: number
  effective_strength: number
  confidence: number
  observation_count: number
  created_at: number
  last_seen_at: number
  expires_at: number | null
  origin_instance_id: string | null
  imported_from_instance_id: string | null
  derived_by_instance_id: string | null
  lineage: string[]
}

export interface MemoryGraph {
  nodes: MemoryNode[]
  relationships: MemoryRelationship[]
  truncated: boolean
  total_nodes: number
  total_relationships: number
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
  scope: string
  source_object: string
  source_label: string
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

export interface TelemetryPipelineLane {
  queue_depth: number
  queue_capacity: number
  peak_queue_depth: number
  events_received: number
  events_processed: number
  events_dropped: number
  last_queue_wait_ms: number
  max_queue_wait_ms: number
  last_processing_ms: number
  max_processing_ms: number
}

export interface TelemetryPipeline {
  queue_depth: number
  queue_capacity: number
  peak_queue_depth: number
  events_received: number
  events_processed: number
  events_dropped: number
  security_observations_ingested: number
  last_queue_wait_ms: number
  max_queue_wait_ms: number
  last_processing_ms: number
  max_processing_ms: number
  priority: TelemetryPipelineLane
  routine: TelemetryPipelineLane
  scheduler_priority_weight: number
  scheduler_routine_weight: number
}

export interface TelemetryStatus {
  sources: TelemetrySource[]
  recent_events: number
  pipeline: TelemetryPipeline
}

export interface PackageInventory {
  name: string
  architecture: string
  version: string
  source: string
  first_seen_at: number
  last_seen_at: number
}

export interface VulnerabilityExposure {
  id: string
  cve_id: string
  package: string
  architecture: string
  installed_version: string
  fixed_version: string | null
  severity: string
  status: string
  first_seen_at: number
  last_seen_at: number
  resolution_source: string | null
  awaiting_manual: boolean
  authorised_at: number | null
  ignored_version: string | null
  ignored_at: number | null
}

export interface VulnerabilityStatus {
  records: number
  packages: number
  inventory_packages: number
  open_exposures: number
  source: string | null
  generated_at: number | null
  last_imported_at: number | null
  inventory_last_refreshed_at: number | null
  assessment_last_run_at: number | null
}

export interface VulnerabilityRemediation {
  exposure: VulnerabilityExposure
  action: ActionDetail
}

export interface AntiserumPayloadDeclaration {
  class: string
  path: string
  status: 'populated' | 'empty'
}

export interface AntiserumPackageVerification {
  signature: string
  content_root: string
  attestation: string
  local_trust: string
}

export interface AntiserumPackageSummary {
  antiserum_id: string
  origin: 'manual_export' | 'automatic_export' | 'imported'
  issuer_instance_id: string
  issuer_key_fingerprint: string
  sequence: number
  created_at: string
  expires_at: string | null
  payloads: AntiserumPayloadDeclaration[]
  verification: AntiserumPackageVerification
  size_bytes: number
  knowledge_status: 'source' | 'not_accepted' | 'accepted'
  knowledge_accepted_at: number | null
}

export interface AntiserumKnowledgeAcceptanceResult {
  antiserum_id: string
  accepted_at: number
  graph_nodes: number
  graph_relationships: number
  behaviours: number
  vulnerabilities: number
  vulnerability_candidates: number
  skipped_payloads: string[]
  already_accepted: boolean
}

export interface AntiserumEnvelope {
  format: string
  schema_version: number
  antiserum_id: string
  sequence: number
  issuer: {
    source_type: string
    instance_id: string
    fqdn?: string
    key_id: string
    public_key: string
    key_fingerprint: string
  }
  created_at: string
  expires_at: string | null
  attestation: { path: string; digest: string }
  payloads: AntiserumPayloadDeclaration[]
  content_root: { algorithm: string; value: string }
}

export interface AntiserumAttestation {
  instance_id: string
  key_id: string
  state: string
  export_safety: string
  observed_at: string
  guard_version: string
  policy_revision: number
  integrity: Record<string, string>
  active_findings: number
}

export interface AntiserumPackageDetail {
  summary: AntiserumPackageSummary
  envelope: AntiserumEnvelope
  attestation: AntiserumAttestation
  provenance: { schema_version?: number; sources?: Array<Record<string, unknown>> }
}

export interface AnalysisReview {
  review_id: string
  antiserum_id: string
  label: string | null
  created_at: number
  last_opened_at: number
}

export interface AttackChainRecord {
  id: string
  incident_id: string
  title: string
  original_title: string
  severity: string
  confidence: number
  observed_at: number
  steps: EvidenceObject[]
  relationships: string[]
  evidence_id: string
  matched_cve_ids: string[]
  behaviour_ids: string[]
  behaviour_fingerprint: string | null
  classification_confidence: number | null
}

export interface BehaviourDefinition {
  id: string
  name: string
  description: string
  confidence: number
  severity: string
  techniques: string[]
  conditions: Array<Record<string, unknown>>
  ordered: boolean
  max_interval_seconds: number | null
  source_refs: string[]
  fingerprint: string | null
  origin_instance_id: string | null
  imported_from_instance_id: string | null
  derived_by_instance_id: string | null
  lineage: string[]
  created_at: number
  updated_at: number
}

export interface CveKnowledgeRecord {
  id: string
  name: string | null
  package: string
  affected_before: string | null
  fixed_version: string | null
  severity: string
  cvss: string | null
  exploitability: string | null
  description: string
  published_at: number | null
  modified_at: number | null
  provenance: string
  expires_at: number | null
  behaviour_ids: string[]
}

export interface VulnerabilityCandidateRequest {
  title: string
  description: string
  affected_products: string[]
  affected_versions: string[]
  weaknesses: string[]
  severity: string
  cvss: string | null
  behaviour_ids: string[]
  attack_chain_ids: string[]
  indicator_ids: string[]
  evidence_ids: string[]
  source_antiserum_ids: string[]
  reproduction_notes: string | null
  mitigation_notes: string | null
  discovery_origin: string
  confidence: number
}

export interface VulnerabilityCandidate extends VulnerabilityCandidateRequest {
  candidate_id: string
  cve_id: string | null
  status: string
  created_at: number
  updated_at: number
}

export type RecordExportScope = 'all' | 'selected' | 'active_exposures' | 'associated'

export interface RecordExportOptions {
  scope: RecordExportScope
  selected_ids: string[]
}

export interface GraphExportOptions {
  scope: 'complete' | 'best-path' | 'reachable-graph'
  start_node: string | null
  max_depth: number | null
}

export interface CreateAntiserumRequest {
  graph?: GraphExportOptions
  attack_chains?: RecordExportOptions
  vulnerabilities?: RecordExportOptions
  indicator_hashes?: RecordExportOptions
  indicator_domains?: RecordExportOptions
  indicator_ips?: RecordExportOptions
  indicator_urls?: RecordExportOptions
  behaviours?: RecordExportOptions
}