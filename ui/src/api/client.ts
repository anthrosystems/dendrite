import { emitLocalLive } from '../hooks/live'
import { getApiOrigin } from './runtimeConfig'
import { reportAuthResult, withToken } from './token'
import type {
  ActionDetail,
  ActionSummary,
  CreateAction,
  DaemonStatus,
  GuardStatus,
  Health,
  IntegrityFinding,
  IncidentDetail,
  IncidentSummary,
  MemoryGraph,
  MemoryNeighbours,
  MemoryNode,
  MemoryPath,
  TelemetryEvent,
  TelemetryStatus,
  PackageInventory,
  VulnerabilityExposure,
  VulnerabilityRemediation,
  VulnerabilityStatus,
  AnalysisReview,
  AntiserumKnowledgeAcceptanceResult,
  AntiserumPackageDetail,
  AntiserumPackageSummary,
  AttackChainRecord,
  BehaviourDefinition,
  CreateAntiserumRequest,
  CultureCampaign,
  CveKnowledgeRecord,
  HerdPeerStatus,
  VulnerabilityCandidate,
  VulnerabilityCandidateRequest,
} from './types'

/** Same-origin `/api/v1` unless the runtime config (see `runtimeConfig.ts`)
 * names a different `dendrited` origin. Read live rather than cached in a
 * module-level constant, since `main.tsx` resolves the runtime config
 * before rendering but this stays correct even if that ordering ever
 * changes. */
function apiBase(): string {
  const origin = getApiOrigin()
  return origin ? `${origin}/api/v1` : '/api/v1'
}

export class ApiError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message)
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(withToken(`${apiBase()}${path}`), {
    ...init,
    headers: {
      Accept: 'application/json',
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...init?.headers,
    },
  })
  reportAuthResult(response.status)

  const text = await response.text()
  if (!response.ok) {
    let message = text || `${response.status} ${response.statusText}`
    try {
      const payload = JSON.parse(text) as { error?: string }
      if (payload.error) message = payload.error
    } catch {
      // Preserve the raw response body.
    }
    throw new ApiError(response.status, message)
  }

  return JSON.parse(text) as T
}

const get = <T,>(path: string) => request<T>(path)
const post = async <T,>(path: string, body?: unknown) => {
  const value = await request<T>(path, {
    method: 'POST',
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  emitLocalLive('control', { path })
  return value
}

const del = async <T,>(path: string) => {
  const value = await request<T>(path, { method: 'DELETE' })
  emitLocalLive('control', { path })
  return value
}

async function uploadAntiserum(file: File): Promise<AntiserumPackageSummary> {
  const response = await fetch(withToken(`${apiBase()}/analysis/import`), {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/vnd.dendrite.antiserum' },
    body: file,
  })
  reportAuthResult(response.status)
  const text = await response.text()
  if (!response.ok) {
    let message = text || `${response.status} ${response.statusText}`
    try { message = (JSON.parse(text) as { error?: string }).error ?? message } catch { /* raw */ }
    throw new ApiError(response.status, message)
  }
  emitLocalLive('control', { path: '/analysis/import' })
  return JSON.parse(text) as AntiserumPackageSummary
}

export const api = {
  status: () => get<DaemonStatus>('/status'),
  health: () => get<Health>('/health'),
  guard: () => get<GuardStatus>('/guard'),
  guardFindings: () => get<IntegrityFinding[]>('/guard/findings'),
  telemetryStatus: () => get<TelemetryStatus>('/telemetry/status'),
  telemetryRecent: (limit = 100) => get<TelemetryEvent[]>(`/telemetry/recent?limit=${limit}`),
  incidents: () => get<IncidentSummary[]>('/incidents'),
  incident: (id: string) => get<IncidentDetail>(`/incidents/${encodeURIComponent(id)}`),
  memoryGraph: (limit = 0) => get<MemoryGraph>(`/memory/graph?limit=${limit}`),
  memoryNodes: (kind?: string) =>
    get<MemoryNode[]>(`/memory/nodes${kind ? `?kind=${encodeURIComponent(kind)}` : ''}`),
  memoryRecent: (limit = 20) => get<MemoryNode[]>(`/memory/recent?limit=${limit}`),
  memoryNeighbours: (nodeId: string) =>
    get<MemoryNeighbours>(`/memory/neighbours?node_id=${encodeURIComponent(nodeId)}`),
  memoryPath: (source: string, target: string) =>
    get<MemoryPath | null>(
      `/memory/path?source=${encodeURIComponent(source)}&target=${encodeURIComponent(target)}`,
    ),
  actions: () => get<ActionSummary[]>('/actions'),
  action: (id: string) => get<ActionDetail>(`/actions/${encodeURIComponent(id)}`),
  createAction: (input: CreateAction) => post<ActionDetail>('/actions', input),
  evaluateAction: (id: string) => post<ActionDetail>(`/actions/${encodeURIComponent(id)}/evaluate`),
  reevaluateAction: (id: string) => post<ActionDetail>(`/actions/${encodeURIComponent(id)}/reevaluate`),
  vulnerabilityStatus: () => get<VulnerabilityStatus>('/vulnerabilities/status'),
  vulnerabilityInventory: () => get<PackageInventory[]>('/vulnerabilities/inventory'),
  vulnerabilities: (includeResolved = false) =>
    get<VulnerabilityExposure[]>(`/vulnerabilities?include_resolved=${includeResolved ? 'true' : 'false'}`),
  vulnerability: (id: string) => get<VulnerabilityExposure>(`/vulnerabilities/${encodeURIComponent(id)}`),
  refreshVulnerabilities: () => post<VulnerabilityExposure[]>('/vulnerabilities/refresh'),
  markVulnerabilityManual: (id: string) =>
    post<VulnerabilityExposure>(`/vulnerabilities/${encodeURIComponent(id)}/manual`),
  authoriseVulnerability: (id: string) =>
    post<VulnerabilityExposure>(`/vulnerabilities/${encodeURIComponent(id)}/authorise`),
  updateVulnerability: (id: string) =>
    post<VulnerabilityRemediation>(`/vulnerabilities/${encodeURIComponent(id)}/update`),
  ignoreVulnerability: (id: string) =>
    post<VulnerabilityExposure>(`/vulnerabilities/${encodeURIComponent(id)}/ignore`),
  deleteVulnerability: (id: string) =>
    post<{ deleted: boolean }>(`/vulnerabilities/${encodeURIComponent(id)}/delete`),
  analysisPackages: () => get<AntiserumPackageSummary[]>('/analysis/packages'),
  analysisPackage: (id: string) => get<AntiserumPackageDetail>(`/analysis/packages/${encodeURIComponent(id)}`),
  analysisGraph: (id: string) => get<MemoryGraph>(`/analysis/packages/${encodeURIComponent(id)}/graph`),
  analysisChains: () => get<AttackChainRecord[]>('/analysis/chains'),
  analysisCves: () => get<CveKnowledgeRecord[]>('/analysis/cves'),
  analysisBehaviours: () => get<BehaviourDefinition[]>('/analysis/behaviours'),
  vulnerabilityCandidates: () => get<VulnerabilityCandidate[]>('/analysis/vulnerability-candidates'),
  vulnerabilityCandidate: (id: string) => get<VulnerabilityCandidate>(`/analysis/vulnerability-candidates/${encodeURIComponent(id)}`),
  createVulnerabilityCandidate: (input: VulnerabilityCandidateRequest) => post<VulnerabilityCandidate>('/analysis/vulnerability-candidates', input),
  createAntiserum: (input: CreateAntiserumRequest) => post<AntiserumPackageSummary>('/analysis/export', input),
  importAntiserum: (file: File) => uploadAntiserum(file),
  acceptAntiserumKnowledge: (id: string) =>
    post<AntiserumKnowledgeAcceptanceResult>(`/analysis/packages/${encodeURIComponent(id)}/accept`),
  analysisReviews: () => get<AnalysisReview[]>('/analysis/reviews'),
  createAnalysisReview: (antiserumId: string, label?: string) =>
    post<AnalysisReview>('/analysis/reviews', { antiserum_id: antiserumId, label }),
  openAnalysisReview: (reviewId: string) =>
    post<AnalysisReview>(`/analysis/reviews/${encodeURIComponent(reviewId)}/open`),
  unloadAnalysisReview: (reviewId: string) =>
    del<{ unloaded: boolean; review_id: string }>(`/analysis/reviews/${encodeURIComponent(reviewId)}`),
  antiserumDownloadUrl: (id: string) =>
    withToken(`${apiBase()}/analysis/packages/${encodeURIComponent(id)}/download`),
  cultureCampaigns: () => get<CultureCampaign[]>('/culture/campaigns'),
  createCultureCampaign: (label?: string) =>
    post<CultureCampaign>('/culture/campaigns', label ? { label } : undefined),
  discardCultureCampaign: (campaignId: string) =>
    post<{ discarded: boolean; campaign_id: string }>(
      `/culture/campaigns/${encodeURIComponent(campaignId)}/discard`,
    ),
  herdStatus: () => get<HerdPeerStatus[]>('/herd/status'),
}