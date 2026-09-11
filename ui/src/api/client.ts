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
  MemoryNeighbours,
  MemoryNode,
  MemoryPath,
  TelemetryEvent,
  TelemetryStatus,
} from './types'

const API_BASE = import.meta.env.VITE_DENDRITE_API_BASE ?? '/api/v1'

export class ApiError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message)
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      Accept: 'application/json',
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...init?.headers,
    },
  })

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
const post = <T,>(path: string, body?: unknown) =>
  request<T>(path, {
    method: 'POST',
    body: body === undefined ? undefined : JSON.stringify(body),
  })

export const api = {
  status: () => get<DaemonStatus>('/status'),
  health: () => get<Health>('/health'),
  guard: () => get<GuardStatus>('/guard'),
  guardFindings: () => get<IntegrityFinding[]>('/guard/findings'),
  telemetryStatus: () => get<TelemetryStatus>('/telemetry/status'),
  telemetryRecent: (limit = 100) => get<TelemetryEvent[]>(`/telemetry/recent?limit=${limit}`),
  incidents: () => get<IncidentSummary[]>('/incidents'),
  incident: (id: string) => get<IncidentDetail>(`/incidents/${encodeURIComponent(id)}`),
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
}
