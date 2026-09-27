import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../api/client'
import type { ActionDetail, ActionSummary, Evaluation, TelemetrySource } from '../api/types'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'
import { subscribeLive, type LiveEvent } from '../hooks/live'
import { usePolling } from '../hooks/usePolling'

const MAGI = [
  { key: 'host', name: 'BALTHASAR-2', role: 'Host evaluator' },
  { key: 'user', name: 'CASPER-3', role: 'User evaluator' },
  { key: 'environment', name: 'MELCHIOR-1', role: 'Environment evaluator' },
] as const

const telemetrySourceOrder: Record<string, number> = {
  ebpf: 0,
  fanotify: 1,
  proc_polling: 2,
  filesystem_polling: 3,
}

function telemetrySourceLabel(source: string) {
  switch (source) {
    case 'ebpf': return 'EBPF'
    case 'fanotify': return 'Fanotify'
    case 'proc_polling': return 'Proc polling'
    case 'filesystem_polling': return 'Filesystem polling'
    default: return source.replaceAll('_', ' ')
  }
}

function latestAction(rows: ActionSummary[] | null | undefined) {
  return [...(rows ?? [])].sort((a, b) => (b.updated_at - a.updated_at) || b.id.localeCompare(a.id))[0] ?? null
}

function sourceStatus(sources: TelemetrySource[] | undefined, source: string) {
  return sources?.find(item => item.source === source)?.status ?? 'unknown'
}

function verdictFor(evaluations: Evaluation[], key: string) {
  return evaluations.find(item => item.evaluator === key)?.verdict ?? 'idle'
}

function gateValue(value: string | null | undefined) {
  return value ?? 'pending'
}

function isActionDetail(value: unknown): value is ActionDetail {
  if (!value || typeof value !== 'object') return false
  return 'proposal' in value && 'evaluations' in value && 'transactions' in value
}

export function SystemMap() {
  const status = usePolling(useCallback(() => api.status(), []), 5000, 'status')
  const guard = usePolling(useCallback(() => api.guard(), []), 5000, 'guard')
  const telemetry = usePolling(useCallback(() => api.telemetryStatus(), []), 5000, 'telemetry-status')
  const actions = usePolling(useCallback(() => api.actions(), []), 5000, 'actions')
  const incidents = usePolling(useCallback(() => api.incidents(), []), 5000, 'incidents')
  const [detail, setDetail] = useState<ActionDetail | null>(null)
  const latest = useMemo(() => latestAction(actions.data), [actions.data])

  const loadLatest = useCallback(async () => {
    const rows = await api.actions()
    const newest = latestAction(rows)
    if (!newest) {
      setDetail(null)
      return
    }
    setDetail(await api.action(newest.id))
  }, [])

  useEffect(() => {
    if (!latest) {
      setDetail(null)
      return
    }
    let cancelled = false
    void api.action(latest.id).then(value => { if (!cancelled) setDetail(value) }).catch(() => undefined)
    return () => { cancelled = true }
  }, [latest?.id, latest?.updated_at])

  useEffect(() => subscribeLive((event: LiveEvent) => {
    if (event.kind === 'incidents') {
      void incidents.refresh()
      return
    }
    if (event.kind === 'control') {
      if (isActionDetail(event.payload)) setDetail(event.payload)
      else void loadLatest()
      void actions.refresh()
      void guard.refresh()
    }
  }), [actions.refresh, guard.refresh, incidents.refresh, loadLatest])

  const evaluations = detail?.evaluations ?? []
  const guardLocked = guard.data?.authority === 'removed'

  const refresh = () => {
    void status.refresh(); void guard.refresh(); void telemetry.refresh()
    void actions.refresh(); void incidents.refresh(); void loadLatest()
  }

  return (
    <section className="page-stack">
      <PageHeader
        eyebrow="System topology"
        title="System Map"
        description="How telemetry, MAGI evaluation, policy and Guard connect for the most recent action decision on this host."
        onRefresh={refresh}
      />

      {(status.error || guard.error || telemetry.error || actions.error) && (
        <div className="error-banner">{status.error ?? guard.error ?? telemetry.error ?? actions.error}</div>
      )}

      <div className="overview-metrics">
        <article>
          <span>Observations</span>
          <strong>{status.data?.observations_ingested ?? '—'}</strong>
          <small>this daemon session</small>
        </article>
        <article>
          <span>Open incidents</span>
          <strong>{status.data?.incidents_open ?? '—'}</strong>
          <small>correlated detections</small>
        </article>
        <article>
          <span>Memory nodes</span>
          <strong>{status.data?.memory_nodes_known ?? '—'}</strong>
          <small><a href="#/memory">known graph entities</a></small>
        </article>
        <article>
          <span>Authority</span>
          <strong><StatusPill value={guard.data?.authority ?? 'unknown'} /></strong>
          <small>Guard boundary</small>
        </article>
      </div>

      <div className="dashboard-grid">
        <article className="surface">
          <div className="surface-heading">
            <div>
              <span className="eyebrow">01 · Sensing &amp; knowledge</span>
              <h2>Telemetry &amp; correlation</h2>
            </div>
          </div>
          <div className="source-list">
            {['ebpf', 'fanotify', 'proc_polling', 'filesystem_polling']
              .sort((left, right) => (telemetrySourceOrder[left] ?? 99) - (telemetrySourceOrder[right] ?? 99))
              .map(source => (
                <div key={source}>
                  <span>{telemetrySourceLabel(source)}</span>
                  <StatusPill value={sourceStatus(telemetry.data?.sources, source)} />
                </div>
              ))}
          </div>
          <div className="compact-list">
            <a href="#/memory" className="compact-row">
              <StatusPill value="graph" />
              <div><strong>Memory Graph</strong><small>Tiered short/long-term correlation store</small></div>
              <strong>{status.data?.memory_nodes_known?.toLocaleString() ?? '—'}</strong>
            </a>
            <a href="#/incidents" className="compact-row">
              <StatusPill value="engine" />
              <div><strong>Incident engine</strong><small>Correlated threat evidence</small></div>
              <strong>{incidents.data?.length ?? status.data?.incidents_open ?? '—'}</strong>
            </a>
          </div>
        </article>

        <article className="surface">
          <div className="surface-heading">
            <div>
              <span className="eyebrow">02 · Decision plane</span>
              <h2>MAGI quorum</h2>
            </div>
            <span>{detail?.proposal.id ?? 'No active proposal'}</span>
          </div>
          <div className="source-list">
            {MAGI.map(unit => (
              <div key={unit.key}>
                <span>{unit.name} <small>{unit.role}</small></span>
                <StatusPill value={verdictFor(evaluations, unit.key)} />
              </div>
            ))}
          </div>
          <div className="source-list">
            <div><span>Quorum</span><StatusPill value={gateValue(detail?.proposal.quorum)} /></div>
            <div><span>Policy</span><StatusPill value={gateValue(detail?.proposal.policy)} /></div>
          </div>
        </article>

        <article className={`surface ${guardLocked ? 'trust-hero--restricted' : ''}`}>
          <div className="surface-heading">
            <div>
              <span className="eyebrow">03 · Authority &amp; response</span>
              <h2>Guard boundary</h2>
            </div>
          </div>
          <div className="source-list">
            <div><span>Guard</span><StatusPill value={gateValue(detail?.proposal.guard ?? guard.data?.authority)} /></div>
            <div><span>Host trust</span><StatusPill value={guard.data?.trust_state ?? 'unknown'} /></div>
          </div>
          <a href="#/magi" className="compact-row">
            <StatusPill value="action" />
            <div><strong>Action coordinator</strong><small>Response controller</small></div>
            <StatusPill value={detail ? gateValue(detail.proposal.status) : 'idle'} />
          </a>
          <div className="transaction-track">
            {['proposal', 'prepare', 'revalidate', 'commit', 'verify'].map(state => {
              const complete = state === 'proposal' ? Boolean(detail) : detail?.transactions.some(event => event.state === state)
              return (
                <div className="transaction-step" key={state}>
                  <span className={`transaction-dot ${complete ? 'transaction-dot--completed' : ''}`} />
                  <div><strong>{state.replaceAll('_', ' ')}</strong></div>
                </div>
              )
            })}
          </div>
        </article>

        <article className="surface">
          <div className="surface-heading">
            <div>
              <span className="eyebrow">Batch 9</span>
              <h2>Not shown above</h2>
            </div>
          </div>
          <div className="compact-list">
            <a href="#/culture" className="compact-row">
              <StatusPill value="prepared" />
              <div><strong>Culture</strong><small>Isolated analysis workspaces — scaffold only, no execution yet</small></div>
            </a>
            <a href="#/herd" className="compact-row">
              <StatusPill value="unknown" />
              <div><strong>Herd</strong><small>Per-host push status — no cross-host fleet view yet</small></div>
            </a>
          </div>
        </article>
      </div>
    </section>
  )
}
