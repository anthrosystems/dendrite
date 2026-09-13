import { useCallback, useEffect, useMemo, useState, type CSSProperties } from 'react'
import { api } from '../api/client'
import type { ActionDetail, ActionSummary, Evaluation, TelemetryEvent, TelemetrySource } from '../api/types'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'
import { subscribeLive, type LiveEvent } from '../hooks/live'
import { usePolling } from '../hooks/usePolling'

const MAGI = [
  { key: 'host', name: 'BALTHASAR-2', role: 'HOST' },
  { key: 'user', name: 'CASPER-3', role: 'USER' },
  { key: 'environment', name: 'MELCHIOR-1', role: 'ENVIRONMENT' },
] as const

function latestAction(rows: ActionSummary[] | null | undefined) {
  return [...(rows ?? [])].sort((a, b) => (b.updated_at - a.updated_at) || b.id.localeCompare(a.id))[0] ?? null
}

function sourceStatus(sources: TelemetrySource[] | undefined, source: string) {
  return sources?.find(item => item.source === source)?.status ?? 'unknown'
}

function verdictFor(evaluations: Evaluation[], key: string) {
  return evaluations.find(item => item.evaluator === key)?.verdict?.toUpperCase() ?? 'IDLE'
}

function gateValue(value: string | null | undefined) {
  return (value ?? 'PENDING').replaceAll('_', ' ').toUpperCase()
}

function gateTone(value: string | null | undefined) {
  const normalised = (value ?? '').toLowerCase()
  if (['approved', 'allow', 'available', 'trusted', 'completed', 'verified'].includes(normalised)) return 'good'
  if (['deny', 'denied', 'removed', 'blocked', 'failed', 'compromised', 'quarantined', 'not_authorised'].includes(normalised)) return 'bad'
  return 'warn'
}

function isRecent(event: TelemetryEvent, seconds = 7) {
  return Date.now() / 1000 - event.observed_at <= seconds
}

function isActionDetail(value: unknown): value is ActionDetail {
  if (!value || typeof value !== 'object') return false
  return 'proposal' in value && 'evaluations' in value && 'transactions' in value
}

function Rail({ active, label, direction = 'down' }: { active: boolean; label: string; direction?: 'down' | 'right' }) {
  return (
    <div className={`sys-rail sys-rail--${direction} ${active ? 'is-active' : ''}`} aria-label={label}>
      <span className="sys-rail-line" />
      {active && <i className="sys-rail-pulse" />}
    </div>
  )
}

export function SystemMap() {
  const status = usePolling(useCallback(() => api.status(), []), 5000, 'status')
  const guard = usePolling(useCallback(() => api.guard(), []), 5000, 'guard')
  const telemetry = usePolling(useCallback(() => api.telemetryStatus(), []), 5000, 'telemetry-status')
  const recentTelemetry = usePolling(useCallback(() => api.telemetryRecent(160), []), 5000, 'telemetry-recent-160')
  const actions = usePolling(useCallback(() => api.actions(), []), 5000, 'actions')
  const incidents = usePolling(useCallback(() => api.incidents(), []), 5000, 'incidents')
  const [detail, setDetail] = useState<ActionDetail | null>(null)
  const [decisionPulse, setDecisionPulse] = useState(0)
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
    if (event.kind === 'telemetry') {
      void recentTelemetry.refresh()
      return
    }
    if (event.kind === 'incidents') {
      void incidents.refresh()
      return
    }
    if (event.kind === 'control') {
      if (isActionDetail(event.payload)) setDetail(event.payload)
      else void loadLatest()
      setDecisionPulse(value => value + 1)
      void actions.refresh()
      void guard.refresh()
    }
  }), [actions.refresh, guard.refresh, incidents.refresh, recentTelemetry.refresh, loadLatest])

  const evaluations = detail?.evaluations ?? []
  const recentHostTelemetry = (recentTelemetry.data ?? []).filter(event => event.scope !== 'dendrite_control_plane' && isRecent(event))
  const telemetryActive = recentHostTelemetry.length > 0
  const incidentActive = recentHostTelemetry.some(event => event.incident_ids.length > 0)
  const decisionActive = Boolean(detail && (detail.proposal.status === 'proposed' || Date.now() / 1000 - detail.proposal.updated_at < 20))
  const hasEvaluations = evaluations.length > 0
  const guardLocked = guard.data?.authority === 'removed'

  const refresh = () => {
    void status.refresh(); void guard.refresh(); void telemetry.refresh(); void recentTelemetry.refresh()
    void actions.refresh(); void incidents.refresh(); void loadLatest()
  }

  return (
    <section className="page-stack system-map-page">
      <PageHeader
        eyebrow="System topology // live state"
        title="System Map"
        description="Live operational map of Dendrite. Static channels show architecture; animated signals represent recorded telemetry, incident, MAGI, policy, Guard and action state."
        onRefresh={refresh}
      />

      {(status.error || guard.error || telemetry.error || actions.error) && (
        <div className="error-banner">{status.error ?? guard.error ?? telemetry.error ?? actions.error}</div>
      )}

      <div className={`system-map-v2 ${guardLocked ? 'is-critical' : ''}`}>
        <header className="system-map-v2-hud">
          <div><span>DENDRITE / SYSTEM MAP / LIVE</span><strong>{guardLocked ? 'AUTHORITY RESTRICTED' : 'SYSTEM NOMINAL'}</strong></div>
          <div className="system-map-v2-metrics">
            <span>OBSERVATIONS <b>{status.data?.observations_ingested ?? '—'}</b></span>
            <span>INCIDENTS <b>{status.data?.incidents_open ?? '—'}</b></span>
            <span>MEMORY <b>{status.data?.memory_nodes_known ?? '—'}</b></span>
            <span>AUTHORITY <b>{(guard.data?.authority ?? 'unknown').toUpperCase()}</b></span>
          </div>
        </header>

        <section className="system-zone system-zone--sensing">
          <div className="system-zone-heading"><span>01</span><div><strong>SENSING / KNOWLEDGE</strong><small>HOST OBSERVATION AND CORRELATION</small></div></div>
          <div className="system-zone-row system-zone-row--three">
            <article className={`instrument-node ${telemetryActive ? 'is-active' : ''}`}>
              <span className="instrument-code">SENSOR ARRAY</span><h2>TELEMETRY</h2>
              <div className="instrument-status-grid">
                {['ebpf', 'fanotify', 'proc_polling', 'filesystem_polling'].map(source => (
                  <div key={source}><span>{source.replaceAll('_', ' ').toUpperCase()}</span><StatusPill value={sourceStatus(telemetry.data?.sources, source)} /></div>
                ))}
              </div>
            </article>

            <article className={`instrument-node instrument-node--core ${telemetryActive ? 'is-active' : ''}`}>
              <span className="instrument-code">RUNTIME CORE</span><h2>DENDRITE CORE</h2>
              <div className="core-reactor-v2"><i /><i /><i /></div>
              <strong>dendrited {status.data?.version ?? '—'}</strong>
            </article>

            <div className="instrument-stack">
              <a className="instrument-node instrument-node--compact" href="#/memory">
                <span className="instrument-code">KNOWLEDGE PLANE</span><h2>MEMORY GRAPH</h2>
                <strong>{status.data?.memory_nodes_known?.toLocaleString() ?? '—'} NODES</strong>
              </a>
              <a className={`instrument-node instrument-node--compact ${incidentActive ? 'is-active' : ''}`} href="#/incidents">
                <span className="instrument-code">CORRELATION ENGINE</span><h2>INCIDENT ENGINE</h2>
                <strong>{incidents.data?.length ?? status.data?.incidents_open ?? '—'} OPEN</strong>
              </a>
            </div>
          </div>
          <div className="system-flow-row"><Rail active={telemetryActive} label="Recorded telemetry entering Dendrite Core" direction="right" /><Rail active={incidentActive} label="Recorded correlation entering decision plane" direction="right" /></div>
        </section>

        <section className="system-zone system-zone--decision" key={decisionPulse}>
          <div className="system-zone-heading"><span>02</span><div><strong>DECISION PLANE / MAGI</strong><small>{detail?.proposal.id ?? 'NO ACTIVE PROPOSAL'}</small></div></div>
          <div className={`magi-console ${decisionActive ? 'is-evaluating' : ''}`}>
            <div className="magi-geometry" aria-hidden="true"><i /><i /><i /></div>
            {MAGI.map((unit, index) => {
              const evaluation = evaluations.find(item => item.evaluator === unit.key)
              const verdict = verdictFor(evaluations, unit.key)
              return (
                <article className={`magi-console-unit magi-console-unit--${unit.key} verdict-${verdict.toLowerCase()}`} style={{ '--magi-delay': `${index * 180}ms` } as CSSProperties} key={unit.key}>
                  <div className="magi-console-verdict">{verdict}</div>
                  <div className="magi-console-glyph"><i /></div>
                  <h3>{unit.name}</h3>
                  <small>{unit.role} EVALUATOR</small>
                  <p>{evaluation?.reason ?? 'Awaiting evaluation state.'}</p>
                </article>
              )
            })}
            <div className="magi-console-centre"><span>MAGI</span><b>{hasEvaluations ? 'DELIBERATION RECORDED' : decisionActive ? 'EVALUATING' : 'STANDBY'}</b></div>
          </div>

          <Rail active={hasEvaluations} label="MAGI verdicts entering quorum" />
          <div className="decision-gates">
            <article className={`decision-gate tone-${gateTone(detail?.proposal.quorum)}`}><span>QUORUM</span><strong>{gateValue(detail?.proposal.quorum)}</strong></article>
            <Rail active={Boolean(detail?.proposal.quorum)} label="Quorum entering policy" direction="right" />
            <article className={`decision-gate tone-${gateTone(detail?.proposal.policy)}`}><span>POLICY</span><strong>{gateValue(detail?.proposal.policy)}</strong></article>
          </div>
        </section>

        <section className="system-zone system-zone--authority">
          <div className="system-zone-heading"><span>03</span><div><strong>AUTHORITY / RESPONSE</strong><small>PRIVILEGED ACTION BOUNDARY</small></div></div>
          <Rail active={Boolean(detail?.proposal.policy)} label="Policy entering Guard" />
          <article className={`guard-boundary-v2 tone-${gateTone(detail?.proposal.guard ?? guard.data?.authority)}`}>
            <div><span>GUARD / AUTHORITY BOUNDARY</span><strong>{gateValue(detail?.proposal.guard ?? guard.data?.authority)}</strong></div>
            <div><span>HOST TRUST</span><strong>{(guard.data?.trust_state ?? 'UNKNOWN').toUpperCase()}</strong></div>
          </article>
          <Rail active={detail?.proposal.guard === 'allow'} label="Guard authorised action coordinator" />
          <a className="action-coordinator-v2" href="#/magi">
            <span className="instrument-code">RESPONSE CONTROLLER</span>
            <h2>ACTION COORDINATOR</h2>
            <strong>{detail ? gateValue(detail.proposal.status) : 'IDLE'}</strong>
            <div className="transaction-track-v2">
              {['proposal', 'prepare', 'revalidate', 'commit', 'verify'].map(state => {
                const complete = state === 'proposal' ? Boolean(detail) : detail?.transactions.some(event => event.state === state)
                return <span className={complete ? 'is-complete' : ''} key={state}><i />{state.toUpperCase()}</span>
              })}
            </div>
          </a>
        </section>

        <section className="system-secondary-strip">
          <article><span>ADAPTIVE / SELF</span><strong>NOT EXPOSED</strong><small>Batch 7 maturity API required</small></article>
          <article><span>THREAT KNOWLEDGE</span><strong>PARTIAL</strong><small>Batch 6+ knowledge plane</small></article>
          <article><span>LIVE SIGNAL</span><strong>{telemetryActive ? 'ACTIVE' : 'QUIET'}</strong><small>Animations represent recorded events only</small></article>
        </section>

        <footer className="system-map-v2-footer">
          <span><i className="legend-dot legend-dot--pulse" /> moving signal = recorded activity</span>
          <span><i className="legend-dot legend-dot--idle" /> static channel = architecture</span>
          <span><i className="legend-dot legend-dot--good" /> cyan = approved / available</span>
          <span><i className="legend-dot legend-dot--warn" /> amber = pending / evaluating</span>
          <span><i className="legend-dot legend-dot--bad" /> red = denied / authority removed</span>
        </footer>
      </div>
    </section>
  )
}
