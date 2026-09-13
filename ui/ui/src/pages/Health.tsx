import { useCallback } from 'react'
import { api } from '../api/client'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'
import { usePolling } from '../hooks/usePolling'

function formatTime(value: number) {
  return new Date(value * 1000).toLocaleString()
}

const severityOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  warning: 2,
  informational: 3,
}


const telemetrySourceOrder = ['ebpf', 'fanotify', 'proc_polling', 'filesystem_polling']

function orderedSources<T extends { source: string }>(sources: T[]) {
  const rank = new Map(telemetrySourceOrder.map((source, index) => [source, index]))
  return [...sources].sort((left, right) => {
    const leftRank = rank.get(left.source) ?? Number.MAX_SAFE_INTEGER
    const rightRank = rank.get(right.source) ?? Number.MAX_SAFE_INTEGER
    return leftRank - rightRank || left.source.localeCompare(right.source)
  })
}

function sourceLabel(value: string) {
  switch (value) {
    case 'ebpf': return 'eBPF'
    case 'fanotify': return 'fanotify'
    case 'proc_polling': return '/proc polling'
    case 'filesystem_polling': return 'filesystem polling'
    default: return value.replaceAll('_', ' ')
  }
}

export function HealthPage() {
  const health = usePolling(useCallback(() => api.health(), []), 5000, 'health')
  const status = usePolling(useCallback(() => api.status(), []), 5000, 'status')
  const telemetry = usePolling(useCallback(() => api.telemetryStatus(), []), 5000, 'telemetry-status')
  const guard = usePolling(useCallback(() => api.guard(), []), 5000, 'guard')
  const findings = usePolling(useCallback(() => api.guardFindings(), []), 5000, 'guard-findings')

  const trustState = guard.data?.trust_state ?? 'unknown'
  const authority = guard.data?.authority ?? 'unknown'
  const authorityRemoved = authority === 'removed'
  const sortedFindings = [...(findings.data ?? [])].sort((a, b) => {
    const severityDifference = (severityOrder[a.severity] ?? 999) - (severityOrder[b.severity] ?? 999)
    return severityDifference !== 0 ? severityDifference : b.recorded_at - a.recorded_at
  })

  const refresh = () => {
    void health.refresh()
    void status.refresh()
    void telemetry.refresh()
    void guard.refresh()
    void findings.refresh()
  }

  return (
    <section className="page-stack health-page">
      <PageHeader
        eyebrow="Runtime // Self // authority"
        title="System Health"
        description="Runtime health, host trust, Guard authority, Self-model availability, integrity findings and telemetry collectors in one system view."
        onRefresh={refresh}
      />

      {(health.error || status.error || telemetry.error || guard.error || findings.error) && (
        <div className="error-banner">
          {health.error ?? status.error ?? telemetry.error ?? guard.error ?? findings.error}
        </div>
      )}

      <section className={`trust-hero health-trust-hero ${authorityRemoved ? 'trust-hero--restricted' : ''}`}>
        <div className="trust-emblem"><span /><span /></div>
        <div className="trust-hero-copy">
          <span className="eyebrow">Host trust / Guard authority</span>
          <h2>{trustState.replaceAll('_', ' ')}</h2>
          <p>
            {authorityRemoved
              ? 'Guard has removed execution authority. Actions remain blocked even if MAGI and policy would otherwise approve them.'
              : 'Guard currently permits execution authority, subject to MAGI quorum, policy and action-specific checks.'}
          </p>
        </div>
        <div className="trust-hero-status">
          <div><span>Execution authority</span><StatusPill value={authority} /></div>
          <small>{guard.data?.findings_count ?? 0} integrity findings</small>
        </div>
      </section>

      <div className="health-overview-grid health-overview-grid--expanded">
        <article className="surface subsystem-card">
          <div><span className="subsystem-icon">D</span><div><span>Core runtime</span><strong>Dendrite daemon</strong></div></div>
          <StatusPill value={health.data?.daemon ?? 'unknown'} />
          <small>dendrited {status.data?.version ?? '—'}</small>
        </article>
        <article className="surface subsystem-card">
          <div><span className="subsystem-icon">M</span><div><span>Knowledge subsystem</span><strong>Memory Graph</strong></div></div>
          <StatusPill value={health.data?.memory ?? 'unknown'} />
          <small>{status.data?.memory_nodes_known ?? '—'} known nodes</small>
        </article>
        <article className="surface subsystem-card">
          <div><span className="subsystem-icon">G</span><div><span>Authority subsystem</span><strong>Guard</strong></div></div>
          <StatusPill value={health.data?.guard ?? 'unknown'} />
          <small>Trust state: {trustState.replaceAll('_', ' ')}</small>
        </article>
        <article className="surface subsystem-card subsystem-card--self">
          <div><span className="subsystem-icon">S</span><div><span>Adaptive identity</span><strong>Self model</strong></div></div>
          <StatusPill value="not exposed" />
          <small>The daemon does not expose Self maturity/baseline state yet.</small>
        </article>
      </div>

      <div className="health-detail-grid">
        <article className="surface">
          <div className="surface-heading">
            <div><span className="eyebrow">Interfaces</span><h2>Local endpoints</h2></div>
          </div>
          <div className="key-value-list">
            <div><span>CLI Unix socket</span><code>{status.data?.socket_path ?? '—'}</code></div>
            <div><span>HTTP API endpoint</span><code>127.0.0.1:8766</code></div>
            <div><span>WebSocket live stream</span><code>127.0.0.1:8767</code></div>
            <div><span>UI role</span><strong>Optional local client</strong></div>
          </div>
        </article>

        <article className="surface">
          <div className="surface-heading">
            <div><span className="eyebrow">Telemetry</span><h2>Collectors</h2></div>
          </div>
          <div className="source-list source-list--verbose">
            {orderedSources(telemetry.data?.sources ?? []).map(source => (
              <div key={source.source}>
                <div>
                  <strong>{sourceLabel(source.source)}</strong>
                  <small>{source.detail}</small>
                </div>
                <StatusPill value={source.status} />
              </div>
            ))}
          </div>
        </article>
      </div>

      {telemetry.data?.pipeline && (
        <article className="surface">
          <div className="surface-heading">
            <div><span className="eyebrow">Ingestion pressure</span><h2>Telemetry pipeline</h2></div>
            <span>{telemetry.data.pipeline.queue_depth.toLocaleString()} / {telemetry.data.pipeline.queue_capacity.toLocaleString()} queued</span>
          </div>
          <div className="health-ingestion-lanes">
            <div className="health-ingestion-lane health-ingestion-lane--high">
              <div><span>High-value</span><strong>{telemetry.data.pipeline.high_value.queue_depth.toLocaleString()} / {telemetry.data.pipeline.high_value.queue_capacity.toLocaleString()}</strong></div>
              <small>{telemetry.data.pipeline.high_value.events_dropped.toLocaleString()} dropped · max wait {telemetry.data.pipeline.high_value.max_queue_wait_ms} ms</small>
            </div>
            <div className="health-ingestion-lane health-ingestion-lane--routine">
              <div><span>Routine</span><strong>{telemetry.data.pipeline.routine.queue_depth.toLocaleString()} / {telemetry.data.pipeline.routine.queue_capacity.toLocaleString()}</strong></div>
              <small>{telemetry.data.pipeline.routine.events_dropped.toLocaleString()} dropped · max wait {telemetry.data.pipeline.routine.max_queue_wait_ms} ms</small>
            </div>
          </div>
          <div className="telemetry-pipeline-grid telemetry-pipeline-grid--health">
            <div><span>Peak combined queue</span><strong>{telemetry.data.pipeline.peak_queue_depth.toLocaleString()}</strong></div>
            <div><span>Total dropped</span><strong>{telemetry.data.pipeline.events_dropped.toLocaleString()}</strong></div>
            <div><span>Max combined wait</span><strong>{telemetry.data.pipeline.max_queue_wait_ms} ms</strong></div>
            <div><span>Max processing time</span><strong>{telemetry.data.pipeline.max_processing_ms} ms</strong></div>
          </div>
        </article>
      )}

      <article className="surface health-self-section">
        <div className="surface-heading">
          <div><span className="eyebrow">Self / trust separation</span><h2>Adaptive host identity</h2></div>
          <span>Backend API required</span>
        </div>
        <p>
          Guard trust and Self are related but not identical. Guard currently exposes host trust and action authority. The planned Self model will expose learned host identity, maturity, expected behaviour and confidence here when Batch 7 implements that API. This UI does not invent those values in the meantime.
        </p>
      </article>

      <article className="surface">
        <div className="surface-heading">
          <div><span className="eyebrow">Guard integrity</span><h2>Integrity findings</h2></div>
          <span>{sortedFindings.length} recorded</span>
        </div>

        {sortedFindings.length === 0 ? (
          <div className="quiet-state">
            <span className="quiet-mark">✓</span>
            <div><strong>No integrity findings</strong><small>Guard has not recorded an integrity violation.</small></div>
          </div>
        ) : (
          <div className="integrity-list">
            {sortedFindings.map(finding => (
              <article key={finding.id} className={`integrity-row integrity-row--${finding.severity}`}>
                <span className="integrity-severity-line" />
                <div className="integrity-labelled-status">
                  <span>Finding severity</span>
                  <StatusPill value={finding.severity} />
                </div>
                <div>
                  <code>{finding.target}</code>
                  <strong>{finding.description}</strong>
                </div>
                <time>{formatTime(finding.recorded_at)}</time>
              </article>
            ))}
          </div>
        )}
      </article>

      <div className="boundary-statement">
        <strong>UI boundary</strong>
        <p>
          This interface is a client of Dendrite. It does not own Memory Graph state, evaluator decisions, Guard authority, Self state or detection logic.
        </p>
      </div>
    </section>
  )
}
