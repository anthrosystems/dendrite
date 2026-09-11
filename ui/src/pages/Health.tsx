import { useCallback } from 'react'
import { api } from '../api/client'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'
import { usePolling } from '../hooks/usePolling'

export function HealthPage() {
  const health = usePolling(useCallback(() => api.health(), []), 5000)
  const status = usePolling(useCallback(() => api.status(), []), 5000)
  const telemetry = usePolling(useCallback(() => api.telemetryStatus(), []), 5000)

  return (
    <section className="page-stack">
      <PageHeader
        eyebrow="Runtime"
        title="System Health"
        description="Daemon, memory, Guard, local interfaces and telemetry source availability."
        onRefresh={() => {
          void health.refresh()
          void status.refresh()
          void telemetry.refresh()
        }}
      />

      {(health.error || status.error || telemetry.error) && (
        <div className="error-banner">{health.error ?? status.error ?? telemetry.error}</div>
      )}

      <div className="health-overview-grid">
        <article className="surface subsystem-card">
          <div><span className="subsystem-icon">D</span><div><span>Core</span><strong>Daemon</strong></div></div>
          <StatusPill value={health.data?.daemon ?? 'unknown'} />
          <small>dendrited {status.data?.version ?? '—'}</small>
        </article>
        <article className="surface subsystem-card">
          <div><span className="subsystem-icon">M</span><div><span>Knowledge</span><strong>Memory Graph</strong></div></div>
          <StatusPill value={health.data?.memory ?? 'unknown'} />
          <small>{status.data?.memory_nodes_known ?? '—'} known nodes</small>
        </article>
        <article className="surface subsystem-card">
          <div><span className="subsystem-icon">G</span><div><span>Authority</span><strong>Guard</strong></div></div>
          <StatusPill value={health.data?.guard ?? 'unknown'} />
          <small>trust boundary</small>
        </article>
      </div>

      <div className="health-detail-grid">
        <article className="surface">
          <div className="surface-heading">
            <div><span className="eyebrow">Interfaces</span><h2>Local endpoints</h2></div>
          </div>
          <div className="key-value-list">
            <div><span>CLI socket</span><code>{status.data?.socket_path ?? '—'}</code></div>
            <div><span>HTTP API</span><code>127.0.0.1:8766</code></div>
            <div><span>UI</span><strong>optional client</strong></div>
          </div>
        </article>

        <article className="surface">
          <div className="surface-heading">
            <div><span className="eyebrow">Telemetry</span><h2>Collectors</h2></div>
          </div>
          <div className="source-list">
            {(telemetry.data?.sources ?? []).map(source => (
              <div key={source.source}>
                <span>{source.source.replaceAll('_', ' ')}</span>
                <StatusPill value={source.status} />
              </div>
            ))}
          </div>
        </article>
      </div>

      <div className="boundary-statement">
        <strong>UI boundary</strong>
        <p>
          This interface is a client of Dendrite. It does not own Memory Graph state, evaluator
          decisions, Guard authority, or detection logic.
        </p>
      </div>
    </section>
  )
}
