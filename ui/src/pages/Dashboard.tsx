import { useCallback } from 'react'
import { api } from '../api/client'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'
import { usePolling } from '../hooks/usePolling'

function formatTime(value: number) {
  return new Date(value * 1000).toLocaleTimeString()
}

export function Dashboard() {
  const status = usePolling(useCallback(() => api.status(), []), 4000)
  const health = usePolling(useCallback(() => api.health(), []), 5000)
  const guard = usePolling(useCallback(() => api.guard(), []), 5000)
  const incidents = usePolling(useCallback(() => api.incidents(), []), 5000)
  const telemetry = usePolling(useCallback(() => api.telemetryRecent(8), []), 3000)
  const sources = usePolling(useCallback(() => api.telemetryStatus(), []), 5000)

  const refresh = () => {
    void status.refresh()
    void health.refresh()
    void guard.refresh()
    void incidents.refresh()
    void telemetry.refresh()
    void sources.refresh()
  }

  return (
    <section className="page-stack">
      <PageHeader
        eyebrow="Local endpoint"
        title="Overview"
        description="Live protection state, current risk and recent host activity."
        onRefresh={refresh}
      />

      {(status.error || health.error || guard.error) && (
        <div className="error-banner">{status.error ?? health.error ?? guard.error}</div>
      )}

      <div className="hero-status">
        <div className="hero-status-main">
          <span className="eyebrow">Protection state</span>
          <div className="hero-status-title">
            <span className={`protection-orb protection-orb--${guard.data?.authority === 'available' ? 'good' : 'bad'}`} />
            <h2>{guard.data?.authority === 'available' ? 'Protection authority available' : 'Protection authority restricted'}</h2>
          </div>
          <p>
            Guard is <strong>{guard.data?.trust_state ?? 'unknown'}</strong>.
            {' '}MAGI and policy decisions remain subject to the Guard authority boundary.
          </p>
        </div>
        <div className="hero-status-side">
          <StatusPill value={guard.data?.trust_state ?? 'unknown'} />
          <span>dendrited {status.data?.version ?? '—'}</span>
        </div>
      </div>

      <div className="overview-metrics">
        <article>
          <span>Open incidents</span>
          <strong>{status.data?.incidents_open ?? '—'}</strong>
          <small>current correlated detections</small>
        </article>
        <article>
          <span>Observations</span>
          <strong>{status.data?.observations_ingested ?? '—'}</strong>
          <small>this daemon session</small>
        </article>
        <article>
          <span>Memory nodes</span>
          <strong>{status.data?.memory_nodes_known ?? '—'}</strong>
          <small>known graph entities</small>
        </article>
        <article>
          <span>Integrity findings</span>
          <strong>{guard.data?.findings_count ?? '—'}</strong>
          <small>persisted Guard findings</small>
        </article>
      </div>

      <div className="dashboard-grid">
        <article className="surface dashboard-incidents">
          <div className="surface-heading">
            <div>
              <span className="eyebrow">Detection</span>
              <h2>Open incidents</h2>
            </div>
            <a href="#/incidents">View all</a>
          </div>
          {(incidents.data ?? []).length === 0 ? (
            <div className="quiet-state">
              <span className="quiet-mark">✓</span>
              <div><strong>No incidents recorded</strong><small>No correlated threat evidence is currently open.</small></div>
            </div>
          ) : (
            <div className="compact-list">
              {incidents.data?.slice(0, 5).map(incident => (
                <a href="#/incidents" key={incident.id} className="compact-row">
                  <StatusPill value={incident.severity} />
                  <div>
                    <strong>{incident.summary}</strong>
                    <small>{incident.id} · {incident.evidence_count} evidence</small>
                  </div>
                  <time>{formatTime(incident.last_seen_at)}</time>
                </a>
              ))}
            </div>
          )}
        </article>

        <article className="surface dashboard-activity">
          <div className="surface-heading">
            <div>
              <span className="eyebrow">Activity</span>
              <h2>Latest events</h2>
            </div>
            <a href="#/activity">Live feed</a>
          </div>
          {(telemetry.data ?? []).length === 0 ? (
            <div className="empty-state">No recent telemetry.</div>
          ) : (
            <div className="activity-mini-list">
              {telemetry.data?.slice(0, 6).map(event => (
                <div className="activity-mini-row" key={event.id}>
                  <span className={`activity-dot activity-dot--${event.source}`} />
                  <div>
                    <strong>{event.event.replaceAll('_', ' ')}</strong>
                    <small>{event.target_label ?? event.target_object ?? event.source_object}</small>
                  </div>
                  <time>{formatTime(event.observed_at)}</time>
                </div>
              ))}
            </div>
          )}
        </article>

        <article className="surface dashboard-sources">
          <div className="surface-heading">
            <div>
              <span className="eyebrow">Sensors</span>
              <h2>Telemetry sources</h2>
            </div>
          </div>
          <div className="source-list">
            {(sources.data?.sources ?? []).map(source => (
              <div key={source.source}>
                <span>{source.source.replaceAll('_', ' ')}</span>
                <StatusPill value={source.status} />
              </div>
            ))}
          </div>
        </article>

        <article className="surface dashboard-health">
          <div className="surface-heading">
            <div>
              <span className="eyebrow">System</span>
              <h2>Subsystem health</h2>
            </div>
            <a href="#/health">Details</a>
          </div>
          <div className="source-list">
            <div><span>Daemon</span><StatusPill value={health.data?.daemon ?? 'unknown'} /></div>
            <div><span>Memory Graph</span><StatusPill value={health.data?.memory ?? 'unknown'} /></div>
            <div><span>Guard</span><StatusPill value={health.data?.guard ?? 'unknown'} /></div>
          </div>
        </article>
      </div>
    </section>
  )
}
