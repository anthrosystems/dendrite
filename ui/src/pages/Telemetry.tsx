import { useCallback } from 'react'
import { api } from '../api/client'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'
import { usePolling } from '../hooks/usePolling'

function formatTime(value: number) {
  return new Date(value * 1000).toLocaleTimeString()
}

function readable(value: string) {
  return value.replaceAll('_', ' ')
}

export function Telemetry() {
  const recent = usePolling(useCallback(() => api.telemetryRecent(120), []), 2000)
  const status = usePolling(useCallback(() => api.telemetryStatus(), []), 5000)

  return (
    <section className="page-stack">
      <PageHeader
        eyebrow="Linux telemetry"
        title="Activity"
        description="Normalised process and filesystem activity entering Dendrite's observation pipeline."
        onRefresh={() => {
          void recent.refresh()
          void status.refresh()
        }}
      />

      {(recent.error || status.error) && (
        <div className="error-banner">{recent.error ?? status.error}</div>
      )}

      <div className="sensor-strip">
        {(status.data?.sources ?? []).map(source => (
          <article key={source.source}>
            <div>
              <span className={`sensor-dot sensor-dot--${source.status}`} />
              <strong>{readable(source.source)}</strong>
            </div>
            <StatusPill value={source.status} />
            <small>{source.detail}</small>
          </article>
        ))}
      </div>

      <article className="surface activity-surface">
        <div className="surface-heading">
          <div>
            <span className="eyebrow">Live event stream</span>
            <h2>{status.data?.recent_events ?? recent.data?.length ?? 0} buffered events</h2>
          </div>
          <span>Newest first · real daemon telemetry</span>
        </div>

        {(recent.data ?? []).length === 0 ? (
          <div className="empty-state">No telemetry events have been collected since this daemon started.</div>
        ) : (
          <div className="activity-stream">
            {recent.data?.map(event => (
              <article className="activity-event" key={event.id}>
                <div className="activity-time">
                  <span className={`activity-source-dot activity-source-dot--${event.source}`} />
                  <time>{formatTime(event.observed_at)}</time>
                </div>
                <div className="activity-event-body">
                  <div className="activity-event-title">
                    <strong>{readable(event.event)}</strong>
                    <StatusPill value={event.source} />
                    {event.process_id && <span className="pid-tag">PID {event.process_id}</span>}
                  </div>
                  <div className="activity-route">
                    <code>{event.source_object}</code>
                    <span>→</span>
                    <code>{event.target_object ?? '—'}</code>
                  </div>
                  {event.target_label && <small>{event.target_label}</small>}
                </div>
                <div className="activity-observation">
                  <span>{readable(event.observation_kind)}</span>
                  {event.incident_ids.map(id => <a href="#/incidents" key={id}>{id}</a>)}
                </div>
              </article>
            ))}
          </div>
        )}
      </article>
    </section>
  )
}
