import { useCallback, useEffect, useState } from 'react'
import { api } from '../api/client'
import type { IncidentDetail, IncidentSummary } from '../api/types'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'
import { usePolling } from '../hooks/usePolling'

function formatTime(value: number) {
  return new Date(value * 1000).toLocaleString()
}

export function Incidents() {
  const load = useCallback(() => api.incidents(), [])
  const { data, error, refresh } = usePolling(load, 5000)
  const [selected, setSelected] = useState<string | null>(null)
  const [detail, setDetail] = useState<IncidentDetail | null>(null)

  useEffect(() => {
    if (!selected) {
      setDetail(null)
      return
    }
    void api.incident(selected).then(setDetail).catch(() => setDetail(null))
  }, [selected, data])

  const incidents: IncidentSummary[] = data ?? []

  return (
    <section className="page-stack">
      <PageHeader
        eyebrow="Detection"
        title="Incidents"
        description="Correlated evidence that Dendrite has promoted into persistent security incidents."
        onRefresh={() => void refresh()}
      />
      {error && <div className="error-banner">{error}</div>}

      <div className="master-detail">
        <article className="surface master-list">
          <div className="list-toolbar">
            <span>{incidents.length} incidents</span>
            <span>Newest activity first</span>
          </div>
          {incidents.length === 0 ? (
            <div className="empty-state">No incidents recorded.</div>
          ) : incidents.map(incident => (
            <button
              key={incident.id}
              className={`incident-row ${selected === incident.id ? 'selected' : ''}`}
              onClick={() => setSelected(incident.id)}
            >
              <span className={`severity-rail severity-rail--${incident.severity}`} />
              <div className="incident-row-body">
                <div>
                  <StatusPill value={incident.severity} />
                  <StatusPill value={incident.status} />
                </div>
                <strong>{incident.summary}</strong>
                <small>{incident.id}</small>
              </div>
              <div className="incident-row-meta">
                <strong>{incident.evidence_count}</strong>
                <span>evidence</span>
                <time>{formatTime(incident.last_seen_at)}</time>
              </div>
            </button>
          ))}
        </article>

        <article className="surface detail-surface">
          {!detail ? (
            <div className="detail-placeholder">
              <span className="detail-placeholder-mark">△</span>
              <strong>Select an incident</strong>
              <p>Evidence, related objects and recorded threat paths will appear here.</p>
            </div>
          ) : (
            <>
              <div className="detail-header">
                <div>
                  <span className="eyebrow">{detail.incident.id}</span>
                  <h2>{detail.incident.summary}</h2>
                </div>
                <div className="inline-meta">
                  <StatusPill value={detail.incident.severity} />
                  <StatusPill value={detail.incident.status} />
                </div>
              </div>

              <div className="detail-facts">
                <div><span>First seen</span><strong>{formatTime(detail.incident.first_seen_at)}</strong></div>
                <div><span>Last seen</span><strong>{formatTime(detail.incident.last_seen_at)}</strong></div>
                <div><span>Evidence</span><strong>{detail.evidence.length}</strong></div>
              </div>

              <section className="detail-section">
                <div className="section-label">Related objects</div>
                <div className="object-stack">
                  {detail.related_objects.map(object => <code key={object}>{object}</code>)}
                </div>
              </section>

              <section className="detail-section">
                <div className="section-label">Evidence</div>
                <div className="evidence-stack">
                  {detail.evidence.map(item => (
                    <article key={item.id} className="evidence-card">
                      <div>
                        <span>{item.source.replaceAll('_', ' ')}</span>
                        <strong>{item.confidence}%</strong>
                      </div>
                      <p>{item.description}</p>
                      <small>{formatTime(item.observed_at)} · {item.id}</small>
                    </article>
                  ))}
                </div>
              </section>
            </>
          )}
        </article>
      </div>
    </section>
  )
}
