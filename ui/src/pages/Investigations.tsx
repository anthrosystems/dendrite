import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../api/client'
import type { EvidenceObject, IncidentDetail, IncidentSummary, MemoryNode } from '../api/types'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'
import { usePolling } from '../hooks/usePolling'
import { provenanceBadge } from '../utils/provenance'

type Tab = 'incidents' | 'threats' | 'chains'

type Chain = {
  incident: IncidentDetail
  evidenceIds: string[]
  score: string | null
  nodes: EvidenceObject[]
  firstSeen: number
  lastSeen: number
}

function formatTime(value: number) {
  return new Date(value * 1000).toLocaleString()
}

function parseChain(description: string): { score: string | null; nodes: string[] } | null {
  if (!description.startsWith('Threat path: ')) return null
  const body = description.slice('Threat path: '.length)
  const [pathPart, suffix] = body.split(' (', 2)
  const nodes = pathPart.split(' -> ').filter(Boolean)
  const score = suffix?.match(/score\s+(\d+)/)?.[1] ?? null
  return nodes.length > 1 ? { nodes, score } : null
}

export function Investigations() {
  const incidentsLoad = useCallback(() => api.incidents(), [])
  const threatsLoad = useCallback(() => api.memoryNodes('threat'), [])
  const statusLoad = useCallback(() => api.status(), [])
  const incidents = usePolling(incidentsLoad, 5000, 'investigations-incidents')
  const threats = usePolling(threatsLoad, 12000, 'investigations-threats')
  const status = usePolling(statusLoad, 12000, 'investigations-status')
  const [tab, setTab] = useState<Tab>('incidents')
  const [selected, setSelected] = useState<string | null>(null)
  const [detail, setDetail] = useState<IncidentDetail | null>(null)
  const [details, setDetails] = useState<IncidentDetail[]>([])

  useEffect(() => {
    if (!selected) {
      setDetail(null)
      return
    }
    void api.incident(selected).then(setDetail).catch(() => setDetail(null))
  }, [selected, incidents.data])

  useEffect(() => {
    let cancelled = false
    async function loadDetails() {
      const summaries = incidents.data ?? []
      const next = await Promise.all(summaries.map(item => api.incident(item.id)))
      if (!cancelled) setDetails(next)
    }
    void loadDetails().catch(() => {
      if (!cancelled) setDetails([])
    })
    return () => { cancelled = true }
  }, [incidents.data])

  const chains = useMemo(() => {
    // Evidence records are intentionally preserved in the incident detail, but an
    // attack chain is a canonical ordered path. Repeated evidence for the same path
    // strengthens/supports that chain; it does not create another visual chain.
    const grouped = new Map<string, Chain>()
    for (const incident of details) {
      for (const evidence of incident.evidence) {
        const parsed = parseChain(evidence.description)
        if (!parsed || evidence.objects.length < 2) continue
        const key = `${incident.incident.id}::${evidence.objects.map(object => object.id).join(' -> ')}`
        const existing = grouped.get(key)
        if (existing) {
          existing.evidenceIds.push(evidence.id)
          existing.firstSeen = Math.min(existing.firstSeen, evidence.observed_at)
          existing.lastSeen = Math.max(existing.lastSeen, evidence.observed_at)
          const previousScore = Number(existing.score ?? -1)
          const nextScore = Number(parsed.score ?? -1)
          if (nextScore > previousScore) existing.score = parsed.score
          continue
        }
        grouped.set(key, {
          incident,
          evidenceIds: [evidence.id],
          score: parsed.score,
          nodes: evidence.objects,
          firstSeen: evidence.observed_at,
          lastSeen: evidence.observed_at,
        })
      }
    }
    return [...grouped.values()].sort((left, right) => right.lastSeen - left.lastSeen)
  }, [details])

  const incidentRows: IncidentSummary[] = incidents.data ?? []
  const threatRows: MemoryNode[] = threats.data ?? []
  const localInstanceId = status.data?.instance_id ?? null

  function refresh() {
    void incidents.refresh()
    void threats.refresh()
    void status.refresh()
  }

  return (
    <section className="page-stack investigations-page">
      <PageHeader
        eyebrow="Detection & investigation"
        title="Investigations"
        description="One workspace for active security incidents, persistent threat knowledge, and the attack chains that connect evidence into a case."
        onRefresh={refresh}
      />

      {(incidents.error || threats.error) && (
        <div className="error-banner">{incidents.error ?? threats.error}</div>
      )}

      <div className="investigation-tabs" role="tablist" aria-label="Investigation view">
        <button className={tab === 'incidents' ? 'active' : ''} onClick={() => setTab('incidents')}>
          Incidents <span>{incidentRows.length}</span>
        </button>
        <button className={tab === 'threats' ? 'active' : ''} onClick={() => setTab('threats')}>
          Threat knowledge <span>{threatRows.length}</span>
        </button>
        <button className={tab === 'chains' ? 'active' : ''} onClick={() => setTab('chains')}>
          Attack chains <span>{chains.length}</span>
        </button>
      </div>

      <div className="investigation-explainer surface">
        <div><strong>Incident</strong><span>A live/persistent case created from correlated evidence.</span></div>
        <div><strong>Threat knowledge</strong><span>Threat entities remembered in the Memory Graph, whether or not they currently belong to an open case.</span></div>
        <div><strong>Attack chain</strong><span>The evidence-backed path showing how related objects form a suspicious sequence.</span></div>
      </div>

      {tab === 'incidents' && (
        <div className="master-detail">
          <article className="surface master-list">
            <div className="list-toolbar">
              <span>{incidentRows.length} incidents</span>
              <span>Newest activity first</span>
            </div>
            {incidentRows.length === 0 ? (
              <div className="empty-state">No incidents recorded.</div>
            ) : incidentRows.map(incident => (
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
                    {detail.related_objects.map(object => (
                      <code className="canonical-object-id" key={object}>{object}</code>
                    ))}
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
                        {item.objects.length > 0 && (
                          <div className="evidence-path-objects">
                            {item.objects.map((object, index) => (
                              <div className="evidence-path-object" key={`${object.id}-${index}`}>
                                <strong>{object.label}</strong>
                                <div className="evidence-path-canonical">
                                  <span className="entity-provenance-badge">{provenanceBadge(object, localInstanceId)}</span>
                                  <code>{object.id}</code>
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                        <small>{formatTime(item.observed_at)} · {item.id}</small>
                      </article>
                    ))}
                  </div>
                </section>
              </>
            )}
          </article>
        </div>
      )}

      {tab === 'threats' && (
        <article className="surface">
          <div className="surface-heading">
            <div>
              <span className="eyebrow">Memory-backed knowledge</span>
              <h2>{threatRows.length} threat entities</h2>
            </div>
            <span>These are persistent Memory Graph entities, not a duplicate incident list.</span>
          </div>
          {threatRows.length === 0 ? (
            <div className="empty-state">No threat nodes currently exist in memory.</div>
          ) : (
            <div className="threat-grid">
              {threatRows.map(threat => (
                <article className="threat-card" key={threat.id}>
                  <div className="threat-card-top">
                    <StatusPill value={threat.state} />
                    <StatusPill value={threat.priority} />
                  </div>
                  <strong>{threat.label}</strong>
                  <span className="entity-provenance-badge">{provenanceBadge(threat, localInstanceId)}</span>
                  <code title={threat.id}>{threat.id}</code>
                  <div className="threat-card-meta">
                    <span>Retention {threat.retention}</span>
                    <time>{formatTime(threat.last_seen_at)}</time>
                  </div>
                </article>
              ))}
            </div>
          )}
        </article>
      )}

      {tab === 'chains' && (
        <article className="surface">
          <div className="surface-heading">
            <div>
              <span className="eyebrow">Evidence-backed paths</span>
              <h2>{chains.length} unique attack {chains.length === 1 ? 'chain' : 'chains'}</h2>
            </div>
            <span>Identical ordered paths are shown once; repeated evidence is retained as supporting evidence.</span>
          </div>
          {chains.length === 0 ? (
            <div className="empty-state">No attack-chain evidence has been recorded.</div>
          ) : (
            <div className="chain-list">
              {chains.map(chain => (
                <article className="chain-card" key={`${chain.incident.incident.id}-${chain.nodes.map(node => node.id).join('>')}`}>
                  <div className="chain-card-header">
                    <div>
                      <StatusPill value={chain.incident.incident.severity} />
                      <strong>{chain.incident.incident.summary}</strong>
                    </div>
                    <div className="chain-card-meta">
                      {chain.score && <span className="chain-score">Score {chain.score}</span>}
                      <span className="chain-support">{chain.evidenceIds.length} supporting evidence</span>
                      <code>{chain.incident.incident.id}</code>
                    </div>
                  </div>
                  <div className="chain-flow">
                    {chain.nodes.map((node, index) => (
                      <div className="chain-node-wrap" key={`${node.id}-${index}`}>
                        <div className="chain-node">
                          <span>Step {String(index + 1).padStart(2, '0')}</span>
                          <strong>{node.label}</strong>
                          <div className="chain-node-identity">
                            <span className="entity-provenance-badge">{provenanceBadge(node, localInstanceId)}</span>
                            <code title={node.id}>{node.id}</code>
                          </div>
                        </div>
                        {index < chain.nodes.length - 1 && (
                          <div className="chain-arrow"><span /><b>→</b></div>
                        )}
                      </div>
                    ))}
                  </div>
                </article>
              ))}
            </div>
          )}
        </article>
      )}
    </section>
  )
}
