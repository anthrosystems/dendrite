import { useCallback, useEffect, useState } from 'react'
import { api } from '../api/client'
import type { IncidentDetail } from '../api/types'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'
import { usePolling } from '../hooks/usePolling'

type Chain = {
  incident: IncidentDetail
  evidenceId: string
  score: string | null
  nodes: string[]
}

function parseChain(description: string): { score: string | null; nodes: string[] } | null {
  if (!description.startsWith('Threat path: ')) return null
  const body = description.slice('Threat path: '.length)
  const [pathPart, suffix] = body.split(' (', 2)
  const nodes = pathPart.split(' -> ').filter(Boolean)
  const score = suffix?.match(/score\s+(\d+)/)?.[1] ?? null
  return nodes.length > 1 ? { nodes, score } : null
}

export function AttackChains() {
  const incidents = usePolling(useCallback(() => api.incidents(), []), 6000)
  const [chains, setChains] = useState<Chain[]>([])

  useEffect(() => {
    let cancelled = false
    async function load() {
      const summaries = incidents.data ?? []
      const details = await Promise.all(summaries.map(item => api.incident(item.id)))
      if (cancelled) return

      const next: Chain[] = []
      for (const incident of details) {
        for (const evidence of incident.evidence) {
          const parsed = parseChain(evidence.description)
          if (parsed) {
            next.push({
              incident,
              evidenceId: evidence.id,
              score: parsed.score,
              nodes: parsed.nodes,
            })
          }
        }
      }
      setChains(next)
    }

    void load().catch(() => setChains([]))
    return () => {
      cancelled = true
    }
  }, [incidents.data])

  return (
    <section className="page-stack">
      <PageHeader
        eyebrow="Correlation"
        title="Attack Chains"
        description="Recorded threat paths extracted only from incident evidence already produced by Dendrite."
        onRefresh={() => void incidents.refresh()}
      />
      {incidents.error && <div className="error-banner">{incidents.error}</div>}

      <article className="surface">
        <div className="surface-heading">
          <div>
            <span className="eyebrow">Evidence-backed</span>
            <h2>{chains.length} recorded chains</h2>
          </div>
          <span>Full relationship metadata will appear when the daemon exposes it.</span>
        </div>

        {chains.length === 0 ? (
          <div className="empty-state">No attack-chain evidence has been recorded.</div>
        ) : (
          <div className="chain-list">
            {chains.map(chain => (
              <article className="chain-card" key={`${chain.incident.incident.id}-${chain.evidenceId}`}>
                <div className="chain-card-header">
                  <div>
                    <StatusPill value={chain.incident.incident.severity} />
                    <strong>{chain.incident.incident.summary}</strong>
                  </div>
                  <div>
                    {chain.score && <span className="chain-score">score {chain.score}</span>}
                    <code>{chain.incident.incident.id}</code>
                  </div>
                </div>
                <div className="chain-flow">
                  {chain.nodes.map((node, index) => (
                    <div className="chain-node-wrap" key={`${node}-${index}`}>
                      <div className="chain-node">
                        <span>{node.split(':', 1)[0]}</span>
                        <code>{node}</code>
                      </div>
                      {index < chain.nodes.length - 1 && (
                        <div className="chain-arrow">
                          <span />
                          <b>→</b>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </article>
            ))}
          </div>
        )}
      </article>
    </section>
  )
}
