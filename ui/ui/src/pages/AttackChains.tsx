import { useCallback } from 'react'
import { api } from '../api/client'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'
import { usePolling } from '../hooks/usePolling'
import { provenanceBadge } from '../utils/provenance'

export function AttackChains() {
  const chains = usePolling(useCallback(() => api.analysisChains(), []), 6000, 'attack-chains')
  const status = usePolling(useCallback(() => api.status(), []), 12000, 'attack-chain-status')
  const localInstanceId = status.data?.instance_id ?? null
  const rows = chains.data ?? []

  return (
    <section className="page-stack">
      <PageHeader
        eyebrow="Correlation"
        title="Attack Chains"
        description="Evidence-backed threat paths with behaviour fingerprints and later CVE/vulnerability classification layered onto the same canonical chain identity."
        onRefresh={() => void chains.refresh()}
      />
      {chains.error && <div className="error-banner">{chains.error}</div>}

      <article className="surface">
        <div className="surface-heading">
          <div>
            <span className="eyebrow">Evidence-backed</span>
            <h2>{rows.length} recorded chains</h2>
          </div>
          <span>Classification enriches a chain; it never rewrites its canonical chain ID.</span>
        </div>

        {rows.length === 0 ? (
          <div className="empty-state">No attack-chain evidence has been recorded.</div>
        ) : (
          <div className="chain-list">
            {rows.map(chain => (
              <article className="chain-card" key={chain.id}>
                <div className="chain-card-header">
                  <div>
                    <StatusPill value={chain.severity} />
                    <strong>{chain.title}</strong>
                    {chain.title !== chain.original_title && <small>Originally: {chain.original_title}</small>}
                  </div>
                  <div>
                    {chain.classification_confidence != null && <span className="chain-score">Classification {chain.classification_confidence}%</span>}
                    <code>{chain.id}</code>
                  </div>
                </div>

                {(chain.matched_cve_ids.length > 0 || chain.behaviour_ids.length > 0) && (
                  <div className="chain-classification-strip">
                    {chain.matched_cve_ids.length > 0 && <div><span>Matched vulnerability</span><strong>{chain.matched_cve_ids.join(', ')}</strong></div>}
                    {chain.behaviour_ids.length > 0 && <div><span>Behaviours</span><strong>{chain.behaviour_ids.join(', ')}</strong></div>}
                    {chain.behaviour_fingerprint && <div><span>Behaviour fingerprint</span><code>{chain.behaviour_fingerprint}</code></div>}
                  </div>
                )}

                <div className="chain-flow">
                  {chain.steps.map((node, index) => (
                    <div className="chain-node-wrap" key={`${node.id}-${index}`}>
                      <div className="chain-node">
                        <strong>{node.label}</strong>
                        <div className="chain-node-identity">
                          <span className="entity-provenance-badge">{provenanceBadge(node, localInstanceId)}</span>
                          <code title={node.id}>{node.id}</code>
                        </div>
                      </div>
                      {index < chain.steps.length - 1 && (
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
