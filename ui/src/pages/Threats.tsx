import { useCallback } from 'react'
import { api } from '../api/client'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'
import { usePolling } from '../hooks/usePolling'

function formatTime(value: number) {
  return new Date(value * 1000).toLocaleString()
}

export function Threats() {
  const threats = usePolling(useCallback(() => api.memoryNodes('threat'), []), 6000)

  return (
    <section className="page-stack">
      <PageHeader
        eyebrow="Knowledge"
        title="Threats"
        description="Threat entities currently represented in the real Memory Graph."
        onRefresh={() => void threats.refresh()}
      />
      {threats.error && <div className="error-banner">{threats.error}</div>}

      <article className="surface">
        <div className="surface-heading">
          <div>
            <span className="eyebrow">Memory-backed</span>
            <h2>{threats.data?.length ?? 0} known threat entities</h2>
          </div>
          <span>No separate threat catalogue is invented by the UI.</span>
        </div>

        {(threats.data ?? []).length === 0 ? (
          <div className="empty-state">No threat nodes currently exist in memory.</div>
        ) : (
          <div className="threat-grid">
            {threats.data?.map(threat => (
              <article className="threat-card" key={threat.id}>
                <div className="threat-card-top">
                  <StatusPill value={threat.state} />
                  <StatusPill value={threat.priority} />
                </div>
                <strong>{threat.label}</strong>
                <code>{threat.id}</code>
                <div className="threat-card-meta">
                  <span>retention {threat.retention}</span>
                  <time>{formatTime(threat.last_seen_at)}</time>
                </div>
              </article>
            ))}
          </div>
        )}
      </article>
    </section>
  )
}
