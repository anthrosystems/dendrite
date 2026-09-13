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

export function GuardPage() {
  const status = usePolling(useCallback(() => api.guard(), []), 5000)
  const findings = usePolling(useCallback(() => api.guardFindings(), []), 5000)
  const trustState = status.data?.trust_state ?? 'unknown'
  const authority = status.data?.authority ?? 'unknown'
  const authorityRemoved = authority === 'removed'

  const sortedFindings = [...(findings.data ?? [])].sort((a, b) => {
    const difference = (severityOrder[a.severity] ?? 999) - (severityOrder[b.severity] ?? 999)
    return difference !== 0 ? difference : b.recorded_at - a.recorded_at
  })

  return (
    <section className="page-stack">
      <PageHeader
        eyebrow="Authority boundary"
        title="Self & Trust"
        description="Guard trust state and integrity findings. The separate Self model is not exposed by the daemon API yet."
        onRefresh={() => {
          void status.refresh()
          void findings.refresh()
        }}
      />

      {(status.error || findings.error) && (
        <div className="error-banner">{status.error ?? findings.error}</div>
      )}

      <div className={`trust-hero ${authorityRemoved ? 'trust-hero--restricted' : ''}`}>
        <div className="trust-emblem"><span /><span /></div>
        <div className="trust-hero-copy">
          <span className="eyebrow">{authorityRemoved ? 'Execution authority removed' : 'Execution authority available'}</span>
          <h2>{trustState.replaceAll('_', ' ')}</h2>
          <p>
            {authorityRemoved
              ? 'Guard is preventing action execution while host trust is not established.'
              : 'Host trust is established. Guard may allow actions that also pass MAGI and policy.'}
          </p>
        </div>
        <div className="trust-hero-status">
          <StatusPill value={authority} />
          <small>{status.data?.findings_count ?? 0} integrity findings</small>
        </div>
      </div>

      <div className="self-grid">
        <article className="surface self-state-card">
          <span className="eyebrow">Guard</span>
          <div><span>Trust state</span><StatusPill value={trustState} /></div>
          <div><span>Authority</span><StatusPill value={authority} /></div>
          <div><span>Integrity findings</span><strong>{status.data?.findings_count ?? 0}</strong></div>
        </article>

        <article className="surface self-model-card">
          <span className="eyebrow">Self model</span>
          <h2>Not exposed yet</h2>
          <p>
            Dendrite's planned Self model remains a separate security concept. The UI will not
            invent identity, baseline or expected-state data until the daemon exposes it.
          </p>
          <span className="availability-tag">API required</span>
        </article>
      </div>

      <article className="surface">
        <div className="surface-heading">
          <div>
            <span className="eyebrow">Integrity</span>
            <h2>Findings</h2>
          </div>
          <span>Critical findings are shown first</span>
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
                <StatusPill value={finding.severity} />
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
    </section>
  )
}
