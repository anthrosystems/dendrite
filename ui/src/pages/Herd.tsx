import { useCallback } from 'react'
import { api } from '../api/client'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'
import { usePolling } from '../hooks/usePolling'

function formatTime(value: number | null) {
  return value ? new Date(value * 1000).toLocaleString() : '—'
}

function peerState(lastSuccessAt: number | null, lastError: string | null, lastAttemptAt: number | null) {
  if (lastError && (lastAttemptAt ?? 0) >= (lastSuccessAt ?? 0)) return 'failed'
  if (lastSuccessAt) return 'ok'
  if (lastAttemptAt) return 'pending'
  return 'unknown'
}

export function Herd() {
  const status = usePolling(useCallback(() => api.herdStatus(), []), 10000, 'herd-status')
  const rows = status.data ?? []

  return (
    <section className="page-stack">
      <PageHeader
        eyebrow="Batch 9 // full-mesh"
        title="Herd"
        description="Automated, no-leader Antiserum exchange between operator-configured peer hosts. Every node pushes its own signed state to every configured peer on a timer — the same way a Proxmox cluster replicates configuration to every node rather than through one."
        onRefresh={() => void status.refresh()}
      />

      {status.error && <div className="error-banner">{status.error}</div>}

      <article className="surface self-model-card">
        <span className="eyebrow">Design</span>
        <h2>Push-only, no auto-accept</h2>
        <p>
          A push only verifies, deduplicates and stores a signed <code>.danti</code> package on the
          receiving peer — it does not merge into that peer&apos;s live Memory Graph or vulnerability
          data. Merging stays an explicit operator action from the <a href="#/analysis">Analysis</a> page
          on the receiving host. There is no leader, no election and no pull-based reconciliation:
          an unreachable peer simply fails that tick and is retried on the next one.
        </p>
        <span className="availability-tag">Configured via /etc/dendrite/herd.json</span>
      </article>

      <article className="surface">
        <div className="surface-heading">
          <div>
            <span className="eyebrow">Peers</span>
            <h2>{rows.length} Configured peer{rows.length === 1 ? '' : 's'}</h2>
          </div>
        </div>

        {rows.length === 0 ? (
          <div className="empty-state">
            No peers are configured on this host. Add entries to <code>herd.json</code> (see{' '}
            <code>docs/CONFIGURATION.md</code>) and this table will populate on the next push cycle.
          </div>
        ) : (
          <div className="inventory-table-wrap">
            <table className="inventory-table">
              <thead>
                <tr>
                  <th>Peer</th>
                  <th>Base URL</th>
                  <th>Status</th>
                  <th>Last attempt</th>
                  <th>Last success</th>
                  <th>Packages pushed</th>
                </tr>
              </thead>
              <tbody>
                {rows.map(peer => (
                  <tr key={peer.label}>
                    <td><strong>{peer.label}</strong></td>
                    <td><code>{peer.base_url}</code></td>
                    <td>
                      <StatusPill value={peerState(peer.last_success_at, peer.last_error, peer.last_attempt_at)} />
                      {peer.last_error && <small className="herd-peer-error">{peer.last_error}</small>}
                    </td>
                    <td>{formatTime(peer.last_attempt_at)}</td>
                    <td>{formatTime(peer.last_success_at)}</td>
                    <td>{peer.packages_pushed.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </article>
    </section>
  )
}
