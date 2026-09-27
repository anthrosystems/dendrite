import { useCallback, useState } from 'react'
import { api } from '../api/client'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'
import { usePolling } from '../hooks/usePolling'

function formatTime(value: number) {
  return new Date(value * 1000).toLocaleString()
}

export function Culture() {
  const campaigns = usePolling(useCallback(() => api.cultureCampaigns(), []), 10000, 'culture-campaigns')
  const [label, setLabel] = useState('')
  const [working, setWorking] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)

  const createCampaign = async () => {
    setWorking(true)
    setActionError(null)
    try {
      await api.createCultureCampaign(label.trim() || undefined)
      setLabel('')
      await campaigns.refresh()
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error))
    } finally {
      setWorking(false)
    }
  }

  const discardCampaign = async (campaignId: string) => {
    const confirmed = window.confirm(
      `Discard campaign ${campaignId}? This permanently deletes its isolated database snapshots and workspace. It does not affect any live Dendrite data.`,
    )
    if (!confirmed) return
    setWorking(true)
    setActionError(null)
    try {
      await api.discardCultureCampaign(campaignId)
      await campaigns.refresh()
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error))
    } finally {
      setWorking(false)
    }
  }

  const rows = campaigns.data ?? []

  return (
    <section className="page-stack">
      <PageHeader
        eyebrow="Batch 9 // scaffold"
        title="Culture"
        description="Isolated, snapshot-only workspaces for future adaptive malware analysis. A campaign copies the live memory, self and incident databases into its own workspace and never mutates production state."
        onRefresh={() => void campaigns.refresh()}
      />

      {(campaigns.error || actionError) && (
        <div className="error-banner">{actionError ?? campaigns.error}</div>
      )}

      <article className="surface self-model-card">
        <span className="eyebrow">Isolation &amp; safety</span>
        <h2>No execution yet — scaffold only</h2>
        <p>
          A campaign is a set of isolated SQLite snapshots under its own workspace directory.
          Experimentation is expected to run only against those copies; nothing here can mutate
          the active Dendrite databases.
        </p>
        <p>
          Sandboxed execution and any resulting counter-action are intentionally not implemented:
          Dendrite has no working process-kill, file-quarantine or network-isolation capability
          yet (a stubbed <code>ActionExecutor</code>/<code>CampaignSandbox</code> interface exists
          and logs a <code>NotImplemented</code> outcome rather than silently doing nothing). Real
          counter-execution must still go through the normal MAGI → policy → Guard → transaction
          pipeline once that capability exists.
        </p>
        <span className="availability-tag">Guard database excluded when privilege-separated</span>
      </article>

      <article className="surface">
        <div className="surface-heading">
          <div>
            <span className="eyebrow">New workspace</span>
            <h2>Create campaign</h2>
          </div>
        </div>
        <div className="culture-create-form">
          <input
            value={label}
            onChange={event => setLabel(event.target.value)}
            placeholder="Optional label, e.g. sample-2026-09"
            disabled={working}
            onKeyDown={event => {
              if (event.key === 'Enter' && !working) void createCampaign()
            }}
          />
          <button className="primary-button" disabled={working} onClick={() => void createCampaign()}>
            {working ? 'Working…' : 'New Campaign'}
          </button>
        </div>
      </article>

      <article className="surface">
        <div className="surface-heading">
          <div>
            <span className="eyebrow">Workspaces</span>
            <h2>{rows.length} Campaign{rows.length === 1 ? '' : 's'}</h2>
          </div>
        </div>

        {rows.length === 0 ? (
          <div className="quiet-state">
            <span className="quiet-mark">✓</span>
            <div><strong>No campaigns yet</strong><small>Create one above to snapshot the live databases into a new isolated workspace.</small></div>
          </div>
        ) : (
          <div className="compact-list">
            {rows.map(campaign => (
              <div className="compact-row" key={campaign.campaign_id}>
                <StatusPill value={campaign.state} />
                <div>
                  <strong>{campaign.label || campaign.campaign_id}</strong>
                  <small>
                    {campaign.campaign_id} · {campaign.run_count} run{campaign.run_count === 1 ? '' : 's'} ·{' '}
                    <code>{campaign.workspace}</code>
                  </small>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <time>{formatTime(campaign.created_at)}</time>
                  <button
                    className="ghost-button danger-action"
                    disabled={working}
                    onClick={() => void discardCampaign(campaign.campaign_id)}
                  >
                    Discard
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </article>
    </section>
  )
}
