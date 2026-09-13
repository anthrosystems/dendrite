import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../api/client'
import type { BehaviourDefinition, CveKnowledgeRecord, PackageInventory, VulnerabilityExposure, VulnerabilityRemediation } from '../api/types'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'
import { usePolling } from '../hooks/usePolling'

function formatTime(value: number | null) {
  return value ? new Date(value * 1000).toLocaleString() : '—'
}

export function Vulnerabilities() {
  const [includeResolved, setIncludeResolved] = useState(false)
  const [view, setView] = useState<'exposures' | 'inventory'>('exposures')
  const load = useCallback(() => api.vulnerabilities(includeResolved), [includeResolved])
  const exposures = usePolling(load, 7000, `vulnerabilities-${includeResolved}`)
  const status = usePolling(useCallback(() => api.vulnerabilityStatus(), []), 10000, 'vulnerability-status')
  const inventory = usePolling(useCallback(() => api.vulnerabilityInventory(), []), 30000, 'vulnerability-inventory')
  const cveKnowledge = usePolling(useCallback(() => api.analysisCves(), []), 30000, 'vulnerability-cve-knowledge')
  const behaviourKnowledge = usePolling(useCallback(() => api.analysisBehaviours(), []), 30000, 'vulnerability-behaviour-knowledge')
  const [selected, setSelected] = useState<string | null>(null)
  const [detail, setDetail] = useState<VulnerabilityExposure | null>(null)
  const [remediation, setRemediation] = useState<VulnerabilityRemediation | null>(null)
  const [working, setWorking] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const [refreshNotice, setRefreshNotice] = useState<string | null>(null)

  useEffect(() => {
    if (!selected) {
      setDetail(null)
      setRemediation(null)
      return
    }
    void api.vulnerability(selected).then(setDetail).catch(() => setDetail(null))
  }, [selected, exposures.data])

  const rows = useMemo(() => exposures.data ?? [], [exposures.data])
  const selectedCveKnowledge = useMemo<CveKnowledgeRecord | null>(() => {
    if (!detail) return null
    return (cveKnowledge.data ?? []).find(record => record.id === detail.cve_id && record.package === detail.package)
      ?? (cveKnowledge.data ?? []).find(record => record.id === detail.cve_id)
      ?? null
  }, [detail, cveKnowledge.data])
  const behaviourById = useMemo(() => new Map((behaviourKnowledge.data ?? []).map((behaviour: BehaviourDefinition) => [behaviour.id, behaviour])), [behaviourKnowledge.data])

  const refreshAll = async () => {
    await Promise.all([exposures.refresh(), status.refresh(), inventory.refresh(), cveKnowledge.refresh(), behaviourKnowledge.refresh()])
    if (selected) setDetail(await api.vulnerability(selected))
  }

  const runAssessmentRefresh = async () => {
    setWorking(true)
    setActionError(null)
    setRefreshNotice(null)
    try {
      const detected = await api.refreshVulnerabilities()
      await refreshAll()
      const [latestStatus, latestInventory] = await Promise.all([
        api.vulnerabilityStatus(),
        api.vulnerabilityInventory(),
      ])
      const scope = `${latestInventory.length.toLocaleString()} installed packages against ${latestStatus.records.toLocaleString()} CVE records across ${latestStatus.packages.toLocaleString()} packages`
      setRefreshNotice(
        detected.length === 0
          ? `Assessment complete: checked ${scope}. No vulnerable package exposures were detected.`
          : `Assessment complete: checked ${scope}. Detected ${detected.length.toLocaleString()} active vulnerability exposure${detected.length === 1 ? '' : 's'}.`,
      )
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error))
    } finally {
      setWorking(false)
    }
  }

  const mutate = async (fn: () => Promise<VulnerabilityExposure>) => {
    setWorking(true)
    setActionError(null)
    try {
      const next = await fn()
      setDetail(next)
      setRemediation(null)
      await refreshAll()
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error))
    } finally {
      setWorking(false)
    }
  }

  const runUpdate = async () => {
    if (!detail) return
    setWorking(true)
    setActionError(null)
    try {
      const result = await api.updateVulnerability(detail.id)
      setRemediation(result)
      setDetail(result.exposure)
      await refreshAll()
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error))
    } finally {
      setWorking(false)
    }
  }

  const runDelete = async () => {
    if (!detail) return
    const confirmed = window.confirm(
      `Permanently delete this exposure record (${detail.cve_id})? This cannot be undone and there is no re-raise mechanism — if this CVE is genuinely still relevant, "Ignore" is the reversible alternative. Normally the wrong tool outside debugging.`,
    )
    if (!confirmed) return
    setWorking(true)
    setActionError(null)
    try {
      await api.deleteVulnerability(detail.id)
      setDetail(null)
      setRemediation(null)
      await refreshAll()
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error))
    } finally {
      setWorking(false)
    }
  }

  return (
    <section className="page-stack">
      <PageHeader
        eyebrow="Batch 6"
        title="Vulnerabilities"
        description="Version-aware package exposures and the authorised remediation path. CVE knowledge is evidence, never execution authority."
        onRefresh={() => void refreshAll()}
      />

      {(exposures.error || status.error || inventory.error || cveKnowledge.error || behaviourKnowledge.error || actionError) && (
        <div className="error-banner">{actionError ?? exposures.error ?? status.error ?? inventory.error ?? cveKnowledge.error ?? behaviourKnowledge.error}</div>
      )}
      {refreshNotice && <div className="success-banner">{refreshNotice}</div>}

      <div className="overview-metrics vulnerability-metrics">
        <article><span>Open exposures</span><strong>{status.data?.open_exposures ?? '—'}</strong><small>host package matches</small></article>
        <article><span>CVE records</span><strong>{status.data?.records ?? '—'}</strong><small>{status.data?.packages ?? '—'} packages represented</small></article>
        <article><span>Inventory</span><strong>{status.data?.inventory_packages ?? '—'}</strong><small>installed packages indexed</small></article>
        <article><span>Last assessment</span><strong className="metric-time">{formatTime(status.data?.assessment_last_run_at ?? null)}</strong><small>{status.data?.source ?? 'local knowledge'}</small></article>
      </div>

      <div className="vulnerability-toolbar surface">
        <div className="vulnerability-tabs">
          <button className={view === 'exposures' ? 'active' : ''} onClick={() => setView('exposures')}>Exposures</button>
          <button className={view === 'inventory' ? 'active' : ''} onClick={() => setView('inventory')}>Package inventory</button>
        </div>
        {view === 'exposures' && <label><input type="checkbox" checked={includeResolved} onChange={event => setIncludeResolved(event.target.checked)} /> Include resolved</label>}
        <button className="secondary-button" disabled={working} onClick={() => void runAssessmentRefresh()}>{working ? 'Refreshing…' : 'Refresh inventory & assessment'}</button>
      </div>

      {view === 'inventory' ? (
        <article className="surface inventory-surface">
          <div className="list-toolbar"><span>{(inventory.data ?? []).length} Installed packages</span><span>dpkg inventory</span></div>
          <div className="inventory-table-wrap">
            <table className="inventory-table">
              <thead><tr><th>Package</th><th>Architecture</th><th>Installed version</th><th>Source</th><th>Last seen</th></tr></thead>
              <tbody>{(inventory.data ?? []).map((pkg: PackageInventory) => (
                <tr key={`${pkg.name}:${pkg.architecture}`}><td>{pkg.name}</td><td>{pkg.architecture}</td><td><code>{pkg.version}</code></td><td>{pkg.source}</td><td>{formatTime(pkg.last_seen_at)}</td></tr>
              ))}</tbody>
            </table>
          </div>
        </article>
      ) : (
        <div className="master-detail vulnerability-master-detail">
          <article className="surface master-list">
            <div className="list-toolbar"><span>{rows.length} Exposures</span><span>Severity / activity</span></div>
            {rows.length === 0 ? <div className="empty-state">No vulnerability exposures recorded.</div> : rows.map(row => (
              <button key={row.id} className={`vulnerability-row ${selected === row.id ? 'selected' : ''}`} onClick={() => setSelected(row.id)}>
                <span className={`severity-rail severity-rail--${row.severity}`} />
                <div className="vulnerability-row-body">
                  <div><StatusPill value={row.severity} /><StatusPill value={row.status} /></div>
                  <strong>{row.cve_id}</strong>
                  <small>{row.package}:{row.architecture} · {row.installed_version}</small>
                </div>
                <time>{formatTime(row.last_seen_at)}</time>
              </button>
            ))}
          </article>

          <article className="surface detail-surface">
            {!detail ? (
              <div className="detail-placeholder"><span className="detail-placeholder-mark">△</span><strong>Select an exposure</strong><p>Package state, authority and remediation progress will appear here.</p></div>
            ) : (
              <>
                <div className="detail-header">
                  <div><span className="eyebrow">{detail.id}</span><h2>{detail.cve_id}</h2><code className="surface-subcode">{detail.package}:{detail.architecture}</code></div>
                  <div className="inline-meta"><StatusPill value={detail.severity} /><StatusPill value={detail.status} /></div>
                </div>

                <div className="detail-facts vulnerability-facts">
                  <div><span>Installed</span><strong>{detail.installed_version}</strong></div>
                  <div><span>Fixed version</span><strong>{detail.fixed_version ?? 'Unknown'}</strong></div>
                  <div><span>Authorised</span><strong>{formatTime(detail.authorised_at)}</strong></div>
                  <div><span>Last seen</span><strong>{formatTime(detail.last_seen_at)}</strong></div>
                </div>

                <section className="detail-section">
                  <div className="section-label">Associated activity</div>
                  {!selectedCveKnowledge ? (
                    <p>No enriched CVE activity knowledge is loaded for this exposure.</p>
                  ) : selectedCveKnowledge.behaviour_ids.length === 0 ? (
                    <p>{selectedCveKnowledge.name ? <><strong>{selectedCveKnowledge.name}</strong> · </> : null}This CVE record has no associated behaviour definitions yet.</p>
                  ) : (
                    <div className="vulnerability-behaviour-list">
                      {selectedCveKnowledge.behaviour_ids.map(id => {
                        const behaviour = behaviourById.get(id)
                        return <div key={id}><strong>{behaviour?.name ?? id}</strong><small>{behaviour?.description ?? id}</small>{behaviour && <StatusPill value={`${behaviour.confidence}% confidence`} />}</div>
                      })}
                    </div>
                  )}
                </section>

                <section className="detail-section">
                  <div className="section-label">Authority path</div>
                  <div className="authority-flow">
                    <div className={detail.awaiting_manual || detail.status === 'authorised' ? 'complete' : ''}><span>1</span><strong>Manual review</strong><small>Operator acknowledges the exposure.</small></div>
                    <div className={detail.status === 'authorised' ? 'complete' : ''}><span>2</span><strong>User authority</strong><small>Explicit authority is recorded.</small></div>
                    <div className={remediation ? 'complete' : ''}><span>3</span><strong>MAGI → Policy → Guard</strong><small>No UI shortcut to package mutation.</small></div>
                  </div>
                </section>

                {detail.status !== 'resolved' && detail.status !== 'ignored' && (
                  <div className="remediation-controls">
                    {detail.status === 'open' && <button className="primary-button" disabled={working} onClick={() => void mutate(() => api.markVulnerabilityManual(detail.id))}>Mark for manual remediation</button>}
                    {detail.status === 'awaiting_revalidation' && <button className="primary-button" disabled={working} onClick={() => void mutate(() => api.authoriseVulnerability(detail.id))}>Authorise remediation</button>}
                    {detail.status === 'authorised' && <button className="primary-button danger-action" disabled={working || !detail.fixed_version} onClick={() => void runUpdate()}>Execute authorised package update</button>}
                    {!detail.fixed_version && <small>No fixed version is known; Dendrite will not mutate this package.</small>}
                    {(detail.status === 'open' || detail.status === 'awaiting_revalidation') && (
                      <button className="ghost-button" disabled={working} onClick={() => void mutate(() => api.ignoreVulnerability(detail.id))}>
                        Ignore
                      </button>
                    )}
                  </div>
                )}

                {detail.status === 'resolved' && <div className="success-banner">Exposure resolved{detail.resolution_source ? ` · ${detail.resolution_source}` : ''}.</div>}

                {detail.status === 'ignored' && (
                  <div className="empty-state">
                    Ignored{detail.ignored_version ? ` at version ${detail.ignored_version}` : ''}
                    {detail.ignored_at ? ` (${formatTime(detail.ignored_at)})` : ''}. Will automatically
                    reappear if the package is updated while still matching this CVE, or if a later
                    attack chain/behaviour match references it.
                  </div>
                )}

                <div className="remediation-controls">
                  <button className="ghost-button danger-action" disabled={working} onClick={() => void runDelete()}>
                    Delete exposure
                  </button>
                  <small>Permanent, no re-raise — normally the wrong choice outside debugging. "Ignore" above is the reversible alternative.</small>
                </div>

                {remediation && (
                  <section className="detail-section">
                    <div className="section-label">Latest remediation transaction</div>
                    <div className="decision-strip">
                      <div><span>Quorum</span><StatusPill value={remediation.action.proposal.quorum ?? 'pending'} /></div>
                      <div><span>Policy</span><StatusPill value={remediation.action.proposal.policy ?? 'pending'} /></div>
                      <div><span>Guard</span><StatusPill value={remediation.action.proposal.guard ?? 'pending'} /></div>
                      <div><span>Action</span><StatusPill value={remediation.action.proposal.status} /></div>
                    </div>
                    <div className="magi-compact">
                      {remediation.action.evaluations.map(item => <div key={item.evaluator}><strong>{item.evaluator}</strong><StatusPill value={item.verdict} /><small>{item.reason}</small></div>)}
                    </div>
                    <div className="transaction-track">
                      {remediation.action.transactions.map((event, index) => (
                        <div className="transaction-step" key={`${event.state}-${index}`}><span className={`transaction-dot transaction-dot--${event.status}`} /><div><strong>{event.state.replaceAll('_', ' ')}</strong><small>{event.status.replaceAll('_', ' ')} · {formatTime(event.recorded_at)}</small>{event.message && <p>{event.message}</p>}</div></div>
                      ))}
                    </div>
                    <a className="inline-link" href="#/magi">Open full MAGI & Response history</a>
                  </section>
                )}
              </>
            )}
          </article>
        </div>
      )}
    </section>
  )
}