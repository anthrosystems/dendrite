import { FormEvent, useCallback, useEffect, useState } from 'react'
import { api } from '../api/client'
import type { ActionDetail, ActionSummary, IncidentSummary } from '../api/types'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'
import { usePolling } from '../hooks/usePolling'

function formatTime(value: number) {
  return new Date(value * 1000).toLocaleString()
}

const magiNames: Record<string, { name: string; role: string }> = {
  host: { name: 'Balthasar', role: 'Host' },
  user: { name: 'Casper', role: 'User' },
  environment: { name: 'Melchior', role: 'Environment' },
}

export function Actions() {
  const actions = usePolling(useCallback(() => api.actions(), []), 5000)
  const incidents = usePolling(useCallback(() => api.incidents(), []), 5000)
  const [selected, setSelected] = useState<string | null>(null)
  const [detail, setDetail] = useState<ActionDetail | null>(null)
  const [incidentId, setIncidentId] = useState('')
  const [target, setTarget] = useState('')
  const [action, setAction] = useState('observe')
  const [mutationError, setMutationError] = useState<string | null>(null)
  const [working, setWorking] = useState(false)

  useEffect(() => {
    if (!selected) {
      setDetail(null)
      return
    }
    void api.action(selected).then(setDetail).catch(error => setMutationError(String(error)))
  }, [selected, actions.data])

  useEffect(() => {
    if (!incidentId && incidents.data?.[0]) setIncidentId(incidents.data[0].id)
  }, [incidents.data, incidentId])

  async function createProposal(event: FormEvent) {
    event.preventDefault()
    if (!incidentId || !target) return
    setWorking(true)
    setMutationError(null)
    try {
      const created = await api.createAction({ incident_id: incidentId, action, target })
      setSelected(created.proposal.id)
      setDetail(created)
      await actions.refresh()
    } catch (error) {
      setMutationError(error instanceof Error ? error.message : String(error))
    } finally {
      setWorking(false)
    }
  }

  async function evaluate() {
    if (!selected) return
    setWorking(true)
    setMutationError(null)
    try {
      const evaluated = await api.evaluateAction(selected)
      setDetail(evaluated)
      await actions.refresh()
    } catch (error) {
      setMutationError(error instanceof Error ? error.message : String(error))
    } finally {
      setWorking(false)
    }
  }

  const rows: ActionSummary[] = actions.data ?? []
  const incidentRows: IncidentSummary[] = incidents.data ?? []

  return (
    <section className="page-stack">
      <PageHeader
        eyebrow="Decision authority"
        title="MAGI & Response"
        description="Proposal review, evaluator verdicts, quorum, policy, Guard authority and transaction history."
        onRefresh={() => void actions.refresh()}
      />

      {(actions.error || mutationError) && (
        <div className="error-banner">{mutationError ?? actions.error}</div>
      )}

      <div className="response-layout">
        <div className="response-column">
          <article className="surface proposal-composer">
            <div className="surface-heading">
              <div>
                <span className="eyebrow">Safe response</span>
                <h2>New action proposal</h2>
              </div>
              <span>Observe and warn only</span>
            </div>
            <form className="proposal-form" onSubmit={createProposal}>
              <label>
                <span>Incident</span>
                <select value={incidentId} onChange={event => setIncidentId(event.target.value)}>
                  <option value="">Select incident</option>
                  {incidentRows.map(incident => (
                    <option key={incident.id} value={incident.id}>
                      {incident.id} · {incident.summary}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                <span>Action</span>
                <select value={action} onChange={event => setAction(event.target.value)}>
                  <option value="observe">Observe</option>
                  <option value="warn">Warn</option>
                </select>
              </label>
              <label className="proposal-target">
                <span>Target object ID</span>
                <input
                  value={target}
                  onChange={event => setTarget(event.target.value)}
                  placeholder="process:1234:..."
                />
              </label>
              <button className="primary-button" disabled={working || !incidentId || !target}>
                Create proposal
              </button>
            </form>
          </article>

          <article className="surface proposal-list">
            <div className="surface-heading">
              <div>
                <span className="eyebrow">History</span>
                <h2>Action proposals</h2>
              </div>
              <span>{rows.length}</span>
            </div>
            {rows.length === 0 ? (
              <div className="empty-state">No action proposals recorded.</div>
            ) : (
              <div className="proposal-rows">
                {rows.map(row => (
                  <button
                    key={row.id}
                    className={selected === row.id ? 'selected' : ''}
                    onClick={() => setSelected(row.id)}
                  >
                    <span className={`proposal-state proposal-state--${row.status}`} />
                    <div>
                      <strong>{row.action.replaceAll('_', ' ')} → {row.target}</strong>
                      <small>{row.id} · {row.incident_id}</small>
                    </div>
                    <div className="proposal-row-state">
                      <StatusPill value={row.status} />
                      <time>{formatTime(row.updated_at)}</time>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </article>
        </div>

        <article className="surface response-detail">
          {!detail ? (
            <div className="detail-placeholder">
              <span className="detail-placeholder-mark">△</span>
              <strong>Select a proposal</strong>
              <p>MAGI verdicts, authority gates and the transaction lifecycle will appear here.</p>
            </div>
          ) : (
            <>
              <div className="detail-header">
                <div>
                  <span className="eyebrow">{detail.proposal.id}</span>
                  <h2>{detail.proposal.action.replaceAll('_', ' ')} → {detail.proposal.target}</h2>
                  <code className="surface-subcode">{detail.proposal.incident_id}</code>
                </div>
                <StatusPill value={detail.proposal.status} />
              </div>

              <div className="decision-strip">
                <div><span>Quorum</span><StatusPill value={detail.proposal.quorum ?? 'pending'} /></div>
                <div><span>Policy</span><StatusPill value={detail.proposal.policy ?? 'pending'} /></div>
                <div><span>Guard</span><StatusPill value={detail.proposal.guard ?? 'pending'} /></div>
                <div><span>Trust</span><StatusPill value={detail.proposal.trust_state ?? 'pending'} /></div>
              </div>

              <section className="detail-section">
                <div className="section-label">MAGI evaluators</div>
                {detail.evaluations.length === 0 ? (
                  <div className="empty-inline">Proposal has not been evaluated.</div>
                ) : (
                  <div className="magi-console">
                    {detail.evaluations.map(item => {
                      const identity = magiNames[item.evaluator] ?? { name: item.evaluator, role: item.evaluator }
                      return (
                        <article key={item.evaluator}>
                          <div className="magi-identity">
                            <span className="magi-node" />
                            <div><strong>{identity.name}</strong><small>{identity.role}</small></div>
                          </div>
                          <StatusPill value={item.verdict} />
                          <p>{item.reason}</p>
                        </article>
                      )
                    })}
                  </div>
                )}
              </section>

              <section className="detail-section">
                <div className="section-label">Transaction</div>
                <div className="transaction-track">
                  {detail.transactions.map((event, index) => (
                    <div className="transaction-step" key={`${event.state}-${index}`}>
                      <span className={`transaction-dot transaction-dot--${event.status}`} />
                      <div>
                        <strong>{event.state.replaceAll('_', ' ')}</strong>
                        <small>{event.status.replaceAll('_', ' ')} · {formatTime(event.recorded_at)}</small>
                        {event.message && <p>{event.message}</p>}
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <div className="authority-note">
                <span>Authority requirement</span>
                <strong>{detail.guard_requirement.replaceAll('_', ' ')}</strong>
              </div>

              {detail.proposal.status === 'proposed' && (
                <button className="primary-button evaluate-button" disabled={working} onClick={() => void evaluate()}>
                  Evaluate proposal
                </button>
              )}
            </>
          )}
        </article>
      </div>
    </section>
  )
}
