import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { api } from '../api/client'
import type {
  AnalysisReview,
  AntiserumKnowledgeAcceptanceResult,
  AntiserumPackageDetail,
  AntiserumPackageSummary,
  AttackChainRecord,
  BehaviourDefinition,
  CreateAntiserumRequest,
  CveKnowledgeRecord,
  GraphExportOptions,
  MemoryGraph,
  MemoryNode,
  RecordExportOptions,
  VulnerabilityCandidate,
  VulnerabilityCandidateRequest,
} from '../api/types'
import { ForceGraph, type GraphSettings } from '../components/ForceGraph'
import { ForceGraph3D } from '../components/ForceGraph3D'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'
import { provenanceBadge } from '../utils/provenance'

const graphSettings: GraphSettings = {
  nodeScale: 1,
  linkScale: 1,
  labelThreshold: 1.05,
  centreForce: 0.45,
  repelForce: 0.8,
  linkForce: 1.15,
  linkDistance: 92,
  showArrows: false,
  relationshipStrengthMin: 0,
  strengthEncoding: 'both',
  clusterByKind: true,
  groupCohesion: 1.7,
  groupSeparation: 1.35,
  interGroupAttraction: 0.75,
}

type TopTab = 'review' | 'import' | 'create' | 'candidate'
type ReviewTab = 'overview' | 'graph' | 'payloads' | 'provenance' | 'verification'
type IncludeKey =
  | 'graph'
  | 'attackChains'
  | 'vulnerabilities'
  | 'indicatorHashes'
  | 'indicatorDomains'
  | 'indicatorIps'
  | 'indicatorUrls'
  | 'behaviours'

const ACTIVE_REVIEW_STORAGE_KEY = 'dendrite.analysis.activeReview.v1'

function initialReviewId() {
  try {
    return window.sessionStorage.getItem(ACTIVE_REVIEW_STORAGE_KEY)
  } catch {
    return null
  }
}

const includeLabels: Array<[IncludeKey, string]> = [
  ['graph', 'Memory Graph'],
  ['attackChains', 'Attack Chains'],
  ['vulnerabilities', 'Vulnerabilities / CVEs'],
  ['indicatorHashes', 'Hash Indicators'],
  ['indicatorDomains', 'Domain Indicators'],
  ['indicatorIps', 'IP Indicators'],
  ['indicatorUrls', 'URL Indicators'],
  ['behaviours', 'Behaviours'],
]

function splitList(value: string) {
  return [
    ...new Set(
      value
        .split(/[\n,]/)
        .map(item => item.trim())
        .filter(Boolean),
    ),
  ]
}

function fmtBytes(value: number) {
  if (value < 1024) return `${value} B`
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`
  return `${(value / 1024 / 1024).toFixed(1)} MiB`
}

function packageOrigin(value: AntiserumPackageSummary['origin']) {
  return value === 'manual_export'
    ? 'Manual export'
    : value === 'automatic_export'
      ? 'Automatic export'
      : 'Imported'
}

export function Analysis() {
  const [tab, setTab] = useState<TopTab>('review')
  const [reviewTab, setReviewTab] = useState<ReviewTab>('overview')
  const [packages, setPackages] = useState<AntiserumPackageSummary[]>([])
  const [reviews, setReviews] = useState<AnalysisReview[]>([])
  const [selectedReviewId, setSelectedReviewId] = useState<string | null>(initialReviewId)
  const [detail, setDetail] = useState<AntiserumPackageDetail | null>(null)
  const [analysisGraph, setAnalysisGraph] = useState<MemoryGraph | null>(null)
  const [liveGraph, setLiveGraph] = useState<MemoryGraph | null>(null)
  const [chains, setChains] = useState<AttackChainRecord[]>([])
  const [cves, setCves] = useState<CveKnowledgeRecord[]>([])
  const [behaviours, setBehaviours] = useState<BehaviourDefinition[]>([])
  const [candidates, setCandidates] = useState<VulnerabilityCandidate[]>([])
  const [selectedNode, setSelectedNode] = useState<MemoryNode | null>(null)
  const [viewMode, setViewMode] = useState<'2d' | '3d'>('2d')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [acceptanceResult, setAcceptanceResult] =
    useState<AntiserumKnowledgeAcceptanceResult | null>(null)

  const [include, setInclude] = useState<Record<IncludeKey, boolean>>({
    graph: true,
    attackChains: true,
    vulnerabilities: false,
    indicatorHashes: false,
    indicatorDomains: false,
    indicatorIps: false,
    indicatorUrls: false,
    behaviours: false,
  })

  const [graphScope, setGraphScope] =
    useState<GraphExportOptions['scope']>('complete')
  const [startNode, setStartNode] = useState('')
  const [depth, setDepth] = useState<string>('unlimited')
  const [chainScope, setChainScope] =
    useState<RecordExportOptions['scope']>('all')
  const [selectedChains, setSelectedChains] = useState<string[]>([])
  const [cveScope, setCveScope] =
    useState<RecordExportOptions['scope']>('all')
  const [selectedCves, setSelectedCves] = useState<string[]>([])
  const [selectedBehaviours, setSelectedBehaviours] = useState<string[]>([])

  const [indicatorScopes, setIndicatorScopes] = useState<
    Record<
      | 'indicatorHashes'
      | 'indicatorDomains'
      | 'indicatorIps'
      | 'indicatorUrls'
      | 'behaviours',
      'all' | 'selected'
    >
  >({
    indicatorHashes: 'all',
    indicatorDomains: 'all',
    indicatorIps: 'all',
    indicatorUrls: 'all',
    behaviours: 'all',
  })

  const [candidateForm, setCandidateForm] = useState({
    title: '',
    description: '',
    affectedProducts: '',
    affectedVersions: '',
    weaknesses: '',
    severity: 'unknown',
    cvss: '',
    behaviourIds: '',
    attackChainIds: '',
    reproductionNotes: '',
    mitigationNotes: '',
    confidence: '50',
  })

  const [createdCandidate, setCreatedCandidate] =
    useState<VulnerabilityCandidate | null>(null)

  const selectedReview =
    reviews.find(review => review.review_id === selectedReviewId) ?? null

  const refresh = useCallback(async () => {
    try {
      const [
        packageRows,
        reviewRows,
        graphRows,
        chainRows,
        cveRows,
        behaviourRows,
        candidateRows,
      ] = await Promise.all([
        api.analysisPackages(),
        api.analysisReviews(),
        api.memoryGraph(0),
        api.analysisChains(),
        api.analysisCves(),
        api.analysisBehaviours(),
        api.vulnerabilityCandidates(),
      ])

      setPackages(packageRows)
      setReviews(reviewRows)
      setLiveGraph(graphRows)
      setChains(chainRows)
      setCves(cveRows)
      setBehaviours(behaviourRows)
      setCandidates(candidateRows)

      setSelectedReviewId(current =>
        current && reviewRows.some(row => row.review_id === current)
          ? current
          : reviewRows[0]?.review_id ?? null,
      )

      setError(null)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause))
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  useEffect(() => {
    try {
      if (selectedReviewId) {
        window.sessionStorage.setItem(
          ACTIVE_REVIEW_STORAGE_KEY,
          selectedReviewId,
        )
      } else {
        window.sessionStorage.removeItem(ACTIVE_REVIEW_STORAGE_KEY)
      }
    } catch {
      // Review sessions remain server-side even if browser storage is unavailable.
    }
  }, [selectedReviewId])

  useEffect(() => {
    if (!selectedReview) {
      setDetail(null)
      setAnalysisGraph(null)
      return
    }

    let cancelled = false

    void Promise.all([
      api.openAnalysisReview(selectedReview.review_id),
      api.analysisPackage(selectedReview.antiserum_id),
      api.analysisGraph(selectedReview.antiserum_id),
    ])
      .then(([, packageDetail, graph]) => {
        if (cancelled) return

        setDetail(packageDetail)
        setAnalysisGraph(graph)
        setSelectedNode(null)
        setAcceptanceResult(null)
        setError(null)
      })
      .catch(cause => {
        if (!cancelled) {
          setError(cause instanceof Error ? cause.message : String(cause))
        }
      })

    return () => {
      cancelled = true
    }
  }, [selectedReview?.review_id, selectedReview?.antiserum_id])

  const visibleKinds = useMemo(
    () => new Set((analysisGraph?.nodes ?? []).map(node => node.kind)),
    [analysisGraph],
  )

  async function createReview(antiserumId: string) {
    setBusy(true)

    try {
      const review = await api.createAnalysisReview(antiserumId)
      await refresh()
      setSelectedReviewId(review.review_id)
      setTab('review')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  async function unloadReview() {
    if (!selectedReview) return

    setBusy(true)

    try {
      await api.unloadAnalysisReview(selectedReview.review_id)
      setSelectedReviewId(null)
      setDetail(null)
      setAnalysisGraph(null)
      await refresh()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  async function importFile(file: File) {
    setBusy(true)

    try {
      const imported = await api.importAntiserum(file)
      const review = await api.createAnalysisReview(imported.antiserum_id)

      await refresh()

      setSelectedReviewId(review.review_id)
      setTab('review')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  async function acceptKnowledge() {
    if (
      !detail ||
      detail.summary.origin !== 'imported' ||
      detail.summary.knowledge_status !== 'not_accepted'
    ) {
      return
    }

    const confirmed = window.confirm(
      'Accept this Antiserum package into Dendrite knowledge? This will merge supported graph, behaviour and vulnerability knowledge into the active databases. The package itself will remain stored for review and provenance.',
    )

    if (!confirmed) return

    setBusy(true)

    try {
      const result = await api.acceptAntiserumKnowledge(
        detail.summary.antiserum_id,
      )

      setAcceptanceResult(result)

      const refreshed = await api.analysisPackage(
        detail.summary.antiserum_id,
      )

      setDetail(refreshed)

      await refresh()

      setError(null)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  function knowledgeSelection(
    key:
      | 'indicatorHashes'
      | 'indicatorDomains'
      | 'indicatorIps'
      | 'indicatorUrls'
      | 'behaviours',
  ): RecordExportOptions | undefined {
    if (!include[key]) return undefined

    return {
      scope: indicatorScopes[key],
      selected_ids:
        key === 'behaviours' && indicatorScopes[key] === 'selected'
          ? selectedBehaviours
          : [],
    }
  }

  async function createPackage() {
    const request: CreateAntiserumRequest = {}

    if (include.graph) {
      request.graph = {
        scope: graphScope,
        start_node:
          graphScope === 'complete'
            ? null
            : startNode || null,
        max_depth:
          depth === 'unlimited'
            ? null
            : Number(depth),
      }
    }

    if (include.attackChains) {
      request.attack_chains = {
        scope:
          !include.graph && chainScope === 'associated'
            ? 'all'
            : chainScope,
        selected_ids: selectedChains,
      }
    }

    if (include.vulnerabilities) {
      request.vulnerabilities = {
        scope: cveScope,
        selected_ids: selectedCves,
      }
    }

    request.indicator_hashes = knowledgeSelection('indicatorHashes')
    request.indicator_domains = knowledgeSelection('indicatorDomains')
    request.indicator_ips = knowledgeSelection('indicatorIps')
    request.indicator_urls = knowledgeSelection('indicatorUrls')
    request.behaviours = knowledgeSelection('behaviours')

    setBusy(true)

    try {
      const created = await api.createAntiserum(request)

      await refresh()
      await createReview(created.antiserum_id)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  async function createCandidate() {
    const request: VulnerabilityCandidateRequest = {
      title: candidateForm.title.trim(),
      description: candidateForm.description.trim(),
      affected_products: splitList(candidateForm.affectedProducts),
      affected_versions: splitList(candidateForm.affectedVersions),
      weaknesses: splitList(candidateForm.weaknesses),
      severity: candidateForm.severity,
      cvss: candidateForm.cvss.trim() || null,
      behaviour_ids: splitList(candidateForm.behaviourIds),
      attack_chain_ids: splitList(candidateForm.attackChainIds),
      indicator_ids: [],
      evidence_ids: [],
      source_antiserum_ids: selectedReview
        ? [selectedReview.antiserum_id]
        : [],
      reproduction_notes:
        candidateForm.reproductionNotes.trim() || null,
      mitigation_notes:
        candidateForm.mitigationNotes.trim() || null,
      discovery_origin: 'manual',
      confidence: Math.max(
        0,
        Math.min(
          100,
          Number(candidateForm.confidence) || 0,
        ),
      ),
    }

    setBusy(true)

    try {
      const candidate =
        await api.createVulnerabilityCandidate(request)

      setCreatedCandidate(candidate)

      await refresh()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="page-stack analysis-page">
      <PageHeader
        eyebrow="Portable security intelligence"
        title="Analysis"
        description="Create, verify, import and review signed Antiserum packages without changing the live Memory Graph view."
        onRefresh={() => void refresh()}
      />

      {error && (
        <div className="error-banner">
          {error}
        </div>
      )}

      <div
        className="investigation-tabs analysis-tabs"
        role="tablist"
        aria-label="Analysis workspace"
      >
        <button
          className={tab === 'review' ? 'active' : ''}
          onClick={() => setTab('review')}
        >
          Review <span>{reviews.length}</span>
        </button>

        <button
          className={tab === 'import' ? 'active' : ''}
          onClick={() => setTab('import')}
        >
          Import Antiserum Package
        </button>

        <button
          className={tab === 'create' ? 'active' : ''}
          onClick={() => setTab('create')}
        >
          Create Antiserum Package
        </button>

        <button
          className={tab === 'candidate' ? 'active' : ''}
          onClick={() => setTab('candidate')}
        >
          Create Vulnerability Candidate
        </button>
      </div>

      {tab === 'review' && (
        <div className="analysis-review-stack">
          {reviews.length === 0 ? (
            <article className="surface analysis-empty-review">
              <strong>No active reviews</strong>
              <p>
                Import an Antiserum package or load one already stored on this
                Dendrite host.
              </p>
              <button
                className="primary-button"
                onClick={() => setTab('import')}
              >
                Go to Import Antiserum Package
              </button>
            </article>
          ) : (
            <>
              <article className="surface analysis-review-toolbar">
                <label>
                  <span>Current review</span>

                  <select
                    value={selectedReviewId ?? ''}
                    onChange={event =>
                      setSelectedReviewId(event.target.value)
                    }
                  >
                    {reviews.map(review => (
                      <option
                        key={review.review_id}
                        value={review.review_id}
                      >
                        {review.label || review.antiserum_id}
                      </option>
                    ))}
                  </select>
                </label>

                <button onClick={() => setTab('import')}>
                  New Review
                </button>

                <button
                  className="danger-outline"
                  disabled={busy || !selectedReview}
                  onClick={() => void unloadReview()}
                >
                  Unload Review
                </button>
              </article>

              {detail && (
                <>
                  <article className="surface analysis-knowledge-status">
                    <div>
                      <span className="eyebrow">
                        Knowledge state
                      </span>

                      <h3>
                        {detail.summary.knowledge_status === 'accepted'
                          ? 'Accepted into Dendrite'
                          : detail.summary.knowledge_status === 'source'
                            ? 'Source knowledge'
                            : 'Package only'}
                      </h3>

                      <p>
                        {detail.summary.knowledge_status === 'accepted'
                          ? `Supported knowledge from this package was accepted${detail.summary.knowledge_accepted_at
                            ? ` on ${new Date(
                              detail.summary.knowledge_accepted_at * 1000,
                            ).toLocaleString()}`
                            : ''
                          }. The original .danti package remains unchanged.`
                          : detail.summary.knowledge_status === 'source'
                            ? 'This package was created from this Dendrite host; its knowledge already exists in the active databases.'
                            : 'This package is stored and reviewable, but its knowledge has not been merged into the active Dendrite databases.'}
                      </p>
                    </div>

                    {detail.summary.origin === 'imported' &&
                      detail.summary.knowledge_status === 'not_accepted' && (
                        <button
                          className="primary-button"
                          disabled={busy}
                          onClick={() => void acceptKnowledge()}
                        >
                          Accept Knowledge
                        </button>
                      )}
                  </article>

                  {acceptanceResult && (
                    <article className="surface analysis-acceptance-result">
                      <strong>Knowledge accepted</strong>

                      <p>
                        {acceptanceResult.graph_nodes} graph nodes ·{' '}
                        {acceptanceResult.graph_relationships} relationships ·{' '}
                        {acceptanceResult.behaviours} behaviours ·{' '}
                        {acceptanceResult.vulnerabilities} vulnerabilities ·{' '}
                        {acceptanceResult.vulnerability_candidates} candidates
                      </p>

                      {acceptanceResult.skipped_payloads.length > 0 && (
                        <small>
                          Not merged:{' '}
                          {acceptanceResult.skipped_payloads.join(' · ')}
                        </small>
                      )}
                    </article>
                  )}

                  <div className="analysis-review-tabs">
                    {(
                      [
                        'overview',
                        'graph',
                        'payloads',
                        'provenance',
                        'verification',
                      ] as ReviewTab[]
                    ).map(value => (
                      <button
                        key={value}
                        className={
                          reviewTab === value
                            ? 'active'
                            : ''
                        }
                        onClick={() => setReviewTab(value)}
                      >
                        {value[0].toUpperCase() + value.slice(1)}
                      </button>
                    ))}
                  </div>

                  {reviewTab === 'overview' && (
                    <Overview detail={detail} />
                  )}

                  {reviewTab === 'payloads' && (
                    <Payloads detail={detail} />
                  )}

                  {reviewTab === 'provenance' && (
                    <Provenance detail={detail} />
                  )}

                  {reviewTab === 'verification' && (
                    <Verification detail={detail} />
                  )}

                  {reviewTab === 'graph' && (
                    <article className="surface analysis-graph-surface">
                      <div className="surface-heading">
                        <div>
                          <span className="eyebrow">
                            Package graph
                          </span>
                          <h2>
                            {analysisGraph?.nodes.length ?? 0} nodes
                          </h2>
                        </div>

                        <div className="analysis-graph-actions">
                          <button
                            className={
                              viewMode === '2d'
                                ? 'active'
                                : ''
                            }
                            onClick={() => setViewMode('2d')}
                          >
                            2D
                          </button>

                          <button
                            className={
                              viewMode === '3d'
                                ? 'active'
                                : ''
                            }
                            onClick={() => setViewMode('3d')}
                          >
                            3D
                          </button>
                        </div>
                      </div>

                      <div className="analysis-graph-layout">
                        <div className="analysis-graph-canvas">
                          {analysisGraph && viewMode === '2d' && (
                            <ForceGraph
                              graph={analysisGraph}
                              visibleKinds={visibleKinds}
                              search=""
                              selectedId={selectedNode?.id ?? null}
                              settings={graphSettings}
                              reheatToken={0}
                              onSelect={setSelectedNode}
                            />
                          )}

                          {analysisGraph && viewMode === '3d' && (
                            <ForceGraph3D
                              graph={analysisGraph}
                              visibleKinds={visibleKinds}
                              search=""
                              selectedId={selectedNode?.id ?? null}
                              settings={graphSettings}
                              onSelect={setSelectedNode}
                            />
                          )}
                        </div>

                        <aside className="analysis-node-inspector">
                          {!selectedNode ? (
                            <p>
                              Select a graph node to inspect its canonical
                              identity and provenance.
                            </p>
                          ) : (
                            <>
                              <span className="eyebrow">
                                {selectedNode.kind.replaceAll('_', ' ')}
                              </span>

                              <h3>{selectedNode.label}</h3>

                              <span className="entity-provenance-badge">
                                {provenanceBadge(
                                  selectedNode,
                                  detail.envelope.issuer.instance_id,
                                )}
                              </span>

                              <code>{selectedNode.id}</code>

                              <small>
                                Origin{' '}
                                {selectedNode.origin_instance_id ?? 'unknown'}
                              </small>

                              <small>
                                Lineage{' '}
                                {selectedNode.lineage.join(' → ') || '—'}
                              </small>

                              {selectedNode.correlation_keys.length > 0 && (
                                <div className="analysis-correlation-keys">
                                  <span>Correlation keys</span>

                                  {selectedNode.correlation_keys.map(value => (
                                    <code key={value}>
                                      {value}
                                    </code>
                                  ))}
                                </div>
                              )}
                            </>
                          )}
                        </aside>
                      </div>
                    </article>
                  )}
                </>
              )}
            </>
          )}
        </div>
      )}

      {tab === 'import' && (
        <div className="analysis-import-grid">
          <article className="surface analysis-import-card">
            <span className="eyebrow">
              From file
            </span>

            <h2>Import Antiserum Package</h2>

            <p>
              The package is parsed, signature/content verified, replay checked,
              then stored on this Dendrite host. Importing a package does not
              merge its knowledge into the active databases.
            </p>

            <label className="analysis-file-input">
              <span>
                {busy
                  ? 'Working…'
                  : 'Choose .danti package'}
              </span>

              <input
                type="file"
                accept=".danti,application/vnd.dendrite.antiserum"
                disabled={busy}
                onChange={event => {
                  const file = event.target.files?.[0]

                  if (file) {
                    void importFile(file)
                  }

                  event.currentTarget.value = ''
                }}
              />
            </label>
          </article>

          <article className="surface analysis-package-list">
            <div className="surface-heading">
              <div>
                <span className="eyebrow">
                  On-device
                </span>

                <h2>
                  {packages.length} Antiserum packages
                </h2>
              </div>
            </div>

            {packages.length === 0 ? (
              <div className="empty-state">
                No Antiserum packages are stored on this host.
              </div>
            ) : (
              packages.map(item => (
                <div
                  className="analysis-package-row"
                  key={item.antiserum_id}
                >
                  <div>
                    <strong>
                      {item.antiserum_id}
                    </strong>

                    <small>
                      {packageOrigin(item.origin)} ·{' '}
                      {new Date(item.created_at).toLocaleString()} ·{' '}
                      {item.knowledge_status === 'accepted'
                        ? 'Knowledge accepted'
                        : item.knowledge_status === 'source'
                          ? 'Source knowledge'
                          : 'Package only'}
                    </small>
                  </div>

                  <div className="analysis-package-actions">
                    <button
                      disabled={busy}
                      onClick={() =>
                        void createReview(item.antiserum_id)
                      }
                    >
                      Review
                    </button>

                    <a
                      href={api.antiserumDownloadUrl(item.antiserum_id)}
                      download={`${item.antiserum_id}.danti`}
                    >
                      Download
                    </a>
                  </div>
                </div>
              ))
            )}
          </article>
        </div>
      )}

      {tab === 'create' && (
        <div className="analysis-create-layout">
          <article className="surface analysis-create-main">
            <div className="surface-heading">
              <div>
                <span className="eyebrow">
                  Export scope
                </span>

                <h2>Create Antiserum Package</h2>
              </div>

              <span>
                Provenance is always included.
              </span>
            </div>

            <div className="analysis-include-grid">
              {includeLabels.map(([key, label]) => (
                <label
                  key={key}
                  className={`analysis-include-option ${include[key]
                    ? 'selected'
                    : ''
                    }`}
                >
                  <input
                    type="checkbox"
                    checked={include[key]}
                    onChange={event =>
                      setInclude(current => ({
                        ...current,
                        [key]: event.target.checked,
                      }))
                    }
                  />

                  <span>{label}</span>
                </label>
              ))}
            </div>

            {include.graph && (
              <OptionSection title="Memory Graph">
                <RadioRow
                  value={graphScope}
                  onChange={value =>
                    setGraphScope(
                      value as GraphExportOptions['scope'],
                    )
                  }
                  options={[
                    ['complete', 'Complete Graph'],
                    ['best-path', 'Best Path'],
                    ['reachable-graph', 'Reachable Graph'],
                  ]}
                />

                {graphScope !== 'complete' && (
                  <div className="analysis-setting-grid">
                    <label>
                      <span>Starting node</span>

                      <select
                        value={startNode}
                        onChange={event =>
                          setStartNode(event.target.value)
                        }
                      >
                        <option value="">
                          Select node…
                        </option>

                        {(liveGraph?.nodes ?? []).map(node => (
                          <option
                            key={node.id}
                            value={node.id}
                          >
                            {node.label} · {node.id}
                          </option>
                        ))}
                      </select>
                    </label>

                    <label>
                      <span>Maximum depth</span>

                      <select
                        value={depth}
                        onChange={event =>
                          setDepth(event.target.value)
                        }
                      >
                        <option value="unlimited">
                          Unlimited
                        </option>

                        {[1, 2, 3, 4, 5, 6, 8, 10, 16, 32].map(value => (
                          <option
                            key={value}
                            value={String(value)}
                          >
                            {value}
                          </option>
                        ))}
                      </select>
                    </label>
                  </div>
                )}
              </OptionSection>
            )}

            {include.attackChains && (
              <OptionSection title="Attack Chains">
                <RadioRow
                  value={chainScope}
                  onChange={value =>
                    setChainScope(
                      value as RecordExportOptions['scope'],
                    )
                  }
                  options={
                    (include.graph
                      ? [
                        ['all', 'All detected chains'],
                        ['selected', 'Selected chains'],
                        [
                          'associated',
                          'Associated with graph scope',
                        ],
                      ]
                      : [
                        ['all', 'All detected chains'],
                        ['selected', 'Selected chains'],
                      ]) as Array<[string, string]>
                  }
                />

                {chainScope === 'selected' && (
                  <CheckList
                    rows={chains.map(chain => [
                      chain.id,
                      `${chain.title} · ${chain.id}`,
                    ])}
                    selected={selectedChains}
                    onChange={setSelectedChains}
                    empty="No attack chains are available."
                  />
                )}
              </OptionSection>
            )}

            {include.vulnerabilities && (
              <OptionSection title="Vulnerabilities / CVEs">
                <RadioRow
                  value={cveScope}
                  onChange={value =>
                    setCveScope(
                      value as RecordExportOptions['scope'],
                    )
                  }
                  options={[
                    ['all', 'All vulnerability knowledge'],
                    [
                      'active_exposures',
                      'Active CVE exposures only',
                    ],
                    [
                      'selected',
                      'Selected CVEs / candidates',
                    ],
                  ]}
                />

                {cveScope === 'selected' && (
                  <CheckList
                    rows={[
                      ...[
                        ...new Map(
                          cves.map(cve => [
                            cve.id,
                            [
                              cve.id,
                              `${cve.name || cve.id} · ${cve.package}`,
                            ] as [string, string],
                          ]),
                        ).values(),
                      ],
                      ...candidates.map(
                        candidate =>
                          [
                            candidate.candidate_id,
                            `${candidate.title} · ${candidate.candidate_id}`,
                          ] as [string, string],
                      ),
                    ]}
                    selected={selectedCves}
                    onChange={setSelectedCves}
                    empty="No vulnerability knowledge is available."
                  />
                )}
              </OptionSection>
            )}

            {(
              [
                ['indicatorHashes', 'Hash Indicators'],
                ['indicatorDomains', 'Domain Indicators'],
                ['indicatorIps', 'IP Indicators'],
                ['indicatorUrls', 'URL Indicators'],
                ['behaviours', 'Behaviours'],
              ] as Array<
                [
                  | 'indicatorHashes'
                  | 'indicatorDomains'
                  | 'indicatorIps'
                  | 'indicatorUrls'
                  | 'behaviours',
                  string,
                ]
              >
            ).map(
              ([key, label]) =>
                include[key] && (
                  <OptionSection
                    key={key}
                    title={label}
                  >
                    <RadioRow
                      value={indicatorScopes[key]}
                      onChange={value =>
                        setIndicatorScopes(current => ({
                          ...current,
                          [key]: value as 'all' | 'selected',
                        }))
                      }
                      options={[
                        ['all', 'All'],
                        ['selected', 'Selected'],
                      ]}
                    />

                    {indicatorScopes[key] === 'selected' &&
                      (key === 'behaviours' ? (
                        <CheckList
                          rows={behaviours.map(behaviour => [
                            behaviour.id,
                            `${behaviour.name} · ${behaviour.id}`,
                          ])}
                          selected={selectedBehaviours}
                          onChange={setSelectedBehaviours}
                          empty="No behaviour knowledge is available."
                        />
                      ) : (
                        <CheckList
                          rows={[]}
                          selected={[]}
                          onChange={() => { }}
                          empty={`No ${label.toLowerCase()} knowledge is available for selection yet.`}
                        />
                      ))}

                    <p className="analysis-muted">
                      If the selected Dendrite knowledge store is empty, the
                      payload remains authenticated and is marked{' '}
                      <code>empty</code>.
                    </p>
                  </OptionSection>
                ),
            )}

            <div className="analysis-create-footer">
              <span>
                Provenance · mandatory
              </span>

              <button
                className="primary-button"
                disabled={
                  busy ||
                  !Object.values(include).some(Boolean) ||
                  (include.graph &&
                    graphScope !== 'complete' &&
                    !startNode)
                }
                onClick={() => void createPackage()}
              >
                {busy
                  ? 'Creating…'
                  : 'Create Antiserum Package'}
              </button>
            </div>
          </article>
        </div>
      )}

      {tab === 'candidate' && (
        <div className="analysis-candidate-layout">
          <article className="surface analysis-candidate-form">
            <div className="surface-heading">
              <div>
                <span className="eyebrow">
                  Research knowledge
                </span>

                <h2>
                  Create Vulnerability Candidate
                </h2>
              </div>

              <span>
                Local Dendrite knowledge, not an official CVE.
              </span>
            </div>

            <div className="analysis-candidate-grid">
              <label>
                <span>Title</span>

                <input
                  value={candidateForm.title}
                  onChange={event =>
                    setCandidateForm(current => ({
                      ...current,
                      title: event.target.value,
                    }))
                  }
                  placeholder="Descriptive vulnerability name"
                />
              </label>

              <label>
                <span>Severity</span>

                <select
                  value={candidateForm.severity}
                  onChange={event =>
                    setCandidateForm(current => ({
                      ...current,
                      severity: event.target.value,
                    }))
                  }
                >
                  {[
                    'unknown',
                    'informational',
                    'low',
                    'medium',
                    'high',
                    'critical',
                  ].map(value => (
                    <option
                      key={value}
                      value={value}
                    >
                      {value}
                    </option>
                  ))}
                </select>
              </label>

              <label className="analysis-candidate-wide">
                <span>Description</span>

                <textarea
                  rows={5}
                  value={candidateForm.description}
                  onChange={event =>
                    setCandidateForm(current => ({
                      ...current,
                      description: event.target.value,
                    }))
                  }
                  placeholder="What was discovered, why it matters, and what evidence supports it."
                />
              </label>

              <label>
                <span>Affected products</span>

                <input
                  value={candidateForm.affectedProducts}
                  onChange={event =>
                    setCandidateForm(current => ({
                      ...current,
                      affectedProducts: event.target.value,
                    }))
                  }
                  placeholder="package-a, product-b"
                />
              </label>

              <label>
                <span>Affected versions</span>

                <input
                  value={candidateForm.affectedVersions}
                  onChange={event =>
                    setCandidateForm(current => ({
                      ...current,
                      affectedVersions: event.target.value,
                    }))
                  }
                  placeholder="1.0-1.4, before 2.0"
                />
              </label>

              <label>
                <span>CWE candidates</span>

                <input
                  value={candidateForm.weaknesses}
                  onChange={event =>
                    setCandidateForm(current => ({
                      ...current,
                      weaknesses: event.target.value,
                    }))
                  }
                  placeholder="CWE-79, CWE-94"
                />
              </label>

              <label>
                <span>CVSS estimate</span>

                <input
                  value={candidateForm.cvss}
                  onChange={event =>
                    setCandidateForm(current => ({
                      ...current,
                      cvss: event.target.value,
                    }))
                  }
                  placeholder="9.8"
                />
              </label>

              <label>
                <span>Behaviour IDs</span>

                <input
                  value={candidateForm.behaviourIds}
                  onChange={event =>
                    setCandidateForm(current => ({
                      ...current,
                      behaviourIds: event.target.value,
                    }))
                  }
                  placeholder="behaviour:..."
                />
              </label>

              <label>
                <span>Attack chain IDs</span>

                <input
                  value={candidateForm.attackChainIds}
                  onChange={event =>
                    setCandidateForm(current => ({
                      ...current,
                      attackChainIds: event.target.value,
                    }))
                  }
                  placeholder="chain:..."
                />
              </label>

              <label>
                <span>Confidence</span>

                <input
                  type="number"
                  min="0"
                  max="100"
                  value={candidateForm.confidence}
                  onChange={event =>
                    setCandidateForm(current => ({
                      ...current,
                      confidence: event.target.value,
                    }))
                  }
                />
              </label>

              <label className="analysis-candidate-wide">
                <span>Reproduction notes</span>

                <textarea
                  rows={4}
                  value={candidateForm.reproductionNotes}
                  onChange={event =>
                    setCandidateForm(current => ({
                      ...current,
                      reproductionNotes: event.target.value,
                    }))
                  }
                />
              </label>

              <label className="analysis-candidate-wide">
                <span>Mitigation notes</span>

                <textarea
                  rows={4}
                  value={candidateForm.mitigationNotes}
                  onChange={event =>
                    setCandidateForm(current => ({
                      ...current,
                      mitigationNotes: event.target.value,
                    }))
                  }
                />
              </label>
            </div>

            {selectedReview && (
              <p className="analysis-muted">
                Current Antiserum review{' '}
                <code>{selectedReview.antiserum_id}</code> will be recorded as a
                source.
              </p>
            )}

            {createdCandidate && (
              <div className="success-banner">
                Created {createdCandidate.candidate_id}. It remains Dendrite
                research knowledge until explicitly submitted/assigned through
                an external CVE process.
              </div>
            )}

            <div className="analysis-create-footer">
              <span>
                Draft · manual origin
              </span>

              <button
                className="primary-button"
                disabled={
                  busy ||
                  !candidateForm.title.trim() ||
                  !candidateForm.description.trim() ||
                  splitList(candidateForm.affectedProducts).length === 0
                }
                onClick={() => void createCandidate()}
              >
                {busy
                  ? 'Creating…'
                  : 'Create Vulnerability Candidate'}
              </button>
            </div>
          </article>

          <article className="surface analysis-candidate-list">
            <div className="surface-heading">
              <div>
                <span className="eyebrow">
                  Local research
                </span>

                <h2>
                  {candidates.length} Candidates
                </h2>
              </div>
            </div>

            {candidates.length === 0 ? (
              <div className="empty-state">
                No Dendrite Vulnerability Candidates have been created.
              </div>
            ) : (
              candidates.map(candidate => (
                <div
                  className="analysis-package-row"
                  key={candidate.candidate_id}
                >
                  <div>
                    <strong>
                      {candidate.title}
                    </strong>

                    <small>
                      {candidate.candidate_id} · {candidate.severity} ·{' '}
                      {candidate.confidence}% confidence
                    </small>
                  </div>

                  <StatusPill value={candidate.status} />
                </div>
              ))
            )}
          </article>
        </div>
      )}
    </section>
  )
}

function Overview({
  detail,
}: {
  detail: AntiserumPackageDetail
}) {
  const populated = detail.summary.payloads
    .filter(payload => payload.status === 'populated')
    .map(payload => payload.class)

  return (
    <article className="surface analysis-overview">
      <div className="detail-header">
        <div>
          <span className="eyebrow">
            {packageOrigin(detail.summary.origin)}
          </span>

          <h2>{detail.summary.antiserum_id}</h2>
        </div>

        <StatusPill value={detail.attestation.state} />
      </div>

      <div className="detail-facts analysis-facts">
        <div>
          <span>Issuer</span>
          <strong>{detail.summary.issuer_instance_id}</strong>
        </div>

        <div>
          <span>Sequence</span>
          <strong>{detail.summary.sequence}</strong>
        </div>

        <div>
          <span>Created</span>
          <strong>
            {new Date(detail.summary.created_at).toLocaleString()}
          </strong>
        </div>

        <div>
          <span>Size</span>
          <strong>{fmtBytes(detail.summary.size_bytes)}</strong>
        </div>

        <div>
          <span>Payloads</span>
          <strong>
            {populated.join(', ') || 'Provenance only'}
          </strong>
        </div>

        <div>
          <span>Export safety</span>
          <strong>{detail.attestation.export_safety}</strong>
        </div>
      </div>

      <section className="detail-section">
        <div className="section-label">
          Content root
        </div>

        <code>{detail.envelope.content_root.value}</code>
      </section>

      <section className="detail-section">
        <div className="section-label">
          Signing key
        </div>

        <code>{detail.summary.issuer_key_fingerprint}</code>
      </section>
    </article>
  )
}

function Payloads({
  detail,
}: {
  detail: AntiserumPackageDetail
}) {
  return (
    <article className="surface analysis-payloads">
      <div className="surface-heading">
        <div>
          <span className="eyebrow">
            Authenticated contents
          </span>

          <h2>Payloads</h2>
        </div>
      </div>

      {detail.summary.payloads.map(payload => (
        <div
          className="analysis-payload-row"
          key={payload.class}
        >
          <div>
            <strong>
              {payload.class.replaceAll('-', ' ')}
            </strong>

            <code>{payload.path}</code>
          </div>

          <StatusPill value={payload.status} />
        </div>
      ))}
    </article>
  )
}

function Provenance({
  detail,
}: {
  detail: AntiserumPackageDetail
}) {
  const sources = detail.provenance.sources ?? []

  return (
    <article className="surface analysis-provenance">
      <div className="surface-heading">
        <div>
          <span className="eyebrow">
            Source assertions
          </span>

          <h2>Provenance</h2>
        </div>

        <span>
          {sources.length} sources
        </span>
      </div>

      <pre>
        {JSON.stringify(detail.provenance, null, 2)}
      </pre>
    </article>
  )
}

function Verification({
  detail,
}: {
  detail: AntiserumPackageDetail
}) {
  const rows = [
    [
      'Envelope signature',
      detail.summary.verification.signature,
    ],
    [
      'Merkle content root',
      detail.summary.verification.content_root,
    ],
    [
      'Attestation',
      detail.summary.verification.attestation,
    ],
    [
      'Local trust',
      detail.summary.verification.local_trust,
    ],
  ]

  return (
    <article className="surface analysis-verification">
      <div className="surface-heading">
        <div>
          <span className="eyebrow">
            Trust boundary
          </span>

          <h2>Verification</h2>
        </div>
      </div>

      {rows.map(([label, value]) => (
        <div
          className="analysis-verification-row"
          key={label}
        >
          <span>{label}</span>
          <StatusPill value={value} />
        </div>
      ))}

      <p>
        Signature validity authenticates the immediate exporter key. It does not
        grant execution authority or imply local trust.
      </p>
    </article>
  )
}

function OptionSection({
  title,
  children,
}: {
  title: string
  children: ReactNode
}) {
  return (
    <section className="analysis-option-section">
      <div className="section-label">
        {title}
      </div>

      {children}
    </section>
  )
}

function RadioRow({
  value,
  onChange,
  options,
}: {
  value: string
  onChange: (value: string) => void
  options: Array<[string, string]>
}) {
  return (
    <div className="analysis-radio-row">
      {options.map(([id, label]) => (
        <label
          key={id}
          className={
            value === id
              ? 'selected'
              : ''
          }
        >
          <input
            type="radio"
            checked={value === id}
            onChange={() => onChange(id)}
          />

          {label}
        </label>
      ))}
    </div>
  )
}

function CheckList({
  rows,
  selected,
  onChange,
  empty,
}: {
  rows: Array<[string, string]>
  selected: string[]
  onChange: (value: string[]) => void
  empty: string
}) {
  if (rows.length === 0) {
    return (
      <p className="analysis-muted">
        {empty}
      </p>
    )
  }

  return (
    <div className="analysis-check-list">
      {rows.map(([id, label]) => (
        <label key={id}>
          <input
            type="checkbox"
            checked={selected.includes(id)}
            onChange={event =>
              onChange(
                event.target.checked
                  ? [...selected, id]
                  : selected.filter(value => value !== id),
              )
            }
          />

          <span>{label}</span>
        </label>
      ))}
    </div>
  )
}