import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { api } from '../api/client'
import type { MemoryNode } from '../api/types'
import { ForceGraph, type GraphSettings } from '../components/ForceGraph'
import { ForceGraph3D } from '../components/ForceGraph3D'
import { Icons } from '../components/Icons'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'
import { usePolling } from '../hooks/usePolling'
import { instanceLabel, lineageLabel, localObjectId, provenanceBadge } from '../utils/provenance'

const kindOrder = [
  'process',
  'file',
  'host',
  'network_endpoint',
  'service',
  'user',
  'container',
  'incident',
  'threat',
]

const kindColours: Record<string, string> = {
  process: '#8fd8a3',
  file: '#aaa5dc',
  threat: '#ef8484',
  host: '#dfc46f',
  network_endpoint: '#78b9df',
  service: '#d59ad8',
  user: '#f2d35f',
  container: '#89c8bd',
  incident: '#e88787',
}

const retentionOrder = ['short_term', 'long_term', 'persistent'] as const

const retentionDescriptions: Record<string, string> = {
  short_term: 'Recent or episodic memory that is expected to decay first.',
  long_term: 'Durable semantic memory such as process identities, executables and threat knowledge.',
  persistent: 'Authority/system memory intended to survive normal decay.',
}

// Tuned after a real-world graph reached ~10k nodes and the default
// repel/centre/separation balance caused a visible "explosion" on
// render/reheat before settling (see WebGLMemoryGraph.tsx's
// MAX_CLUSTER_SPAWN_RADIUS/MAX_NODE_SPEED comments for the underlying
// density-scaling fix — these defaults are the other half: less outward
// push, more inward pull, so even a dense graph settles calmly instead of
// relying on the safety-net clamp to catch it).
const defaultSettings: GraphSettings = {
  nodeScale: 1,
  linkScale: 1,
  labelThreshold: 1.05,
  centreForce: 1.2,
  repelForce: 0.25,
  linkForce: 1.15,
  linkDistance: 92,
  showArrows: false,
  relationshipStrengthMin: 0,
  strengthEncoding: 'both',
  clusterByKind: true,
  groupCohesion: 1.7,
  groupSeparation: 0.7,
  interGroupAttraction: 0.75,
}


const GRAPH_CONTROL_STORAGE_KEY = 'dendrite.memoryGraph.controls.v1'

type GraphSections = {
  filters: boolean
  groups: boolean
  display: boolean
  forces: boolean
}

type PersistedGraphControls = {
  settings: GraphSettings
  hiddenKinds: string[]
  hiddenRetentions: string[]
  hiddenOrigins: string[]
  search: string
  viewMode: '2d' | '3d'
  controlsOpen: boolean
  sections: GraphSections
}

const defaultSections: GraphSections = {
  filters: true,
  groups: true,
  display: true,
  forces: true,
}

function loadPersistedControls(): PersistedGraphControls {
  const fallback: PersistedGraphControls = {
    settings: defaultSettings,
    hiddenKinds: [],
    hiddenRetentions: [],
    hiddenOrigins: [],
    search: '',
    viewMode: '2d',
    controlsOpen: true,
    sections: defaultSections,
  }

  try {
    const raw = window.localStorage.getItem(GRAPH_CONTROL_STORAGE_KEY)
    if (!raw) return fallback
    const parsed = JSON.parse(raw) as Partial<PersistedGraphControls>
    return {
      settings: { ...defaultSettings, ...(parsed.settings ?? {}) },
      hiddenKinds: Array.isArray(parsed.hiddenKinds) ? parsed.hiddenKinds.filter(value => typeof value === 'string') : [],
      hiddenRetentions: Array.isArray(parsed.hiddenRetentions)
        ? parsed.hiddenRetentions.filter(value => typeof value === 'string')
        : [],
      hiddenOrigins: Array.isArray(parsed.hiddenOrigins) ? parsed.hiddenOrigins.filter(value => typeof value === 'string') : [],
      search: typeof parsed.search === 'string' ? parsed.search : '',
      viewMode: parsed.viewMode === '3d' ? '3d' : '2d',
      controlsOpen: typeof parsed.controlsOpen === 'boolean' ? parsed.controlsOpen : true,
      sections: { ...defaultSections, ...(parsed.sections ?? {}) },
    }
  } catch {
    return fallback
  }
}

function formatTime(value: number) {
  return new Date(value * 1000).toLocaleString()
}

function displayLabel(value: string) {
  return value
    .replaceAll('_', ' ')
    .replace(/\b\w/g, character => character.toUpperCase())
}

function ControlSection({
  title,
  open,
  onToggle,
  children,
}: {
  title: string
  open: boolean
  onToggle: () => void
  children: ReactNode
}) {
  return (
    <section className={`graph-control-section ${open ? 'open' : ''}`}>
      <button className="graph-control-section-title" onClick={onToggle}>
        <span>{open ? '⌄' : '›'}</span>
        {title}
      </button>
      {open && <div className="graph-control-section-body">{children}</div>}
    </section>
  )
}

function Slider({
  label,
  value,
  min,
  max,
  step,
  onChange,
}: {
  label: string
  value: number
  min: number
  max: number
  step: number
  onChange: (value: number) => void
}) {
  return (
    <label className="graph-slider">
      <div><span>{label}</span><output>{value.toFixed(step < 1 ? 2 : 0)}</output></div>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={event => onChange(Number(event.target.value))}
      />
    </label>
  )
}

export function Memory() {
  const graph = usePolling(useCallback(() => api.memoryGraph(0), []), 30000, 'memory-graph-full')
  const status = usePolling(useCallback(() => api.status(), []), 30000, 'memory-status')
  const [persisted] = useState(loadPersistedControls)
  const [selected, setSelected] = useState<MemoryNode | null>(null)
  const [search, setSearch] = useState(persisted.search)
  const [hiddenKinds, setHiddenKinds] = useState<Set<string>>(() => new Set(persisted.hiddenKinds))
  const [hiddenRetentions, setHiddenRetentions] = useState<Set<string>>(() => new Set(persisted.hiddenRetentions))
  const [hiddenOrigins, setHiddenOrigins] = useState<Set<string>>(() => new Set(persisted.hiddenOrigins))
  const [settings, setSettings] = useState<GraphSettings>(persisted.settings)
  const [reheatToken, setReheatToken] = useState(0)
  const [renderToken, setRenderToken] = useState(0)
  const [controlsOpen, setControlsOpen] = useState(persisted.controlsOpen)
  const [viewMode, setViewMode] = useState<'2d' | '3d'>(persisted.viewMode)
  const [sections, setSections] = useState<GraphSections>(persisted.sections)
  const localInstanceId = status.data?.instance_id ?? null

  useEffect(() => {
    const state: PersistedGraphControls = {
      settings,
      hiddenKinds: [...hiddenKinds],
      hiddenRetentions: [...hiddenRetentions],
      hiddenOrigins: [...hiddenOrigins],
      search,
      viewMode,
      controlsOpen,
      sections,
    }
    try {
      window.localStorage.setItem(GRAPH_CONTROL_STORAGE_KEY, JSON.stringify(state))
    } catch {
      // The graph remains fully usable when storage is unavailable.
    }
  }, [settings, hiddenKinds, hiddenRetentions, hiddenOrigins, search, viewMode, controlsOpen, sections])

  const kinds = useMemo(() => {
    const present = new Set((graph.data?.nodes ?? []).map(node => node.kind))
    return [...present].sort((left, right) => {
      const li = kindOrder.indexOf(left)
      const ri = kindOrder.indexOf(right)
      if (li === -1 && ri === -1) return left.localeCompare(right)
      if (li === -1) return 1
      if (ri === -1) return -1
      return li - ri
    })
  }, [graph.data])

  const visibleKinds = useMemo(
    () => new Set(kinds.filter(kind => !hiddenKinds.has(kind))),
    [kinds, hiddenKinds],
  )

  const retentionCounts = useMemo(() => {
    const counts: Record<string, number> = { short_term: 0, long_term: 0, persistent: 0 }
    for (const node of graph.data?.nodes ?? []) {
      counts[node.retention] = (counts[node.retention] ?? 0) + 1
    }
    return counts
  }, [graph.data])

  const origins = useMemo(() => {
    const counts = new Map<string, number>()
    for (const node of graph.data?.nodes ?? []) {
      const origin = node.origin_instance_id ?? localInstanceId ?? 'unknown'
      counts.set(origin, (counts.get(origin) ?? 0) + 1)
    }
    return [...counts.entries()].sort(([left], [right]) => {
      if (left === localInstanceId) return -1
      if (right === localInstanceId) return 1
      return left.localeCompare(right)
    })
  }, [graph.data, localInstanceId])

  const filteredGraph = useMemo(() => {
    if (!graph.data) return null
    const nodes = graph.data.nodes.filter(node => {
      const origin = node.origin_instance_id ?? localInstanceId ?? 'unknown'
      return !hiddenRetentions.has(node.retention) && !hiddenOrigins.has(origin)
    })
    const included = new Set(nodes.map(node => node.id))
    const relationships = graph.data.relationships.filter(edge => {
      const origin = edge.origin_instance_id ?? localInstanceId ?? 'unknown'
      return !hiddenRetentions.has(edge.retention)
        && !hiddenOrigins.has(origin)
        && included.has(edge.source)
        && included.has(edge.target)
    })
    return { ...graph.data, nodes, relationships }
  }, [graph.data, hiddenRetentions, hiddenOrigins, localInstanceId])

  const selectedEdges = useMemo(() => {
    if (!selected || !filteredGraph) return []
    return filteredGraph.relationships.filter(
      edge => edge.source === selected.id || edge.target === selected.id,
    )
  }, [selected, filteredGraph])

  const graphStats = useMemo(() => {
    if (!filteredGraph) return null

    const nodes = filteredGraph.nodes.filter(node => visibleKinds.has(node.kind))
    const nodeIds = new Set(nodes.map(node => node.id))
    const relationships = filteredGraph.relationships.filter(edge =>
      nodeIds.has(edge.source)
      && nodeIds.has(edge.target)
      && edge.effective_strength >= settings.relationshipStrengthMin,
    )

    const relationshipCount = relationships.length
    const averageStrength = relationshipCount === 0
      ? 0
      : relationships.reduce((sum, edge) => sum + edge.effective_strength, 0) / relationshipCount
    const averageConfidence = relationshipCount === 0
      ? 0
      : relationships.reduce((sum, edge) => sum + edge.confidence, 0) / relationshipCount
    const strongestRelationship = relationshipCount === 0
      ? 0
      : Math.max(...relationships.map(edge => edge.effective_strength))

    const connectedIds = new Set<string>()
    for (const edge of relationships) {
      connectedIds.add(edge.source)
      connectedIds.add(edge.target)
    }

    const shortTermExpiringSoon = nodes.filter(node => {
      if (node.retention !== 'short_term' || node.expires_at === null) return false
      const lifetime = Math.max(1, node.expires_at - node.created_at)
      const remaining = Math.max(0, node.expires_at - Date.now() / 1000)
      return remaining / lifetime <= 0.30
    }).length

    return {
      visibleNodes: nodes.length,
      visibleRelationships: relationshipCount,
      averageStrength,
      averageConfidence,
      strongestRelationship,
      connectedNodes: connectedIds.size,
      isolatedNodes: Math.max(0, nodes.length - connectedIds.size),
      averageDegree: nodes.length === 0 ? 0 : (relationshipCount * 2) / nodes.length,
      shortTermExpiringSoon,
    }
  }, [filteredGraph, visibleKinds, settings.relationshipStrengthMin])

  const nodesById = useMemo(
    () => new Map((filteredGraph?.nodes ?? []).map(node => [node.id, node])),
    [filteredGraph],
  )

  function toggleKind(kind: string) {
    setHiddenKinds(current => {
      const next = new Set(current)
      if (next.has(kind)) next.delete(kind)
      else next.add(kind)
      return next
    })
    setReheatToken(value => value + 1)
  }

  function toggleRetention(retention: string) {
    setHiddenRetentions(current => {
      const next = new Set(current)
      if (next.has(retention)) next.delete(retention)
      else next.add(retention)
      return next
    })
    setSelected(null)
    setReheatToken(value => value + 1)
  }

  function toggleOrigin(origin: string) {
    setHiddenOrigins(current => {
      const next = new Set(current)
      if (next.has(origin)) next.delete(origin)
      else next.add(origin)
      return next
    })
    setSelected(null)
    setReheatToken(value => value + 1)
  }

  function setRetentionPreset(preset: 'all' | 'recent' | 'established') {
    if (preset === 'recent') setHiddenRetentions(new Set(['long_term', 'persistent']))
    else if (preset === 'established') setHiddenRetentions(new Set(['short_term']))
    else setHiddenRetentions(new Set())
    setSelected(null)
    setReheatToken(value => value + 1)
  }

  function updateSetting<K extends keyof GraphSettings>(key: K, value: GraphSettings[K]) {
    setSettings(current => ({ ...current, [key]: value }))
    if (
      key === 'relationshipStrengthMin'
      || key === 'centreForce'
      || key === 'repelForce'
      || key === 'linkForce'
      || key === 'linkDistance'
      || key === 'clusterByKind'
      || key === 'groupCohesion'
      || key === 'groupSeparation'
      || key === 'interGroupAttraction'
    ) {
      setReheatToken(value => value + 1)
    }
  }

  function rerenderGraph() {
    setReheatToken(value => value + 1)
    setRenderToken(value => value + 1)
  }

  function resetGraphControls() {
    setSettings(defaultSettings)
    setHiddenKinds(new Set())
    setHiddenRetentions(new Set())
    setHiddenOrigins(new Set())
    setSearch('')
    setViewMode('2d')
    setSections(defaultSections)
    setControlsOpen(true)
    setReheatToken(value => value + 1)
    setRenderToken(value => value + 1)
  }

  function toggleSection(key: keyof typeof sections) {
    setSections(current => ({ ...current, [key]: !current[key] }))
  }

  return (
    <section className="page-stack memory-page memory-page--obsidian">
      <PageHeader
        eyebrow="Adaptive memory"
        title="Memory Graph"
        description="Interactive projection of Dendrite's real STM/LTM graph, with Obsidian-style exploration controls over real memory state."
        onRefresh={() => void graph.refresh()}
      />

      {graph.error && <div className="error-banner">{graph.error}</div>}
      {graph.data && graphStats && (
        <div className="memory-graph-summary memory-graph-summary--stats">
          <div className="memory-graph-stat">
            <span>Nodes</span>
            <strong>{graph.data.total_nodes.toLocaleString()}</strong>
          </div>
          <div className="memory-graph-stat">
            <span>Relationships</span>
            <strong>{graph.data.total_relationships.toLocaleString()}</strong>
          </div>
          <div className="memory-graph-stat">
            <span>Visible</span>
            <strong>{graphStats.visibleNodes.toLocaleString()} nodes · {graphStats.visibleRelationships.toLocaleString()} links</strong>
          </div>
          <div className="memory-graph-stat">
            <span>Avg strength</span>
            <strong>{graphStats.averageStrength.toFixed(0)}%</strong>
          </div>
          <div className="memory-graph-stat">
            <span>Avg confidence</span>
            <strong>{graphStats.averageConfidence.toFixed(0)}%</strong>
          </div>
          <div className="memory-graph-stat">
            <span>Strongest link</span>
            <strong>{graphStats.strongestRelationship.toFixed(0)}%</strong>
          </div>
          <div className="memory-graph-stat">
            <span>Avg degree</span>
            <strong>{graphStats.averageDegree.toFixed(2)}</strong>
          </div>
          <div className="memory-graph-stat">
            <span>Connected / isolated</span>
            <strong>{graphStats.connectedNodes.toLocaleString()} / {graphStats.isolatedNodes.toLocaleString()}</strong>
          </div>
          <div className="memory-graph-stat">
            <span>STM near expiry</span>
            <strong>{graphStats.shortTermExpiringSoon.toLocaleString()}</strong>
          </div>
        </div>
      )}

      <div className="memory-graph-layout memory-graph-layout--obsidian">
        <article className="memory-graph-stage memory-graph-stage--obsidian">
          {filteredGraph ? (
            viewMode === '2d' ? (
              <ForceGraph
                key={`2d:${renderToken}`}
                graph={filteredGraph}
                visibleKinds={visibleKinds}
                search={search}
                selectedId={selected?.id ?? null}
                settings={settings}
                reheatToken={reheatToken}
                onSelect={setSelected}
              />
            ) : (
              <ForceGraph3D
                key={`3d:${renderToken}`}
                graph={filteredGraph}
                visibleKinds={visibleKinds}
                search={search}
                selectedId={selected?.id ?? null}
                settings={settings}
                onSelect={setSelected}
              />
            )
          ) : (
            <div className="graph-loading">Loading Memory Graph…</div>
          )}

          <aside className={`graph-control-panel ${controlsOpen ? 'open' : 'collapsed'}`}>
            <div className="graph-control-panel-header">
              <div>
                <span className="graph-control-mark">⌘</span>
                <strong>Graph controls</strong>
              </div>
              <button onClick={() => setControlsOpen(value => !value)}>{controlsOpen ? '×' : '☰'}</button>
            </div>

            {controlsOpen && (
              <div className="graph-control-panel-scroll">
                <div className="graph-control-actions">
                  <button className="graph-control-action graph-control-action--primary" onClick={rerenderGraph}>
                    Re-render graph
                  </button>
                  <button className="graph-control-action" onClick={resetGraphControls}>
                    Reset controls
                  </button>
                  <p>
                    Display changes are immediate. Force changes reheat the simulation and settle over time;
                    re-render rebuilds the layout using the current controls.
                  </p>
                </div>

                <ControlSection
                  title="Filters"
                  open={sections.filters}
                  onToggle={() => toggleSection('filters')}
                >
                  <div className="memory-search memory-search--panel">
                    <Icons.search />
                    <input
                      value={search}
                      onChange={event => setSearch(event.target.value)}
                      placeholder="Search nodes"
                    />
                    {search && <button onClick={() => setSearch('')}>×</button>}
                  </div>
                  <small className="graph-control-help">Search highlights matches without removing graph context.</small>

                  <div className="graph-filter-subsection">
                    <div className="graph-filter-subsection-heading">
                      <strong>Dendrite hosts</strong>
                      <span>Filter graph knowledge by the instance that originally observed or derived it.</span>
                    </div>
                    <div className="graph-retention-list graph-origin-list">
                      {origins.map(([origin, count]) => {
                        const enabled = !hiddenOrigins.has(origin)
                        return (
                          <label key={origin} className={enabled ? 'enabled' : ''}>
                            <input type="checkbox" checked={enabled} onChange={() => toggleOrigin(origin)} />
                            <span>
                              <strong>{origin === localInstanceId ? 'Local' : instanceLabel(origin, localInstanceId)}</strong>
                              <small>{origin}</small>
                            </span>
                            <output>{count.toLocaleString()}</output>
                          </label>
                        )
                      })}
                    </div>
                    <div className="graph-control-inline-actions">
                      <button onClick={() => { setHiddenOrigins(new Set()); setSelected(null); setReheatToken(value => value + 1) }}>Show all</button>
                      <button onClick={() => { setHiddenOrigins(new Set(origins.map(([origin]) => origin))); setSelected(null); setReheatToken(value => value + 1) }}>Hide all</button>
                    </div>
                  </div>

                  <div className="graph-filter-subsection">
                    <div className="graph-filter-subsection-heading">
                      <strong>Memory retention</strong>
                      <span>Filter STM, LTM and persistent memory independently.</span>
                    </div>
                    <div className="graph-retention-presets">
                      <button onClick={() => setRetentionPreset('all')}>All memory</button>
                      <button onClick={() => setRetentionPreset('recent')}>Recent activity</button>
                      <button onClick={() => setRetentionPreset('established')}>Established memory</button>
                    </div>
                    <div className="graph-retention-list">
                      {retentionOrder.map(retention => {
                        const enabled = !hiddenRetentions.has(retention)
                        return (
                          <label key={retention} className={enabled ? 'enabled' : ''} data-retention={retention}>
                            <input
                              type="checkbox"
                              checked={enabled}
                              onChange={() => toggleRetention(retention)}
                            />
                            <span>
                              <strong>{displayLabel(retention)}</strong>
                              <small>{retentionDescriptions[retention]}</small>
                            </span>
                            <output>{(retentionCounts[retention] ?? 0).toLocaleString()}</output>
                          </label>
                        )
                      })}
                    </div>
                  </div>
                </ControlSection>

                <ControlSection
                  title="Groups"
                  open={sections.groups}
                  onToggle={() => toggleSection('groups')}
                >
                  <div className="graph-group-list">
                    {kinds.map(kind => {
                      const enabled = !hiddenKinds.has(kind)
                      return (
                        <label key={kind} className={enabled ? 'enabled' : ''}>
                          <input type="checkbox" checked={enabled} onChange={() => toggleKind(kind)} />
                          <span className="graph-group-colour" style={{ background: kindColours[kind] ?? '#96a39b' }} />
                          <span>{displayLabel(kind)}</span>
                        </label>
                      )
                    })}
                  </div>
                  <div className="graph-control-inline-actions">
                    <button onClick={() => { setHiddenKinds(new Set()); setReheatToken(value => value + 1) }}>Show all</button>
                    <button onClick={() => { setHiddenKinds(new Set(kinds)); setReheatToken(value => value + 1) }}>Hide all</button>
                  </div>
                </ControlSection>

                <ControlSection
                  title="Display"
                  open={sections.display}
                  onToggle={() => toggleSection('display')}
                >
                  <div className="graph-view-switch" role="group" aria-label="Graph view">
                    <button className={viewMode === '2d' ? 'is-active' : ''} onClick={() => setViewMode('2d')}>2D</button>
                    <button className={viewMode === '3d' ? 'is-active' : ''} onClick={() => setViewMode('3d')}>3D</button>
                  </div>
                  <small className="graph-control-help">2D is the investigative view. 3D is an exploratory spatial projection of the complete graph.</small>
                  <label className="graph-toggle-row">
                    <span>Arrows</span>
                    <input
                      type="checkbox"
                      checked={settings.showArrows}
                      onChange={event => updateSetting('showArrows', event.target.checked)}
                    />
                  </label>
                  <label className="graph-select-row">
                    <span>Relationship strength display</span>
                    <select
                      value={settings.strengthEncoding}
                      onChange={event => updateSetting('strengthEncoding', event.target.value as GraphSettings['strengthEncoding'])}
                    >
                      <option value="colour">Colour</option>
                      <option value="width">Line width</option>
                      <option value="both">Colour + line width</option>
                    </select>
                  </label>
                  <div className="graph-strength-key" aria-label="Relationship strength colour key">
                    <span>Weak</span><i /><span>Medium</span><i /><span>Strong</span>
                  </div>
                  <Slider label="Minimum relationship strength" value={settings.relationshipStrengthMin} min={0} max={100} step={1} onChange={value => updateSetting('relationshipStrengthMin', value)} />
                  <small className="graph-setting-help">Hides weaker links visually and from the force layout. Higher values expose the strongest structure and reduce clutter.</small>
                  <Slider label="Text fade threshold" value={settings.labelThreshold} min={0.35} max={2.5} step={0.05} onChange={value => updateSetting('labelThreshold', value)} />
                  <small className="graph-setting-help">Zoom level at which ordinary node labels appear. Selected, hovered and search-matched nodes remain labelled.</small>
                  <Slider label="Node size" value={settings.nodeScale} min={0.45} max={2.4} step={0.05} onChange={value => updateSetting('nodeScale', value)} />
                  <Slider label="Link thickness" value={settings.linkScale} min={0.25} max={2.5} step={0.05} onChange={value => updateSetting('linkScale', value)} />
                </ControlSection>

                <ControlSection
                  title="Forces"
                  open={sections.forces}
                  onToggle={() => toggleSection('forces')}
                >
                  <label className="graph-toggle-row">
                    <span>Cluster related node families</span>
                    <input
                      type="checkbox"
                      checked={settings.clusterByKind}
                      onChange={event => updateSetting('clusterByKind', event.target.checked)}
                    />
                  </label>
                  <Slider label="Group cohesion" value={settings.groupCohesion} min={0} max={3} step={0.05} onChange={value => updateSetting('groupCohesion', value)} />
                  <small className="graph-setting-help">Pulls nodes of the same type toward their local centroid. Increase this for tighter process/file/network/etc. islands.</small>
                  <Slider label="Group separation" value={settings.groupSeparation} min={0} max={3} step={0.05} onChange={value => updateSetting('groupSeparation', value)} />
                  <small className="graph-setting-help">Repels type-clusters from one another so they form distinct islands instead of one circular cloud.</small>
                  <Slider label="Inter-group attraction" value={settings.interGroupAttraction} min={0} max={3} step={0.05} onChange={value => updateSetting('interGroupAttraction', value)} />
                  <small className="graph-setting-help">Moves whole clusters toward related clusters using their aggregate cross-type relationship strength.</small>
                  <Slider label="Centre force" value={settings.centreForce} min={0.05} max={3} step={0.05} onChange={value => updateSetting('centreForce', value)} />
                  <small className="graph-setting-help">Keeps the whole map from drifting away. Too much makes the graph collapse into a round ball.</small>
                  <Slider label="Repel force" value={settings.repelForce} min={0.1} max={3} step={0.05} onChange={value => updateSetting('repelForce', value)} />
                  <small className="graph-setting-help">Pushes individual nodes apart. Increase it for more breathing room; decrease it for denser clusters.</small>
                  <Slider label="Relationship attraction" value={settings.linkForce} min={0.1} max={3} step={0.05} onChange={value => updateSetting('linkForce', value)} />
                  <small className="graph-setting-help">How strongly linked nodes pull toward each other. Strong edges naturally pull harder than weak ones.</small>
                  <Slider label="Relationship distance" value={settings.linkDistance} min={30} max={180} step={1} onChange={value => updateSetting('linkDistance', value)} />
                  <small className="graph-setting-help">Preferred spacing between connected nodes. Larger values stretch clusters and reveal their internal structure.</small>
                  <div className="graph-force-actions">
                    <button className="graph-animate-button" onClick={() => setReheatToken(value => value + 1)}>
                      Reflow layout
                    </button>
                    <small className="graph-setting-help">
                      Reflow keeps current node positions but gives the force simulation fresh energy.
                    </small>
                  </div>
                </ControlSection>
              </div>
            )}
          </aside>

          <aside className={`memory-inspector memory-inspector--overlay ${selected ? 'memory-inspector--open' : ''}`}>
            {selected && (
              <>
                <div className="memory-inspector-header">
                  <div>
                    <div className="memory-inspector-title-row">
                      <span className={`entity-kind entity-kind--${selected.kind}`}>{displayLabel(selected.kind)}</span>
                      <span className="entity-provenance-badge">{provenanceBadge(selected, localInstanceId)}</span>
                    </div>
                    <h2>{selected.label}</h2>
                    <code className="memory-local-id">{localObjectId(selected.id, selected.origin_instance_id)}</code>
                    <details className="canonical-id">
                      <summary>Canonical ID</summary>
                      <code>{selected.id}</code>
                    </details>
                  </div>
                  <button onClick={() => setSelected(null)}>×</button>
                </div>

                <div className="memory-inspector-status memory-inspector-status--labelled">
                  <div>
                    <span>Memory state</span>
                    <StatusPill value={selected.state} />
                    <small>Current lifecycle state of this remembered entity.</small>
                  </div>
                  <div>
                    <span>Memory priority</span>
                    <StatusPill value={selected.priority} />
                    <small>How strongly Dendrite prioritises this memory for retention/reasoning.</small>
                  </div>
                  <div>
                    <span>Retention class</span>
                    <StatusPill value={selected.retention} />
                    <small>How long this memory is intended to remain relevant before expiry/archival.</small>
                  </div>
                </div>

                <div className="memory-inspector-facts">
                  <div><span>First seen</span><strong>{formatTime(selected.created_at)}</strong></div>
                  <div><span>Last seen</span><strong>{formatTime(selected.last_seen_at)}</strong></div>
                  <div><span>Expires</span><strong>{selected.expires_at ? formatTime(selected.expires_at) : 'never'}</strong></div>
                  <div><span>Relationships</span><strong>{selectedEdges.length}</strong></div>
                  {selected.origin_instance_id && (
                    <div className="provenance-fact">
                      <span>Origin</span>
                      <strong title={selected.origin_instance_id}>{instanceLabel(selected.origin_instance_id, localInstanceId)}</strong>
                      {selected.origin_instance_id !== localInstanceId && <small>{selected.origin_instance_id}</small>}
                    </div>
                  )}
                  {selected.lineage.length > 0 && (
                    <div className="provenance-fact provenance-fact--lineage">
                      <span>Lineage</span>
                      <div className="lineage-chips">
                        {selected.lineage.map((instanceId, index) => (
                          <span key={`${instanceId}-${index}`} title={instanceId}>
                            {lineageLabel(instanceId, localInstanceId)}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {selected.imported_from_instance_id && (
                    <div className="provenance-fact">
                      <span>Imported from</span>
                      <strong title={selected.imported_from_instance_id}>{instanceLabel(selected.imported_from_instance_id, localInstanceId)}</strong>
                      <small>{selected.imported_from_instance_id}</small>
                    </div>
                  )}
                  {selected.derived_by_instance_id && (
                    <div className="provenance-fact">
                      <span>Derived by</span>
                      <strong title={selected.derived_by_instance_id}>{instanceLabel(selected.derived_by_instance_id, localInstanceId)}</strong>
                      {selected.derived_by_instance_id !== localInstanceId && <small>{selected.derived_by_instance_id}</small>}
                    </div>
                  )}
                </div>

                {selected.correlation_keys.length > 0 && (
                  <section className="memory-inspector-section">
                    <div className="section-label">Correlation keys</div>
                    <div className="memory-correlation-keys">
                      {selected.correlation_keys.map(value => <code key={value}>{value}</code>)}
                    </div>
                    <small>Host-scoped object IDs remain distinct. These keys allow equivalent observations on other Dendrite hosts to correlate without collapsing provenance.</small>
                  </section>
                )}

                <section className="memory-inspector-section">
                  <div className="section-label">Relationships</div>
                  {selectedEdges.length === 0 ? (
                    <div className="empty-inline">No relationships connected to this node in the loaded graph.</div>
                  ) : (
                    <div className="relationship-inspector-list">
                      {[...selectedEdges]
                        .sort((a, b) => b.effective_strength - a.effective_strength)
                        .slice(0, 40)
                        .map(edge => {
                          const outgoing = edge.source === selected.id
                          const otherId = outgoing ? edge.target : edge.source
                          const otherNode = nodesById.get(otherId)
                          return (
                            <article key={edge.id} className="relationship-inspector-card">
                              <div className="relationship-inspector-top">
                                <div>
                                  <span className="relationship-direction">{outgoing ? 'OUTGOING' : 'INCOMING'}</span>
                                  <strong>{displayLabel(edge.kind)}</strong>
                                </div>
                                <span>{edge.effective_strength}% strength</span>
                              </div>
                              <button
                                className="relationship-node-link"
                                onClick={() => otherNode && setSelected(otherNode)}
                                disabled={!otherNode}
                              >
                                <span className={`entity-kind entity-kind--${otherNode?.kind ?? 'unknown'}`}>{displayLabel(otherNode?.kind ?? 'unknown')}</span>
                                <div>
                                  <strong>{otherNode?.label ?? localObjectId(otherId, otherNode?.origin_instance_id)}</strong>
                                  {otherNode && <span className="relationship-origin">{provenanceBadge(otherNode, localInstanceId)}</span>}
                                  <code title={otherId}>{localObjectId(otherId, otherNode?.origin_instance_id)}</code>
                                </div>
                              </button>
                              <div className="relationship-metadata">
                                <div><span>Relationship state</span><StatusPill value={edge.state} /></div>
                                <div><span>Retention class</span><StatusPill value={edge.retention} /></div>
                              </div>
                              <div className="relationship-bars">
                                <div><span style={{ width: `${edge.effective_strength}%` }} /></div>
                                <small>Effective strength {edge.effective_strength}% · Confidence {edge.confidence}% · {edge.observation_count} observations</small>
                              </div>
                            </article>
                          )
                        })}
                    </div>
                  )}
                </section>

                <div className="graph-semantics">
                  <span>Edge colour/width = effective relationship strength</span>
                  <span>Edge opacity = relationship confidence</span>
                  <span>Dotted = near expiry</span>
                  <span>Faded = inactive memory</span>
                </div>
              </>
            )}
          </aside>
        </article>
      </div>
    </section>
  )
}
