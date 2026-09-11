import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../api/client'
import type { MemoryNode, MemoryPath } from '../api/types'
import { NodeGraph } from '../components/NodeGraph'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'
import { usePolling } from '../hooks/usePolling'

const kinds = ['', 'process', 'file', 'user', 'host', 'network_endpoint', 'service', 'container', 'incident', 'threat']

export function Memory() {
  const [kind, setKind] = useState('')
  const [selected, setSelected] = useState<string | null>(null)
  const [neighbours, setNeighbours] = useState<string[]>([])
  const [pathTarget, setPathTarget] = useState('')
  const [path, setPath] = useState<MemoryPath | null | undefined>(undefined)
  const loadNodes = useCallback(() => api.memoryNodes(kind || undefined), [kind])
  const nodes = usePolling(loadNodes, 6000)

  useEffect(() => {
    if (!selected) {
      setNeighbours([])
      return
    }
    void api.memoryNeighbours(selected)
      .then(result => setNeighbours(result.neighbours))
      .catch(() => setNeighbours([]))
  }, [selected])

  const byId = useMemo(() => new Map((nodes.data ?? []).map(node => [node.id, node])), [nodes.data])
  const selectedNode = selected ? byId.get(selected) : undefined

  async function findPath() {
    if (!selected || !pathTarget.trim()) return
    setPath(await api.memoryPath(selected, pathTarget.trim()))
  }

  return (
    <section className="page-stack">
      <PageHeader
        eyebrow="Adaptive memory"
        title="Memory Graph"
        description="A projection of Dendrite's real STM/LTM entities and graph relationships."
        onRefresh={() => void nodes.refresh()}
      />

      {nodes.error && <div className="error-banner">{nodes.error}</div>}

      <div className="memory-controls">
        <div className="segmented-filter">
          {kinds.slice(0, 6).map(value => (
            <button
              key={value || 'all'}
              className={kind === value ? 'active' : ''}
              onClick={() => setKind(value)}
            >
              {value ? value.replaceAll('_', ' ') : 'all'}
            </button>
          ))}
          <select value={kind} onChange={event => setKind(event.target.value)}>
            {kinds.map(value => (
              <option key={value || 'all'} value={value}>{value || 'all kinds'}</option>
            ))}
          </select>
        </div>
        <span>{nodes.data?.length ?? 0} entities</span>
      </div>

      <div className="memory-workbench">
        <article className="surface memory-browser">
          <div className="entity-list">
            {(nodes.data ?? []).map((node: MemoryNode) => (
              <button
                key={node.id}
                className={selected === node.id ? 'selected' : ''}
                onClick={() => setSelected(node.id)}
              >
                <span className={`entity-kind entity-kind--${node.kind}`}>{node.kind}</span>
                <div>
                  <strong>{node.label}</strong>
                  <code>{node.id}</code>
                </div>
                <StatusPill value={node.state} />
              </button>
            ))}
            {(nodes.data ?? []).length === 0 && <div className="empty-state">No memory nodes.</div>}
          </div>
        </article>

        <div className="memory-main">
          <article className="surface memory-graph-surface">
            {!selected ? (
              <div className="detail-placeholder">
                <span className="detail-placeholder-mark">⌘</span>
                <strong>Select an entity</strong>
                <p>Its recorded neighbourhood will be projected here.</p>
              </div>
            ) : (
              <>
                <div className="surface-heading">
                  <div>
                    <span className="eyebrow">Selected entity</span>
                    <h2>{selectedNode?.label ?? selected}</h2>
                    <code className="surface-subcode">{selected}</code>
                  </div>
                  <span>{neighbours.length} relationships</span>
                </div>
                <NodeGraph centre={selected} neighbours={neighbours} onSelect={setSelected} />
              </>
            )}
          </article>

          <article className="surface path-surface">
            <div className="surface-heading">
              <div>
                <span className="eyebrow">Graph reasoning</span>
                <h2>Path explorer</h2>
              </div>
              <span>Uses daemon path discovery directly</span>
            </div>
            <div className="path-search">
              <input
                value={pathTarget}
                onChange={event => setPathTarget(event.target.value)}
                placeholder="Target node ID"
              />
              <button onClick={() => void findPath()} disabled={!selected || !pathTarget.trim()}>
                Find path
              </button>
            </div>

            {path === null && <div className="empty-inline">No path found.</div>}
            {path && (
              <div className="path-chain">
                <div className="path-score"><span>Weakest-link score</span><strong>{path.score}</strong></div>
                <div className="path-nodes">
                  {path.nodes.map((node, index) => (
                    <div key={`${node}-${index}`}>
                      <code>{node}</code>
                      {index < path.nodes.length - 1 && <span>→</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </article>
        </div>
      </div>
    </section>
  )
}
