import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../api/client'
import type { MemoryNode } from '../api/types'
import { NodeGraph } from '../components/NodeGraph'
import { PageHeader } from '../components/PageHeader'
import { usePolling } from '../hooks/usePolling'

export function Topology() {
  const nodes = usePolling(useCallback(() => api.memoryRecent(100), []), 6000)
  const [selected, setSelected] = useState<string | null>(null)
  const [neighbours, setNeighbours] = useState<string[]>([])

  useEffect(() => {
    if (!selected) {
      setNeighbours([])
      return
    }
    void api.memoryNeighbours(selected)
      .then(result => setNeighbours(result.neighbours))
      .catch(() => setNeighbours([]))
  }, [selected])

  const byId = useMemo(
    () => new Map((nodes.data ?? []).map(node => [node.id, node])),
    [nodes.data],
  )

  return (
    <section className="page-stack">
      <PageHeader
        eyebrow="Knowledge"
        title="Relationships"
        description="Neighbour relationships reported by the Memory Graph. Edge strength/type are not guessed when the API does not provide them."
        onRefresh={() => void nodes.refresh()}
      />

      {nodes.error && <div className="error-banner">{nodes.error}</div>}

      <div className="topology-layout">
        <article className="surface topology-list">
          <div className="surface-heading">
            <div>
              <span className="eyebrow">Recent entities</span>
              <h2>Select a node</h2>
            </div>
            <span>{nodes.data?.length ?? 0}</span>
          </div>
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
              </button>
            ))}
          </div>
        </article>

        <article className="surface topology-graph">
          {!selected ? (
            <div className="detail-placeholder">
              <span className="detail-placeholder-mark">⌘</span>
              <strong>Select a graph entity</strong>
              <p>Dendrite will render only relationships returned by the Memory Graph.</p>
            </div>
          ) : (
            <>
              <div className="surface-heading">
                <div>
                  <span className="eyebrow">Neighbourhood</span>
                  <h2>{byId.get(selected)?.label ?? selected}</h2>
                </div>
                <span>{neighbours.length} adjacent nodes</span>
              </div>
              <NodeGraph centre={selected} neighbours={neighbours} onSelect={setSelected} />
              <div className="graph-data-note">
                <strong>Relationship semantics</strong>
                <span>
                  Current API exposes adjacency only. Strength, confidence, expiry and relationship
                  kind will drive edge thickness/fading once exposed.
                </span>
              </div>
            </>
          )}
        </article>
      </div>
    </section>
  )
}
