import type { MemoryGraph, MemoryNode } from '../api/types'
import type { GraphSettings } from './ForceGraph'
import { WebGLMemoryGraph } from './WebGLMemoryGraph'

interface Props {
  graph: MemoryGraph
  visibleKinds: Set<string>
  search: string
  selectedId: string | null
  settings: GraphSettings
  onSelect: (node: MemoryNode | null) => void
}

export function ForceGraph3D(props: Props) {
  return <WebGLMemoryGraph mode="3d" {...props} />
}
