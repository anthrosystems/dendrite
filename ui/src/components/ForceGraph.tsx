import type { MemoryGraph, MemoryNode } from '../api/types'
import { WebGLMemoryGraph } from './WebGLMemoryGraph'

export type GraphSettings = {
  nodeScale: number
  linkScale: number
  labelThreshold: number
  centreForce: number
  repelForce: number
  linkForce: number
  linkDistance: number
  showArrows: boolean
  relationshipStrengthMin: number
  strengthEncoding: 'colour' | 'width' | 'both'
}

interface Props {
  graph: MemoryGraph
  visibleKinds: Set<string>
  search: string
  selectedId: string | null
  settings: GraphSettings
  reheatToken: number
  onSelect: (node: MemoryNode | null) => void
}

export function ForceGraph(props: Props) {
  return <WebGLMemoryGraph mode="2d" {...props} />
}
