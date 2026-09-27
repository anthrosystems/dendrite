import { useEffect, useMemo, useRef, useState } from 'react'
import type { MemoryGraph, MemoryNode, MemoryRelationship } from '../api/types'
import type { GraphSettings } from './ForceGraph'
import { kindColourRgb01 } from '../utils/nodeColours'

type Mode = '2d' | '3d'

type SimNode = MemoryNode & {
  x: number
  y: number
  z: number
  vx: number
  vy: number
  vz: number
  radius: number
  degree: number
}

type ViewState = {
  x: number
  y: number
  zoom: number
  yaw: number
  pitch: number
  camera: number
}

type Props = {
  mode: Mode
  graph: MemoryGraph
  visibleKinds: Set<string>
  search: string
  selectedId: string | null
  settings: GraphSettings
  reheatToken?: number
  onSelect: (node: MemoryNode | null) => void
}

// Per-node velocity clamp applied every simulation frame, after all forces
// for that frame have accumulated but before damping/integration. This is a
// hard safety net independent of any GraphSettings slider: no reasonable
// combination of forces should ever be able to fling a node further than
// this per frame, so a bug or an unusually dense graph produces a capped
// (if still visibly energetic) settle rather than nodes rocketing off
// past the visible canvas. See SPAWN_SPACING below for the other half of
// the fix — this clamp bounds the *symptom*, that bounds the *cause*.
const MAX_NODE_SPEED = 30

// Newly-spawned nodes are placed on a global Vogel/Fibonacci golden-angle
// spiral (no per-kind grouping — Dendrite previously assigned every node an
// artificial per-kind/per-label cluster and anchored spirals per-cluster;
// that's been removed in favour of pure link+repel+centre physics, matching
// the minimal force model real graph-visualisation tools such as Obsidian's
// graph view use) sized so density stays roughly constant as the graph
// grows. This constant is the per-node spacing factor: spawn radius for
// the node at spiral index i is SPAWN_SPACING * sqrt(i). Previously,
// nodes spawned inside a hard-capped-at-120px per-kind cluster anchor,
// which packed far too densely past a few hundred nodes per cluster —
// at 10k+ nodes concentrated in one or two kind clusters, that meant
// nearly every node spawned overlapping several others, and the resulting
// repulsion saturated on nearly every pairwise sample at once — visually,
// the graph "exploding" outward on first render/reheat before settling.
// A global spiral with constant per-node spacing avoids that density trap
// at any node count, with no hard cap needed.
const SPAWN_SPACING = 14

function hash(value: string) {
  let h = 2166136261
  for (let i = 0; i < value.length; i += 1) {
    h ^= value.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return h >>> 0
}

function random01(seed: number, salt: number) {
  const value = Math.sin((seed + salt) * 12.9898) * 43758.5453
  return value - Math.floor(value)
}

function nodeColour(kind: string) {
  return kindColourRgb01(kind)
}

function lifetimeOpacity(retention: string, createdAt: number, expiresAt: number | null, nowSeconds: number) {
  if (retention !== 'short_term' || expiresAt === null) return 1
  const lifetime = Math.max(1, expiresAt - createdAt)
  const remaining = Math.max(0, expiresAt - nowSeconds)
  const ratio = Math.max(0, Math.min(1, remaining / lifetime))
  if (ratio >= 0.60) return 1
  if (ratio >= 0.30) return 0.78 + ((ratio - 0.30) / 0.30) * 0.22
  if (ratio >= 0.10) return 0.56 + ((ratio - 0.10) / 0.20) * 0.22
  // STM should look old, not disappear into the black canvas before it actually expires.
  return 0.38 + (ratio / 0.10) * 0.18
}

function strengthColour(strength: number): [number, number, number] {
  // Relationship strength uses a neutral luminance scale on purpose. Node/group
  // colours carry entity semantics; edge colours must never compete with them.
  const value = Math.max(0, Math.min(100, strength)) / 100
  const level = 0.30 + value * 0.62
  return [level, level, level]
}

function createShader(gl: WebGL2RenderingContext, type: number, source: string) {
  const shader = gl.createShader(type)
  if (!shader) throw new Error('Unable to allocate WebGL shader')
  gl.shaderSource(shader, source)
  gl.compileShader(shader)
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    throw new Error(gl.getShaderInfoLog(shader) ?? 'WebGL shader compilation failed')
  }
  return shader
}

function createProgram(gl: WebGL2RenderingContext, vertex: string, fragment: string) {
  const program = gl.createProgram()
  if (!program) throw new Error('Unable to allocate WebGL program')
  gl.attachShader(program, createShader(gl, gl.VERTEX_SHADER, vertex))
  gl.attachShader(program, createShader(gl, gl.FRAGMENT_SHADER, fragment))
  gl.linkProgram(program)
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
    throw new Error(gl.getProgramInfoLog(program) ?? 'WebGL program link failed')
  }
  return program
}

const VERTEX_SHADER = `#version 300 es
precision highp float;
in vec3 a_position;
in vec4 a_colour;
in float a_size;
uniform vec2 u_resolution;
uniform vec2 u_pan;
uniform float u_zoom;
uniform float u_mode3d;
uniform float u_yaw;
uniform float u_pitch;
uniform float u_camera;
out vec4 v_colour;

vec3 rotate3d(vec3 p) {
  float cy = cos(u_yaw); float sy = sin(u_yaw);
  float cp = cos(u_pitch); float sp = sin(u_pitch);
  vec3 y = vec3(cy*p.x + sy*p.z, p.y, -sy*p.x + cy*p.z);
  return vec3(y.x, cp*y.y - sp*y.z, sp*y.y + cp*y.z);
}

void main() {
  vec2 screen;
  float pointScale = u_zoom;
  if (u_mode3d > .5) {
    vec3 p = rotate3d(a_position);
    float depth = max(180.0, u_camera - p.z);
    float perspective = u_camera / depth;
    screen = p.xy * u_zoom * perspective + u_pan;
    pointScale *= perspective;
  } else {
    screen = a_position.xy * u_zoom + u_pan;
  }
  vec2 clip = screen / max(u_resolution * .5, vec2(1.0));
  gl_Position = vec4(clip.x, -clip.y, 0.0, 1.0);
  gl_PointSize = clamp(a_size * pointScale, 1.5, 28.0);
  v_colour = a_colour;
}`

const POINT_FRAGMENT_SHADER = `#version 300 es
precision highp float;
in vec4 v_colour;
out vec4 outColour;
void main() {
  vec2 p = gl_PointCoord * 2.0 - 1.0;
  float r2 = dot(p,p);
  if (r2 > 1.0) discard;
  float edge = smoothstep(1.0, .72, r2);
  outColour = vec4(v_colour.rgb, v_colour.a * edge);
}`

const LINE_FRAGMENT_SHADER = `#version 300 es
precision highp float;
in vec4 v_colour;
out vec4 outColour;
void main() { outColour = v_colour; }
`

function truncateLabel(value: string) {
  return value.length <= 36 ? value : `${value.slice(0, 33)}…`
}

export function WebGLMemoryGraph({
  mode,
  graph,
  visibleKinds,
  search,
  selectedId,
  settings,
  reheatToken = 0,
  onSelect,
}: Props) {
  const hostRef = useRef<HTMLDivElement | null>(null)
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const labelsRef = useRef<HTMLCanvasElement | null>(null)
  const nodesRef = useRef<SimNode[]>([])
  const edgesRef = useRef<MemoryRelationship[]>([])
  const frameRef = useRef<number | null>(null)
  const lastPointerMoveRef = useRef(0)
  const hoverDebounceRef = useRef<number | null>(null)
  const pendingHoverIdRef = useRef<string | null>(null)
  const dragRef = useRef<{ x: number; y: number; panX: number; panY: number; yaw: number; pitch: number; node: SimNode | null; moved: number; unfocused: boolean } | null>(null)
  const viewRef = useRef<ViewState>({ x: 0, y: 0, zoom: 0.7, yaw: -0.5, pitch: 0.28, camera: 1700 })
  const [hoveredId, setHoveredId] = useState<string | null>(null)
  const [autoOrbit, setAutoOrbit] = useState(false)
  const [viewRevision, setViewRevision] = useState(0)
  const [webglError, setWebglError] = useState<string | null>(null)

  const visibleNodeIds = useMemo(
    () => new Set(graph.nodes.filter(node => visibleKinds.has(node.kind)).map(node => node.id)),
    [graph.nodes, visibleKinds],
  )

  // Distinct from searchMatches.size > 0: a non-empty query with zero matches
  // must still be treated as "searching" (hide everything) rather than as
  // "not searching" (show everything) — searchMatches alone can't tell those
  // two states apart, since both produce an empty set.
  const searchActive = useMemo(() => search.trim().length > 0, [search])

  const searchMatches = useMemo(() => {
    const query = search.trim().toLowerCase()
    if (!query) return new Set<string>()
    return new Set(graph.nodes
      .filter(node => visibleNodeIds.has(node.id))
      .filter(node => node.id.toLowerCase().includes(query) || node.label.toLowerCase().includes(query))
      .map(node => node.id))
  }, [graph.nodes, search, visibleNodeIds])

  useEffect(() => {
    const degree = new Map<string, number>()
    for (const edge of graph.relationships) {
      degree.set(edge.source, (degree.get(edge.source) ?? 0) + 1)
      degree.set(edge.target, (degree.get(edge.target) ?? 0) + 1)
    }

    // Global Vogel/Fibonacci golden-angle spiral: node i sits at radius
    // SPAWN_SPACING * sqrt(i), angle i * golden-angle. This keeps spawn
    // density constant regardless of node count (no per-kind anchors, no
    // hard radius cap) and starting positions already trace a rough ring,
    // which the link+repel+centre physics below then relaxes into a real
    // topology-driven layout rather than fighting an artificial grouping.
    const golden = Math.PI * (3 - Math.sqrt(5))

    const previous = new Map(nodesRef.current.map(node => [node.id, node]))
    let spawnIndex = 0
    nodesRef.current = graph.nodes.map(node => {
      const existing = previous.get(node.id)
      if (existing) return {
        ...existing,
        ...node,
        degree: degree.get(node.id) ?? 0,
        radius: Math.min(3.1 + Math.sqrt(degree.get(node.id) ?? 0) * 0.72, 11),
      }
      const seed = hash(node.id)
      const i = spawnIndex
      spawnIndex += 1
      const radius = SPAWN_SPACING * Math.sqrt(i)
      const angle = i * golden + (random01(seed, 7) - 0.5) * 0.18
      return {
        ...node,
        x: Math.cos(angle) * radius,
        y: Math.sin(angle) * radius,
        z: (random01(seed, 19) - 0.5) * radius * 0.6,
        vx: 0,
        vy: 0,
        vz: 0,
        degree: degree.get(node.id) ?? 0,
        radius: Math.min(3.1 + Math.sqrt(degree.get(node.id) ?? 0) * 0.72, 11),
      }
    })
    edgesRef.current = graph.relationships
    setViewRevision(value => value + 1)
  }, [graph])

  useEffect(() => () => {
    if (hoverDebounceRef.current !== null) window.clearTimeout(hoverDebounceRef.current)
  }, [])

  useEffect(() => {
    for (const node of nodesRef.current) {
      const seed = hash(`${node.id}:${reheatToken}`)
      node.vx += (random01(seed, 31) - 0.5) * 1.1
      node.vy += (random01(seed, 37) - 0.5) * 1.1
      node.vz += (random01(seed, 41) - 0.5) * 0.8
    }
  }, [reheatToken, settings, visibleKinds])

  useEffect(() => {
    const hostCandidate = hostRef.current
    const canvasCandidate = canvasRef.current
    const labelsCandidate = labelsRef.current
    if (!hostCandidate || !canvasCandidate || !labelsCandidate) return

    // Copy the narrowed DOM references into explicitly non-null locals before
    // creating any callbacks. TypeScript does not preserve ref/null narrowing
    // across delayed closures such as ResizeObserver/requestAnimationFrame.
    const host: HTMLDivElement = hostCandidate
    const canvas: HTMLCanvasElement = canvasCandidate
    const labels: HTMLCanvasElement = labelsCandidate
    const glCandidate = canvas.getContext('webgl2', { antialias: false, alpha: true, powerPreference: 'high-performance' })
    const labelContextCandidate = labels.getContext('2d')
    if (!glCandidate || !labelContextCandidate) {
      setWebglError('WebGL2 is unavailable in this browser/GPU configuration.')
      return
    }
    const gl: WebGL2RenderingContext = glCandidate
    const labelContext: CanvasRenderingContext2D = labelContextCandidate
    setWebglError(null)

    let pointProgram: WebGLProgram
    let lineProgram: WebGLProgram
    try {
      pointProgram = createProgram(gl, VERTEX_SHADER, POINT_FRAGMENT_SHADER)
      lineProgram = createProgram(gl, VERTEX_SHADER, LINE_FRAGMENT_SHADER)
    } catch (error) {
      setWebglError(error instanceof Error ? error.message : String(error))
      return
    }

    const pointPosition = gl.createBuffer()
    const pointColour = gl.createBuffer()
    const pointSize = gl.createBuffer()
    const linePosition = gl.createBuffer()
    const lineColour = gl.createBuffer()
    if (!pointPosition || !pointColour || !pointSize || !linePosition || !lineColour) {
      setWebglError('WebGL buffer allocation failed.')
      return
    }

    gl.enable(gl.BLEND)
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA)

    function resize() {
      const rect = host.getBoundingClientRect()
      const dpr = Math.min(window.devicePixelRatio || 1, 1.5)
      for (const target of [canvas, labels]) {
        target.width = Math.max(1, Math.floor(rect.width * dpr))
        target.height = Math.max(1, Math.floor(rect.height * dpr))
        target.style.width = `${rect.width}px`
        target.style.height = `${rect.height}px`
      }
      gl.viewport(0, 0, canvas.width, canvas.height)
    }

    function useCommonUniforms(program: WebGLProgram) {
      const view = viewRef.current
      gl.useProgram(program)
      gl.uniform2f(gl.getUniformLocation(program, 'u_resolution'), canvas.width, canvas.height)
      gl.uniform2f(gl.getUniformLocation(program, 'u_pan'), view.x * (canvas.width / Math.max(canvas.clientWidth, 1)), view.y * (canvas.height / Math.max(canvas.clientHeight, 1)))
      gl.uniform1f(gl.getUniformLocation(program, 'u_zoom'), view.zoom * (canvas.width / Math.max(canvas.clientWidth, 1)))
      gl.uniform1f(gl.getUniformLocation(program, 'u_mode3d'), mode === '3d' ? 1 : 0)
      gl.uniform1f(gl.getUniformLocation(program, 'u_yaw'), view.yaw)
      gl.uniform1f(gl.getUniformLocation(program, 'u_pitch'), view.pitch)
      gl.uniform1f(gl.getUniformLocation(program, 'u_camera'), view.camera)
    }

    function bindAttribute(program: WebGLProgram, name: string, buffer: WebGLBuffer, size: number) {
      const location = gl.getAttribLocation(program, name)
      if (location < 0) return
      gl.bindBuffer(gl.ARRAY_BUFFER, buffer)
      gl.enableVertexAttribArray(location)
      gl.vertexAttribPointer(location, size, gl.FLOAT, false, 0, 0)
    }

    let settledFrames = 0
    let lastSimulation = performance.now()
    let lastRender = 0

    function simulate(now: number) {
      if (now - lastSimulation < 32) return
      const dt = Math.min((now - lastSimulation) / 1000, 0.05)
      lastSimulation = now
      const nodes = nodesRef.current.filter(node => visibleNodeIds.has(node.id))
      if (nodes.length === 0 || settledFrames > 180) return
      const index = new Map(nodes.map(node => [node.id, node]))
      const edges = edgesRef.current.filter(edge => index.has(edge.source) && index.has(edge.target) && edge.effective_strength >= settings.relationshipStrengthMin)
      const speed = dt * 60
      const damping = Math.pow(0.80, speed)

      for (const edge of edges) {
        const a = index.get(edge.source)!
        const b = index.get(edge.target)!
        const dx = b.x - a.x
        const dy = b.y - a.y
        const dz = mode === '3d' ? b.z - a.z : 0
        const distance = Math.max(Math.hypot(dx, dy, dz), 1)
        const desired = settings.linkDistance + (100 - edge.effective_strength) * 0.20
        const weight = (0.30 + edge.effective_strength / 70) * settings.linkForce
        const force = (distance - desired) * weight * 0.00010 * speed
        a.vx += dx / distance * force; a.vy += dy / distance * force
        b.vx -= dx / distance * force; b.vy -= dy / distance * force
        if (mode === '3d') { a.vz += dz / distance * force; b.vz -= dz / distance * force }
      }

      const samples = nodes.length > 12000 ? 5 : nodes.length > 6000 ? 8 : 14
      for (let i = 0; i < nodes.length; i += 1) {
        const a = nodes[i]
        for (let sample = 1; sample <= samples; sample += 1) {
          const b = nodes[(i + sample * 131) % nodes.length]
          if (a === b) continue
          let dx = a.x - b.x, dy = a.y - b.y, dz = mode === '3d' ? a.z - b.z : 0
          let distanceSq = dx * dx + dy * dy + dz * dz
          if (distanceSq < 9) { dx = 3; dy = 0; dz = 0; distanceSq = 9 }
          const distance = Math.sqrt(distanceSq)
          const force = Math.min(0.9, settings.repelForce * 1900 / distanceSq) * 0.016 * speed
          a.vx += dx / distance * force; a.vy += dy / distance * force
          if (mode === '3d') a.vz += dz / distance * force
        }
        a.vx += -a.x * settings.centreForce * 0.000006 * speed
        a.vy += -a.y * settings.centreForce * 0.000006 * speed
        if (mode === '3d') a.vz += -a.z * settings.centreForce * 0.000004 * speed
      }

      let movement = 0
      for (const node of nodes) {
        if (dragRef.current?.node === node) continue
        const speedSq = node.vx * node.vx + node.vy * node.vy + node.vz * node.vz
        if (speedSq > MAX_NODE_SPEED * MAX_NODE_SPEED) {
          const scale = MAX_NODE_SPEED / Math.sqrt(speedSq)
          node.vx *= scale; node.vy *= scale; node.vz *= scale
        }
        node.vx *= damping; node.vy *= damping; node.vz *= damping
        node.x += node.vx * speed; node.y += node.vy * speed
        if (mode === '3d') node.z += node.vz * speed
        movement += Math.abs(node.vx) + Math.abs(node.vy) + Math.abs(node.vz) * 0.4
      }
      settledFrames = movement < 0.04 * nodes.length ? settledFrames + 1 : 0
    }

    function project(node: SimNode) {
      const rect = canvas.getBoundingClientRect()
      const view = viewRef.current
      if (mode === '2d') {
        return { x: rect.width / 2 + view.x + node.x * view.zoom, y: rect.height / 2 + view.y + node.y * view.zoom, scale: view.zoom, depth: 0 }
      }
      const cy = Math.cos(view.yaw), sy = Math.sin(view.yaw)
      const cp = Math.cos(view.pitch), sp = Math.sin(view.pitch)
      const rx = cy * node.x + sy * node.z
      const rz0 = -sy * node.x + cy * node.z
      const ry = cp * node.y - sp * rz0
      const rz = sp * node.y + cp * rz0
      const depth = Math.max(180, view.camera - rz)
      const perspective = view.camera / depth
      return {
        x: rect.width / 2 + view.x + rx * view.zoom * perspective,
        y: rect.height / 2 + view.y + ry * view.zoom * perspective,
        scale: view.zoom * perspective,
        depth: rz,
      }
    }

    function trackSelectedNode() {
      if (!selectedId) return
      const drag = dragRef.current
      if (drag && !drag.node) return
      const node = nodesRef.current.find(item => item.id === selectedId)
      if (!node || !visibleNodeIds.has(node.id)) return

      const view = viewRef.current
      let targetX: number
      let targetY: number
      if (mode === '3d') {
        const cy = Math.cos(view.yaw), sy = Math.sin(view.yaw)
        const cp = Math.cos(view.pitch), sp = Math.sin(view.pitch)
        const rx = cy * node.x + sy * node.z
        const rz0 = -sy * node.x + cy * node.z
        const ry = cp * node.y - sp * rz0
        const rz = sp * node.y + cp * rz0
        const depth = Math.max(180, view.camera - rz)
        const perspective = view.camera / depth
        targetX = -rx * view.zoom * perspective
        targetY = -ry * view.zoom * perspective
      } else {
        targetX = -node.x * view.zoom
        targetY = -node.y * view.zoom
      }

      // Follow rather than snap, so a moving/dragged selected node remains readable
      // without making the camera feel rigid.
      const follow = 0.22
      view.x += (targetX - view.x) * follow
      view.y += (targetY - view.y) * follow
    }

    function render() {
      trackSelectedNode()
      const rect = canvas.getBoundingClientRect()
      const dpr = canvas.width / Math.max(rect.width, 1)
      // A search query that matches nothing hides the whole graph rather than
      // falling back to "no search" and showing everything — see searchActive.
      const nodes = searchActive && searchMatches.size === 0
        ? []
        : nodesRef.current.filter(node => visibleNodeIds.has(node.id))
      const index = new Map(nodes.map(node => [node.id, node]))
      const activeId = hoveredId ?? selectedId
      const hasSearch = searchMatches.size > 0
      const adaptiveFloor = activeId || hasSearch
        ? settings.relationshipStrengthMin
        : nodes.length > 12000 && viewRef.current.zoom < 0.75
          ? Math.max(settings.relationshipStrengthMin, 48)
          : nodes.length > 7000 && viewRef.current.zoom < 1.0
            ? Math.max(settings.relationshipStrengthMin, 26)
            : settings.relationshipStrengthMin
      const edges = edgesRef.current.filter(edge => index.has(edge.source) && index.has(edge.target) && edge.effective_strength >= adaptiveFloor)

      const nowSeconds = Date.now() / 1000
      const nodePositions = new Float32Array(nodes.length * 3)
      const nodeColours = new Float32Array(nodes.length * 4)
      const nodeSizes = new Float32Array(nodes.length)
      for (let i = 0; i < nodes.length; i += 1) {
        const node = nodes[i]
        const selected = node.id === selectedId
        const hovered = node.id === hoveredId
        const match = hasSearch && searchMatches.has(node.id)
        const [r, g, b] = nodeColour(node.kind)
        const ttlAlpha = lifetimeOpacity(node.retention, node.created_at, node.expires_at, nowSeconds)
        let alpha = node.state === 'expired' || node.state === 'revoked' || node.state === 'superseded' ? 0.18 : 0.92
        if (hasSearch && !match) alpha *= 0.24
        if (activeId && node.id !== activeId) alpha *= 0.72
        if (selected || hovered || match) alpha = 1
        alpha *= selected || hovered ? Math.max(0.22, ttlAlpha) : ttlAlpha
        nodePositions.set([node.x, node.y, mode === '3d' ? node.z : 0], i * 3)
        nodeColours.set([selected || hovered ? 1 : r, selected || hovered ? 1 : g, selected || hovered ? 1 : b, alpha], i * 4)
        nodeSizes[i] = (selected ? node.radius + 5 : hovered ? node.radius + 3 : node.radius) * settings.nodeScale * 2.0
      }

      const linePositions = new Float32Array(edges.length * 6)
      const lineColours = new Float32Array(edges.length * 8)
      let lineOffset = 0
      for (const edge of edges) {
        const a = index.get(edge.source)!, b = index.get(edge.target)!
        const [r, g, bl] = strengthColour(edge.effective_strength)
        const ttlAlpha = lifetimeOpacity(edge.retention, edge.created_at, edge.expires_at, nowSeconds)
        let alpha = 0.055 + edge.confidence / 100 * 0.20
        if (activeId) alpha = edge.source === activeId || edge.target === activeId ? Math.max(alpha, 0.72) : alpha * 0.12
        if (hasSearch) alpha = searchMatches.has(edge.source) || searchMatches.has(edge.target) ? Math.max(alpha, 0.48) : alpha * 0.10
        alpha *= Math.max(0.55, ttlAlpha)
        linePositions.set([a.x, a.y, mode === '3d' ? a.z : 0, b.x, b.y, mode === '3d' ? b.z : 0], lineOffset * 6)
        lineColours.set([r, g, bl, alpha, r, g, bl, alpha], lineOffset * 8)
        lineOffset += 1
      }

      gl.clearColor(0, 0, 0, 0)
      gl.clear(gl.COLOR_BUFFER_BIT)

      useCommonUniforms(lineProgram)
      gl.bindBuffer(gl.ARRAY_BUFFER, linePosition); gl.bufferData(gl.ARRAY_BUFFER, linePositions, gl.DYNAMIC_DRAW)
      gl.bindBuffer(gl.ARRAY_BUFFER, lineColour); gl.bufferData(gl.ARRAY_BUFFER, lineColours, gl.DYNAMIC_DRAW)
      bindAttribute(lineProgram, 'a_position', linePosition, 3)
      bindAttribute(lineProgram, 'a_colour', lineColour, 4)
      gl.disableVertexAttribArray(gl.getAttribLocation(lineProgram, 'a_size'))
      gl.vertexAttrib1f(gl.getAttribLocation(lineProgram, 'a_size'), 1)
      gl.drawArrays(gl.LINES, 0, edges.length * 2)

      useCommonUniforms(pointProgram)
      gl.bindBuffer(gl.ARRAY_BUFFER, pointPosition); gl.bufferData(gl.ARRAY_BUFFER, nodePositions, gl.DYNAMIC_DRAW)
      gl.bindBuffer(gl.ARRAY_BUFFER, pointColour); gl.bufferData(gl.ARRAY_BUFFER, nodeColours, gl.DYNAMIC_DRAW)
      gl.bindBuffer(gl.ARRAY_BUFFER, pointSize); gl.bufferData(gl.ARRAY_BUFFER, nodeSizes, gl.DYNAMIC_DRAW)
      bindAttribute(pointProgram, 'a_position', pointPosition, 3)
      bindAttribute(pointProgram, 'a_colour', pointColour, 4)
      bindAttribute(pointProgram, 'a_size', pointSize, 1)
      gl.drawArrays(gl.POINTS, 0, nodes.length)

      labelContext.setTransform(dpr, 0, 0, dpr, 0, 0)
      labelContext.clearRect(0, 0, rect.width, rect.height)
      const candidates = nodes
        .filter(node => node.id === selectedId || node.id === hoveredId || searchMatches.has(node.id) || (viewRef.current.zoom >= settings.labelThreshold && node.degree >= 4))
        .sort((a, b) => b.degree - a.degree)
        .slice(0, hasSearch ? 180 : 90)
      labelContext.font = '12px ui-monospace, SFMono-Regular, Consolas, monospace'
      labelContext.textAlign = 'center'
      labelContext.textBaseline = 'top'
      for (const node of candidates) {
        const p = project(node)
        if (p.x < -40 || p.y < -40 || p.x > rect.width + 40 || p.y > rect.height + 40) continue
        const ttlAlpha = lifetimeOpacity(node.retention, node.created_at, node.expires_at, nowSeconds)
        labelContext.globalAlpha = (node.id === selectedId || node.id === hoveredId || searchMatches.has(node.id) ? 1 : 0.68) * Math.max(0.42, ttlAlpha)
        labelContext.fillStyle = '#ffffff'
        labelContext.fillText(truncateLabel(node.label), p.x, p.y + Math.max(7, node.radius * p.scale) + 5)
      }
      labelContext.globalAlpha = 1
    }

    function loop(now: number) {
      if (autoOrbit && mode === '3d' && !dragRef.current) viewRef.current.yaw += 0.00025 * Math.min(40, now - lastRender)
      simulate(now)
      const targetInterval = settledFrames > 180 && !autoOrbit && !dragRef.current ? 180 : 33
      if (now - lastRender >= targetInterval) {
        render(); lastRender = now
      }
      frameRef.current = requestAnimationFrame(loop)
    }

    resize()
    const observer = new ResizeObserver(resize)
    observer.observe(host)
    frameRef.current = requestAnimationFrame(loop)
    return () => {
      observer.disconnect()
      if (frameRef.current) cancelAnimationFrame(frameRef.current)
      gl.deleteProgram(pointProgram); gl.deleteProgram(lineProgram)
      gl.deleteBuffer(pointPosition); gl.deleteBuffer(pointColour); gl.deleteBuffer(pointSize); gl.deleteBuffer(linePosition); gl.deleteBuffer(lineColour)
    }
  }, [mode, visibleNodeIds, searchActive, searchMatches, selectedId, hoveredId, settings, autoOrbit, viewRevision])

  function projectForHit(node: SimNode) {
    const canvas = canvasRef.current
    if (!canvas) return { x: 0, y: 0, scale: 1, depth: 0 }
    const rect = canvas.getBoundingClientRect()
    const view = viewRef.current
    if (mode === '2d') return { x: rect.width / 2 + view.x + node.x * view.zoom, y: rect.height / 2 + view.y + node.y * view.zoom, scale: view.zoom, depth: 0 }
    const cy = Math.cos(view.yaw), sy = Math.sin(view.yaw), cp = Math.cos(view.pitch), sp = Math.sin(view.pitch)
    const rx = cy * node.x + sy * node.z
    const rz0 = -sy * node.x + cy * node.z
    const ry = cp * node.y - sp * rz0
    const rz = sp * node.y + cp * rz0
    const depth = Math.max(180, view.camera - rz)
    const perspective = view.camera / depth
    return { x: rect.width / 2 + view.x + rx * view.zoom * perspective, y: rect.height / 2 + view.y + ry * view.zoom * perspective, scale: view.zoom * perspective, depth: rz }
  }

  function hitNode(clientX: number, clientY: number) {
    const canvas = canvasRef.current
    if (!canvas) return null
    const rect = canvas.getBoundingClientRect()
    const x = clientX - rect.left, y = clientY - rect.top
    let best: SimNode | null = null
    let bestDistance = Infinity
    let bestDepth = -Infinity
    if (searchActive && searchMatches.size === 0) return null
    for (const node of nodesRef.current) {
      if (!visibleNodeIds.has(node.id)) continue
      const p = projectForHit(node)
      const distance = Math.hypot(x - p.x, y - p.y)
      const hitRadius = Math.max(6, node.radius * settings.nodeScale * p.scale + 4)
      if (distance <= hitRadius && (distance < bestDistance || (mode === '3d' && p.depth > bestDepth))) {
        best = node; bestDistance = distance; bestDepth = p.depth
      }
    }
    return best
  }

  function fitView() {
    const canvas = canvasRef.current
    if (!canvas) return
    const nodes = nodesRef.current.filter(node => visibleNodeIds.has(node.id))
    if (nodes.length === 0) return
    if (mode === '3d') {
      viewRef.current = { ...viewRef.current, x: 0, y: 0, zoom: 0.78, yaw: -0.55, pitch: 0.30, camera: 1900 }
    } else {
      let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity
      for (const node of nodes) { minX = Math.min(minX, node.x); minY = Math.min(minY, node.y); maxX = Math.max(maxX, node.x); maxY = Math.max(maxY, node.y) }
      const rect = canvas.getBoundingClientRect()
      const scale = Math.min((rect.width - 100) / Math.max(maxX - minX, 100), (rect.height - 100) / Math.max(maxY - minY, 100))
      viewRef.current = { ...viewRef.current, zoom: Math.max(0.08, Math.min(2.5, scale)), x: -((minX + maxX) / 2) * scale, y: -((minY + maxY) / 2) * scale }
    }
    setViewRevision(value => value + 1)
  }

  function focusSelected() {
    const node = nodesRef.current.find(item => item.id === selectedId)
    if (!node) return
    const zoom = Math.max(viewRef.current.zoom, 1.4)
    viewRef.current.zoom = zoom
    if (mode === '2d') {
      viewRef.current.x = -node.x * zoom
      viewRef.current.y = -node.y * zoom
    }
    setViewRevision(value => value + 1)
  }

  return (
    <div className={`force-graph-host webgl-graph webgl-graph--${mode}`} ref={hostRef}>
      <canvas
        ref={canvasRef}
        className="webgl-graph-canvas"
        onContextMenu={event => event.preventDefault()}
        onPointerDown={event => {
          event.currentTarget.setPointerCapture(event.pointerId)
          // Capture the node under the pointer at press time. The simulation and
          // selected-node camera follow can move it before pointer-up, so re-hit-testing
          // on release would make a normal click intermittently clear the selection.
          const node = hitNode(event.clientX, event.clientY)
          dragRef.current = {
            x: event.clientX, y: event.clientY,
            panX: viewRef.current.x, panY: viewRef.current.y,
            yaw: viewRef.current.yaw, pitch: viewRef.current.pitch,
            node, moved: 0, unfocused: false,
          }
        }}
        onPointerMove={event => {
          const drag = dragRef.current
          if (drag) {
            const dx = event.clientX - drag.x, dy = event.clientY - drag.y
            drag.moved = Math.abs(dx) + Math.abs(dy)
            // A real drag (not just a click) that didn't start on the currently
            // focused node — including starting on empty space or a different
            // node — unfocuses it. Dragging the focused node itself (to move it,
            // in 2D mode) must never unfocus it.
            if (!drag.unfocused && drag.moved >= 5 && selectedId && drag.node?.id !== selectedId) {
              drag.unfocused = true
              onSelect(null)
            }
            if (drag.node && mode === '2d') {
              drag.node.x += dx / Math.max(viewRef.current.zoom, 0.05)
              drag.node.y += dy / Math.max(viewRef.current.zoom, 0.05)
              drag.x = event.clientX; drag.y = event.clientY
              drag.node.vx = 0; drag.node.vy = 0
            } else if (mode === '3d') {
              viewRef.current.yaw = drag.yaw + dx * 0.006
              // Inverted from a raw dy mapping: dragging down should tilt the
              // view toward the viewer (as if pulling it down), not away.
              viewRef.current.pitch = Math.max(-1.35, Math.min(1.35, drag.pitch - dy * 0.006))
            } else {
              viewRef.current.x = drag.panX + dx
              viewRef.current.y = drag.panY + dy
            }
            return
          }
          const now = performance.now()
          if (now - lastPointerMoveRef.current < 75) return
          lastPointerMoveRef.current = now
          const nextHoverId = hitNode(event.clientX, event.clientY)?.id ?? null
          // Sample the hit test at the 75ms rate above, but only *commit* it
          // (setHoveredId, which re-dims every other node) after a short
          // settle delay. Sweeping the cursor across the canvas otherwise
          // commits a new hoveredId on nearly every sampled move, and the
          // whole-graph dim/highlight repaint that follows reads as the
          // entire graph flashing.
          if (nextHoverId === pendingHoverIdRef.current) return
          pendingHoverIdRef.current = nextHoverId
          if (hoverDebounceRef.current !== null) window.clearTimeout(hoverDebounceRef.current)
          hoverDebounceRef.current = window.setTimeout(() => {
            hoverDebounceRef.current = null
            setHoveredId(pendingHoverIdRef.current)
          }, 150)
        }}
        onPointerUp={event => {
          const drag = dragRef.current
          if (drag && drag.moved < 5) {
            // Prefer the press-time hit so moving nodes remain clickable. Only fall
            // back to a release-time hit when the press started on empty graph space.
            const hit = drag.node ?? hitNode(event.clientX, event.clientY)
            onSelect(hit ?? null)
          }
          dragRef.current = null
        }}
        onPointerLeave={() => {
          dragRef.current = null
          if (hoverDebounceRef.current !== null) {
            window.clearTimeout(hoverDebounceRef.current)
            hoverDebounceRef.current = null
          }
          pendingHoverIdRef.current = null
          setHoveredId(null)
        }}
        onWheel={event => {
          event.preventDefault()
          event.stopPropagation()
          const factor = Math.exp(-event.deltaY * 0.0014)
          viewRef.current.zoom = Math.max(0.05, Math.min(8, viewRef.current.zoom * factor))
          setViewRevision(value => value + 1)
        }}
        onDoubleClick={() => fitView()}
      />
      <canvas ref={labelsRef} className="webgl-graph-labels" />
      {webglError && <div className="graph-webgl-error">{webglError}</div>}
      <div className="graph-hud graph-hud--top">
        <span className="graph-renderer-badge">WEBGL2</span>
        {mode === '3d' && <button className={autoOrbit ? 'active' : ''} onClick={() => setAutoOrbit(value => !value)}>Orbit</button>}
        <button onClick={() => { viewRef.current.zoom *= 1.2; setViewRevision(value => value + 1) }}>+</button>
        <button onClick={() => { viewRef.current.zoom /= 1.2; setViewRevision(value => value + 1) }}>−</button>
        <button onClick={fitView}>Fit</button>
        {selectedId && <button onClick={focusSelected}>Focus</button>}
      </div>
    </div>
  )
}