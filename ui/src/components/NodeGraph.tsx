interface Props {
  centre: string
  neighbours: string[]
  onSelect?: (id: string) => void
}

function short(value: string) {
  if (value.length <= 28) return value
  return `${value.slice(0, 13)}…${value.slice(-12)}`
}

function kind(value: string) {
  return value.split(':', 1)[0] || 'node'
}

export function NodeGraph({ centre, neighbours, onSelect }: Props) {
  const cx = 360
  const cy = 230
  const count = Math.max(neighbours.length, 1)
  const ring = neighbours.length > 8 ? 165 : 145

  return (
    <div className="graph-canvas">
      <svg viewBox="0 0 720 460" role="img" aria-label={`Neighbours of ${centre}`}>
        <defs>
          <radialGradient id="graphGlow">
            <stop offset="0%" stopColor="currentColor" stopOpacity=".16" />
            <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
          </radialGradient>
        </defs>

        <circle cx={cx} cy={cy} r="190" className="graph-orbit" />

        {neighbours.map((node, index) => {
          const angle = (Math.PI * 2 * index) / count - Math.PI / 2
          const x = cx + Math.cos(angle) * ring
          const y = cy + Math.sin(angle) * ring
          return (
            <g key={node}>
              <line x1={cx} y1={cy} x2={x} y2={y} className="graph-edge" />
              <g
                className={`graph-node graph-node--neighbour graph-node--${kind(node)}`}
                onClick={() => onSelect?.(node)}
              >
                <circle cx={x} cy={y} r="21" className="graph-node-halo" />
                <circle cx={x} cy={y} r="8" className="graph-node-core" />
                <text x={x} y={y + 37} textAnchor="middle">{short(node)}</text>
              </g>
            </g>
          )
        })}

        <g className={`graph-node graph-node--centre graph-node--${kind(centre)}`}>
          <circle cx={cx} cy={cy} r="42" className="graph-centre-halo" />
          <circle cx={cx} cy={cy} r="13" className="graph-node-core" />
          <text x={cx} y={cy + 58} textAnchor="middle">{short(centre)}</text>
        </g>
      </svg>
    </div>
  )
}
