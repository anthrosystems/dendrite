interface Props {
  label: string
  value: string | number
  detail?: string
}

export function MetricCard({ label, value, detail }: Props) {
  return (
    <article className="metric-card">
      <span className="eyebrow">{label}</span>
      <strong>{value}</strong>
      {detail && <span className="metric-detail">{detail}</span>}
    </article>
  )
}
