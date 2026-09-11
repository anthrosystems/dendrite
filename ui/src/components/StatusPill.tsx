interface Props {
  value: string
}

export function StatusPill({ value }: Props) {
  const normalised = value.toLowerCase()
  const tone =
    ['ok', 'open', 'observed', 'active', 'available', 'allow', 'approved', 'completed', 'trusted', 'verified'].includes(normalised)
      ? 'good'
      : ['warning', 'warn', 'degraded', 'fallback', 'standby', 'pending', 'recovering', 'abstain'].includes(normalised)
        ? 'warn'
        : ['critical', 'high', 'error', 'removed', 'deny', 'denied', 'blocked', 'compromised', 'quarantined', 'suspected', 'not_authorised', 'failed'].includes(normalised)
          ? 'bad'
          : 'neutral'

  return <span className={`status-pill status-pill--${tone}`}>{value.replaceAll('_', ' ')}</span>
}
