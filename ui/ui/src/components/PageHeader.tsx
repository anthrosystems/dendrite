import type { ReactNode } from 'react'
import { Icons } from './Icons'

interface Props {
  eyebrow: string
  title: string
  description?: string
  actions?: ReactNode
  onRefresh?: () => void
}

export function PageHeader({ eyebrow, title, description, actions, onRefresh }: Props) {
  return (
    <header className="page-titlebar">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      <div className="page-actions">
        {actions}
        {onRefresh && (
          <button className="icon-button" onClick={onRefresh} title="Refresh">
            <Icons.refresh />
          </button>
        )}
      </div>
    </header>
  )
}
