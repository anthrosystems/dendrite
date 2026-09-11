import { useCallback, useEffect, useState } from 'react'
import { api } from '../api/client'
import { Icons } from '../components/Icons'
import { StatusPill } from '../components/StatusPill'
import { usePolling } from '../hooks/usePolling'
import { Dashboard } from '../pages/Dashboard'
import { Incidents } from '../pages/Incidents'
import { Memory } from '../pages/Memory'
import { Telemetry } from '../pages/Telemetry'
import { Actions } from '../pages/Actions'
import { GuardPage } from '../pages/Guard'
import { HealthPage } from '../pages/Health'
import { Threats } from '../pages/Threats'
import { AttackChains } from '../pages/AttackChains'
import { Topology } from '../pages/Topology'

type Page =
  | 'dashboard'
  | 'activity'
  | 'incidents'
  | 'threats'
  | 'chains'
  | 'memory'
  | 'topology'
  | 'magi'
  | 'self'
  | 'health'

type NavItem = {
  id: Page
  label: string
  icon: keyof typeof Icons
}

const groups: Array<{ label: string; items: NavItem[] }> = [
  {
    label: 'Operations',
    items: [
      { id: 'dashboard', label: 'Overview', icon: 'overview' },
      { id: 'activity', label: 'Activity', icon: 'activity' },
      { id: 'incidents', label: 'Incidents', icon: 'incidents' },
      { id: 'threats', label: 'Threats', icon: 'threats' },
      { id: 'chains', label: 'Attack Chains', icon: 'chain' },
    ],
  },
  {
    label: 'Knowledge',
    items: [
      { id: 'memory', label: 'Memory Graph', icon: 'memory' },
      { id: 'topology', label: 'Relationships', icon: 'topology' },
    ],
  },
  {
    label: 'Authority',
    items: [
      { id: 'magi', label: 'MAGI & Response', icon: 'magi' },
      { id: 'self', label: 'Self & Trust', icon: 'self' },
      { id: 'health', label: 'System Health', icon: 'health' },
    ],
  },
]

const allItems = groups.flatMap(group => group.items)

function pageFromHash(): Page {
  const value = window.location.hash.replace('#/', '')
  return allItems.some(item => item.id === value) ? value as Page : 'dashboard'
}

export function App() {
  const [page, setPage] = useState<Page>(pageFromHash)
  const status = usePolling(useCallback(() => api.status(), []), 5000)
  const guard = usePolling(useCallback(() => api.guard(), []), 5000)

  useEffect(() => {
    const listener = () => setPage(pageFromHash())
    window.addEventListener('hashchange', listener)
    return () => window.removeEventListener('hashchange', listener)
  }, [])

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#/dashboard">
          <div className="brand-mark" aria-hidden="true">
            <span />
            <span />
            <span />
            <i />
          </div>
          <div>
            <strong>DENDRITE</strong>
            <small>endpoint security</small>
          </div>
        </a>

        <div className="nav-groups">
          {groups.map(group => (
            <section className="nav-group" key={group.label}>
              <span className="nav-group-label">{group.label}</span>
              <nav>
                {group.items.map(item => {
                  const Icon = Icons[item.icon]
                  return (
                    <a
                      key={item.id}
                      href={`#/${item.id}`}
                      className={page === item.id ? 'active' : ''}
                    >
                      <Icon />
                      <span>{item.label}</span>
                    </a>
                  )
                })}
              </nav>
            </section>
          ))}
        </div>

        <div className="sidebar-status">
          <div className="sidebar-status-row">
            <span className="node-indicator" />
            <div>
              <strong>Local node</strong>
              <small>{status.data ? `dendrited ${status.data.version}` : 'connecting…'}</small>
            </div>
          </div>
          <div className="sidebar-trust">
            <span>Trust</span>
            <StatusPill value={guard.data?.trust_state ?? 'unknown'} />
          </div>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div className="topbar-context">
            <span className="live-dot" />
            <span>Local protection</span>
          </div>
          <div className="topbar-meta">
            <span>{status.data?.observations_ingested ?? '—'} observations</span>
            <span>{status.data?.incidents_open ?? '—'} open incidents</span>
            <StatusPill value={guard.data?.authority ?? 'unknown'} />
          </div>
        </header>

        <main className="content">
          {page === 'dashboard' && <Dashboard />}
          {page === 'activity' && <Telemetry />}
          {page === 'incidents' && <Incidents />}
          {page === 'threats' && <Threats />}
          {page === 'chains' && <AttackChains />}
          {page === 'memory' && <Memory />}
          {page === 'topology' && <Topology />}
          {page === 'magi' && <Actions />}
          {page === 'self' && <GuardPage />}
          {page === 'health' && <HealthPage />}
        </main>
      </section>
    </div>
  )
}
