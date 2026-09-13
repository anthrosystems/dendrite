import { useCallback, useEffect, useState } from 'react'
import { api } from '../api/client'
import { Icons } from '../components/Icons'
import { StatusPill } from '../components/StatusPill'
import { usePolling } from '../hooks/usePolling'
import { Dashboard } from '../pages/Dashboard'
import { Investigations } from '../pages/Investigations'
import { Memory } from '../pages/Memory'
import { Analysis } from '../pages/Analysis'
import { Telemetry } from '../pages/Telemetry'
import { Actions } from '../pages/Actions'
import { HealthPage } from '../pages/Health'
import { Vulnerabilities } from '../pages/Vulnerabilities'
import { SystemMap } from '../pages/SystemMap'

type Page =
  | 'dashboard'
  | 'activity'
  | 'investigations'
  | 'vulnerabilities'
  | 'memory'
  | 'analysis'
  | 'system-map'
  | 'magi'
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
      { id: 'investigations', label: 'Investigations', icon: 'incidents' },
      { id: 'vulnerabilities', label: 'Vulnerabilities', icon: 'vulnerabilities' },
    ],
  },
  {
    label: 'Knowledge',
    items: [
      { id: 'memory', label: 'Memory Graph', icon: 'memory' },
      { id: 'analysis', label: 'Analysis', icon: 'chain' },
    ],
  },
  {
    label: 'System',
    items: [
      { id: 'system-map', label: 'System Map', icon: 'topology' },
      { id: 'magi', label: 'MAGI & Response', icon: 'magi' },
      { id: 'health', label: 'System Health', icon: 'health' },
    ],
  },
]

const allItems = groups.flatMap(group => group.items)

function pageFromHash(): Page {
  const value = window.location.hash.replace('#/', '')
  if (value === 'incidents' || value === 'threats' || value === 'chains') return 'investigations'
  return allItems.some(item => item.id === value) ? value as Page : 'dashboard'
}

export function App() {
  const [page, setPage] = useState<Page>(pageFromHash)
  const status = usePolling(useCallback(() => api.status(), []), 5000, 'status')
  const guard = usePolling(useCallback(() => api.guard(), []), 5000, 'guard')

  useEffect(() => {
    const listener = () => setPage(pageFromHash())
    window.addEventListener('hashchange', listener)
    return () => window.removeEventListener('hashchange', listener)
  }, [])

  const localState = status.data ? 'ready' : status.error ? 'error' : 'checking'
  const localCopy = status.data
    ? `dendrited ${status.data.version}`
    : status.error
      ? 'Local API unavailable'
      : 'Checking local API…'

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#/dashboard">
          <div className="brand-mark" aria-hidden="true"><span /><span /><span /><i /></div>
          <div><strong>DENDRITE</strong><small>Endpoint security</small></div>
        </a>

        <div className="nav-groups">
          {groups.map(group => (
            <section className="nav-group" key={group.label}>
              <span className="nav-group-label">{group.label}</span>
              <nav>
                {group.items.map(item => {
                  const Icon = Icons[item.icon]
                  return (
                    <a key={item.id} href={`#/${item.id}`} className={page === item.id ? 'active' : ''}>
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
            <span className={`node-indicator node-indicator--${localState}`} />
            <div><strong>Local node</strong><small>{localCopy}</small></div>
          </div>
          <div className="sidebar-trust"><span>Trust</span><StatusPill value={guard.data?.trust_state ?? 'unknown'} /></div>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div className="topbar-context">
            <span className={`live-dot live-dot--${localState}`} />
            <span>{localState === 'ready' ? 'Local API ready' : localState === 'error' ? 'Local API unavailable' : 'Checking local API'}</span>
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
          {page === 'investigations' && <Investigations />}
          {page === 'vulnerabilities' && <Vulnerabilities />}
          {page === 'memory' && <Memory />}
          {page === 'analysis' && <Analysis />}
          {page === 'system-map' && <SystemMap />}
          {page === 'magi' && <Actions />}
          {page === 'health' && <HealthPage />}
        </main>
      </section>
    </div>
  )
}
