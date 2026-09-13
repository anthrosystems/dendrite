import { useCallback, useMemo, useState } from 'react'
import { api } from '../api/client'
import { Icons } from '../components/Icons'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'
import { usePolling } from '../hooks/usePolling'

function formatTime(value: number) {
  return new Date(value * 1000).toLocaleTimeString()
}

function readable(value: string) {
  const text = value.replaceAll('_', ' ')
  return text.length === 0 ? text : text[0].toUpperCase() + text.slice(1)
}


const telemetrySourceOrder = ['ebpf', 'fanotify', 'proc_polling', 'filesystem_polling']

function orderedSources<T extends { source: string }>(sources: T[]) {
  const rank = new Map(telemetrySourceOrder.map((source, index) => [source, index]))
  return [...sources].sort((left, right) => {
    const leftRank = rank.get(left.source) ?? Number.MAX_SAFE_INTEGER
    const rightRank = rank.get(right.source) ?? Number.MAX_SAFE_INTEGER
    return leftRank - rightRank || left.source.localeCompare(right.source)
  })
}

function sourceLabel(value: string) {
  switch (value) {
    case 'ebpf': return 'eBPF'
    case 'fanotify': return 'fanotify'
    case 'proc_polling': return '/proc polling'
    case 'filesystem_polling': return 'filesystem polling'
    default: return readable(value)
  }
}


function laneUtilisation(depth: number, capacity: number) {
  if (capacity <= 0) return 0
  return Math.min(100, Math.round((depth / capacity) * 100))
}

export function Telemetry() {
  const recent = usePolling(useCallback(() => api.telemetryRecent(120), []), 2000, 'telemetry-recent-120')
  const status = usePolling(useCallback(() => api.telemetryStatus(), []), 5000, 'telemetry-status')
  const [search, setSearch] = useState('')

  const filteredEvents = useMemo(() => {
    const events = recent.data ?? []
    const query = search.trim().toLowerCase()
    if (!query) return events
    return events.filter(event => [
      event.event, event.source, event.source_label, event.source_object,
      event.target_label, event.target_object, event.observation_kind, event.scope,
      event.process_id ? String(event.process_id) : '',
    ].some(field => (field ?? '').toLowerCase().includes(query)))
  }, [recent.data, search])

  return (
    <section className="page-stack">
      <PageHeader
        eyebrow="Linux telemetry"
        title="Activity"
        description="Normalised process and filesystem activity entering Dendrite's observation pipeline."
        onRefresh={() => {
          void recent.refresh()
          void status.refresh()
        }}
      />

      {(recent.error || status.error) && (
        <div className="error-banner">{recent.error ?? status.error}</div>
      )}

      <div className="sensor-strip">
        {orderedSources(status.data?.sources ?? []).map(source => (
          <article key={source.source}>
            <div>
              <span className={`sensor-dot sensor-dot--${source.status}`} />
              <strong>{sourceLabel(source.source)}</strong>
            </div>
            <StatusPill value={source.status} />
            <small>{source.detail}</small>
          </article>
        ))}
      </div>


      {status.data?.pipeline && (
        <article className="surface telemetry-pipeline-surface telemetry-pipeline-surface--lanes">
          <div className="surface-heading">
            <div>
              <span className="eyebrow">Ingestion Pipeline</span>
              <h2>{status.data.pipeline.queue_depth.toLocaleString()} / {status.data.pipeline.queue_capacity.toLocaleString()} queued</h2>
            </div>
            <span>
              Scheduler {status.data.pipeline.scheduler_priority_weight}:{status.data.pipeline.scheduler_routine_weight}
              {' '}priority:routine
            </span>
          </div>

          <div className="ingestion-lanes">
            {([
              ['Priority', status.data.pipeline.priority, 'high'],
              ['Routine', status.data.pipeline.routine, 'routine'],
            ] as const).map(([label, lane, tone]) => (
              <section className={`ingestion-lane ingestion-lane--${tone}`} key={label}>
                <div className="ingestion-lane-head">
                  <div><span>{label} lane</span><strong>{lane.queue_depth.toLocaleString()} / {lane.queue_capacity.toLocaleString()}</strong></div>
                  <b>{laneUtilisation(lane.queue_depth, lane.queue_capacity)}%</b>
                </div>
                <div className="ingestion-lane-meter" aria-hidden="true">
                  <i style={{ width: `${laneUtilisation(lane.queue_depth, lane.queue_capacity)}%` }} />
                </div>
                <div className="ingestion-lane-stats">
                  <div><span>Received</span><strong>{lane.events_received.toLocaleString()}</strong></div>
                  <div><span>Processed</span><strong>{lane.events_processed.toLocaleString()}</strong></div>
                  <div><span>Dropped</span><strong>{lane.events_dropped.toLocaleString()}</strong></div>
                  <div><span>Peak</span><strong>{lane.peak_queue_depth.toLocaleString()}</strong></div>
                  <div><span>Last wait</span><strong>{lane.last_queue_wait_ms} ms</strong></div>
                  <div><span>Max wait</span><strong>{lane.max_queue_wait_ms} ms</strong></div>
                  <div><span>Last processing</span><strong>{lane.last_processing_ms} ms</strong></div>
                  <div><span>Max processing</span><strong>{lane.max_processing_ms} ms</strong></div>
                </div>
              </section>
            ))}
          </div>

          <div className="telemetry-pipeline-grid telemetry-pipeline-grid--combined">
            <div><span>Total received</span><strong>{status.data.pipeline.events_received.toLocaleString()}</strong></div>
            <div><span>Total processed</span><strong>{status.data.pipeline.events_processed.toLocaleString()}</strong></div>
            <div><span>Total dropped</span><strong>{status.data.pipeline.events_dropped.toLocaleString()}</strong></div>
            <div><span>Peak combined queue</span><strong>{status.data.pipeline.peak_queue_depth.toLocaleString()}</strong></div>
            <div><span>Security observations</span><strong>{status.data.pipeline.security_observations_ingested.toLocaleString()}</strong></div>
            <div><span>Max combined wait</span><strong>{status.data.pipeline.max_queue_wait_ms} ms</strong></div>
          </div>
        </article>
      )}

      <article className="surface activity-surface">
        <div className="surface-heading">
          <div>
            <span className="eyebrow">Live Event Stream</span>
            <h2>{status.data?.recent_events ?? recent.data?.length ?? 0} Buffered events</h2>
          </div>
          <span>Newest first · Real daemon telemetry</span>
        </div>

        <div className="memory-search memory-search--panel">
          <Icons.search />
          <input
            value={search}
            onChange={event => setSearch(event.target.value)}
            placeholder="Search events"
          />
          {search && <button onClick={() => setSearch('')}>×</button>}
        </div>

        {(recent.data ?? []).length === 0 ? (
          <div className="empty-state">No telemetry events have been collected since this daemon started.</div>
        ) : filteredEvents.length === 0 ? (
          <div className="empty-state">No buffered events match "{search}".</div>
        ) : (
          <div className="activity-stream">
            {filteredEvents.map(event => (
              <article className="activity-event" key={event.id}>
                <div className="activity-time">
                  <span className={`activity-source-dot activity-source-dot--${event.source}`} />
                  <time>{formatTime(event.observed_at)}</time>
                </div>
                <div className="activity-event-body">
                  <div className="activity-event-title">
                    <strong>{readable(event.event)}</strong>
                    <StatusPill value={event.source} />
                    {event.process_id && <span className="pid-tag">PID {event.process_id}</span>}
                  </div>
                  <div className="activity-route">
                    <code>{event.source_label || event.source_object}</code>
                    <span>→</span>
                    <code>{event.target_label || event.target_object || '—'}</code>
                  </div>
                  <small>{event.source_object}{event.target_object ? ` → ${event.target_object}` : ''}</small>
                </div>
                <div className="activity-observation">
                  <span>{readable(event.observation_kind)}</span>
                  <span>{readable(event.scope)}</span>
                  {event.incident_ids.map(id => <a href="#/investigations" key={id}>{id}</a>)}
                </div>
              </article>
            ))}
          </div>
        )}
      </article>
    </section>
  )
}