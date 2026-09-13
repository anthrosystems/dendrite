import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { subscribeLive, type LiveEvent } from './live'

type CacheEntry = {
  data: unknown
  updatedAt: number
}

const cache = new Map<string, CacheEntry>()
const inflight = new Map<string, Promise<unknown>>()

function liveRefreshDelay(cacheKey: string, event: LiveEvent): number | null {
  if (event.kind === 'pipeline') {
    if (cacheKey === 'status' || cacheKey === 'health') return 1000
    return null
  }

  if (event.kind === 'control') {
    if (cacheKey === 'actions' || cacheKey === 'incidents' || cacheKey === 'guard' || cacheKey === 'guard-findings' || cacheKey === 'status' || cacheKey === 'health') return 100
    return null
  }

  if (event.kind === 'incidents') {
    if (cacheKey === 'incidents' || cacheKey === 'actions') return 150
    if (cacheKey.startsWith('memory-graph-') || cacheKey === 'memory-threats') return 1500
    if (cacheKey === 'status') return 500
    return null
  }

  if (event.kind === 'telemetry') {
    if (cacheKey === 'status' || cacheKey === 'health') return 1000
    if (cacheKey.startsWith('memory-graph-')) return null
    return null
  }

  return null
}

function applyLivePayload<T>(cacheKey: string, current: T | null, event: LiveEvent): T | null {
  if (event.kind === 'telemetry' && cacheKey.startsWith('telemetry-recent-')) {
    const limit = Number(cacheKey.split('-').at(-1) ?? '100')
    const rows = Array.isArray(current) ? current : []
    const payload = event.payload as { id?: string }
    const next = [payload, ...rows.filter(row => (row as { id?: string }).id !== payload.id)].slice(
      0,
      Number.isFinite(limit) ? limit : 100,
    )
    return next as unknown as T
  }

  if (event.kind === 'pipeline' && cacheKey === 'telemetry-status' && current && typeof current === 'object') {
    return { ...(current as object), pipeline: event.payload } as unknown as T
  }

  return current
}

export function usePolling<T>(
  load: () => Promise<T>,
  intervalMs = 15000,
  cacheKey?: string,
) {
  const stableKey = useMemo(() => cacheKey ?? load.toString(), [cacheKey, load])
  const cached = cache.get(stableKey)
  const [data, setData] = useState<T | null>(() => (cached?.data as T | undefined) ?? null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(() => cached === undefined)
  const [refreshing, setRefreshing] = useState(false)
  const liveRefreshTimer = useRef<number | null>(null)

  const refresh = useCallback(async () => {
    setRefreshing(true)
    try {
      let pending = inflight.get(stableKey) as Promise<T> | undefined
      if (!pending) {
        pending = load()
        inflight.set(stableKey, pending)
      }
      const value = await pending
      cache.set(stableKey, { data: value, updatedAt: Date.now() })
      setData(value)
      setError(null)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught))
    } finally {
      inflight.delete(stableKey)
      setLoading(false)
      setRefreshing(false)
    }
  }, [load, stableKey])

  useEffect(() => {
    const entry = cache.get(stableKey)
    if (entry) {
      setData(entry.data as T)
      setLoading(false)
    }

    void refresh()
    const fallbackTimer = window.setInterval(() => {
      if (document.visibilityState === 'visible') void refresh()
    }, Math.max(intervalMs, 10000))

    const unsubscribe = subscribeLive(event => {
      setData(current => {
        const next = applyLivePayload(stableKey, current, event)
        if (next !== current && next !== null) {
          cache.set(stableKey, { data: next, updatedAt: Date.now() })
        }
        return next
      })

      const delay = liveRefreshDelay(stableKey, event)
      if (delay === null || document.visibilityState !== 'visible' || liveRefreshTimer.current !== null) {
        return
      }
      liveRefreshTimer.current = window.setTimeout(() => {
        liveRefreshTimer.current = null
        void refresh()
      }, delay)
    })

    return () => {
      window.clearInterval(fallbackTimer)
      unsubscribe()
      if (liveRefreshTimer.current !== null) {
        window.clearTimeout(liveRefreshTimer.current)
        liveRefreshTimer.current = null
      }
    }
  }, [intervalMs, refresh, stableKey])

  return { data, error, loading, refreshing, refresh }
}
