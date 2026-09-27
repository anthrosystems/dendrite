import { getApiOrigin } from '../api/runtimeConfig'
import { withToken } from '../api/token'

export type LiveEvent = {
  kind: string
  payload: unknown
}

const LIVE_EVENT_NAME = 'dendrite-live'
let socket: WebSocket | null = null
let reconnectTimer: number | null = null
let started = false

function websocketUrl() {
  const origin = getApiOrigin()
  const base = origin
    ? `${origin.replace(/^http/, 'ws')}/ws`
    : `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws`
  return withToken(base)
}

function connect() {
  if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
    return
  }

  socket = new WebSocket(websocketUrl())
  socket.addEventListener('message', event => {
    try {
      const detail = JSON.parse(String(event.data)) as LiveEvent
      window.dispatchEvent(new CustomEvent<LiveEvent>(LIVE_EVENT_NAME, { detail }))
    } catch {
      // Ignore malformed live frames; REST remains the source of truth.
    }
  })
  socket.addEventListener('close', () => {
    socket = null
    if (reconnectTimer === null) {
      reconnectTimer = window.setTimeout(() => {
        reconnectTimer = null
        connect()
      }, 1000)
    }
  })
  socket.addEventListener('error', () => socket?.close())
}

export function ensureLiveConnection() {
  if (started) return
  started = true
  connect()
}

export function subscribeLive(listener: (event: LiveEvent) => void) {
  ensureLiveConnection()
  const handler = (event: Event) => listener((event as CustomEvent<LiveEvent>).detail)
  window.addEventListener(LIVE_EVENT_NAME, handler)
  return () => window.removeEventListener(LIVE_EVENT_NAME, handler)
}

export function emitLocalLive(kind: string, payload: unknown = null) {
  window.dispatchEvent(new CustomEvent<LiveEvent>(LIVE_EVENT_NAME, { detail: { kind, payload } }))
}
