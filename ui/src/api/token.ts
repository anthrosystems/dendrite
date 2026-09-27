// dendrited's HTTP API and /ws WebSocket upgrade require a bearer token
// (see docs/CONFIGURATION.md's "HTTP API authentication" section). In dev,
// the Vite proxy (see vite.config.ts) reads the token off disk and injects
// it into every proxied request automatically, so nothing here ever needs
// to run there. For a packaged/production build served by the static-only
// dendrite-ui-server (no Node proxy in front of it), the operator pastes
// the token in once via the gate this module backs, and it's kept in
// localStorage from then on.

const STORAGE_KEY = 'dendrite-http-token'

type Listener = () => void
const listeners = new Set<Listener>()
let authRequired = false

function setAuthRequired(value: boolean): void {
  if (authRequired === value) return
  authRequired = value
  listeners.forEach(listener => listener())
}

/** Whether the last API/WebSocket response indicated the stored token
 * (if any) was missing or wrong. Read this to decide whether to show the
 * token-entry gate. */
export function isAuthRequired(): boolean {
  return authRequired
}

export function subscribeAuthRequired(listener: Listener): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

/** Called by the API client with every response status it sees. */
export function reportAuthResult(status: number): void {
  if (status === 401) setAuthRequired(true)
}

export function getStoredToken(): string | null {
  try {
    return window.localStorage.getItem(STORAGE_KEY)
  } catch {
    return null
  }
}

export function setStoredToken(token: string): void {
  const trimmed = token.trim()
  try {
    window.localStorage.setItem(STORAGE_KEY, trimmed)
  } catch {
    // localStorage unavailable (private browsing, storage disabled, etc.)
    // — the token simply won't persist across reloads, and the gate will
    // ask again next time.
  }
  setAuthRequired(false)
}

export function clearStoredToken(): void {
  try {
    window.localStorage.removeItem(STORAGE_KEY)
  } catch {
    // ignore
  }
}

/**
 * Appends the stored token as a `?token=`/`&token=` query parameter rather
 * than an `Authorization` header. `dendrited`'s HTTP API deliberately has
 * no CORS preflight/OPTIONS support (see crates/dendrited/src/http.rs), and
 * a custom header would force a preflight on cross-origin requests — the
 * packaged `dendrite-ui-server` and `dendrited` normally listen on
 * different ports, so this keeps every request "simple" under the CORS
 * spec. When no token is stored yet (always true in dev, where the Vite
 * proxy injects it server-side instead), `url` is returned unchanged.
 */
export function withToken(url: string): string {
  const token = getStoredToken()
  if (!token) return url
  const separator = url.includes('?') ? '&' : '?'
  return `${url}${separator}token=${encodeURIComponent(token)}`
}
