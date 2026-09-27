// Where dendrited's HTTP/WebSocket API lives, read once at startup rather
// than baked into the JS bundle at build time. In the packaged/production
// build, dendrite-ui-server serves this path dynamically from its own
// DENDRITE_UI_API_ORIGIN env var (see crates/dendrite-ui-server/src/main.rs)
// — an operator repointing the UI at a different dendrited origin is an env
// var change plus a restart of that unit, not a UI rebuild. This isn't a
// security boundary either way (whoever can write to the served directory
// already controls everything the UI does), just an ergonomics fix.
//
// In dev (`npm run dev`), `ui/public/dendrite-config.json` is served
// verbatim by Vite with `apiOrigin: null`, matching the dev proxy's
// same-origin relative-path behaviour exactly.

export interface RuntimeConfig {
  apiOrigin: string | null
}

const DEFAULT_CONFIG: RuntimeConfig = { apiOrigin: null }

let cached: RuntimeConfig = DEFAULT_CONFIG
let loaded: Promise<RuntimeConfig> | null = null

async function fetchConfig(): Promise<RuntimeConfig> {
  try {
    const response = await fetch('/dendrite-config.json', { cache: 'no-store' })
    if (!response.ok) return DEFAULT_CONFIG
    const body = (await response.json()) as Partial<RuntimeConfig>
    return { apiOrigin: typeof body.apiOrigin === 'string' ? body.apiOrigin : null }
  } catch {
    // Missing/unreachable — fall back to same-origin relative paths rather
    // than blocking the app from ever rendering.
    return DEFAULT_CONFIG
  }
}

/** Call once, before the app renders, so `getApiOrigin()`/`getWebsocketOrigin()`
 * are stable for the rest of the session. */
export function loadRuntimeConfig(): Promise<RuntimeConfig> {
  if (!loaded) {
    loaded = fetchConfig().then(config => {
      cached = config
      return config
    })
  }
  return loaded
}

/** `null` means same-origin: callers should use a relative path. */
export function getApiOrigin(): string | null {
  return cached.apiOrigin
}
