import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { readFileSync } from 'node:fs'

// dendrited's HTTP API and /ws WebSocket upgrade both require a bearer
// token (see docs/CONFIGURATION.md's "HTTP API authentication" section):
// every non-browser HTTP client was previously completely unauthenticated,
// since the Origin-based check only ever restricted requests a browser
// itself sends. This dev proxy reads the token dendrited wrote to disk and
// injects it into every proxied request automatically, so `npm run dev`
// never requires copy-pasting the token in by hand. The packaged/
// production build (served by the static-only dendrite-ui-server, with no
// Node proxy in front of it) still needs a one-time manual paste-in — see
// `ui/src/api/token.ts`.
const DEV_TOKEN_PATH = process.env.DENDRITE_HTTP_TOKEN_FILE ?? '/tmp/dendrite-http.token'

function readDevToken(): string | undefined {
  try {
    return readFileSync(DEV_TOKEN_PATH, 'utf8').trim()
  } catch {
    // dendrited hasn't started yet, or is using a different token file —
    // proxied requests go out unauthenticated and dendrited will 401 them,
    // which is visible immediately in the browser rather than hanging.
    return undefined
  }
}

// Shared by both the plain-HTTP ('proxyReq') and WebSocket-upgrade
// ('proxyReqWs') http-proxy events below — both hand back an outgoing
// Node ClientRequest that supports setHeader before it's sent.
function injectAuth(proxyReq: { setHeader: (name: string, value: string) => void }) {
  const token = readDevToken()
  if (token) {
    proxyReq.setHeader('Authorization', `Bearer ${token}`)
  }
}

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: {
      // dendrited serves both the HTTP API and the /ws WebSocket upgrade on
      // the same port (see docs/CONFIGURATION.md) — proxy both there.
      '/api': {
        target: 'http://127.0.0.1:8766',
        changeOrigin: false,
        configure: (proxy) => {
          proxy.on('proxyReq', injectAuth)
        },
      },
      '/ws': {
        target: 'ws://127.0.0.1:8766',
        ws: true,
        changeOrigin: false,
        configure: (proxy) => {
          proxy.on('proxyReqWs', injectAuth)
        },
      },
    },
  },
})
