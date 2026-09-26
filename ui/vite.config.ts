import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

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
      },
      '/ws': {
        target: 'ws://127.0.0.1:8766',
        ws: true,
        changeOrigin: false,
      },
    },
  },
})