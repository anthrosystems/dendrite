import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { App } from './app/App'
import { loadRuntimeConfig } from './api/runtimeConfig'
import './styles.css'

// Resolve where dendrited's API/WebSocket lives before the app renders at
// all — client.ts/live.ts read it synchronously via getApiOrigin() from
// then on, so nothing should call either before this settles. Falls back
// to same-origin relative paths on any failure (see runtimeConfig.ts), so
// this never blocks rendering indefinitely.
void loadRuntimeConfig().finally(() => {
  createRoot(document.getElementById('root')!).render(<StrictMode><App /></StrictMode>)
})
