# dendrite-ui

Web-based interface for Dendrite endpoint security, threat analysis, incidents, system state, and Memory Graph visualisation.

## Phase 1

The initial UI is a read-only local operations console. It provides:

- daemon status and session observation counts;
- subsystem health;
- incident list and evidence detail;
- Memory Graph node discovery and kind filtering;
- neighbour visualisation;
- path exploration;
- recent telemetry backed by recently observed memory nodes.

No containment or remediation action can be triggered from Phase 1.

## Requirements

- Node.js 22 or newer;
- the Phase 1 `dendrited` HTTP API listening on `127.0.0.1:8766`.

## Development

```bash
npm install
npm run dev
```

Open `http://127.0.0.1:5173`.

Vite proxies `/api` to `http://127.0.0.1:8766`, so browser development does not require exposing the daemon beyond localhost.

## Build

```bash
npm run build
```

## Security boundary

The UI is not a security authority. Memory Graph findings, evidence and incidents remain informational until they pass the separate Dendrite action-authorisation pipeline.

The Phase 1 HTTP API is read-only and localhost-bound. It is intended for development/local administration, not remote exposure.

Copyright 2026 Anthrosystems
