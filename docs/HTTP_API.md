# Dendrite local HTTP API

`dendrited` exposes a local HTTP API for `ui/`.

Default bind address:

```text
127.0.0.1:8766
```

Override with `DENDRITE_HTTP_ADDR`. The current API is intended for local development/administration and should not be exposed directly to an untrusted network.

## Current endpoints

```text
GET  /api/v1/status
GET  /api/v1/health

GET  /api/v1/incidents
GET  /api/v1/incidents/{id}

GET  /api/v1/memory/nodes
GET  /api/v1/memory/nodes?kind=process
GET  /api/v1/memory/recent?limit=20
GET  /api/v1/memory/neighbours?node_id=...
GET  /api/v1/memory/path?source=...&target=...

GET  /api/v1/guard
GET  /api/v1/guard/findings

GET  /api/v1/telemetry/status
GET  /api/v1/telemetry/recent?limit=100

GET  /api/v1/actions
GET  /api/v1/actions/{id}
POST /api/v1/actions
POST /api/v1/actions/{id}/evaluate
```

Create-action body:

```json
{
  "incident_id": "inc_00000001",
  "action": "observe",
  "target": "process:1234:5678"
}
```

The Unix socket remains the CLI interface and is not replaced by HTTP.

## Validate

```bash
DENDRITE_WATCH_PATHS=/tmp/dendrite-watch cargo run -p dendrited
curl -s http://127.0.0.1:8766/api/v1/status
curl -s http://127.0.0.1:8766/api/v1/telemetry/status

cd ui
npm run dev
```
