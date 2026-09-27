# dendrite-ui-server

A minimal, unprivileged static-file server for the built Dendrite UI (`ui/dist`) — nothing else. It exists as its own binary/systemd unit (`dendrite-ui.service`) specifically so the UI can be stopped, started, or disabled independently of `dendrited` itself: `systemctl disable --now dendrite-ui` touches nothing about telemetry collection, the Memory Graph, or action authorisation.

It serves real files under `DENDRITE_UI_DIR` as-is, and falls back to `index.html` for anything else (a client-side route, a bare `/`, or a path-traversal attempt) — the standard single-page-app static-host convention.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `DENDRITE_UI_DIR` | required, no default | Directory containing the built UI (`ui/dist`). The process refuses to start if this isn't set or doesn't exist |
| `DENDRITE_UI_ADDR` | `127.0.0.1:8767` | Bind address for the static file server |
| `DENDRITE_UI_API_ORIGIN` | unset (same-origin) at the binary level; the `.deb`'s shipped conffile (`packaging/dendrite-ui.env.example`) sets it to `http://127.0.0.1:8766` | Where `dendrited`'s HTTP/WebSocket API lives, from the browser's point of view. Served to the UI at runtime as `/dendrite-config.json` (`{"apiOrigin": ...}`) rather than baked into the JS bundle — see below |

## Why a separate process from `dendrited`

The UI is stateless, unprivileged, and has no security boundary of its own to protect — unlike `dendrited` (telemetry capabilities, Memory Graph, Guard) there's no reason for it to share a process, a systemd unit, or a capability set with the daemon. Splitting it out means:

- it can be disabled/enabled without affecting `dendrited` at all;
- it needs zero Linux capabilities and can be sandboxed harder than `dendrited` can be today (see `packaging/dendrite-ui.service`);
- `dendrited` doesn't need a `DENDRITE_UI_DIR` config option or static-file-serving code path at all.

The trade-off: the UI's JS may now need to talk to `dendrited`'s HTTP/WebSocket port cross-origin rather than same-origin. See `docs/CONFIGURATION.md`'s "The UI, and its own process" section for how that's wired: `dendrite-ui-server` reads `DENDRITE_UI_API_ORIGIN` once at startup and serves it to the browser as `/dendrite-config.json`, which the UI fetches once on load (`ui/src/api/runtimeConfig.ts`) — a deployment repointing the UI at a different `dendrited` origin is an env var change and a unit restart, not a rebuild of `ui/dist`. `dendrited`'s own CORS origin allowlist (`http.rs`) is the other half of making cross-origin calls actually work.

## Testing

```bash
cargo test -p dendrite-ui-server
cargo clippy -p dendrite-ui-server --all-targets -- -D warnings
```
