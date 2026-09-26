# dendrited

Dendrite's core daemon: the central orchestration process that owns the Memory Graph, telemetry collection, incident/evidence state, action-proposal creation, and the local HTTP/WebSocket/Unix-socket surfaces.

```text
telemetry (eBPF / fanotify / /proc / filesystem polling)
   |
   v
observation
   |
   v
Memory Graph ingestion (tiered STM/LTM, batched under load)
   |
   v
threat-path reasoning -> evidence -> incident
   |
   v
action proposal
```

`dendrited` must not bypass MAGI/quorum, policy, `dendrite-guard`, or the transactional executor to reach a privileged action directly — action proposals are not action authority.

## Interfaces

- Unix socket: local IPC for `dendrite-cli` (see `docs/CLI.md`).
- HTTP + WebSocket, one port (`DENDRITE_HTTP_ADDR`, default `127.0.0.1:8766`): the REST API (`docs/API.md`) and the live event stream at `/ws`, used by the operator UI (`docs/UI.md`). Also serves the built UI itself as static files when `DENDRITE_UI_DIR` is set (packaged installs).

See `docs/CONFIGURATION.md` for every environment variable, `docs/architecture.md` for the full design, and `docs/SYSTEM_MAP.md` for end-to-end diagrams.

## Testing

```bash
cargo test -p dendrited
cargo clippy -p dendrited --all-targets -- -D warnings
```
