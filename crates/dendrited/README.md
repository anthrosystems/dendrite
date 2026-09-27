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

- Unix socket: local IPC for `dendrite-cli` (see `CLI.md`, next to `dendrite-cli`'s own crate).
- HTTP + WebSocket, one port (`DENDRITE_HTTP_ADDR`, default `127.0.0.1:8766`): the REST API (`API.md`, in this crate) and the live event stream at `/ws`, used by the operator UI (`../../ui/UI.md`). Also serves the built UI itself as static files when `DENDRITE_UI_DIR` is set (packaged installs).

See `docs/CONFIGURATION.md` for every environment variable, `docs/architecture.md` for the full design, and `docs/SYSTEM_MAP.md` for end-to-end diagrams.

## Testing

```bash
cargo test -p dendrited
cargo clippy -p dendrited --all-targets -- -D warnings
```

`examples/antiserum_smoke.rs` is a live-data integration smoke test for the
Antiserum export pipeline (build → sign → `.danti` round-trip → replay
rejection → tamper rejection), run against whatever real `dendrited` data
directory already exists rather than fixtures:

```bash
cargo run -p dendrited --example antiserum_smoke -- data/antiserum-smoke
```

Point `DENDRITE_SELF_DB`/`DENDRITE_STM_DB`/`DENDRITE_LTM_DB`/
`DENDRITE_INCIDENT_DB`/`DENDRITE_GUARD_DB` at an existing host's data
directory if not running from the repo root's default `data/` layout —
e.g. one created by `scripts/launch_host_a.sh`/`scripts/launch_host_XYZ.sh`
for local dev, or `/var/lib/dendrite/*.sqlite3` for a packaged `.deb`
install (see `packaging/dendrited.service`; needs read access as the
`dendrite` user/group, and an output directory writable by whoever runs
it, since `/var/lib/dendrite` itself is `0750 dendrite:dendrite`).
