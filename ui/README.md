# dendrite-ui

Web-based operator console for Dendrite: daemon status, subsystem health, incidents and evidence, Memory Graph exploration, and the MAGI & Response view for reviewing and authorising action proposals, kept live over the `/ws` event stream.

The UI is a client of `dendrited`'s HTTP/WebSocket surface, same as `dendrite-cli` is a client of its Unix-socket IPC — it is not a security authority. Everything it shows or lets an operator trigger still passes through the same MAGI/quorum, policy, Guard, and transactional-executor pipeline as any other caller; see `../docs/architecture.md` and `../crates/dendrited/API.md`.

See `UI.md` (in this directory) for the full current view/feature reference.

## Requirements

- Node.js 22 or newer;
- a running `dendrited` HTTP/WebSocket listener (`DENDRITE_HTTP_ADDR`, default `127.0.0.1:8766`).

## Development

```bash
npm install
npm run dev
```

Open `http://127.0.0.1:5173`.

Vite proxies `/api` and `/ws` to `http://127.0.0.1:8766`, so browser development does not require exposing the daemon beyond localhost.

## Build

```bash
npm run build
```

The build output (`dist/`) is served by the separate `dendrite-ui-server` process/systemd unit, not by `dendrited` itself — see `crates/dendrite-ui-server/README.md` and `docs/CONFIGURATION.md`'s "The UI, and its own process" section for why it's split out and how the built UI's cross-origin API/WebSocket calls are configured (`VITE_DENDRITE_API_BASE`/`VITE_DENDRITE_WS_URL`). `scripts/build-deb.sh` sets both automatically when building for packaging.

Copyright 2026 Anthrosystems
