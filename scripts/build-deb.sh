#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "=== Building eBPF object ==="
"$ROOT/scripts/build-ebpf.sh"

echo "=== Building UI (ui/dist) ==="
# The UI is served by its own process (dendrite-ui-server, a separate
# systemd unit from dendrited — see packaging/dendrite-ui.service), on a
# different origin than dendrited's own HTTP/WebSocket port by default. No
# build-time origin to bake in any more: dendrite-ui-server serves a small
# runtime config JSON from its own DENDRITE_UI_API_ORIGIN env var (see
# packaging/dendrite-ui.service and crates/dendrite-ui-server/src/main.rs),
# which the UI fetches once on load — so the same build works for every
# deployment, and repointing it at a different dendrited origin is a
# post-install env var change, not a rebuild.
(
    cd "$ROOT/ui"
    npm install
    npm run build
)

echo "=== Building .deb (cargo-deb builds dendrited + dendrite-cli + dendrite-ui-server + dendrite-magi + dendrite-guard itself) ==="
cargo deb -p dendrited "$@"
