#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "=== Building eBPF object ==="
"$ROOT/scripts/build-ebpf.sh"

echo "=== Building UI (ui/dist) ==="
# The UI is served by its own process (dendrite-ui-server, a separate
# systemd unit from dendrited — see packaging/dendrite-ui.service), on a
# different origin than dendrited's own HTTP/WebSocket port. Point the
# built UI's API/WS calls at that port explicitly rather than the relative
# paths used in local dev (where a single origin serves both, via Vite's
# dev-proxy). Override DENDRITE_PACKAGED_HTTP_ORIGIN if the target host
# will expose dendrited's HTTP API somewhere other than 127.0.0.1:8766.
: "${DENDRITE_PACKAGED_HTTP_ORIGIN:=127.0.0.1:8766}"
(
    cd "$ROOT/ui"
    npm install
    VITE_DENDRITE_API_BASE="http://${DENDRITE_PACKAGED_HTTP_ORIGIN}/api/v1" \
        VITE_DENDRITE_WS_URL="ws://${DENDRITE_PACKAGED_HTTP_ORIGIN}/ws" \
        npm run build
)

echo "=== Building .deb (cargo-deb builds dendrited + dendrite-cli + dendrite-ui-server itself) ==="
cargo deb -p dendrited "$@"
