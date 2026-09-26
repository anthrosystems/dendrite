#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "=== Building eBPF object ==="
"$ROOT/scripts/build-ebpf.sh"

echo "=== Building UI (ui/dist) ==="
(cd "$ROOT/ui" && npm install && npm run build)

echo "=== Building .deb (cargo-deb builds dendrited + dendrite-cli itself) ==="
cargo deb -p dendrited "$@"
