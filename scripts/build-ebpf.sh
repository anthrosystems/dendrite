#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT/ebpf/dendrite-ebpf/Cargo.toml"

if ! command -v bpf-linker >/dev/null 2>&1; then
  echo "bpf-linker is required. Recommended: cargo binstall bpf-linker" >&2
  exit 1
fi

cargo +nightly build \
  --manifest-path "$MANIFEST" \
  --target bpfel-unknown-none \
  -Z build-std=core \
  --release

echo "$ROOT/ebpf/dendrite-ebpf/target/bpfel-unknown-none/release/dendrite-ebpf"
