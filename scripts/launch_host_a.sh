#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

DATA_DIR="$PROJECT_ROOT/data"
SOCKET="/tmp/dendrited.sock"

usage() {
    cat <<USAGE
Usage: $0 [--cleanup]

Launches the primary ("Host A") Dendrite instance from the repository's own
data directory, with real eBPF/fanotify telemetry enabled and the
development dendrite-group socket permissions applied. HTTP/WebSocket bind
to 127.0.0.1:8766/8767 (the project defaults).

On a fresh clone with no build yet, this automatically runs
scripts/bootstrap.sh first (builds dendrited/CLI, eBPF, the UI, and sets up
the dev group/capabilities) — no separate setup step needed. Once built,
that step is skipped and this just launches. For a manual rebuild of one
piece (e.g. after editing the UI), call scripts/bootstrap.sh directly —
see its --help.

Flags:
  --cleanup    Delete $DATA_DIR (all DBs, the Antiserum package store, and
               any imported/exported artifacts under it), then exit without
               starting the daemon. Does not touch anything outside data/.
  -h, --help   Show this help.

There is no option to remove Host A's own folder — that is the repository
checkout itself. For disposable additional hosts, use launch_host_b.sh
(which supports --remove-host) instead.
USAGE
}

DO_CLEANUP=0
for arg in "$@"; do
    case "$arg" in
        --cleanup) DO_CLEANUP=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $arg" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ "$DO_CLEANUP" == 1 ]]; then
    if [[ -S "$SOCKET" ]]; then
        echo "Warning: $SOCKET exists — Host A may still be running. Stop it first for a clean cleanup." >&2
    fi
    echo "Cleaning Host A data folder: $DATA_DIR"
    rm -rf "$DATA_DIR"
    exit 0
fi

if [[ ! -x target/debug/dendrited ]]; then
    echo "target/debug/dendrited not found — running first-time bootstrap..."
    "$SCRIPT_DIR/bootstrap.sh"
fi

mkdir -p "$DATA_DIR"

echo "Starting Dendrite Host A — HTTP 127.0.0.1:8766, WS 127.0.0.1:8767"
echo "Data dir: $DATA_DIR"
echo "Socket:   $SOCKET"

DENDRITE_SELF_DB="$DATA_DIR/self.sqlite3" \
DENDRITE_MEMORY_DB="$DATA_DIR/memory.sqlite3" \
DENDRITE_INCIDENT_DB="$DATA_DIR/incidents.sqlite3" \
DENDRITE_GUARD_DB="$DATA_DIR/guard.sqlite3" \
DENDRITE_SOCKET="$SOCKET" \
DENDRITE_HTTP_ADDR="127.0.0.1:8766" \
DENDRITE_WS_ADDR="127.0.0.1:8767" \
DENDRITE_SOCKET_GROUP="${DENDRITE_SOCKET_GROUP:-dendrite}" \
DENDRITE_SOCKET_MODE="${DENDRITE_SOCKET_MODE:-0660}" \
DENDRITE_EBPF="${DENDRITE_EBPF:-1}" \
DENDRITE_FANOTIFY="${DENDRITE_FANOTIFY:-1}" \
target/debug/dendrited