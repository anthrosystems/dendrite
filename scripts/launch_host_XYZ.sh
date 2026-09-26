#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

usage() {
    cat <<USAGE
Usage: $0 [HOST_NAME] [--cleanup] [--remove-host]

Launches an additional Dendrite instance ("Host B", "Host C", ...) entirely
outside the repository, for cross-host / Antiserum testing on one machine.
Instance identity is a random UUID generated once per fresh, empty
self-store, so any number of these can run side by side as genuinely
distinct hosts.

  HOST_NAME    Host label; used for the data directory name and default
               socket path. Default: b

Port defaults for HOST_NAME=b to 127.0.0.1:8866 (HTTP + WebSocket, one
port — see DENDRITE_HOST_HTTP_PORT below), matching the original manual
setup. For any other HOST_NAME you must set DENDRITE_HOST_HTTP_PORT
explicitly — this is deliberate: it forces you to pick a port that doesn't
collide with a host you already have running, rather than guessing at an
auto-assigned one.

Environment overrides:
  DENDRITE_HOST_ROOT        Parent directory for all host folders
                             (default: ~/dendrite-hosts — never inside
                             the repository)
  DENDRITE_HOST_HTTP_PORT   HTTP + WebSocket port for this host (the two
                             share one listener; see docs/ROADMAP.md's
                             Batch 7 "WebSocket merged onto the HTTP port"
                             note)

Flags:
  --cleanup       Delete this host's data/ folder (all DBs, the Antiserum
                  package store, and any imported/exported artifacts under
                  it), then exit without starting the daemon.
  --remove-host   Delete this host's entire folder (data/ plus anything
                  else placed under it), then exit without starting the
                  daemon. Implies --cleanup.
  -h, --help      Show this help.
USAGE
}

HOST_NAME="b"
DO_CLEANUP=0
DO_REMOVE_HOST=0
POSITIONAL=()

for arg in "$@"; do
    case "$arg" in
        --cleanup) DO_CLEANUP=1 ;;
        --remove-host) DO_REMOVE_HOST=1; DO_CLEANUP=1 ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "Unknown flag: $arg" >&2; usage >&2; exit 2 ;;
        *) POSITIONAL+=("$arg") ;;
    esac
done
if [[ ${#POSITIONAL[@]} -gt 1 ]]; then
    echo "Only one HOST_NAME may be given (got: ${POSITIONAL[*]})" >&2
    exit 2
elif [[ ${#POSITIONAL[@]} -eq 1 ]]; then
    HOST_NAME="${POSITIONAL[0]}"
fi

HOST_ROOT="${DENDRITE_HOST_ROOT:-$HOME/dendrite-hosts}"
HOST_DIR="$HOST_ROOT/$HOST_NAME"
DATA_DIR="$HOST_DIR/data"
SOCKET="$HOST_DIR/dendrited.sock"

if [[ "$HOST_NAME" == "b" ]]; then
    HTTP_PORT="${DENDRITE_HOST_HTTP_PORT:-8866}"
else
    if [[ -z "${DENDRITE_HOST_HTTP_PORT:-}" ]]; then
        echo "error: DENDRITE_HOST_HTTP_PORT must be set for any HOST_NAME other than 'b'" >&2
        exit 2
    fi
    HTTP_PORT="$DENDRITE_HOST_HTTP_PORT"
fi

if [[ "$DO_REMOVE_HOST" == 1 ]]; then
    if [[ -S "$SOCKET" ]]; then
        echo "Warning: $SOCKET exists — host '$HOST_NAME' may still be running. Stop it first for a clean removal." >&2
    fi
    echo "Removing entire host folder: $HOST_DIR"
    rm -rf "$HOST_DIR"
    exit 0
fi
if [[ "$DO_CLEANUP" == 1 ]]; then
    if [[ -S "$SOCKET" ]]; then
        echo "Warning: $SOCKET exists — host '$HOST_NAME' may still be running. Stop it first for a clean cleanup." >&2
    fi
    echo "Cleaning host '$HOST_NAME' data folder: $DATA_DIR"
    rm -rf "$DATA_DIR"
    exit 0
fi

cd "$PROJECT_ROOT"
if [[ ! -x target/debug/dendrited ]]; then
    echo "target/debug/dendrited is missing. Run: cargo build -p dendrited -p dendrite-cli" >&2
    exit 1
fi

mkdir -p "$DATA_DIR"

echo "Starting Dendrite host '$HOST_NAME' — HTTP + WebSocket 127.0.0.1:$HTTP_PORT (WS path /ws)"
echo "Data dir: $DATA_DIR"
echo "Socket:   $SOCKET"

DENDRITE_SELF_DB="$DATA_DIR/self.sqlite3" \
DENDRITE_STM_DB="$DATA_DIR/stm.sqlite3" \
DENDRITE_LTM_DB="$DATA_DIR/ltm.sqlite3" \
DENDRITE_INCIDENT_DB="$DATA_DIR/incidents.sqlite3" \
DENDRITE_GUARD_DB="$DATA_DIR/guard.sqlite3" \
DENDRITE_SOCKET="$SOCKET" \
DENDRITE_HTTP_ADDR="127.0.0.1:$HTTP_PORT" \
DENDRITE_SOCKET_GROUP="${DENDRITE_SOCKET_GROUP:-dendrite}" \
DENDRITE_SOCKET_MODE="${DENDRITE_SOCKET_MODE:-0660}" \
DENDRITE_EBPF="${DENDRITE_EBPF:-1}" \
DENDRITE_FANOTIFY="${DENDRITE_FANOTIFY:-1}" \
target/debug/dendrited