#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

WATCH_DIR="${DENDRITE_TEST_WATCH_DIR:-/tmp/dendrite-watch}"
SOCKET="${DENDRITE_SOCKET_PATH:-/tmp/dendrited.sock}"
LOG_FILE="${DENDRITE_TEST_LOG:-/tmp/dendrited-test.log}"

cleanup() {
    if [[ -n "${DAEMON_PID:-}" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo
        echo "Stopping dendrited (PID $DAEMON_PID)..."
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

mkdir -p "$WATCH_DIR"
rm -f "$SOCKET"

echo "Starting dendrited..."
DENDRITE_WATCH_PATHS="$WATCH_DIR" \
    cargo run -p dendrited >"$LOG_FILE" 2>&1 &
DAEMON_PID=$!

echo "Waiting for socket: $SOCKET"
for _ in {1..100}; do
    if [[ -S "$SOCKET" ]]; then
        break
    fi

    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "dendrited exited before becoming ready."
        echo
        cat "$LOG_FILE"
        exit 1
    fi

    sleep 0.1
done

if [[ ! -S "$SOCKET" ]]; then
    echo "Timed out waiting for dendrited."
    echo
    cat "$LOG_FILE"
    exit 1
fi

echo
echo "== Initial status =="
cargo run -q -p dendrite-cli -- status

echo
echo "== Health =="
cargo run -q -p dendrite-cli -- health

echo
echo "== Initial memory =="
cargo run -q -p dendrite-cli -- memory recent 10

echo
echo "Generating filesystem activity..."
TEST_FILE="$WATCH_DIR/dendrite-smoke-$(date +%s).txt"
touch "$TEST_FILE"
echo "hello from Dendrite smoke test" >> "$TEST_FILE"

# Telemetry currently polls every ~2 seconds by default.
sleep 3

echo
echo "== Status after telemetry =="
cargo run -q -p dendrite-cli -- status

echo
echo "== Recent memory =="
cargo run -q -p dendrite-cli -- memory recent 10

echo
echo "== Incidents =="
cargo run -q -p dendrite-cli -- incidents

echo
echo "Smoke test completed successfully."
echo "Daemon log: $LOG_FILE"