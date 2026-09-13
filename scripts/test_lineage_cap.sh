#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

usage() {
    cat <<USAGE
Usage: $0 [--hops N] [--keep-running] [--cleanup]

Exercises the provenance lineage cap (MemoryProvenance::MAX_PROVENANCE_LINEAGE,
currently 10 — see crates/dendrite-memory/src/model.rs) end-to-end: spins up a
chain of N fully independent Dendrite instances (outside the repository, see
launch_host_b.sh for the same underlying approach), seeds one object on the
first, and relays it hop by hop — export -> download -> import -> accept ->
re-export from the new host -> ... — confirming the final host's lineage
array is capped at 10 entries (oldest dropped) rather than growing
unbounded, while origin_instance_id stays asserted as the very first host
throughout, even once it's aged out of the lineage array itself.

Flags:
  --hops N        Number of hosts in the chain. Must be >= 11 for the test
                   to actually exceed the cap. Default: 12.
  --keep-running  Leave all spawned daemons running afterward (their PIDs
                   and data dirs are printed) instead of stopping them.
  --cleanup       Stop any daemons this script's PID file knows about and
                   delete every lineage-chain host folder, then exit
                   without running anything.
  -h, --help      Show this help.

Each host's folder lives under \$DENDRITE_HOST_ROOT (default
~/dendrite-hosts), named lineage-0, lineage-1, .... HTTP/WS ports are
assigned sequentially starting at 9100/9101.
USAGE
}

HOPS=12
KEEP_RUNNING=0
DO_CLEANUP=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --hops)
            HOPS="${2:-}"
            shift 2
            ;;
        --hops=*)
            HOPS="${1#--hops=}"
            shift
            ;;
        --keep-running) KEEP_RUNNING=1; shift ;;
        --cleanup) DO_CLEANUP=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

HOST_ROOT="${DENDRITE_HOST_ROOT:-$HOME/dendrite-hosts}"
PID_FILE="$HOST_ROOT/lineage-chain.pids"
BASE_HTTP_PORT=9100
BASE_WS_PORT=9101

host_dir() { echo "$HOST_ROOT/lineage-$1"; }
http_port() { echo $((BASE_HTTP_PORT + 2 * $1)); }
ws_port() { echo $((BASE_WS_PORT + 2 * $1)); }

if [[ "$DO_CLEANUP" == 1 ]]; then
    if [[ -f "$PID_FILE" ]]; then
        echo "Stopping previously spawned lineage-chain daemons..."
        while read -r pid; do
            kill "$pid" 2>/dev/null || true
        done < "$PID_FILE"
        rm -f "$PID_FILE"
    fi
    echo "Removing all lineage-chain host folders under $HOST_ROOT..."
    rm -rf "$HOST_ROOT"/lineage-*
    exit 0
fi

if ! [[ "$HOPS" =~ ^[0-9]+$ ]] || [[ "$HOPS" -lt 2 ]]; then
    echo "error: --hops must be a positive integer >= 2" >&2
    exit 2
fi
if [[ "$HOPS" -lt 11 ]]; then
    echo "Warning: --hops=$HOPS will not exceed the 10-host cap; the interesting" >&2
    echo "         assertion (lineage truncates rather than growing unbounded)" >&2
    echo "         won't actually trigger. Use --hops 11 or higher for that." >&2
fi

cd "$PROJECT_ROOT"
if [[ ! -x target/debug/dendrited ]] || [[ ! -x target/debug/dendrite-cli ]]; then
    echo "target/debug/dendrited and/or target/debug/dendrite-cli are missing." >&2
    echo "Run: cargo build -p dendrited -p dendrite-cli" >&2
    exit 1
fi

PIDS=()
cleanup_on_exit() {
    if [[ "$KEEP_RUNNING" == 1 ]]; then
        echo
        echo "--keep-running set: leaving ${#PIDS[@]} daemon(s) up."
        printf '%s\n' "${PIDS[@]}" > "$PID_FILE"
        echo "PIDs recorded in $PID_FILE — run '$0 --cleanup' later to stop them and remove their data."
        return
    fi
    echo
    echo "Stopping ${#PIDS[@]} daemon(s)..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
}
trap cleanup_on_exit EXIT

wait_for_ready() {
    local port="$1"
    for _ in $(seq 1 60); do
        if curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/api/v1/status" 2>/dev/null | grep -q '^200$'; then
            return 0
        fi
        sleep 0.5
    done
    echo "error: daemon on port $port never became ready" >&2
    return 1
}

start_hop() {
    local n="$1"
    local dir; dir="$(host_dir "$n")"
    local data="$dir/data"
    local http; http="$(http_port "$n")"
    local ws; ws="$(ws_port "$n")"
    mkdir -p "$data"
    echo "Starting lineage-$n (HTTP 127.0.0.1:$http, WS 127.0.0.1:$ws)..."
    DENDRITE_SELF_DB="$data/self.sqlite3" \
    DENDRITE_MEMORY_DB="$data/memory.sqlite3" \
    DENDRITE_INCIDENT_DB="$data/incidents.sqlite3" \
    DENDRITE_GUARD_DB="$data/guard.sqlite3" \
    DENDRITE_SOCKET="$dir/dendrited.sock" \
    DENDRITE_HTTP_ADDR="127.0.0.1:$http" \
    DENDRITE_WS_ADDR="127.0.0.1:$ws" \
    target/debug/dendrited >"$dir/dendrited.log" 2>&1 &
    PIDS+=("$!")
    wait_for_ready "$http"
}

echo "=== Spinning up $HOPS hosts ==="
for n in $(seq 0 $((HOPS - 1))); do
    start_hop "$n"
done

echo
echo "=== Seeding the test object on lineage-0 ==="
DENDRITE_SOCKET="$(host_dir 0)/dendrited.sock" target/debug/dendrite-cli debug seed-incident lineage-cap-test

export_and_relay() {
    local from="$1"
    local to="$2"
    local from_port; from_port="$(http_port "$from")"
    local to_port; to_port="$(http_port "$to")"
    local pkg="$HOST_ROOT/lineage-relay-$from-to-$to.danti"

    local antiserum_id
    antiserum_id=$(curl -s -X POST "http://127.0.0.1:$from_port/api/v1/analysis/export" \
        -H "Content-Type: application/json" \
        -d '{"graph":{"scope":"complete","start_node":null,"max_depth":null},"attack_chains":{"scope":"all","selected_ids":[]},"vulnerabilities":null,"indicator_hashes":null,"indicator_domains":null,"indicator_ips":null,"indicator_urls":null,"behaviours":{"scope":"all","selected_ids":[]}}' \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["antiserum_id"])')

    curl -s -o "$pkg" "http://127.0.0.1:$from_port/api/v1/analysis/packages/$antiserum_id/download"
    curl -s -X POST "http://127.0.0.1:$to_port/api/v1/analysis/import" --data-binary @"$pkg" >/dev/null
    curl -s -X POST "http://127.0.0.1:$to_port/api/v1/analysis/packages/$antiserum_id/accept" >/dev/null
    rm -f "$pkg"
    echo "  lineage-$from -> lineage-$to (via antiserum $antiserum_id)"
}

echo
echo "=== Relaying through the chain ==="
for n in $(seq 0 $((HOPS - 2))); do
    export_and_relay "$n" "$((n + 1))"
done

echo
echo "=== Result: lineage-cap-test nodes on the final host (lineage-$((HOPS - 1))) ==="
final_port="$(http_port $((HOPS - 1)))"
origin_id=$(DENDRITE_SOCKET="$(host_dir 0)/dendrited.sock" target/debug/dendrite-cli status | awk '/^instance id:/{print $3}')

curl -s "http://127.0.0.1:$final_port/api/v1/memory/graph" | ORIGIN_ID="$origin_id" python3 -c '
import json, os, sys

data = json.load(sys.stdin)
origin_id = os.environ["ORIGIN_ID"]
cap = 10
ok = True

for node in data["nodes"]:
    if "lineage-cap-test" not in node.get("label", ""):
        continue
    lineage = node.get("lineage", [])
    print(node["label"] + ": lineage length=" + str(len(lineage)) + ", origin_instance_id=" + str(node.get("origin_instance_id")))
    if len(lineage) > cap:
        print("  FAIL: lineage exceeds the " + str(cap) + "-host cap")
        ok = False
    if node.get("origin_instance_id") != origin_id:
        print("  FAIL: origin_instance_id changed from the real origin (" + origin_id + ")")
        ok = False
    if len(lineage) == cap and origin_id not in lineage:
        print("  Note: origin host has aged out of the lineage array itself (expected once hops > " + str(cap) + ") - origin_instance_id above is still the source of truth for who originated this.")

sys.exit(0 if ok else 1)
'
result=$?

echo
if [[ "$result" == 0 ]]; then
    echo "PASS: lineage cap held across $HOPS hops."
else
    echo "FAIL: see above."
fi
exit "$result"
