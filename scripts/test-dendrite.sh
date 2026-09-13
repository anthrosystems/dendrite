#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

MODE="${1:-smoke}"
WATCH_DIR="${DENDRITE_TEST_WATCH_DIR:-/tmp/dendrite-watch}"
SOCKET="${DENDRITE_SOCKET_PATH:-/tmp/dendrited.sock}"
HTTP_BASE="${DENDRITE_HTTP_BASE:-http://127.0.0.1:8766/api/v1}"
LOG_FILE="${DENDRITE_TEST_LOG:-/tmp/dendrited-test.log}"
STRESS_EVENTS="${DENDRITE_STRESS_EVENTS:-5000}"
STRESS_WORKERS="${DENDRITE_STRESS_WORKERS:-8}"
GRAPH_EVENTS="${DENDRITE_GRAPH_EVENTS:-3000}"
REQUEST_TIMEOUT="${DENDRITE_TEST_REQUEST_TIMEOUT:-5}"
STARTED_DAEMON=0

usage() {
    cat <<USAGE
Usage: $0 [smoke|activity|graph|incidents|guard|stress|full]

Environment:
  DENDRITE_STRESS_EVENTS=N    Approximate activity operations for stress mode (default: 5000)
  DENDRITE_STRESS_WORKERS=N   Concurrent workers (default: 8)
  DENDRITE_GRAPH_EVENTS=N      Diverse graph-inflation iterations (default: 3000)
  DENDRITE_TEST_WATCH_DIR=DIR Watched filesystem fixture (default: /tmp/dendrite-watch)
  DENDRITE_HTTP_BASE=URL      HTTP API base (default: http://127.0.0.1:8766/api/v1)
  DENDRITE_TEST_REQUEST_TIMEOUT=N  CLI/API timeout in seconds (default: 5)

The script reuses a running daemon when available. If none is running it starts
./target/debug/dendrited, so build it and reapply its required capabilities first.
USAGE
}

case "$MODE" in
    smoke|activity|graph|incidents|guard|stress|full) ;;
    -h|--help|help) usage; exit 0 ;;
    *) echo "Unknown mode: $MODE" >&2; usage >&2; exit 2 ;;
esac

cli() {
    if [[ -x target/debug/dendrite-cli ]]; then
        timeout "${REQUEST_TIMEOUT}s" target/debug/dendrite-cli "$@"
    else
        timeout "${REQUEST_TIMEOUT}s" cargo run -q -p dendrite-cli -- "$@"
    fi
}

cleanup() {
    if [[ "$STARTED_DAEMON" == 1 ]] && [[ -n "${DAEMON_PID:-}" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo
        echo "Stopping dendrited (PID $DAEMON_PID)..."
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

mkdir -p "$WATCH_DIR"

if [[ ! -S "$SOCKET" ]]; then
    if [[ ! -x target/debug/dendrited ]]; then
        echo "target/debug/dendrited is missing. Run: cargo build -p dendrited -p dendrite-cli" >&2
        exit 1
    fi
    echo "Starting dendrited for test..."
    DENDRITE_WATCH_PATHS="$WATCH_DIR" \
    DENDRITE_FANOTIFY="${DENDRITE_FANOTIFY:-1}" \
    DENDRITE_EBPF="${DENDRITE_EBPF:-1}" \
        target/debug/dendrited >"$LOG_FILE" 2>&1 &
    DAEMON_PID=$!
    STARTED_DAEMON=1
fi

for _ in {1..100}; do
    [[ -S "$SOCKET" ]] && break
    if [[ "$STARTED_DAEMON" == 1 ]] && ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "dendrited exited before becoming ready." >&2
        cat "$LOG_FILE" >&2
        exit 1
    fi
    sleep 0.1
done
[[ -S "$SOCKET" ]] || { echo "Timed out waiting for $SOCKET" >&2; exit 1; }

json_field() {
    local json="$1"
    local field="$2"
    python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get(sys.argv[2], 0))' "$json" "$field" 2>/dev/null || echo 0
}

http_latency_ms() {
    local path="${1:-/status}"
    if command -v curl >/dev/null 2>&1; then
        curl --max-time "$REQUEST_TIMEOUT" -fsS -o /dev/null -w '%{time_total}' "$HTTP_BASE$path" 2>/dev/null | \
            awk '{ printf "%.1f", $1 * 1000 }'
    else
        echo "n/a"
    fi
}

activity_once() {
    local root="$1"
    local i="$2"
    local dir="$root/batch-$((i % 32))"
    mkdir -p "$dir"
    printf 'dendrite stress %s %s\n' "$i" "$(date +%s%N)" > "$dir/event-$i.tmp"
    cat "$dir/event-$i.tmp" >/dev/null
    mv "$dir/event-$i.tmp" "$dir/event-$i.dat"
    grep -q dendrite "$dir/event-$i.dat" || true
    rm -f "$dir/event-$i.dat"

    # Short-lived process activity for eBPF process-exec telemetry.
    sh -c ':'

    # Real outbound connect attempts without requiring a listening service.
    if (( i % 8 == 0 )); then
        (exec 3<>/dev/tcp/127.0.0.1/9) 2>/dev/null || true
    fi
}

run_activity() {
    local count="${1:-120}"
    echo "Generating $count mixed process/filesystem/network operations..."
    local root="$WATCH_DIR/test-activity-$$"
    mkdir -p "$root"
    for ((i=1; i<=count; i++)); do activity_once "$root" "$i"; done
    rm -rf "$root"
    sleep 3
}


run_graph_activity() {
    local count="${1:-$GRAPH_EVENTS}"
    local root="$WATCH_DIR/graph-diversity-$$"
    mkdir -p "$root"/{git,python,text,archive,config,logs,tmp,network}

    echo "Generating $count diverse graph-building iterations..."
    echo "This favours variety over raw throughput so the Memory Graph develops multiple visible communities."

    if command -v git >/dev/null 2>&1; then
        git -C "$root/git" init -q >/dev/null 2>&1 || true
        git -C "$root/git" config user.email dendrite-test@localhost >/dev/null 2>&1 || true
        git -C "$root/git" config user.name 'Dendrite Graph Test' >/dev/null 2>&1 || true
    fi

    local commands=(cat grep sed awk sort cut tr head tail wc find basename dirname sha256sum base64 printf test)
    for ((i=1; i<=count; i++)); do
        local family=$((i % 10))
        case "$family" in
            0)
                printf 'git graph sample %s\n' "$i" > "$root/git/file-$((i % 48)).txt"
                if command -v git >/dev/null 2>&1; then
                    git -C "$root/git" add . >/dev/null 2>&1 || true
                    if (( i % 25 == 0 )); then
                        git -C "$root/git" commit -qm "graph-$i" >/dev/null 2>&1 || true
                        git -C "$root/git" status --short >/dev/null 2>&1 || true
                        git -C "$root/git" log -1 --oneline >/dev/null 2>&1 || true
                    fi
                fi
                ;;
            1)
                printf 'alpha beta gamma %s\n' "$i" > "$root/text/text-$((i % 64)).log"
                grep -E 'alpha|gamma' "$root/text/text-$((i % 64)).log" >/dev/null 2>&1 || true
                sed 's/beta/delta/' "$root/text/text-$((i % 64)).log" >/dev/null
                awk '{print $1,$NF}' "$root/text/text-$((i % 64)).log" >/dev/null
                ;;
            2)
                seq 1 24 | sort -nr | head -n 7 | tail -n 3 | wc -l >/dev/null
                printf '%s\n' "graph-$i" | tr '[:lower:]' '[:upper:]' | cut -c1-8 >/dev/null
                ;;
            3)
                mkdir -p "$root/config/service-$((i % 20))"
                printf 'enabled=true\niteration=%s\n' "$i" > "$root/config/service-$((i % 20))/config.ini"
                sha256sum "$root/config/service-$((i % 20))/config.ini" >/dev/null
                base64 "$root/config/service-$((i % 20))/config.ini" >/dev/null
                ;;
            4)
                if command -v python3 >/dev/null 2>&1; then
                    python3 -c 'import json,hashlib,sys; print(hashlib.sha256(json.dumps({"n":int(sys.argv[1])}).encode()).hexdigest())' "$i" >/dev/null
                fi
                ;;
            5)
                printf 'archive %s\n' "$i" > "$root/archive/item-$((i % 32)).txt"
                if command -v tar >/dev/null 2>&1 && (( i % 12 == 0 )); then
                    tar -cf "$root/tmp/archive-$((i % 8)).tar" -C "$root/archive" . >/dev/null 2>&1 || true
                fi
                if command -v gzip >/dev/null 2>&1 && (( i % 18 == 0 )); then
                    printf 'gzip %s\n' "$i" | gzip -c > "$root/tmp/data-$((i % 8)).gz"
                fi
                ;;
            6)
                find "$root" -maxdepth 2 -type f -name '*.txt' | head -n 6 >/dev/null
                basename "$root/text/text-$((i % 64)).log" >/dev/null
                dirname "$root/text/text-$((i % 64)).log" >/dev/null
                ;;
            7)
                printf 'log entry %s %s\n' "$i" "$(date +%s%N)" >> "$root/logs/app-$((i % 12)).log"
                tail -n 2 "$root/logs/app-$((i % 12)).log" >/dev/null
                ;;
            8)
                local port=$((9000 + (i % 32)))
                (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null || true
                ;;
            9)
                local cmd="${commands[$((i % ${#commands[@]}))]}"
                case "$cmd" in
                    cat) cat /etc/hostname >/dev/null 2>&1 || true ;;
                    grep) grep -q root /etc/passwd >/dev/null 2>&1 || true ;;
                    sed) sed -n '1p' /etc/hosts >/dev/null 2>&1 || true ;;
                    awk) awk 'NR==1{print $1}' /etc/hosts >/dev/null 2>&1 || true ;;
                    sort) printf 'c\na\nb\n' | sort >/dev/null ;;
                    cut) printf 'a:b:c\n' | cut -d: -f2 >/dev/null ;;
                    tr) printf 'abc\n' | tr a-z A-Z >/dev/null ;;
                    head) head -n 1 /etc/hosts >/dev/null 2>&1 || true ;;
                    tail) tail -n 1 /etc/hosts >/dev/null 2>&1 || true ;;
                    wc) wc -l /etc/hosts >/dev/null 2>&1 || true ;;
                    find) find "$root" -maxdepth 1 -type d >/dev/null ;;
                    basename) basename "$root/tmp" >/dev/null ;;
                    dirname) dirname "$root/tmp/file" >/dev/null ;;
                    sha256sum) printf '%s' "$i" | sha256sum >/dev/null ;;
                    base64) printf '%s' "$i" | base64 >/dev/null ;;
                    printf) printf '%s' "$i" >/dev/null ;;
                    test) test -d "$root" ;;
                esac
                ;;
        esac
    done

    echo "Diverse activity generated. Allowing collectors to drain..."
    sleep 8
    rm -rf "$root"
    echo "Graph activity complete. Current status:"
    cli status
}

run_incidents() {
    echo "Seeding controlled correlated incidents through the debug interface..."
    cli debug seed-incident "stress-correlated-a"
    cli debug seed-incident "stress-correlated-b"
    cli debug seed-incident "stress-correlated-c"
    sleep 1
    cli incidents
}

run_guard() {
    echo "Recording controlled Guard integrity findings..."
    cli debug guard-finding "test:integrity:config" high "Controlled stress-test integrity mismatch"
    cli debug guard-finding "test:integrity:binary" warning "Controlled stress-test protected-object change"
    echo "Temporarily exercising compromised authority state..."
    cli debug guard-state compromised
    local guard_rc=0
    cli guard || guard_rc=$?
    cli debug guard-state trusted
    echo "Guard restored to trusted after test fixture."
    return "$guard_rc"
}

start_api_probe() {
    local output="$1"
    local stop_file="$2"
    : > "$output"
    (
        while [[ ! -e "$stop_file" ]]; do
            local result
            result="$(curl --max-time "$REQUEST_TIMEOUT" -sS -o /dev/null -w '%{http_code} %{time_total}' "$HTTP_BASE/status" 2>/dev/null || true)"
            if [[ "$result" =~ ^2[0-9][0-9][[:space:]] ]]; then
                awk '{ printf "ok %.3f\n", $2 * 1000 }' <<<"$result" >> "$output"
            else
                echo "timeout" >> "$output"
            fi
            sleep 0.25
        done
    ) &
    API_PROBE_PID=$!
}

report_api_probe() {
    local output="$1"
    python3 - "$output" <<'PYPROBE'
import math, sys
path=sys.argv[1]
values=[]; timeouts=0
for line in open(path, encoding='utf-8'):
    parts=line.split()
    if len(parts)==2 and parts[0]=='ok':
        values.append(float(parts[1]))
    else:
        timeouts += 1
values.sort()
def pct(p):
    if not values: return float('nan')
    i=max(0, min(len(values)-1, math.ceil(len(values)*p)-1))
    return values[i]
def f(v): return 'n/a' if math.isnan(v) else f'{v:.1f} ms'
print(f"API during load: samples={len(values)} timeouts={timeouts} p50={f(pct(.50))} p95={f(pct(.95))} p99={f(pct(.99))} max={f(values[-1] if values else float('nan'))}")
PYPROBE
}

run_stress() {
    local before after before_json after_json before_observations after_observations start_ns end_ns elapsed_ms
    echo "== Dendrite stress test =="
    echo "Approximate operations: $STRESS_EVENTS across $STRESS_WORKERS workers"
    echo "API latency before load: $(http_latency_ms /status) ms"
    before="$(cli status)"
    before_json="$(curl --max-time "$REQUEST_TIMEOUT" -fsS "$HTTP_BASE/status" 2>/dev/null || echo '{}')"
    before_observations="$(json_field "$before_json" observations_ingested)"
    printf '%s\n' "$before"

    local root="$WATCH_DIR/stress-$$"
    mkdir -p "$root"
    start_ns="$(date +%s%N)"

    local probe_file="/tmp/dendrite-api-probe-$$.txt"
    local probe_stop="/tmp/dendrite-api-probe-stop-$$"
    rm -f "$probe_stop"
    start_api_probe "$probe_file" "$probe_stop"

    local worker_pids=()
    for ((worker=0; worker<STRESS_WORKERS; worker++)); do
        (
            for ((i=worker+1; i<=STRESS_EVENTS; i+=STRESS_WORKERS)); do
                activity_once "$root" "$i"
            done
        ) &
        worker_pids+=("$!")
    done
    for worker_pid in "${worker_pids[@]}"; do
        wait "$worker_pid"
    done
    touch "$probe_stop"
    wait "$API_PROBE_PID" 2>/dev/null || true

    end_ns="$(date +%s%N)"
    elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
    rm -rf "$root"

    # Let the collector drain its normal interval before measuring the result.
    sleep 4
    after="$(cli status)"
    after_json="$(curl --max-time "$REQUEST_TIMEOUT" -fsS "$HTTP_BASE/status" 2>/dev/null || echo '{}')"
    after_observations="$(json_field "$after_json" observations_ingested)"
    echo
    echo "== Stress result =="
    printf 'Generation time: %d ms\n' "$elapsed_ms"
    if (( elapsed_ms > 0 )); then
        awk -v n="$STRESS_EVENTS" -v ms="$elapsed_ms" 'BEGIN { printf "Generator throughput: %.1f operations/s\n", n/(ms/1000) }'
    fi
    echo "API latency after load: $(http_latency_ms /status) ms"
    report_api_probe "$probe_file"
    rm -f "$probe_file" "$probe_stop"
    echo "Observations ingested during test: $((after_observations - before_observations))"
    printf '%s\n' "$after"
    echo
    echo "Telemetry pipeline:"
    cli telemetry
    local daemon_pid="${DAEMON_PID:-$(pgrep -x dendrited 2>/dev/null | head -n1 || true)}"
    if [[ -n "$daemon_pid" ]]; then
        ps -o pid=,pcpu=,pmem=,rss=,etime= -p "$daemon_pid" | awk '{ printf "Daemon PID %s · CPU %s%% · MEM %s%% · RSS %s KiB · elapsed %s\n", $1,$2,$3,$4,$5 }'
    fi
    if compgen -G 'data/*.sqlite3' >/dev/null; then
        echo "SQLite store sizes:"
        du -h data/*.sqlite3 | sed 's/^/  /'
    fi
    echo
    echo "Recent telemetry:"
    cli telemetry recent 20
    echo
    echo "Incidents:"
    cli incidents
}

case "$MODE" in
    smoke)
        echo "== Initial status =="; cli status
        echo; echo "== Health =="; cli health
        echo; echo "== Initial memory =="; cli memory recent 10

        echo; echo "Generating filesystem smoke fixture..."
        TEST_FILE="$WATCH_DIR/dendrite-smoke-$(date +%s).txt"
        touch "$TEST_FILE"
        echo "hello from Dendrite smoke test" >> "$TEST_FILE"

        # Also exercise the newer mixed process/filesystem/network telemetry path.
        run_activity 12

        # Telemetry polling/fallback collectors may need a normal collection interval.
        sleep 3
        echo; echo "== Status after telemetry =="; cli status
        echo; echo "== Recent memory =="; cli memory recent 10
        echo; echo "== Incidents =="; cli incidents
        rm -f "$TEST_FILE"
        ;;
    activity) run_activity 250; cli telemetry recent 50 ;;
    graph) run_graph_activity "$GRAPH_EVENTS" ;;
    incidents) run_incidents ;;
    guard) run_guard ;;
    stress) run_stress ;;
    full)
        echo "== Initial status =="; cli status
        run_activity 250
        run_incidents
        run_guard
        run_stress
        ;;
esac

echo
echo "Dendrite $MODE test completed."
[[ "$STARTED_DAEMON" == 1 ]] && echo "Daemon log: $LOG_FILE"
