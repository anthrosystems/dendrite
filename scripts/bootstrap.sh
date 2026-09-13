#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

usage() {
    cat <<USAGE
Usage: $0 [--skip-ebpf] [--skip-ui] [--skip-capabilities] [--force]

Local (not distribution) packaging: gets a fresh clone of this repository to
a runnable state with one command — builds dendrited/dendrite-cli, the eBPF
collector, and the UI, and sets up the development 'dendrite' group and
binary capabilities. Idempotent: re-running skips anything already built,
so this is also safe to call from scripts/launch_host_a.sh on every run,
not just the first one.

This is a dev convenience, not the real distribution packaging (.deb, a
dedicated service account, systemd units) — that's a separate, later
concern. See docs/ROADMAP.md's Batch 7.

Flags:
  --skip-ebpf          Don't build the eBPF object.
  --skip-ui            Don't build the UI.
  --skip-capabilities  Don't touch the 'dendrite' group or run setcap
                        (both require sudo).
  --force              Rebuild eBPF/UI even if already built.
  -h, --help            Show this help.

Any of the four steps below can also fail *individually* without aborting
the others — if eBPF's toolchain (nightly, bpf-linker, libelf-dev,
zlib1g-dev) or the UI's (npm) needs installing, this script installs it
automatically via apt where possible. Genuine build failures after that
(not just a missing tool) fall back to a warning rather than aborting,
since eBPF and the UI are both optional at runtime (Dendrite falls back to
fanotify/polling, and the UI can still be run via 'npm run dev'
separately). curl and a C compiler (build-essential — rusqlite's "bundled"
feature compiles SQLite from source) are on the critical path instead,
since nothing else in this script can proceed without them, so those two
fail the whole script rather than degrading.
USAGE
}

SKIP_EBPF=0
SKIP_UI=0
SKIP_CAPABILITIES=0
FORCE=0
for arg in "$@"; do
    case "$arg" in
        --skip-ebpf) SKIP_EBPF=1 ;;
        --skip-ui) SKIP_UI=1 ;;
        --skip-capabilities) SKIP_CAPABILITIES=1 ;;
        --force) FORCE=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $arg" >&2; usage >&2; exit 2 ;;
    esac
done

echo "== Dendrite local bootstrap =="

APT_UPDATED=0
ensure_apt_packages() {
    if ! command -v apt-get >/dev/null 2>&1; then
        echo "Warning: apt-get not available — can't install: $*" >&2
        echo "  Install these yourself with your system's package manager, then re-run this script." >&2
        return 1
    fi
    if [[ "$APT_UPDATED" == 0 ]]; then
        sudo apt-get update
        APT_UPDATED=1
    fi
    sudo apt-get install -y "$@"
}

if ! command -v curl >/dev/null 2>&1; then
    echo "curl not found — installing it first (needed to install rustup)..."
    ensure_apt_packages curl
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo/rustup not found — installing rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
    echo "rustup installed. rust-toolchain.toml pins the exact version (1.98.0) it'll use for this repo automatically."
fi

echo
echo "-- dendrited + dendrite-cli --"
if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
    echo "No C compiler found — installing build-essential (rusqlite's \"bundled\" feature compiles SQLite from source, needing one)..."
    ensure_apt_packages build-essential
fi
cargo build -p dendrited -p dendrite-cli

EBPF_OBJECT="ebpf/dendrite-ebpf/target/bpfel-unknown-none/release/dendrite-ebpf"
echo
echo "-- eBPF collector --"
if [[ "$SKIP_EBPF" == 1 ]]; then
    echo "Skipped (--skip-ebpf)."
elif [[ -f "$EBPF_OBJECT" && "$FORCE" != 1 ]]; then
    echo "Already built: $EBPF_OBJECT (use --force to rebuild)"
else
    if ! cargo +nightly --version >/dev/null 2>&1; then
        echo "Installing nightly toolchain (needed for eBPF)..."
        rustup toolchain install nightly
    fi
    if ! rustup target list --toolchain nightly --installed 2>/dev/null | grep -q '^bpfel-unknown-none$'; then
        rustup target add bpfel-unknown-none --toolchain nightly
    fi
    # bpf-linker links against libelf/zlib at build and/or link time; not
    # detectable via a simple `command -v` check the way a binary is, so
    # these are just always ensured present before it's needed rather than
    # probed for.
    ensure_apt_packages libelf-dev zlib1g-dev || true
    if ! command -v bpf-linker >/dev/null 2>&1; then
        echo "Installing bpf-linker (needed for eBPF)..."
        # No +toolchain override here — bpf-linker itself just needs a normal
        # (non-nightly) Rust to build, and running from inside the repo
        # already resolves to the pinned 1.98.0 via rust-toolchain.toml,
        # which is guaranteed installed already (step 1 just used it). An
        # explicit `+stable` would risk referencing a toolchain that was
        # never separately installed, since we deliberately install rustup
        # above with --default-toolchain none.
        if command -v cargo-binstall >/dev/null 2>&1; then
            cargo binstall --no-confirm bpf-linker
        else
            cargo install bpf-linker
        fi
    fi
    if bash "$SCRIPT_DIR/build-ebpf.sh"; then
        :
    else
        echo "Warning: eBPF build failed even after installing its toolchain — see the error above." >&2
        echo "  Dendrite still runs fine without it, via fanotify + polling fallback collectors." >&2
    fi
fi

echo
echo "-- UI --"
if [[ "$SKIP_UI" == 1 ]]; then
    echo "Skipped (--skip-ui)."
elif [[ -f "ui/dist/index.html" && "$FORCE" != 1 ]]; then
    echo "Already built: ui/dist (use --force to rebuild)"
else
    if ! command -v npm >/dev/null 2>&1; then
        echo "npm not found — installing Node.js/npm..."
        ensure_apt_packages nodejs npm || true
    fi
    if command -v npm >/dev/null 2>&1; then
        (cd ui && npm install && npm run build)
    else
        echo "Warning: npm still not available — skipping UI build." >&2
        echo "  Install Node.js/npm yourself, then re-run this script or: cd ui && npm install && npm run build" >&2
    fi
fi

echo
echo "-- dendrite group + capabilities --"
if [[ "$SKIP_CAPABILITIES" == 1 ]]; then
    echo "Skipped (--skip-capabilities)."
elif getcap target/debug/dendrited 2>/dev/null | grep -q 'cap_dac_read_search.*cap_sys_admin.*cap_perfmon.*cap_bpf' \
    && getent group dendrite >/dev/null 2>&1 \
    && id -nG "$USER" | grep -qw dendrite; then
    echo "Already set up (group exists, you're in it, binary has the right capabilities)."
else
    sudo groupadd --system dendrite 2>/dev/null || true
    sudo usermod -aG dendrite "$USER"
    sudo setcap cap_bpf,cap_perfmon,cap_sys_admin,cap_dac_read_search+ep target/debug/dendrited
    echo "If you weren't already in the 'dendrite' group, log out/in (or run 'newgrp dendrite') for it to take effect in this shell."
fi

echo
echo "Bootstrap complete. Run: scripts/launch_host_a.sh"