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
separately). curl, a C compiler (build-essential — rusqlite's "bundled"
feature compiles SQLite from source), and the workspace gate itself
(fmt/check/test/clippy, then the real dendrited/dendrite-cli build) are all
on the critical path instead — this script exits immediately (via `set -e`)
on the first failure among those, same as the manual command sequence it
replaces.
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

# cargo install/cargo binstall always place user-level tool binaries (like
# cargo-binstall itself, and bpf-linker below) in $CARGO_HOME/bin regardless
# of how the toolchain itself got installed. The rustup.rs shell installer
# adds this to PATH via ~/.cargo/env, sourced below right after installing
# it — but that only runs when this script is the one installing rustup. A
# system that already has a working `cargo` (e.g. a distro-packaged rustup,
# which some recent Ubuntu releases ship system-wide under /usr/bin) skips
# that branch entirely, and this directory is then silently missing from
# PATH for the rest of this script — breaking cargo-binstall's own
# --self-install (it warns and exits rather than failing loudly) and
# `command -v cargo-binstall` right after it, which together send the eBPF
# section down its from-source `cargo install bpf-linker` fallback instead
# — a path that needs a matching local LLVM/llvm-config and is exactly the
# failure this line prevents. Harmless no-op if the directory doesn't exist
# yet; `source "$HOME/.cargo/env"` below still runs too when applicable, it
# just has nothing left to add at that point.
export PATH="$HOME/.cargo/bin:$PATH"

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
echo "-- workspace gate: fmt/check/test/clippy --"
if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
    echo "No C compiler found — installing build-essential (rusqlite's \"bundled\" feature compiles SQLite from source, needing one)..."
    ensure_apt_packages build-essential
fi
cargo fmt --all
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings

echo
echo "-- dendrited + dendrite-cli --"
cargo build -p dendrited -p dendrite-cli

EBPF_OBJECT="ebpf/dendrite-ebpf/target/bpfel-unknown-none/release/dendrite-ebpf"
echo
echo "-- eBPF collector --"
if [[ "$SKIP_EBPF" == 1 ]]; then
    echo "Skipped (--skip-ebpf)."
elif [[ -f "$EBPF_OBJECT" && "$FORCE" != 1 ]]; then
    echo "Already built: $EBPF_OBJECT (use --force to rebuild)"
else
    # build-ebpf.sh is self-sufficient as of the vmlinux.rs/sched_process_exec
    # patch: it installs its own toolchain (nightly, rust-src, bpf-linker,
    # libelf-dev/zlib1g-dev) and, if ebpf/dendrite-ebpf/src/vmlinux.rs is
    # missing, the kernel-struct-bindings toolchain (bpftool, bindgen-cli,
    # aya-tool) needed to generate it too — nothing left to pre-install here.
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