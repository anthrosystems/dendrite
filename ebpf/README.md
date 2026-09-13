# Dendrite eBPF

Kernel-side telemetry components for Dendrite.

The `ebpf/` tree is deliberately kept outside the main Cargo workspace because
the eBPF program targets the Linux BPF VM rather than the host userspace target
and requires nightly Rust `build-std`.

## Layout

```text
ebpf/
├── README.md
└── dendrite-ebpf/
    ├── Cargo.toml
    └── src/
        └── main.rs
```

The shared kernel/userspace event ABI is not duplicated here. It lives in:

```text
crates/dendrite-ebpf-common/
```

The userspace loader/consumer lives in:

```text
crates/dendrited/src/telemetry.rs
```

## Current telemetry path

```text
sched:sched_process_exec ─┐
                          ├─> dendrite-ebpf
__sys_connect ────────────┘       │
                                  ▼
                           EVENTS ring buffer
                                  │
                                  ▼
                              dendrited
                                  │
                                  ▼
                       normalised observations
                                  │
                                  ▼
                    Memory Graph / evidence / incidents
```

Dendrite currently captures:

- process execution
- outbound IPv4 connection attempts
- outbound IPv6 connection attempts

When eBPF is active, process polling becomes a standby fallback to avoid
duplicating process-start telemetry. Filesystem telemetry remains independent;
fanotify and eBPF may be active at the same time.

## Why this is outside the workspace

The repository root workspace explicitly excludes:

```text
ebpf/dendrite-ebpf
```

The normal Dendrite crates use the project's stable toolchain. The eBPF program
instead builds for:

```text
bpfel-unknown-none
```

using nightly Rust, `rust-src`, `build-std=core`, and `bpf-linker`.

This separation keeps kernel-specific build requirements from leaking into
ordinary Dendrite development.

## Prerequisites

Install nightly Rust with the standard-library source:

```bash
rustup toolchain install nightly --component rust-src
```

Install `bpf-linker`. One supported development route is:

```bash
cargo binstall bpf-linker
```

when `cargo-binstall` is available.

## Build

From the repository root:

```bash
./scripts/build-ebpf.sh
```

The script runs the equivalent of:

```bash
cargo +nightly build \
  --manifest-path ebpf/dendrite-ebpf/Cargo.toml \
  --target bpfel-unknown-none \
  -Z build-std=core \
  --release
```

The default output is:

```text
ebpf/dendrite-ebpf/target/bpfel-unknown-none/release/dendrite-ebpf
```

## Running Dendrite with eBPF enabled

Build the userspace daemon normally, build the eBPF object, then enable the
collector:

```bash
DENDRITE_EBPF=1 \
target/debug/dendrited
```

The object path defaults to:

```text
ebpf/dendrite-ebpf/target/bpfel-unknown-none/release/dendrite-ebpf
```

Override it with:

```bash
DENDRITE_EBPF_OBJECT=/path/to/dendrite-ebpf
```

If loading or attaching the eBPF programs fails, Dendrite is designed to keep
running and fall back to `/proc` process polling.

## Development capabilities

Loading the current tracing programs requires Linux capabilities. For the
development build, Dendrite currently uses:

```bash
sudo setcap \
  cap_bpf,cap_perfmon,cap_sys_admin,cap_dac_read_search+ep \
  target/debug/dendrited
```

Check them with:

```bash
getcap target/debug/dendrited
```

Remove them when finished:

```bash
sudo setcap -r target/debug/dendrited
```

`CAP_SYS_ADMIN` is deliberately treated as a development bridge rather than a
good long-term privilege model. Packaging should place required capabilities
and isolation at the service boundary.

## Quick functional test

Start the daemon with eBPF enabled:

```bash
DENDRITE_EBPF=1 target/debug/dendrited
```

In another terminal, create a short-lived process:

```bash
/bin/true
```

For a local network event:

```bash
python3 -m http.server 9010 --bind 127.0.0.1
```

and from another shell:

```bash
curl http://127.0.0.1:9010/
```

Then inspect telemetry:

```bash
target/debug/dendrite-cli telemetry recent 50
```

Expected eBPF-backed observations include process execution and a connection to
`127.0.0.1:9010`.

## Current boundaries

The current implementation intentionally does not claim full kernel visibility.

It does not yet capture:

- explicit fork/clone lifecycle events as their own event class
- process exit as its own event class
- passive accept/listen network activity
- packet-level traffic
- Unix-domain socket activity
- arbitrary syscall telemetry

The current network probe attaches to the kernel `__sys_connect` symbol, so
kernel compatibility must be tested on supported distributions.

The ring-buffer path requires a sufficiently modern Linux kernel; Dendrite's
current development documentation targets Linux 5.8+ for this path.

## Security model

eBPF is a telemetry source, not an authority source.

Kernel observations may contribute to:

```text
telemetry
→ observations
→ Memory Graph
→ evidence
→ incidents
```

but any privileged response still goes through Dendrite's normal authority
boundary:

```text
MAGI → policy → Guard → PREPARE → REVALIDATE → COMMIT → VERIFY
```

**Evidence is never authority.**
