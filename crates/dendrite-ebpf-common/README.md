# dendrite-ebpf-common

Shared ABI types and constants used by Dendrite's kernel eBPF program and the
userspace `dendrited` collector.

This crate is intentionally small and `no_std`. Its main job is to keep the
binary event layout identical on both sides of the BPF ring buffer.

## Role in Dendrite

```text
kernel eBPF program
        │
        │ EbpfEvent
        ▼
    EVENTS ring buffer
        │
        │ same shared layout
        ▼
     dendrited
        │
        ▼
normalised Observation
        │
        ▼
Memory Graph / evidence / incidents
```

The eBPF program lives in:

```text
ebpf/dendrite-ebpf/
```

The userspace consumer lives primarily in:

```text
crates/dendrited/src/telemetry.rs
```

Both depend on this crate so event IDs, address-family values, command-name
lengths and the `EbpfEvent` memory layout do not drift independently.

## Current event classes

The crate currently defines:

```rust
EVENT_PROCESS_EXEC
EVENT_NETWORK_CONNECT
```

These correspond to:

- process execution from `sched:sched_process_exec`
- outbound IPv4/IPv6 connection attempts from the eBPF `connect` probe

It also defines the address-family values used by the wire format:

```rust
ADDRESS_FAMILY_INET
ADDRESS_FAMILY_INET6
```

and:

```rust
COMM_LEN
```

for the fixed-size Linux command-name field.

## `EbpfEvent`

`EbpfEvent` is a `#[repr(C)]` structure shared across the kernel/userspace
boundary.

Current fields include:

- event kind
- address family
- PID
- TGID
- kernel monotonic timestamp
- destination port
- 16-byte address storage
- fixed-size process command name
- reserved padding used to keep the ABI explicit and stable

The 16-byte address field stores either:

- the first 4 bytes as an IPv4 address, or
- all 16 bytes as an IPv6 address

`EbpfEvent::zeroed(kind)` creates a zero-initialised event with the supplied
event class.

## ABI rules

Changes to `EbpfEvent` are protocol changes between the kernel program and
`dendrited`.

When modifying it:

1. keep `#[repr(C)]`
2. use fixed-size, BPF-safe fields
3. avoid heap-backed or Rust-layout-dependent types
4. update both producer and consumer logic
5. verify the event-size/layout tests
6. rebuild the eBPF object

Do not casually reorder fields. Even when both source trees compile, loading a
kernel object built against one layout while running a userspace daemon built
against another can corrupt event interpretation.

## Why this is a separate crate

The main Dendrite workspace builds with the project's normal Rust toolchain,
while the kernel program is built separately for:

```text
bpfel-unknown-none
```

with nightly Rust and `build-std`.

Keeping the shared ABI in a tiny `no_std` crate lets both build domains consume
the same definitions without pulling userspace-only dependencies into the eBPF
program.

## Build and test

From the repository root, this crate is part of the normal workspace:

```bash
cargo check -p dendrite-ebpf-common
cargo test -p dendrite-ebpf-common
```

To validate the complete userspace workspace:

```bash
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

To rebuild the kernel eBPF program after an ABI change:

```bash
./scripts/build-ebpf.sh
```

## Security boundary

This crate defines telemetry data only.

An `EbpfEvent` is evidence. It does not grant action authority and does not
bypass Dendrite's normal:

```text
MAGI → policy → Guard → transaction
```

path.

**Evidence is never authority.**
