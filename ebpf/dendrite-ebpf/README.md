# dendrite-ebpf

Linux kernel eBPF telemetry program for Dendrite.

This crate produces the BPF object loaded by `dendrited`. It is a `no_std`,
`no_main` Aya eBPF binary and is intentionally excluded from the repository's
normal Cargo workspace.

## What it captures

The current program defines two probes.

### Process execution

Program:

```text
dendrite_process_exec
```

Attachment:

```text
tracepoint sched:sched_process_exec
```

It emits an `EVENT_PROCESS_EXEC` record containing:

- PID
- TGID
- kernel monotonic timestamp
- current Linux command name

Userspace then enriches this with `/proc` information when available and
normalises it into Dendrite observations.

### Outbound network connect

Program:

```text
dendrite_connect
```

Userspace attaches it as a kprobe to:

```text
__sys_connect
```

The program reads the userspace `sockaddr` argument and supports:

- `AF_INET`
- `AF_INET6`

It emits an `EVENT_NETWORK_CONNECT` record containing:

- PID
- TGID
- command name
- address family
- destination address
- destination port
- kernel monotonic timestamp

Unsupported address families are ignored.

## Event transport

Events are written into:

```text
EVENTS
```

an Aya `RingBuf` currently allocated with:

```text
256 KiB
```

The event structure itself comes from:

```text
crates/dendrite-ebpf-common/
```

Do not create a second local copy of the event layout. The kernel producer and
userspace consumer must share the exact same ABI.

## Source structure

```text
src/main.rs
├── LICENSE
├── EVENTS
├── SockAddrIn
├── SockAddrIn6
├── dendrite_process_exec
│   └── try_process_exec
├── dendrite_connect
│   └── try_connect
├── base_event
└── panic_handler
```

The program exports a dual MIT/GPL BPF license string for the kernel loader.

## Build prerequisites

This program is not built by:

```bash
cargo build --workspace
```

Install the eBPF-specific prerequisites:

```bash
rustup toolchain install nightly --component rust-src
```

and install `bpf-linker`.

## Build

Preferred repository command:

```bash
./scripts/build-ebpf.sh
```

Equivalent direct command:

```bash
cargo +nightly build \
  --manifest-path ebpf/dendrite-ebpf/Cargo.toml \
  --target bpfel-unknown-none \
  -Z build-std=core \
  --release
```

Output:

```text
ebpf/dendrite-ebpf/target/bpfel-unknown-none/release/dendrite-ebpf
```

## Userspace loading

`dendrited` loads the resulting object with Aya.

It expects these exact program/map names:

```text
dendrite_process_exec
dendrite_connect
EVENTS
```

The process program is loaded as a tracepoint and attached to:

```text
sched:sched_process_exec
```

The connect program is loaded as a kprobe and attached to:

```text
__sys_connect
```

Renaming any of these requires a corresponding userspace change in
`crates/dendrited/src/telemetry.rs`.

Enable loading with:

```bash
DENDRITE_EBPF=1 target/debug/dendrited
```

Override the object path if required:

```bash
DENDRITE_EBPF_OBJECT=/path/to/dendrite-ebpf
```

## Error handling

Probe entry points return `0` on success and small non-zero codes when an
operation such as reading userspace memory or writing to the ring buffer fails.

For network events:

- unsupported address families are ignored
- failed `sockaddr` reads do not emit partially trusted events
- event output failure is returned as an error code

The panic handler cannot unwind and therefore loops forever, as expected for
this `no_std` BPF target.

## ABI changes

If you change `EbpfEvent` in `dendrite-ebpf-common`:

1. rebuild this eBPF object
2. rebuild `dendrited`
3. run the workspace telemetry tests
4. perform a live eBPF smoke test

Never deploy a kernel object and daemon built against different event layouts.

## Compatibility notes

The current implementation has several deliberate constraints:

- the ring-buffer telemetry path targets Linux 5.8+
- the network probe relies on the `__sys_connect` kernel symbol
- only IPv4 and IPv6 `connect()` attempts are represented
- there is no packet capture
- process exec is captured, but fork and exit do not yet have dedicated event
  records
- eBPF loading requires appropriate Linux capabilities

If eBPF cannot initialise, the userspace daemon is expected to remain alive and
use its process-polling fallback.

## Testing

Build the kernel object:

```bash
./scripts/build-ebpf.sh
```

Build Dendrite:

```bash
cargo build -p dendrited -p dendrite-cli
```

Apply development capabilities as required, then start:

```bash
DENDRITE_EBPF=1 target/debug/dendrited
```

Generate a process event:

```bash
/bin/true
```

Generate a local network event:

```bash
python3 -m http.server 9010 --bind 127.0.0.1
curl http://127.0.0.1:9010/
```

Inspect:

```bash
target/debug/dendrite-cli telemetry recent 50
```

## Security model

This program only produces telemetry.

It cannot directly approve, authorise or execute a Dendrite response. Kernel
events become evidence for higher layers, and privileged actions remain behind:

```text
MAGI → policy → Guard → transaction
```

**Evidence is never authority.**
