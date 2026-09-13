# Dendrite Telemetry

Dendrite normalizes Linux telemetry into observations before graph/correlation reasoning. Raw telemetry is short-lived; semantic Memory Graph knowledge is selective and decays according to memory policy.

## Sources

Current collectors include:

- eBPF process execution/fork/exit and network-connect telemetry;
- fanotify filesystem telemetry;
- `/proc` process polling fallback;
- filesystem polling fallback.

Collector state is exposed through the CLI, HTTP API and Activity/System Health UI.

## Collector precedence and fallback

Dendrite prefers the richer privileged source when available and keeps deterministic fallbacks so a collector failure does not silently stop observation. eBPF/fanotify failure must not grant authority or imply the host is safe.

## Development capabilities

The current development binary can require:

```text
CAP_BPF
CAP_PERFMON
CAP_SYS_ADMIN
CAP_DAC_READ_SEARCH
```

Development setup:

```bash
sudo setcap cap_bpf,cap_perfmon,cap_sys_admin,cap_dac_read_search+ep target/debug/dendrited
```

This is temporary development plumbing. Batch 7 must move capabilities into the packaged systemd service and reduce/isolate privilege where practical.

## Current boundaries

- short-lived processes can still lose perfect PID attribution and collapse to stable process identity;
- fanotify rename/delete/FID handling and dynamic directory marking remain narrower than a full EDR-grade collector;
- telemetry provenance is local today; a future multi-system/federated event stream will need explicit host origin on events rather than inferring it from graph state;
- observations are evidence, not action authority.

Functional and fallback tests live in [`TESTS.md`](TESTS.md).
