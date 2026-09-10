# dendrited

Core Dendrite daemon and host telemetry service.

`dendrited` is the central orchestration process for Dendrite. It is responsible for receiving observations, normalising them into Dendrite's domain model, coordinating the Memory Graph, producing evidence candidates, maintaining incidents, and creating action proposals.

## Intended flow

```text
telemetry
   |
   v
observation
   |
   v
memory ingestion
   |
   v
graph context / detection
   |
   v
evidence candidate
   |
   v
incident
   |
   v
action proposal
```

Action proposals are not action authority.

`dendrited` must not directly bypass quorum, policy, `dendrite-guard`, or the transactional executor.

## Current foundation

The current daemon foundation includes:

- `MemoryStore` ownership;
- observation ingestion;
- object/node persistence;
- relationship observation consolidation;
- graph threat-path lookup;
- conversion of graph findings into evidence candidates;
- basic incident/evidence storage;
- action-proposal creation.

Persistent incident storage, authenticated IPC, and production host telemetry are still to come.

## Future telemetry

Linux telemetry is expected to include mechanisms such as:

- eBPF;
- fanotify;
- filesystem events;
- process events;
- network telemetry.

Telemetry collection should remain separate from privileged action execution.

## Testing

```bash
cargo test -p dendrited
cargo clippy -p dendrited --all-targets -- -D warnings
```
