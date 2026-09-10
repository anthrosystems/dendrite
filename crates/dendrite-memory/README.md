# dendrite-memory

Dendrite Memory Graph and memory lifecycle.

`dendrite-memory` is the semantic and temporal memory subsystem used by `dendrited`. It provides structured graph models, SQLite-backed persistence, lifecycle management, observation consolidation, and graph-reasoning primitives.

## Responsibilities

The crate currently handles:

- memory nodes and relationships;
- typed node and relationship kinds;
- bounded strength, confidence, and decay values;
- short-term, long-term, and persistent retention;
- lifecycle state;
- expiry and purge eligibility;
- linear and exponential decay;
- reinforcement and revocation;
- repeated-observation consolidation;
- inbound and outbound relationship queries;
- neighbour discovery;
- bounded breadth-first traversal;
- directional path finding;
- filtering by relationship kind, state, strength, confidence, and evaluation time;
- ranked paths to threat nodes.

## Memory states

```text
OBSERVED
CORRELATED
SUPPORTED
ESTABLISHED
CONTRADICTED
SUPERSEDED
EXPIRED
REVOKED
```

Only reasoning-active states should participate in normal graph reasoning.

## Lifecycle

Nodes and relationships expire independently.

Relationships are expected to decay and expire more aggressively than nodes. Expired data is not necessarily deleted immediately; purge eligibility is evaluated separately and persistent memories are protected from ordinary purging.

Decay is evaluated non-destructively against stored baseline strength, avoiding repeated maintenance passes compounding decay incorrectly.

## Observation consolidation

Repeated observations of the same semantic relationship are consolidated instead of creating a permanent edge for every raw event.

A consolidated relationship tracks information such as:

- `created_at`
- `last_seen_at`
- `observation_count`
- `expires_at`
- state
- retention
- decay policy
- strength
- confidence
- reinforcement provenance

## Reasoning

The crate provides topology and path primitives, not security authority.

A graph result may contribute evidence to `dendrited`, but `dendrite-memory` must not execute actions or bypass MAGI, policy, guard, or transactional execution.

## Storage

SQLite is currently used as the backing store.

Stored values are decoded and validated at the storage boundary. Corrupt semantic values are surfaced through explicit storage errors rather than silently accepted.

## Tests

```bash
cargo test -p dendrite-memory
cargo clippy -p dendrite-memory --all-targets -- -D warnings
```
