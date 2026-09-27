# dendrite-memory

Dendrite's Memory Graph and memory lifecycle: typed nodes/relationships, bounded strength/confidence/decay, lifecycle state (`OBSERVED -> CORRELATED -> SUPPORTED -> ESTABLISHED`, plus `CONTRADICTED`/`SUPERSEDED`/`EXPIRED`/`REVOKED`), repeated-observation consolidation, and graph-reasoning primitives (neighbour discovery, bounded traversal, ranked threat-path finding).

The crate provides topology and path primitives, not security authority — a graph result may contribute evidence to `dendrited`, but must never bypass MAGI, policy, Guard, or transactional execution.

## Storage

SQLite-backed, split into two physical tiers — short-term (STM) and long-term (LTM) — each with its own writer-actor thread and connection, coordinated so a batch of routine ingestion can read its own earlier writes within one transaction. See `docs/architecture.md` for the full model and `docs/PERFORMANCE.md`'s batching-redesign notes for why this is tiered rather than one connection.

Stored values are decoded and validated at the storage boundary; corrupt semantic values surface as explicit storage errors rather than being silently accepted.

## Tests

```bash
cargo test -p dendrite-memory
cargo clippy -p dendrite-memory --all-targets -- -D warnings
```
