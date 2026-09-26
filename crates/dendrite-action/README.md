# dendrite-action

Dendrite's narrow privileged-action boundary: the only place a detection, incident, or action proposal can turn into a real privileged operation, and only after every gate below approves.

```text
Action proposal -> MAGI / quorum -> Policy -> Guard authority -> Transactional executor
```

```text
PROPOSAL -> PREPARE -> REVALIDATE -> COMMIT -> VERIFY
```

Revalidation runs immediately before commit to reduce TOCTOU risk. Executors expose narrow typed capabilities (observe, warn, restrict/suspend/terminate process, quarantine object, block network destination, isolate host) rather than arbitrary shell or script execution.

> Compromise can remove authority, but cannot create authority.

**Production destructive executors are not yet implemented** — see `docs/ROADMAP.md` for where this sits relative to the `dendrite-guard` process-isolation work it's deliberately sequenced behind. See `docs/architecture.md` for the full authorisation-pipeline design and `docs/API.md` for the action-proposal and MAGI-verdict shapes.

## Testing

```bash
cargo test -p dendrite-action
cargo clippy -p dendrite-action --all-targets -- -D warnings
```
