# dendrite-guard

Independent trust, integrity, and recovery subsystem — the central authority-removal boundary the rest of Dendrite calls through `evaluate_authority`/`trust_state`/`status`/`findings`.

```text
TRUSTED -> DEGRADED -> SUSPECTED -> QUARANTINED -> COMPROMISED -> RECOVERING
```

Action authority is only granted while Guard considers the system trusted. A degraded or compromised state must never increase privileges — it fails closed by design.

> Compromise can remove authority, but cannot create authority.

**Current state is intentionally minimal**: a trust-state enum and an allow/deny match, linked directly into `dendrited`'s own process (no real process boundary yet). Hardening this — including splitting Guard into its own OS process over a dedicated IPC channel — is a deliberately separate, prioritized-ahead-of-destructive-actions batch of work. See `docs/ROADMAP.md`'s Batch 7 findings for the concrete plan and why the four-method call surface above already sets it up well.

## Testing

```bash
cargo test -p dendrite-guard
cargo clippy -p dendrite-guard --all-targets -- -D warnings
```
