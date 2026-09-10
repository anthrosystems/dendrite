# dendrite-guard

Independent trust, integrity, and recovery subsystem.

`dendrite-guard` is intended to act as an independent trust root around Dendrite's security-sensitive components.

## Responsibilities

The final subsystem is expected to protect and assess:

- `dendrited`;
- Dendrite configuration;
- quarantine state;
- databases;
- models;
- policy;
- telemetry mechanisms;
- integrity-critical IPC;
- recovery state.

## Trust states

```text
TRUSTED
DEGRADED
SUSPECTED
QUARANTINED
COMPROMISED
RECOVERING
```

The current foundation only allows action authority while the guard considers the system trusted.

This policy can become more action-specific later, but the initial implementation intentionally fails closed.

## Principle

> Compromise can remove authority, but cannot create authority.

A degraded or compromised state must never increase privileges or action authority.

## Future work

- signed integrity manifests;
- protected health state;
- anti-tamper mechanisms;
- authenticated IPC;
- independent recovery;
- quarantine integrity;
- secure restart/recovery paths.

## Testing

```bash
cargo test -p dendrite-guard
cargo clippy -p dendrite-guard --all-targets -- -D warnings
```
