# dendrite-protocol

Shared domain types and IPC/API protocol definitions.

`dendrite-protocol` provides the common vocabulary shared across Dendrite crates.

It is kept deliberately small and should not contain subsystem implementation logic.

## Current domain types

The crate contains shared definitions for:

- identifiers;
- observations;
- object descriptors;
- evidence;
- incidents;
- severity and confidence;
- action proposals;
- action types;
- MAGI evaluators and verdicts;
- quorum decisions and policy;
- action authorisation;
- transaction state;
- guard decisions;
- trust states;
- integrity findings;
- IPC request/response envelopes.

## MAGI

Evaluator identities:

- `Host` — Balthasar
- `User` — Casper
- `Environment` — Melchior

Verdicts:

```text
APPROVE
DENY
ABSTAIN
VETO
```

Protocol types express decisions. They do not perform privileged actions.

## Dependency direction

Other crates may depend on `dendrite-protocol`.

`dendrite-protocol` should avoid depending on implementation crates so that shared contracts remain stable and dependency cycles are avoided.

## Testing

```bash
cargo test -p dendrite-protocol
cargo clippy -p dendrite-protocol --all-targets -- -D warnings
```
