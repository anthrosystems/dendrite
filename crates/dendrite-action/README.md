# dendrite-action

Privileged action execution and containment.

`dendrite-action` defines Dendrite's narrow privileged-action boundary.

The crate is intentionally structured so that a detection, incident, or action proposal cannot directly perform a privileged operation.

## Authorisation

Execution requires all required gates to approve:

```text
Action proposal
      |
      v
MAGI / quorum
      |
      v
Policy
      |
      v
Guard authority
      |
      v
Transactional executor
```

## Transaction lifecycle

```text
PROPOSAL -> PREPARE -> REVALIDATE -> COMMIT -> VERIFY
```

Revalidation is required immediately before commit to reduce TOCTOU risk.

## Executor design

Executors should expose narrow typed capabilities rather than arbitrary shell or script execution.

Potential action types include:

- observe;
- warn;
- restrict process;
- suspend process;
- terminate process;
- quarantine object;
- block network destination;
- isolate host.

Production destructive executors are not implemented in the current foundation.

## Security principle

> Compromise can remove authority, but cannot create authority.

An unauthorised proposal must never reach the executor.

## Testing

```bash
cargo test -p dendrite-action
cargo clippy -p dendrite-action --all-targets -- -D warnings
```
