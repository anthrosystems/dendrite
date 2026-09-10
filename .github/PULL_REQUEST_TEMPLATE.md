## Summary

Describe what this change does and why.

## Changes

- 
- 

## Testing

Describe the tests and checks you ran.

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

## Security impact

Describe any effect on:

- privilege or authority;
- IPC or trust boundaries;
- telemetry collection;
- Memory Graph semantics;
- incident/evidence handling;
- containment or remediation;
- recovery or anti-tamper behaviour.

Write `None` if the change has no security impact.

## Checklist

- [ ] The change is scoped to the stated purpose.
- [ ] Tests cover the important behaviour.
- [ ] No secrets, credentials, tokens, private host data, or generated build artefacts are included.
- [ ] Security-sensitive changes fail closed where appropriate.
- [ ] Detection/evidence does not bypass quorum, policy, guard, or transactional execution.
- [ ] Public documentation was updated where behaviour changed.
