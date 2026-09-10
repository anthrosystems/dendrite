# dendrite-updater

Software update and remediation subsystem.

`dendrite-updater` defines Dendrite's package remediation, verification, and rollback boundary.

## Intended model

Dendrite should use the operating system's package manager rather than arbitrary downloaded installers or scripts.

The intended update flow is:

```text
candidate
   |
   v
verification
   |
   v
package-manager plan
   |
   v
apply
   |
   v
verify
   |
   +---- failure ----> rollback
```

## Security requirements

The production updater should eventually support:

- signed update verification;
- atomic or transaction-like updates where the OS permits;
- rollback;
- anti-downgrade protection;
- provenance and audit records;
- policy-controlled remediation.

The current foundation includes only interfaces and does not mutate host packages.

## Testing

```bash
cargo test -p dendrite-updater
cargo clippy -p dendrite-updater --all-targets -- -D warnings
```
