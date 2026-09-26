# dendrite-updater

Software update and remediation subsystem: Dendrite's package verification, application, and rollback boundary, built on the host's own package manager rather than arbitrary downloaded installers or scripts.

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

Updates are executed only through this boundary and only under policy/authorisation, the same rule as `dendrite-action`: a remediation candidate is not remediation authority.

See `docs/VULNERABILITIES_AND_UPDATES.md` for the current implementation (including `execute_authorised_vulnerability_update`), what's already enforced, and what's still planned (anti-downgrade protection, provenance/audit records).

## Testing

```bash
cargo test -p dendrite-updater
cargo clippy -p dendrite-updater --all-targets -- -D warnings
```
