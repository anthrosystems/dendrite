# dendrite-cli

Command-line interface for Dendrite.

The public CLI command is:

```text
dendrite
```

The CLI is intended for local and remote administrative interaction with Dendrite through authenticated service interfaces.

## Current commands

The foundation currently scaffolds:

```text
dendrite status
dendrite incidents
dendrite memory
dendrite actions
dendrite health
dendrite version
```

These commands are placeholders until daemon IPC is implemented.

## Intended responsibilities

The CLI should eventually support:

- daemon status;
- incident inspection;
- evidence inspection;
- Memory Graph queries;
- approved action workflows;
- guard/trust health;
- update/remediation status;
- diagnostics.

The CLI should not contain privileged security logic itself.

## Testing

```bash
cargo test -p dendrite-cli
cargo clippy -p dendrite-cli --all-targets -- -D warnings
```
