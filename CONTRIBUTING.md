# Contributing to Dendrite

Thank you for contributing to Dendrite.

Dendrite is a Linux-native endpoint security project. Changes that affect privilege,
authority, telemetry, persistence, containment, recovery, or trust boundaries require
particular care.

## Before contributing

For bugs and feature requests, check existing issues first.

Do not open a public issue for a suspected security vulnerability. Follow
[`SECURITY.md`](SECURITY.md) instead.

## Development environment

Dendrite is primarily developed and tested on Linux.

Install Rust using `rustup` and ensure the `rustfmt` and `clippy` components are
available:

```bash
rustup component add rustfmt clippy
```

Clone the repository and run:

```bash
cargo check --workspace
cargo test --workspace
```

## Required checks

Before submitting a pull request, run:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

Pull requests should not knowingly introduce warnings.

## Architecture

The workspace currently contains:

```text
crates/
├── dendrited
├── dendrite-cli
├── dendrite-memory
├── dendrite-action
├── dendrite-guard
├── dendrite-updater
└── dendrite-protocol
```

The project follows the principle:

> Repository != crate != process != security boundary.

Keep dependencies and authority boundaries narrow.

## Security invariants

The normal response path is:

```text
Detection
    |
    v
Evidence
    |
    v
Incident
    |
    v
Action proposal
    |
    v
MAGI evaluation
    |
    v
Quorum
    |
    v
Policy
    |
    v
Guard authority
    |
    v
Transactional execution
```

A detection, model result, Memory Graph finding, incident, or evidence object must not
grant itself action authority.

Privileged action execution must follow:

```text
PROPOSAL -> PREPARE -> REVALIDATE -> COMMIT -> VERIFY
```

State used to authorise an operation must be revalidated immediately before commit
where TOCTOU is relevant.

Additional principles:

- compromise may remove authority, but must not create authority;
- security-sensitive boundaries should fail closed;
- privileged executors should expose narrow typed operations rather than arbitrary
  shell execution;
- stored or recalled memory is context and evidence, not authority;
- provenance should be retained for security-relevant conclusions;
- destructive behaviour must have explicit tests for rejection and failure paths.

## Rust style

Use standard Rust formatting via `rustfmt`.

Prefer clear domain types over loosely typed strings or integers where practical.
Validate external or persisted data at subsystem boundaries.

British English spelling is preferred in project-owned identifiers and documentation
where it does not conflict with external APIs or established ecosystem terminology.

Examples include:

- `initialise`
- `behaviour`
- `normalise`
- `visualisation`

## Tests

New behaviour should normally include tests.

Security-sensitive changes should test at least:

- the successful path;
- rejection/denial;
- malformed or invalid input;
- boundary values;
- failure before privileged commit where applicable.

Tests should be deterministic and should not require external network access unless
the test is explicitly designed and isolated as an integration test.

## Commits

Keep commits focused and descriptive.

Conventional-style messages are welcome, for example:

```text
feat: add incident correlation
fix: reject expired action authorisation
test: cover relationship decay boundaries
docs: document guard trust states
```

They are not mandatory unless repository policy changes in future.

## Pull requests

A pull request should explain:

- what changed;
- why it changed;
- how it was tested;
- any security or trust-boundary implications.

Large architectural changes should be split when doing so makes review and rollback
safer.

## Generated files and secrets

Do not commit:

- `target/`;
- credentials or API tokens;
- private keys;
- host-specific secrets;
- personal telemetry;
- production quarantine content;
- local databases containing sensitive data.

Use test fixtures containing synthetic data where possible.

## Licence

By contributing to Dendrite, you agree that your contributions are licensed under
the repository's Apache License 2.0.
