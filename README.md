# Dendrite

[![CI](https://github.com/anthrosystems/dendrite/actions/workflows/ci.yml/badge.svg)](https://github.com/anthrosystems/dendrite/actions/workflows/ci.yml)  [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) [![GitHub Release](https://img.shields.io/github/v/release/anthrosystems/dendrite.svg)](https://github.com/anthrosystems/dendrite/releases/latest)

Linux-native endpoint security and threat detection platform with adaptive memory, behavioural analysis, and autonomous response.

Dendrite is an open-source endpoint security project by Anthrosystems. It is designed around an immune-system-inspired architecture: observations are collected from the host, correlated into incidents, enriched through a temporal Memory Graph, evaluated by independent decision components, and only then allowed to progress toward privileged response.

> Copyright 2026 Anthrosystems

## Project status

Dendrite is under active development.

The current implementation includes:

- a Rust workspace containing the core daemon and supporting subsystems;
- a SQLite-backed temporal Memory Graph;
- node and relationship lifecycle handling;
- expiry, purge eligibility, decay, and reinforcement;
- observation consolidation;
- graph traversal and bounded breadth-first search;
- filtered and directional path finding;
- threat-path discovery and ranking;
- shared protocol/domain types;
- daemon-side observation-to-memory integration;
- incident and evidence-candidate scaffolding;
- MAGI/quorum decision types;
- action transaction interfaces;
- guard/trust-state interfaces;
- updater/package-manager interfaces;
- CLI scaffolding.

Privileged containment, anti-tamper enforcement, authenticated IPC, kernel telemetry, and production package mutation are intentionally not yet implemented.

## Architecture

The intended high-level flow is:

```text
Host telemetry
      |
      v
  dendrited
      |
      v
Normalised observation
      |
      v
Memory Graph
      |
      v
Detection / correlation
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
Transactional executor
```

Dendrite separates detection from authority. A threat finding may create evidence, an incident, or an action proposal, but evidence must never grant itself permission to execute an action.

The intended action lifecycle is:

```text
PROPOSAL -> PREPARE -> REVALIDATE -> COMMIT -> VERIFY
```

TOCTOU-sensitive state must be revalidated before commit.

## MAGI

Dendrite uses three independent evaluator roles:

- **Balthasar — Host**
- **Casper — User**
- **Melchior — Environment**

Evaluator verdicts are:

- `APPROVE`
- `DENY`
- `ABSTAIN`
- `VETO`

Quorum and policy are action-specific. No single detection component should be able to bypass the decision and authority chain.

## Memory Graph

`dendrite-memory` provides Dendrite's temporal, provenance-aware, confidence-aware, decaying Memory Graph.

Memory states currently include:

```text
OBSERVED
CORRELATED
SUPPORTED
ESTABLISHED
CONTRADICTED
SUPERSEDED
EXPIRED
REVOKED
```

The Memory Graph supports:

- typed nodes and relationships;
- short-term, long-term, and persistent retention;
- independent node and relationship expiry;
- relationship-first decay;
- linear and exponential decay;
- reinforcement with provenance;
- observation aggregation;
- graph neighbours and traversal;
- directional path queries;
- filtering by relationship kind, state, strength, and confidence;
- time-aware effective-strength evaluation;
- ranked paths to known threat nodes.

Raw events should not become permanent graph edges one-for-one. Repeated observations are consolidated into relationships with fields such as observation count, first/last-seen time, confidence, strength, state, and provenance.

## Workspace

```text
dendrite/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── LICENSE
├── SECURITY.md
├── crates/
│   ├── dendrited/
│   ├── dendrite-cli/
│   ├── dendrite-memory/
│   ├── dendrite-action/
│   ├── dendrite-guard/
│   ├── dendrite-updater/
│   └── dendrite-protocol/
├── python/
│   ├── training/
│   ├── datasets/
│   ├── experiments/
│   └── tools/
├── models/
├── migrations/
├── configs/
├── packaging/
├── tests/
├── docs/
└── scripts/
```

Repository, crate, process, and security boundary are deliberately treated as different concepts.

## Crates

### `dendrited`

Core Dendrite daemon and host telemetry service.

Owns orchestration, observation ingestion, Memory Graph coordination, evidence/incident flow, and the transition toward action proposals.

### `dendrite-cli`

Command-line interface for Dendrite.

The CLI will communicate with Dendrite services through authenticated IPC. The current implementation provides the command hierarchy and placeholder rendering.

### `dendrite-memory`

Dendrite Memory Graph and memory lifecycle.

Provides graph models, SQLite persistence, lifecycle, decay, reinforcement, observation consolidation, traversal, and threat-path reasoning primitives.

### `dendrite-action`

Privileged action execution and containment.

Defines authorisation and transactional execution boundaries. Production destructive executors are deliberately not implemented yet.

### `dendrite-guard`

Independent trust, integrity, and recovery subsystem.

Acts as a separate authority boundary and is intended to protect Dendrite's daemon, configuration, quarantine, databases, models, policy, and telemetry mechanisms.

### `dendrite-updater`

Software update and remediation subsystem.

Defines package-manager, verification, update, and rollback interfaces. Production package mutation is not implemented yet.

### `dendrite-protocol`

Shared domain types and IPC/API protocol definitions.

Contains identifiers, observations, evidence, incidents, action proposals, MAGI/quorum types, trust types, and IPC envelopes.

## Development

Requirements:

- Linux development environment;
- Rust toolchain installed through `rustup`;
- SQLite development support if not using the bundled SQLite feature.

Useful checks:

```bash
cargo fmt --all
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

For the Memory Graph specifically:

```bash
cargo test -p dendrite-memory
```

## Python and machine learning

The core runtime is Rust.

Python is reserved for supporting work such as:

- model training;
- datasets;
- experiments;
- telemetry replay;
- threat-intelligence ingestion;
- offline Memory Graph analysis;
- development tooling.

Dovetail may be used for non-security-critical Python workflows, but it must not become part of Dendrite's privileged authority chain.

## Design principles

- Detection and action remain separate.
- Compromise can remove authority, but cannot create authority.
- Privileged executors expose narrow capabilities rather than arbitrary shell execution.
- Memory is fallible context, not authority.
- Evidence carries provenance.
- Important incident and action history remains auditable.
- Expiry and visual disappearance are not equivalent to immediate physical deletion.
- Security-sensitive boundaries should fail closed.
- Expensive ML should be optional, bounded, and secondary to deterministic/statistical filtering where practical.

## Related repositories

- `anthrosystems/dendrite-ui` — web-based interface for Dendrite endpoint security, threat analysis, incidents, system state, and Memory Graph visualisation.
- `anthrosystems/dendrite-mcp` — optional MCP integration for Dendrite.

## Licence

Apache License 2.0.
