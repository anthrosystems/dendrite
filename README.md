# Dendrite

[![CI](https://github.com/anthrosystems/dendrite/actions/workflows/ci.yml/badge.svg)](https://github.com/anthrosystems/dendrite/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

**Dendrite is a Linux-native endpoint security platform built around adaptive host memory, contextual threat reasoning, and constrained response authority.**

It is inspired by the human immune system, but the biological language is a design aid rather than a literal implementation model. Dendrite observes a host, builds a model of its **Self**, correlates behaviour through a temporal **Memory Graph**, creates evidence and incidents, and only permits response after independent evaluation, policy, and Guard authority checks.

> **Compromise can remove authority, but cannot create authority.**

Dendrite is an open-source project by Anthrosystems.

## Why Dendrite exists

Traditional endpoint protection is good at asking whether a file, process, or behaviour is known to be malicious. Dendrite adds another question:

> **Does this behaviour belong on this particular host, in this context, at this time?**

That requires more than a flat signature database. Dendrite is designed to accumulate security knowledge over time, distinguish host-specific normality from shared threat knowledge, revise what it believes as evidence changes, and keep detection separate from privileged action.

A mature Dendrite installation should be able to learn what is normal without becoming dependent on that learning. A newly installed Dendrite must still protect a host even if the machine was already compromised before installation.

## Core flow

```text
Linux telemetry
      ↓
normalised observations
      ↓
Memory Graph + Self + threat knowledge
      ↓
detection / correlation
      ↓
evidence
      ↓
incident
      ↓
action proposal
      ↓
Host / User / Environment evaluation
      ↓
quorum
      ↓
policy
      ↓
Guard authority
      ↓
PREPARE → REVALIDATE → COMMIT → VERIFY
```

Detection can create evidence, incidents, and action proposals. It cannot grant itself authority to execute an action.

## Current implementation

The repository currently includes:

- Rust workspace with `dendrited`, CLI, Memory Graph, action, Guard, updater, and shared protocol crates;
- SQLite-backed temporal Memory Graph;
- memory lifecycle states, retention classes, decay, reinforcement, revocation, traversal, and threat-path reasoning;
- persistent incidents and evidence with correlation and severity escalation;
- local Unix-socket IPC and localhost HTTP API;
- `/proc` process telemetry;
- filesystem polling fallback;
- real Linux `fanotify` file telemetry with source attribution where available;
- bounded operational telemetry history separate from semantic memory;
- MAGI-style Host/User/Environment evaluation, quorum, and policy decisions;
- action proposals and transactional action state;
- Guard trust state, integrity findings, and authority removal;
- safe non-privileged `observe` and `warn` execution paths;
- web operator UI with Overview, Activity, Incidents, Threats, Attack Chains, Memory Graph, Relationships, MAGI & Response, Self & Trust, and System Health views.

The current incident severity levels are:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

The current persisted incident status is `open`; a richer lifecycle such as investigating/contained/resolved/dismissed is planned rather than implemented today.

## What is planned

Major planned work includes:

- real eBPF process and network telemetry;
- mature Self modelling and bootstrap trust/maturity;
- protection against learning a pre-existing compromise as Self;
- CVE/package/exposure intelligence;
- signed threat-knowledge packages (internally, a **ThreatCell** concept);
- updater/remediation backends with verification and rollback;
- privileged containment executors;
- stronger anti-tamper and recovery isolation;
- ML as a bounded evidence source;
- containers/Kubernetes awareness;
- optional MCP integration and later federation.

See [`docs/architecture.md`](docs/architecture.md) for the design and [`docs/ROADMAP.md`](docs/ROADMAP.md) for implementation status.

## Workspace

```text
dendrite/
├── crates/
│   ├── dendrited/
│   ├── dendrite-cli/
│   ├── dendrite-memory/
│   ├── dendrite-action/
│   ├── dendrite-guard/
│   ├── dendrite-updater/
│   └── dendrite-protocol/
├── ui/
├── python/
├── models/
├── migrations/
├── configs/
├── packaging/
├── tests/
├── docs/
└── scripts/
```

The UI lives in the main repository as a first-class root component. Repository, crate, process, and security boundary are deliberately treated as different concepts.

## Development

Backend checks:

```bash
cargo fmt --all
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

UI:

```bash
cd ui
npm install
npm run build
npm run dev
```

The daemon HTTP API defaults to `127.0.0.1:8766`. The development Unix socket defaults to `/tmp/dendrited.sock`.

## Design principles

- Self is host-specific; threat knowledge can be shared.
- Unknown is not automatically malicious.
- Observation alone is not enough to become trusted Self.
- Detection and action remain separate.
- Evidence is not authority.
- A compromised component can lose authority but cannot create new authority.
- Destructive actions require stronger independent agreement than observation-only actions.
- TOCTOU-sensitive targets are revalidated immediately before commit.
- Raw telemetry is short-lived; semantic memory is selective and decays.
- ML is advisory and bounded, never a direct privileged actuator.
- The UI is a client and must not invent security state.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — canonical technical architecture
- [`docs/SYSTEM_MAP.md`](docs/SYSTEM_MAP.md) — end-to-end system diagrams and boundaries
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — implemented, current, and planned work
- [`docs/HTTP_API.md`](docs/HTTP_API.md) — current local HTTP API

## Licence

Copyright 2026 Anthrosystems.

Licensed under the [Apache License 2.0](LICENSE).
