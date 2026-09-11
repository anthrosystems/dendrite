# Dendrite Roadmap

This roadmap replaces the older permanent batch/phase notes as the high-level status reference. Batch documents can remain in Git history for implementation detail but should not be treated as canonical architecture.

## Implemented foundation

### Memory Graph

Implemented:

- SQLite-backed nodes and relationships;
- memory lifecycle states;
- short-term, long-term, and persistent retention classes;
- expiry and purge eligibility;
- linear/exponential decay;
- reinforcement and revocation with provenance;
- repeated-observation consolidation;
- bounded traversal and neighbours;
- filtered/directional path finding;
- time-aware effective strength;
- ranked threat-path discovery.

### Incidents and correlation

Implemented:

- persistent incidents and evidence;
- correlation/deduplication;
- severity escalation;
- related object storage;
- source-rooted threat-path evidence;
- current severity: low, medium, high, critical;
- current lifecycle status: open.

### IPC, API, and CLI

Implemented:

- local JSON IPC over Unix socket;
- status, health, incidents, memory, actions, Guard, and telemetry commands;
- localhost HTTP API for UI;
- development/debug incident and Guard tooling.

### MAGI, policy, and actions

Implemented:

- Host/User/Environment evaluators;
- approve/deny/abstain/veto verdicts;
- quorum calculation;
- policy decision;
- action proposals;
- transaction state machine;
- safe `observe` and `warn` execution;
- persisted evaluations and transactions.

Production privileged executors for restrict/suspend/terminate/quarantine/block/isolate are not yet enabled.

### Guard

Implemented:

- persistent Guard trust state;
- integrity findings;
- Guard decision in every executable action authorisation;
- authority removal when trust is not acceptable;
- verified fail-closed path before PREPARE.

### Linux telemetry — Batch 5A

Implemented:

- `/proc` process polling;
- filesystem polling fallback;
- real fanotify collector;
- PID attribution where the process is still resolvable;
- source-aware telemetry normalisation;
- bounded recent event feed;
- CLI/API/UI telemetry status and activity stream.

Known limitations:

- newly created directories are not dynamically fanotify-marked yet;
- rename/delete/FID handling is limited;
- short-lived process attribution can fall back to host-local identity;
- no real eBPF source yet.

### Operator UI

Implemented:

- Overview;
- Activity;
- Incidents;
- Threats;
- Attack Chains;
- Memory Graph;
- Relationships;
- MAGI & Response;
- Self & Trust;
- System Health.

The UI only renders real backend state. Full Self data is intentionally not fabricated before the backend exposes it.

## Next: Batch 5B — eBPF telemetry

Primary goals:

- real process exec/fork/exit telemetry;
- network connect attribution;
- BPF event transport/ring buffer;
- kernel capability/feature handling;
- fallback behaviour when eBPF is unavailable;
- integration into the same normalised observation pipeline;
- harden short-lived process identity.

## Self model and bootstrap safety

Implement explicit Self maturity:

```text
UNINITIALISED → BOOTSTRAPPING → PROVISIONAL → ESTABLISHED → MATURE
```

Requirements:

- fresh installation is not assumed clean;
- innate protection works with no mature Self;
- observation frequency alone cannot establish trusted Self;
- threat/CVE/integrity/incident evidence can block Self promotion;
- established Self remains revisable and revocable.

## Vulnerability intelligence and updater

Implement:

- package inventory;
- distro/package manager abstraction;
- CVE ↔ package ↔ version ↔ fixed-version relationships;
- actual-exposure assessment rather than CVE presence alone;
- security update planning;
- transactional prepare/apply/verify;
- rollback and anti-downgrade where supported.

## Threat knowledge / ThreatCell

Implement a signed portable threat-knowledge format containing selected:

- indicators;
- behavioural patterns;
- attack chains;
- malicious infrastructure;
- CVE/exploit knowledge;
- provenance, confidence, version, expiry, and signatures.

Maturity:

```text
CANDIDATE → LOCAL → VALIDATED → TRUSTED → GLOBAL
```

Host-specific Self does not become globally shareable threat knowledge.

## Privileged response

Implement real constrained executors for:

- restrict process;
- suspend process;
- terminate process;
- quarantine object;
- block network destination;
- isolate host.

Requirements:

- no generic shell/script primitive;
- action-specific quorum/policy;
- target revalidation;
- transactional commit/verify;
- rollback where meaningful;
- Guard authority required throughout.

## Guard hardening

Planned:

- signed integrity manifests;
- stronger process/config/database/quarantine protection;
- authenticated/protected IPC;
- service hardening and least privilege;
- independent recovery/re-attestation;
- safer privileged telemetry model;
- optional TPM/LSM integration where useful.

## ML and adaptive detection

Later:

- CPU-first bounded models;
- event-driven inference;
- statistical filters before neural models;
- behavioural/sequence models;
- graph-context models;
- evaluator consequence models;
- model signing, compatibility, and resource budgets.

ML remains evidence, never direct authority.

## Later platform work

- container and Kubernetes context;
- stronger fleet/federation knowledge exchange;
- optional MCP server;
- richer operator graph exploration;
- production packaging and service installation once alpha is stable.

## Alpha acceptance scenarios

Before calling the architecture successful, Dendrite should demonstrate at least these behaviours:

1. **Pre-existing compromise:** install Dendrite onto an infected host and detect/respond without first learning the infection as Self.
2. **Contextual false-positive suppression:** same suspicious primitive behaves differently under strongly established benign context.
3. **Weak-signal attack chain:** multiple individually weak observations combine into strong graph evidence.
4. **Decay:** stale relationships lose influence without deleting the historical entity immediately.
5. **Contradiction/revocation:** previously reinforced knowledge can be corrected.
6. **Guard authority removal:** quorum and policy approve, Guard denies, and no transaction reaches PREPARE.
7. **ThreatCell propagation:** one validated signed knowledge package improves detection on a fresh host without importing another host's Self.
8. **CVE exposure context:** Dendrite distinguishes installed-but-not-exposed from actually reachable/exploitable vulnerability state.
