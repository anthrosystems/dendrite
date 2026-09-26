# Dendrite System Map

This document is the compact whole-system view of Dendrite. Detailed rules live in [`architecture.md`](architecture.md).

## Protection pipeline

```text
                           DENDRITE
                              │
                 ┌────────────┴────────────┐
                 │                         │
          SHARED / INNATE             HOST SELF
          THREAT KNOWLEDGE             MEMORY
                 │                         │
                 └────────────┬────────────┘
                              │
                         SURVEILLANCE
                              │
                  /proc / fanotify / eBPF
                              │
                              ▼
                         OBSERVATIONS
                              │
                 ┌────────────┼────────────┐
                 │            │            │
               RULES      MEMORY GRAPH   SELF
                 │            │            │
                 └────────────┼────────────┘
                              ▼
                      DETECTION / DANGER
                              │
                              ▼
                           EVIDENCE
                              │
                              ▼
                           INCIDENT
                              │
                              ▼
                       ACTION PROPOSAL
                              │
                  ┌───────────┼───────────┐
                  │           │           │
              BALTHASAR     CASPER     MELCHIOR
                 HOST        USER      ENVIRONMENT
                  │           │           │
                  └───────────┼───────────┘
                              ▼
                           QUORUM
                              │
                           POLICY
                              │
                            GUARD
                              │
                              ▼
                         AUTHORISED?
                              │
                              ▼
               PREPARE → REVALIDATE → COMMIT
                                         │
                                         ▼
                                       VERIFY
                                         │
                                         ▼
                            AUDIT / MEMORY UPDATE
```

## Bootstrap on an unknown host

```text
Dendrite installed
       │
       ├── Self maturity: BOOTSTRAPPING
       └── Host trust: UNKNOWN
              │
              ▼
      innate protection active
              │
      ┌───────┼─────────┬──────────────┐
      ▼       ▼         ▼              ▼
 threat   integrity   CVE/package   behaviour/
 cells     checks     exposure       attack chains
      └───────┼─────────┴──────────────┘
              ▼
      provisional observations
              │
              ▼
      contamination checks
              │
              ▼
       promote / reject Self
```

The host is not assumed clean just because Dendrite has only just been installed.

## Knowledge domains

```text
GLOBAL                       ENVIRONMENT                    HOST SELF
──────────────────           ──────────────────             ──────────────────
known malware                distro/package knowledge       normal processes
malicious infrastructure     common service behaviour       local file behaviour
attack techniques            container/K8s knowledge        normal network graph
attack chains                general platform context       users/privileges
CVEs/exploit knowledge                                      local relationships
```

Global/environment knowledge may be distributed. Host Self normally remains local.

## Antiserum lifecycle

```text
new local finding
      ↓
CANDIDATE
      ↓
LOCAL
      ↓ validation / provenance / corroboration
VALIDATED
      ↓ trusted signing / review policy
TRUSTED
      ↓
GLOBAL
      ↓
other Dendrite hosts receive signed threat knowledge
```

Antiserum is an internal name for a signed threat-knowledge package. Distribution never grants direct action authority.

## Memory lifecycle

```text
raw telemetry
    ↓
short-lived operational events
    ↓
observations
    ↓
consolidation
    ↓
semantic relationships
    ↓
reinforcement / contradiction / decay
    ↓
ESTABLISHED / EXPIRED / REVOKED / ...
```

Current Memory Graph states:

```text
OBSERVED → CORRELATED → SUPPORTED → ESTABLISHED
     │          │             │
     └──────────┴─────────────┴──→ CONTRADICTED / SUPERSEDED / EXPIRED / REVOKED
```

## Authority boundary

```text
Threat evidence
     │
     └── may increase confidence / create proposal

Threat evidence
     X
     └── may NOT create action authority

Authority = quorum + policy + Guard + successful revalidation
```

Core invariant:

> **Compromise can remove authority, but cannot create authority.**

## Cross-host correlation

```text
Host A observation (A::object)
          │
          ├── fingerprint / correlation key ──┐
          └── behaviour binding ───────────────┤
                                               ├── shared semantic knowledge
Host B observation (B::object)                 │
          ├── fingerprint / correlation key ──┤
          └── behaviour binding ───────────────┘
```

Object identity and provenance stay host-scoped. Correlation is represented rather than identity being rewritten.

## Analysis workspace

```text
.danti package ── verify/store ──► on-device Antiserum store
                                      │
                       ┌──────────────┴──────────────┐
                       ▼                             ▼
                server-side Review             Accept Knowledge
                (no authority)                 (explicit operator action)
                       │                             │
                       ▼                             ▼
             shared Graph renderer       supported semantic stores
             (Analysis page only)         Memory / behaviour / CVE / candidates
```

The normal Memory Graph page continues to use the live Memory Graph data source.

## Culture foundation

```text
ACTIVE DBs                         CAMPAIGN WORKSPACE
self.sqlite3      ── snapshot ──► self.sqlite3
stm.sqlite3       ── snapshot ──► stm.sqlite3
ltm.sqlite3       ── snapshot ──► ltm.sqlite3
incidents.sqlite3 ── snapshot ──► incidents.sqlite3
guard.sqlite3     ── snapshot ──► guard.sqlite3
                                  artifacts/
```

There is no reverse automatic database merge. Future promotion/export is explicit and goes through normal knowledge/trust boundaries.