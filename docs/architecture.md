# Dendrite Architecture

This is the canonical technical architecture for Dendrite.

Dendrite is a Linux-native endpoint security platform inspired by the human immune system. The analogy is useful for separating **innate protection**, **adaptive Self**, **memory**, **threat recognition**, and **response**, but it does not override ordinary security engineering.

> **The biology should inspire the architecture, not constrain it.**

## 1. Security invariants

Dendrite is built around a small set of non-negotiable rules:

1. **Evidence is not authority.** Rules, telemetry, Memory Graph reasoning, ML, CVEs, and threat intelligence may create evidence or proposals but cannot grant themselves privileged execution.
2. **Detection and action are separate.** Detection determines what may be happening; quorum, policy, Guard, and the executor determine whether and how to act.
3. **Compromise can remove authority, but cannot create authority.** A degraded component reduces capability rather than increasing attacker power.
4. **Self is learned, not blindly trusted.** Repetition and familiarity are evidence of normality, not proof of legitimacy.
5. **Protection must work before Self is mature.** A fresh installation may have poor host-specific context, but innate protection remains active.
6. **Revalidate before commitment.** Objects, process identity, hashes, authority, and policy must be checked again immediately before a privileged action.
7. **Prefer reduced capability over unsafe autonomous action.**
8. **The daemon owns security state.** CLI, UI, MCP, and external tools are clients; they do not own memory, authority, or detection truth.

## 2. Runtime architecture

```text
kernel / fanotify / eBPF
          │
          ▼
      collectors
          │
          ▼
   normalisation
          │
          ▼
     observations
          │
    ┌─────┼─────────────┐
    ▼     ▼             ▼
  rules  Self       Memory Graph
    │     │             │
    └─────┼─────────────┘
          ▼
 detection / correlation
          │
          ▼
       evidence
          │
          ▼
       incident
          │
          ▼
   action proposal
          │
   ┌──────┼──────────┐
   ▼      ▼          ▼
  Host   User    Environment
   └──────┼──────────┘
          ▼
        quorum
          │
        policy
          │
         Guard
          │
          ▼
 PREPARE → REVALIDATE
          │
    COMMIT → VERIFY
```

The current implementation has `/proc`, filesystem polling, and fanotify telemetry. Real eBPF process/network telemetry is the next collector stage.

## 3. Self and bootstrap trust

### 3.1 Self

Self is Dendrite's host-specific model of expected state and behaviour. It may include:

- normal process and parent/child relationships;
- executable identity and package ownership;
- filesystem access patterns;
- network relationships;
- users and privilege behaviour;
- services;
- containers and Kubernetes context;
- established temporal relationships in the Memory Graph.

Self is not a permanent allowlist. Known entities can become suspicious when behaviour changes.

### 3.2 A fresh installation may already be compromised

Dendrite must assume that installation time is **not** a trusted baseline. Otherwise persistent malware present before installation could simply be learned as normal.

Self therefore needs an explicit maturity model, conceptually:

```text
UNINITIALISED
    ↓
BOOTSTRAPPING
    ↓
PROVISIONAL
    ↓
ESTABLISHED
    ↓
MATURE
```

This is separate from host/Guard trust state:

```text
UNKNOWN / TRUSTED / DEGRADED / SUSPECTED / COMPROMISED / ...
```

A fresh host should begin approximately as:

```text
Self maturity: BOOTSTRAPPING
Host trust:    UNKNOWN
```

not as an implicitly trusted clean machine.

### 3.3 Innate protection before Self

An immature Self reduces adaptive confidence; it does **not** disable protection. Dendrite can still use independently established knowledge such as:

- signed threat knowledge;
- malware hashes and known malicious infrastructure;
- CVE and package exposure intelligence;
- known exploit/attack techniques;
- package and system-file integrity;
- dangerous behavioural rules;
- attack-chain knowledge;
- Guard integrity state.

This gives Dendrite two complementary protection paths:

```text
             DENDRITE
                │
       ┌────────┴────────┐
       │                 │
    INNATE            ADAPTIVE
   PROTECTION            SELF
       │                 │
 immediate/shared    learned/local
       └────────┬────────┘
                ▼
             evidence
```

### 3.4 Self promotion must resist contamination

Observation alone cannot promote behaviour into trusted Self.

A candidate relationship should be checked against available negative evidence before becoming established Self:

```text
observation
    ↓
provisional candidate
    ↓
check threat knowledge / integrity / package ownership /
CVE exposure / incident history / attack-chain evidence
    ↓
benign over sufficient time and context?
    ↓
reinforce Self candidate
    ↓
ESTABLISHED SELF
```

Frequent malicious behaviour remains malicious behaviour. Persistence is not legitimacy.

## 4. Memory Graph

The Dendrite Memory Graph is a temporal, provenance-aware, confidence-aware, decaying knowledge graph backed initially by SQLite.

It represents entities and relationships such as processes, files, hosts, users, services, network endpoints, incidents, and threats.

Current memory states are:

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

Current retention classes include short-term, long-term, and persistent memory.

Important distinction:

```text
TTL   = active relevance / retention window
decay = influence on current reasoning
purge = physical removal/archive policy
```

Relationships generally decay before nodes. Repeated observations are consolidated instead of becoming permanent one-event-per-edge history.

A semantic relationship may retain:

```text
created_at
last_seen_at
observation_count
confidence
strength
decay policy
expires_at
state
retention
reinforcement provenance
```

Confirmed threat knowledge may be reinforced, but only relevant relationships should be strengthened. If a conclusion is revoked, reinforcement must be removable and normal decay must resume.

### Graph reasoning

Dendrite can traverse causal/contextual paths in both directions, for example:

```text
nginx → bash → curl → malicious endpoint
```

A strong terminal threat association can justify immediate escalation to an incident or proposal, but it never bypasses quorum, policy, Guard, revalidation, or transaction execution.

## 5. Telemetry and observations

All collectors feed the same normalisation path. Collector identity is metadata, not authority.

Current sources:

```text
proc_polling
filesystem_polling
fanotify
ebpf              # reserved/not yet built
```

The operational telemetry feed is short-lived and separate from semantic Memory Graph state.

Current fanotify scope includes existing directories marked at daemon startup and file-open / file-write events. Dynamic new-directory marking, richer rename/delete handling, and FID-based identity are later hardening work.

## 6. Evidence and incidents

Detectors create structured evidence candidates. Evidence may come from:

```text
rules
Self model
Memory Graph
machine learning
kernel telemetry
filesystem telemetry
network telemetry
```

Incidents aggregate correlated evidence and related objects.

Current incident severity values are:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

The current persistent incident implementation uses `open` as its active status. A future lifecycle should separate workflow state from severity, for example:

```text
OPEN → INVESTIGATING → CONTAINED → RESOLVED
                     └────────────→ DISMISSED
```

Severity, lifecycle status, and response action are distinct concepts.

## 7. Action proposals and response

Current action types are:

```text
OBSERVE
WARN
RESTRICT_PROCESS
SUSPEND_PROCESS
TERMINATE_PROCESS
QUARANTINE_OBJECT
BLOCK_NETWORK_DESTINATION
ISOLATE_HOST
```

`observe` and `warn` are currently the safe non-privileged execution paths. The more destructive actions exist as protocol/action types but production privileged executors are not yet enabled.

Avoid generic privileged primitives such as arbitrary shell execution or arbitrary path deletion.

Every authorised action follows:

```text
PROPOSAL
   ↓
PREPARE
   ↓
REVALIDATE
   ↓
COMMIT
   ↓
VERIFY
```

If target identity, hash, PID identity, quorum, policy, or Guard authority no longer matches, abort.

## 8. MAGI / independent evaluation

The internal MAGI names map to conventional perspectives:

| Internal | Public perspective | Question |
|---|---|---|
| Balthasar | Host | What does this mean for the machine? |
| Casper | User | What does this mean for the user and their data? |
| Melchior | Environment | What does this mean for surrounding systems/network? |

Verdicts are:

```text
APPROVE
DENY
ABSTAIN
VETO
```

The default implementation requires two approvals, with deny/veto blocking. Longer term, quorum should be action-specific: observation can require little authority while isolation or destructive remediation requires stronger independent agreement.

The evaluators should eventually reason from genuinely different evidence/perspectives rather than acting as three duplicate risk scores.

## 9. Guard and trust

Current Guard trust states are:

```text
TRUSTED
DEGRADED
SUSPECTED
QUARANTINED
COMPROMISED
RECOVERING
```

Guard sits in the executable authorisation path. Even if quorum approves and policy allows, Guard can remove authority.

```text
quorum: APPROVED
policy: ALLOW
Guard:  DENY
        ↓
NO EXECUTION
```

This enforces the central invariant:

> **Compromise can remove authority, but cannot create authority.**

Longer-term Guard responsibilities include integrity manifests, trust-root protection, anti-tamper, health state, recovery, quarantine integrity, and secure restart/re-attestation.

## 10. CVE and vulnerability intelligence

Vulnerability knowledge should be contextual rather than a flat CVE list.

At minimum:

```text
CVE ↔ package ↔ installed version ↔ fixed version ↔ severity ↔ exploitability
```

The Memory Graph can then represent host exposure:

```text
host
 └── installed_package → package/version
                           └── affected_by → CVE
                                              ├── severity
                                              ├── exploitability
                                              └── attack technique
```

Dendrite should distinguish:

```text
"a CVE exists"
```

from:

```text
"this host is actually exposed and the affected path is reachable"
```

Potential context includes service reachability, enabled vulnerable functionality, package provenance, exploit availability, current attack-chain evidence, and whether a fixed package version is available.

`dendrite-updater` should use the operating system package manager, validate the whole transaction, verify results, and roll back where supported. Generated privileged repair scripts are explicitly outside the autonomous model.

## 11. Shared threat knowledge / ThreatCell

Dendrite should share malicious knowledge without sharing host-specific normality.

```text
GLOBAL
├── threat signatures / antibodies
├── malware intelligence
├── attack-chain knowledge
├── malicious infrastructure / reputation
├── generic malicious behaviour
└── vulnerability / exploit knowledge

ENVIRONMENT
├── distro/package knowledge
├── common service behaviour
├── container behaviour
└── Kubernetes behaviour

HOST SELF
├── installed software
├── normal processes
├── normal filesystem behaviour
├── normal network behaviour
└── host-specific relationships
```

A portable signed knowledge object can be represented internally as a **ThreatCell** and exposed publicly with conventional wording such as *Threat Knowledge Package*.

Conceptual contents:

```text
ThreatCell
├── id / version / issuer
├── signatures and provenance
├── validity / expiry
├── hashes / domains / IPs / certificates
├── behavioural patterns
├── attack chains
├── CVEs / exploit relationships
├── confidence
└── maturity
```

Threat knowledge maturity follows:

```text
CANDIDATE → LOCAL → VALIDATED → TRUSTED → GLOBAL
```

A local discovery cannot automatically become globally trusted or gain destructive authority. Packages must be signed, provenance-aware, revocable, and independently verifiable.

Benign/negative knowledge is much more host-specific than malicious knowledge and therefore requires stricter sharing rules.

## 12. Machine learning

ML is an evidence source, not the security authority.

Preferred flow:

```text
high-volume telemetry
       ↓
rules / statistics / Self
       ↓
small suspicious subset
       ↓
ML
       ↓
structured evidence
       ↓
normal incident / authority pipeline
```

Models are untrusted data: verify signatures and compatibility, enforce CPU/memory/thread budgets, and sandbox loading where practical. Training/research can live in Python; production privileged execution remains Rust-controlled.

## 13. UI and operator interfaces

The UI lives at `ui/` in the main repository and is a client of `dendrited`.

Current information architecture:

```text
Operations
├── Overview
├── Activity
├── Incidents
├── Threats
└── Attack Chains

Knowledge
├── Memory Graph
└── Relationships

Authority
├── MAGI & Response
├── Self & Trust
└── System Health
```

The Memory Graph must project real STM/LTM state. It must not fabricate relationships, confidence, expiry, threat state, or Self data.

The desired graph is a large force-directed, Obsidian-like workspace with filtering, pan/zoom, movable nodes, and semantics driven by actual relationship metadata:

```text
thick edge  = stronger relationship
thin edge   = weaker relationship
dotted edge = near expiry
faded node  = lower current relevance/inactive state
badge/icon  = actual state/priority/threat status
```

No fake neural animation or AI theatre.

## 14. Repository and security boundaries

Current repository layout:

```text
dendrite/
├── crates/
│   ├── dendrited
│   ├── dendrite-cli
│   ├── dendrite-memory
│   ├── dendrite-action
│   ├── dendrite-guard
│   ├── dendrite-updater
│   └── dendrite-protocol
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

There is no separate vaccination/ThreatCell crate requirement. Threat sharing is a data and trust problem, not automatically a new security boundary.

> **Repository ≠ crate ≠ process ≠ security boundary.**

Optional `dendrite-mcp` remains a separate process/repository if implemented. It should default to read-only and route mutations through the same normal authority chain.

## 15. Immune-system mapping

The biology is internal vocabulary only:

| Biology | Dendrite concept |
|---|---|
| Organism | Linux host |
| Self | Host-specific normality |
| Non-self | Unknown/contextually abnormal behaviour |
| Innate immunity | Rules, verified threat/CVE knowledge, integrity checks |
| Adaptive immunity | Learned Self and behavioural context |
| Antigen | Normalised security-relevant characteristic |
| Antibody | Detection signature/model/validated threat pattern |
| Dendritic cell | Observation/event processing |
| Memory B/T | Persistent threat knowledge |
| NK cell | Anomaly detection |
| Regulatory T | False-positive/tolerance control |
| Cytotoxic T | Termination response |
| Macrophage | Quarantine/remediation |
| Vaccination | Signed pre-deployed/shared threat knowledge |
| Immunosuppression | Attacks against Dendrite itself |
| Autoimmunity | False-positive harmful response |

The MAGI/quorum system is Dendrite-specific rather than a literal biological mapping.

## 16. Design test

Dendrite should justify its extra machinery by doing something materially better or safer than a simple risk-score engine. Alpha should demonstrate scenarios such as:

- suppressing a false positive because established host context supports benign behaviour;
- escalating a weak-signal attack chain because graph context connects it to strong terminal evidence;
- allowing stale relationships to decay instead of permanently poisoning future decisions;
- revoking previously reinforced knowledge when contradictory evidence arrives;
- detecting/protecting a host before Self is mature;
- refusing to learn persistent pre-existing compromise as Self;
- blocking execution when quorum/policy approve but Guard authority is removed.

If those distinctions are not observable, the architecture is complexity without sufficient benefit.
