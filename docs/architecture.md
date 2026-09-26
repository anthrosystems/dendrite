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

### Physical storage: STM/LTM split, one writer per file

The Memory Graph is physically split into two SQLite databases — short-term retention lives in `stm.sqlite3`, long-term/persistent retention in `ltm.sqlite3` — but this is a storage-layer detail, not a second graph: higher-level code continues to reason about one logical Memory Graph, and a relationship may freely connect nodes that physically live in different tiers.

SQLite serialises writers per physical file, so each of the two files has exactly one dedicated writer; any number of independent read connections may exist concurrently (used by the runtime and by each ingestion worker) without competing for that write lock. Promotion between tiers (a record's retention changing to `LongTerm`/`Persistent`) is destination-first and idempotent — write the new tier, confirm it, then remove the stale copy — so a failure between those two steps leaves the record temporarily duplicated rather than lost, never the reverse ordering.

Two invariants worth stating explicitly, both learned from real failures during development: don't let workers open independent physical writer connections to these files again — multiple `DaemonCore`/`MemoryStore` instances each writing to the same file produced `SQLITE_BUSY`/"database is locked" under real load, which is the reason the one-writer-per-file design exists at all. And don't route telemetry draining through the runtime's own control-plane thread as an alternative way to get a single writer — that was tried, and under full-host telemetry it pinned the runtime thread at 100% CPU and starved IPC (control-plane requests, including the CLI, became unresponsive). Priority/routine ingestion staying on their own dedicated worker threads, separate from runtime/IPC handling, is load-bearing for control-plane responsiveness, not just a performance nicety.

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
ebpf
```

The operational telemetry feed is short-lived and separate from semantic Memory Graph state.

Ingestion is split into two dedicated worker threads/queues by relevance, not by source: **priority** for anything already threat-relevant or high/critical severity, **routine** for everything else — the overwhelming majority of raw volume. Each has its own queue and its own worker, so routine volume can never delay priority processing by occupying a shared thread; they only share the underlying storage layer's writer actors (see the Memory Graph section's STM/LTM note), not execution. Routine's threat-path search additionally runs at a shallower traversal depth than priority's, on the reasoning that routine telemetry has a near-zero hit rate for genuine threat connections and a connection only reachable many hops away was already a weak signal regardless of lane.

Fanotify watches every real mounted filesystem by default (`FAN_MARK_FILESYSTEM`, one mark per mount, not a directory walk), narrowed or excluded via configuration — see `CONFIGURATION.md` for the full mechanism.

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

The evaluators should eventually reason from genuinely different evidence/perspectives rather than acting as three duplicate risk scores. Evaluation itself now runs as its own process (`dendrite-magi`), reached from `dendrited` over a Unix socket rather than in-process — see `crates/dendrite-magi/README.md` and `docs/ROADMAP.md`'s Batch 7 notes for why, and for the fail-closed (abstain-on-unreachable) behaviour that follows from it. This is also the intended integration point for an MCP-connected evaluator per seat (a full replacement of that seat's internal vote, not an advisor alongside it) — designed for today, not yet built.

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

## 11. Shared threat knowledge / Antiserum

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

A portable signed knowledge object can be represented internally as a **Antiserum** and exposed publicly with conventional wording such as *Threat Knowledge Package*.

Conceptual contents:

```text
Antiserum
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

There is no separate vaccination/Antiserum crate requirement. Threat sharing is a data and trust problem, not automatically a new security boundary.

> **Repository ≠ crate ≠ process ≠ security boundary.**

Optional `dendrite-mcp` remains a separate process/repository if implemented. It should default to read-only and route mutations through the same normal authority chain.

## 15. Immune-system mapping

The biology is internal vocabulary only:

| Biology                            | Dendrite concept                                       | Function                                                                                                          |
| ---------------------------------- | ------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| Organism                           | Linux host                                             | The protected environment whose integrity and behaviour Dendrite models.                                          |
| Self                               | Host-specific normality                                | Defines recognised legitimate behaviour, identities, software and relationships for this particular host.         |
| Non-self                           | Unknown/contextually abnormal behaviour                | Behaviour not sufficiently recognised as Self; prompts scrutiny but is not automatically malicious.               |
| Innate immunity                    | Rules, verified threat/CVE knowledge, integrity checks | Provides immediate protection without needing the host to learn the threat first.                                 |
| Adaptive immunity                  | Learned Self and behavioural context                   | Learns host-specific behaviour and improves contextual discrimination over time.                                  |
| Antigen                            | Normalised security-relevant characteristic            | A feature Dendrite can recognise and reason about: hash, path, behaviour, endpoint, sequence, identity, etc.      |
| Epitope                            | Distinctive feature within an antigen                  | A particularly useful sub-characteristic used to recognise a larger malicious object or behaviour.                |
| Antibody                           | Detection signature/model/validated threat pattern     | Recognises a known malicious characteristic or behavioural pattern.                                               |
| Dendritic cell                     | Observation/event processing                           | Collects and contextualises telemetry, then presents security-relevant information to higher reasoning layers.    |
| Antigen presentation               | Evidence/context construction                          | Converts raw observations into structured evidence that other components can evaluate.                            |
| Pattern-recognition receptor (PRR) | Innate detector / matcher                              | Recognises known suspicious structural patterns without requiring learned host context.                           |
| PAMP                               | Known malicious/inherently suspicious pattern          | A broadly recognisable threat characteristic associated with known hostile behaviour.                             |
| DAMP                               | Host distress / integrity signal                       | Indicates damage or abnormal host state even when the originating threat is not yet known.                        |
| Memory B/T cell                    | Persistent threat knowledge                            | Retains validated threat recognition so previously encountered threats can be recognised rapidly.                 |
| Immune memory                      | Long-term threat memory                                | Preserves significant security knowledge after the original event has passed.                                     |
| NK cell                            | Anomaly detection                                      | Detects seriously abnormal behaviour without requiring an exact known-threat match.                               |
| Regulatory T cell                  | False-positive/tolerance control                       | Prevents excessive responses against legitimate or accepted behaviour.                                            |
| Immune tolerance                   | Trusted Self / established exceptions                  | Allows recognised legitimate behaviour without repeatedly treating it as hostile.                                 |
| Cytotoxic T cell                   | Process termination / destructive containment          | Removes a confirmed dangerous execution entity.                                                                   |
| Macrophage                         | Quarantine/remediation                                 | Contains, removes or cleans harmful objects after detection.                                                      |
| Phagocytosis                       | Quarantine/removal operation                           | Isolates or disposes of a malicious object so it can no longer affect the host.                                   |
| Complement system                  | Fast deterministic supporting controls                 | Amplifies or assists detection/containment using predefined mechanisms rather than adaptive reasoning.            |
| Cytokine                           | Internal security signal                               | Communicates state or urgency between Dendrite subsystems.                                                        |
| Chemokine                          | Targeted escalation/routing signal                     | Directs appropriate detection or response components toward a particular incident/object/context.                 |
| Inflammation                       | Elevated defensive state                               | Temporarily increases scrutiny or defensive activity around an affected subsystem/area.                           |
| Fever                              | Host-wide heightened security posture                  | Raises defensive thresholds or monitoring intensity in response to substantial threat evidence.                   |
| Clonal expansion                   | Reinforcement of validated threat recognition          | Increases the prominence/availability of threat knowledge after repeated corroboration.                           |
| Affinity maturation                | Refinement of threat recognition                       | Improves the specificity of a detector/pattern as better evidence becomes available.                              |
| Vaccination                        | Pre-deployment/import of signed threat knowledge       | Gives a host defensive knowledge before it encounters the underlying threat itself.                               |
| Antiserum                          | Signed portable threat-knowledge package               | Transfers validated malicious knowledge between Dendrite installations without transferring host Self.            |
| Immune repertoire                  | Local collection of threat recognition knowledge       | The set of antibodies/patterns/threat knowledge currently available to Dendrite.                                  |
| Immune surveillance                | Continuous telemetry and correlation                   | Continuously observes the host for malicious, abnormal or integrity-relevant behaviour.                           |
| Lymph node                         | Correlation / investigation layer                      | Brings observations and threat knowledge together so evidence can be correlated into incidents and attack chains. |
| Immunosuppression                  | Attacks against Dendrite itself                        | Attempts to weaken telemetry, Guard, policy, memory or response capabilities.                                     |
| Immune evasion                     | Threat behaviour intended to avoid detection           | Techniques designed to bypass, disguise or suppress Dendrite's recognition mechanisms.                            |
| Autoimmunity                       | False-positive harmful response                        | Dendrite mistakenly treats legitimate Self as hostile and takes damaging action.                                  |
| Immunodeficiency                   | Loss/degradation of defensive capability               | A condition where required telemetry, knowledge, trust or enforcement mechanisms are unavailable.                 |
| Apoptosis                          | Controlled process termination                         | Intentional termination of a compromised/dangerous process rather than uncontrolled failure.                      |
| Infection                          | Active compromise                                      | A threat has successfully established itself or is actively affecting the host.                                   |
| Pathogen                           | Malicious actor/object/software                        | An entity capable of compromising or damaging the protected host.                                                 |


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

## 17. Correlation, behaviour knowledge and attack-chain classification

Canonical Memory/evidence object IDs are host-scoped observation identities. Cross-host correlation is a separate knowledge layer built from normalised fingerprints/correlation keys and reusable behaviour definitions. This prevents independent observations from being collapsed while still allowing Host A and Host B to recognise semantically equivalent artifacts/activity.

Reusable behaviours are declarative detection/classification knowledge, not executable counter logic. They may describe graph relationships/conditions and can be associated with CVEs, attack chains and Antiserum packages. Live chains derive stable behaviour fingerprints and can later be enriched/classified without changing canonical chain/incident identity.

The historical action timeline must remain intact when classification changes: a proposal or action taken while a chain was unknown remains linked to the same chain after later recognition.

## 18. Dendrite Vulnerability Candidates

Dendrite stores first-class research vulnerability candidates separately from authoritative CVE source data. Candidates may be created manually and later derived from reviewed Antiserums, attack chains or contained research campaigns. A candidate can be useful/shareable without an assigned CVE ID. Assignment of a real CVE enriches/associates the candidate rather than rewriting its research provenance.

## 19. Analysis and Antiserum package management

Analysis owns Antiserum package creation/import/review. Server-side review sessions are plural and persistent; the browser only chooses which review to display. The Review graph uses the same renderer implementation as Memory Graph but has its own package-derived graph data source.

Antiserum creation selects semantic knowledge classes while provenance is mandatory. The physical v1 `.danti` package always contains all nine standard payload files, including schema-valid authenticated empty payloads.

Automatic export of an attack chain (triggered by reinforcement, not a one-time event) is deduplicated per `(incident_id, behaviour_fingerprint)` — the fingerprint is a stable structural hash, unlike the chain's own literal ID, which embeds the evidence ID and so changes on every reinforcement. Without this, a persistently reinforced real attack chain would generate an unbounded number of signed packages, one per reinforcement, rather than one per distinct shape.

Imported Antiserum remains evidence. Immediate-exporter authentication, replay protection and package verification do not transfer action authority.

## 20. Culture isolation foundation

Culture (working name; formerly "Adaptive Malware Analysis"/AMA) must never experiment against active Dendrite databases. A campaign snapshots the active Self, STM, LTM, Incidents, and Guard stores into a restricted temporary campaign workspace, and all experimental state changes occur against those copies. The current implementation is only this snapshot/lifecycle skeleton.

Future sample execution must occur in an explicitly contained environment. Proposed counters still use the ordinary MAGI → policy → Guard → transaction pipeline in the contained campaign world. Promotion/export of resulting knowledge is explicit and provenance-preserving; campaigns do not silently mutate production knowledge.