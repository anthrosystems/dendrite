# Dendrite — Architecture and Design Notes

Dendrite is a Linux-native endpoint security and threat-detection platform inspired by the human immune system. The biological terminology is an **internal design language**; public interfaces should use conventional security terminology.

> **The biology should inspire the architecture, not constrain it.**

This document is the canonical concise architecture reference. It intentionally removes duplicated explanations and keeps the design decisions, security boundaries, data model, and implementation roadmap in one place.

---

# 1. Core principles

1. **Self matters.** Dendrite protects a particular host and learns what belongs there.
2. **Evidence is not authority.** Rules, ML, threat intelligence, and Memory Graph knowledge can produce evidence, but cannot grant themselves destructive privileges.
3. **Detection and action are separate.** Detection answers what is happening; policy/quorum decides whether to act; a constrained executor performs the action.
4. **Compromise removes authority, never creates it.** A compromised component should reduce Dendrite's capabilities rather than increase attacker control.
5. **Memory is selective.** Raw telemetry is short-lived; semantic knowledge is consolidated and retained according to value.
6. **ML is advisory.** Deterministic logic and Self filtering should handle cheap/high-volume work before ML is invoked.
7. **The daemon is the product.** CLI, GUI, MCP, and external tooling are clients of `dendrited`.
8. **Repository, crate, process, and security boundary are different concepts.** Do not split code purely because a concept has a name.
9. **Prefer reduced capability over unsafe autonomous action.**
10. **Public UX should be conventional.** Biological and MAGI terminology may appear in internal/debug views, but should not be required knowledge for operators.

---

# 2. Repository and component layout

Dendrite is intentionally split across three repositories:

```text
anthrosystems/
├── dendrite/
├── dendrite-ui/
└── dendrite-mcp/
```

The main repository:

```text
dendrite/
│
├── Cargo.toml
├── Cargo.lock
├── README.md
├── LICENSE
├── SECURITY.md
│
├── crates/
│   ├── dendrited/             # Main daemon + kernel/eBPF telemetry
│   ├── dendrite-cli/          # CLI
│   ├── dendrite-memory/       # Memory Graph, STM/LTM, consolidation, decay
│   ├── dendrite-action/       # Capability-limited privileged executor
│   ├── dendrite-guard/        # Independent trust / anti-tamper / recovery
│   ├── dendrite-updater/      # Package remediation and update integration
│   └── dendrite-protocol/     # Shared domain types + IPC/API protocol
│
├── python/
│   ├── training/
│   ├── datasets/
│   ├── experiments/
│   └── tools/
│
├── models/
├── migrations/
├── configs/
├── packaging/
├── tests/
├── docs/
└── scripts/
```

There is **no separate `dendrite-vaccines` crate**. Vaccination is threat-knowledge distribution, not a standalone security boundary.

Core dependencies:

```text
dendrited
   ├── dendrite-memory
   ├── dendrite-updater
   └── dendrite-protocol

dendrite-action
   └── dendrite-protocol

dendrite-guard
   └── dendrite-protocol

dendrite-cli
   └── dendrite-protocol
```

Potential binaries:

```text
dendrited
dendrite
dendrite-action
dendrite-guard
dendrite-updater
```

> **Repository ≠ Crate ≠ Process ≠ Security boundary.**

---

# 3. High-level runtime architecture

```text
kernel / eBPF / fanotify
          │
          ▼
      collectors
          │
          ▼
     normalization
          │
          ▼
   feature extraction
          │
          ▼
      antigenizer
          │
   ┌──────┼───────────┐
   ▼      ▼           ▼
 rules   Self      Memory Graph
   │      │           │
   └──────┼───────────┘
          ▼
  danger / detection
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
          ▼
    MAGI / quorum
          │
          ▼
   policy authorization
          │
          ▼
   dendrite-action
          │
          ▼
  verify + audit + memory
```

`dendrite-guard` observes the integrity and trust state of the security system itself rather than acting as a second large detection engine.

---

# 4. Self, non-self, antigens, and danger

## Self

Self is Dendrite's host-specific model of normal or expected state:

- normal processes and parent/child relationships
- executables and package ownership
- filesystem patterns
- network relationships
- users and privilege behaviour
- services
- containers and Kubernetes context where applicable
- historical relationships recorded in memory

Self is not a static allowlist. It is a confidence-aware model that can be learned, reinforced, frozen, reviewed, and corrected.

## Non-self

Non-self means unknown, unexpected, suspicious, or contextually inappropriate behaviour. Unknown does **not** automatically mean malicious.

## Antigens

Antigens are normalized security-relevant characteristics derived from raw observations.

Example:

```text
new ELF executable
+ location: /tmp
+ chmod +x
+ executed by nginx
+ outbound network connection
```

The combination is more informative than each raw event individually.

## Danger signals

Danger should be contextual. Useful dimensions include:

- identity
- context
- behaviour
- deviation from Self
- consequences
- known malicious associations
- temporal correlation
- process lineage
- graph relationships

Several weak signals can combine into strong evidence.

---

# 5. Detection pipeline

```text
kernel/eBPF + fanotify
        ↓
collector
        ↓
normalization
        ↓
feature extraction
        ↓
antigenizer
        ↓
innate/Self model
        ↓
danger engine
        ↓
rules / ML / antibodies / threat intelligence
        ↓
incident + proposed response
        ↓
MAGI / quorum / policy
        ↓
IGNORE / OBSERVE / WARN / RESTRICT / SUSPEND /
QUARANTINE / TERMINATE / ISOLATE
        ↓
immune memory
```

A typical attack chain:

```text
webserver RCE
 ↓
curl downloads executable to /tmp
 ↓
chmod +x
 ↓
execute
 ↓
unusual child + download + temp executable + outbound connection
 ↓
antigens / danger
 ↓
rules + Self deviation + ML + antibodies + Memory Graph
 ↓
incident
 ↓
action proposal
 ↓
quorum / policy
 ↓
terminate + quarantine + preserve evidence + block destination
 ↓
learn / reinforce memory
```

---

# 6. Dendrite Memory Graph

The **Dendrite Memory Graph** is a custom temporal, provenance-aware, confidence-aware, decaying knowledge graph. It is a semantic and reasoning layer over structured storage, not a replacement for the database.

It models:

- entities
- relationships
- observations
- episodes
- incidents
- attack chains
- Self knowledge
- threat memory
- provenance
- confidence
- temporal state

Memory states may include:

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

Representative API:

```rust
MemoryGraph::observe(...)
MemoryGraph::relate(...)
MemoryGraph::recall(...)
MemoryGraph::explain(...)
MemoryGraph::reinforce(...)
MemoryGraph::decay(...)
MemoryGraph::supersede(...)
```

Relationships should retain at least:

```text
first_seen
last_seen
count
confidence
strength
decay
provenance
status
```

Storage responsibility:

```text
Graph                 = semantic / causal context and recall
SQL                   = exact state and source of truth
Vector/semantic index = optional retrieval accelerator
```

Initial implementation: `dendrite-memory` as a Rust library used by `dendrited`, backed by SQLite. A separate memory service is only justified later if scaling or isolation requirements demand it.

---

# 7. Short-term and long-term memory

STM and LTM are two timescales of one memory system and should remain inside **one `dendrite-memory` crate**.

```text
dendrite-memory/
├── short_term/
├── long_term/
├── consolidation/
├── decay/
└── ...
```

They can initially share one SQLite database with logically separate tables and migrations.

```text
                    DENDRITE MEMORY
                          │
             ┌────────────┴────────────┐
             │                         │
             ▼                         ▼
      SHORT-TERM MEMORY          LONG-TERM MEMORY
          (STM)                       (LTM)
             │                         │
       recent events             established knowledge
       active episodes           persistent relationships
       investigations            threat memory
       transient context         Self knowledge
       high detail               learned patterns
             │                         │
             └────────────┬────────────┘
                          │
                    MEMORY API
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
           recall       traverse     explain
                          │
                          ▼
                         GUI
```

### STM

Answers: **"What is happening now, and what just happened?"**

- recent observations
- active episodes
- current investigations
- transient context
- high detail
- aggressive TTLs

### LTM

Answers: **"What does Dendrite know that is worth remembering?"**

- established relationships
- Self knowledge
- threat memory
- learned patterns
- important historical evidence

### Consolidation

STM → LTM is **memory consolidation**, not bulk copying.

```text
STM
 │
 ▼
Consolidator
 │
 ├── irrelevant → expire
 ├── useful     → aggregate
 └── important  → promote / reinforce
```

Example: 14,000 nearly identical observations should become one semantic relationship with counts, confidence, first/last seen, and provenance rather than 14,000 permanent graph edges.

---

# 8. Priority, TTL, decay, and reinforcement

Events and relationships should carry priority and retention policy as first-class state.

Example priority classes:

```text
P0 CRITICAL
P1 HIGH
P2 ELEVATED
P3 NORMAL
P4 LOW
```

TTL values are policy/configuration, not hard-coded architecture. A reasonable policy can range from minutes/hours for low-value context to persistent retention for confirmed critical evidence.

Important distinction:

```text
TTL   = retention / active relevance window
decay = how strongly knowledge influences reasoning
purge = physical deletion or archival policy
```

The lifecycle should be:

```text
ACTIVE
  ↓
EXPIRED / HISTORICAL
  ↓
PURGED
```

Visual disappearance must not imply immediate physical deletion.

## Nodes vs relationships

Both may decay independently, but **relationships generally decay first**.

- Node: Dendrite knows an entity/event exists.
- Relationship: Dendrite currently considers a connection meaningful.

Both can carry:

```text
created_at
last_seen
priority
confidence
strength
expires_at
state
retention_class
```

When relationships expire, an orphaned node can later be archived or purged according to node retention policy.

## Confirmed high-risk reinforcement

Confirmed threats may slow or prevent decay for **relevant causal/contextual knowledge**.

Do not reinforce an entire graph neighbourhood just because one node is malicious.

Reinforcement needs provenance:

```text
curl ──connected_to──> 185.x.x.x
confidence: 0.98
strength: 0.94
reinforced_by:
    incident: 1842
    reason: CONFIRMED_HIGH_RISK
    evidence: E1842, E1847, E1851
```

If a verdict is revoked:

```text
THREAT REVOKED
      ↓
remove reinforcement
      ↓
recalculate confidence / strength
      ↓
resume normal decay
```

Evidence must never be able to grant itself permanent authority.

---

# 9. Storage scale and retention

Do not make every raw event a permanent graph edge.

```text
                    DENDRITE STORAGE
                          │
             ┌────────────┼────────────┐
             │            │            │
             ▼            ▼            ▼
         Memory        Evidence      Raw Events
          Graph
             │            │            │
       long-lived      long-lived    short-lived
       knowledge       important     detailed
```

Pipeline:

```text
Raw telemetry
  ↓ normalization
short-lived event store
  ↓ aggregation
observations
  ↓ reinforcement / decay
Memory Graph
```

One relationship can summarize millions of observations:

```text
nginx ──normally_connects──> backend
first_seen: ...
last_seen: ...
observations: 10_384_291
confidence: ...
strength: ...
state: ESTABLISHED
```

Plausible one-year ranges on a normal host are highly workload-dependent, but the architecture should comfortably support roughly:

- 10k–500k entities
- 50k–5m semantic relationships
- 10k–500k episodes
- 10k–1m retained evidence objects
- raw telemetry ranging into GBs depending on configured retention
- core semantic graph from tens/hundreds of MB into low GBs

Queries must be bounded:

```text
max_depth
max_nodes
max_edges
max_time
min_confidence
relationship_types
time_window
```

High-degree hubs such as the Internet, CDNs, DNS providers, or package mirrors need special handling to avoid useless graph explosion.

---

# 10. Graph-based contextual threat propagation

The graph can shortcut expensive analysis when a chain reaches strong terminal evidence.

Example:

```text
nginx → worker → bash → curl → known C2 endpoint
```

Dendrite can traverse both directions:

```text
forward:  process → child → file → network → malicious endpoint
backward: malicious endpoint ← connection ← curl ← bash ← nginx
```

A strong terminal association can cause Dendrite to **skip unnecessary expensive analysis and immediately escalate/create an action proposal**.

"Immediately" does **not** mean bypassing authorization, quorum, policy, target revalidation, or the action transaction.

---

# 11. Evidence, incidents, and action separation

```text
Detection:
    What is happening?

MAGI:
    What does this mean from my perspective?

Quorum:
    Do we have sufficient independent agreement to act?

Action engine:
    How do we safely execute the approved action?
```

Detectors create evidence, incidents, and proposals. They do not directly execute destructive operations.

The protected chain is:

```text
Evidence
  ↓
Incident
  ↓
Proposal
  ↓
Independent evaluation
  ↓
Quorum
  ↓
Policy authorization
  ↓
Action transaction
  ↓
Executor
```

---

# 12. MAGI-style quorum evaluators

MAGI terminology is internal. Public APIs should expose **Host**, **User**, and **Environment**.

| Internal name | Perspective | Core question |
|---|---|---|
| Balthasar | Host | What does this do to the machine? |
| Casper | User | What does this do to the user and their data? |
| Melchior | Environment | What does this do to surrounding systems/network? |

They evaluate the **same incident and action proposal from different perspectives**, not three duplicate detectors voting on the same signal.

Verdicts:

```text
APPROVE
DENY
ABSTAIN
VETO
```

Example quorum policy:

| Action | Host | User | Environment |
|---|---:|---:|---:|
| Observe | — | — | — |
| Warn | Optional | Optional | Optional |
| Restrict process | Required | — | — |
| Quarantine file | Required | Required | — |
| Terminate process | Required | Required | Optional |
| Block network destination | — | — | Required |
| Isolate host | Required | Optional | Required |
| Restore file | Required | Required | — |
| Modify Dendrite | Required | — | Required |

> **The more irreversible the action, the more independent agreement Dendrite requires.**

Veto semantics must be explicit and policy-controlled.

---

# 13. Action executor and TOCTOU safety

`dendrite-action` should be small, boring, auditable, and capability-limited.

Allowed capability families can include:

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

Avoid generic privileged primitives such as:

```text
RUN_COMMAND
EXECUTE_SCRIPT
DELETE_ARBITRARY_PATH
```

Structured action example:

```text
Action {
    type: QUARANTINE_OBJECT,
    object_id: 8172,
    expected_hash: "...",
    incident_id: 1842
}
```

Transaction:

```text
ACTION PROPOSAL
      ↓
PREPARE
      ↓
REVALIDATE
      ↓
COMMIT
      ↓
VERIFY
```

Revalidation protects against TOCTOU attacks. If the object, hash, PID identity, policy, or quorum no longer matches, abort rather than acting on stale evidence.

---

# 14. Trust, anti-tamper, and `dendrite-guard`

Trust states:

```text
TRUSTED
DEGRADED
SUSPECTED
QUARANTINED
COMPROMISED
RECOVERING
```

Principles:

> **Compromise can remove authority, but cannot create authority.**

> **Dendrite prefers reduced capability over unsafe autonomous action.**

If an ML evaluator becomes compromised, for example:

```text
ML trust → 0
quarantine ML component
disable ML votes
continue deterministic rules / Self / memory / trusted evaluators
reduce permitted action set if policy requires
```

`dendrite-guard` should remain an independent, small process responsible for:

- component integrity
- process health
- protected IPC
- trust-root integrity
- evaluator health
- recovery coordination

It should **not** become a second giant detection engine.

Trust roots can include:

- component identities
- signing/public keys
- policy identity
- model trust
- rule trust
- update trust

Recovery:

```text
revoke trust
   ↓
quarantine component
   ↓
preserve evidence
   ↓
restore known-good state
   ↓
verify
   ↓
restart
   ↓
re-attest
   ↓
restore capabilities
```

If recovery fails, enter a safe/degraded mode.

Linux hardening candidates include systemd sandboxing, capabilities, namespaces, seccomp, Landlock, read-only resources, protected Unix sockets, LSM integration, eBPF, and TPM-backed attestation where useful.

---

# 15. Machine learning

ML is an additional source of evidence, not the foundation or final authority.

Preferred structure:

```text
High-volume telemetry
       ↓
Rules / statistics / Self
       ↓
small suspicious subset
       ↓
ML
       ↓
structured evidence
       ↓
normal incident / quorum pipeline
```

Useful lightweight approaches:

- EWMA
- histograms
- z-scores
- counters
- entropy
- rate changes
- sequence likelihoods
- small dense neural networks
- lightweight GRU/statistical sequence models
- graph/relationship models later
- consequence models for MAGI perspectives

Possible behaviour model:

```text
200 → 64 → 32 → 1
```

Possible MAGI models:

```text
50 → 32 → 16 → output
```

Train in Python/PyTorch. Production inference can use a Rust-compatible runtime such as ONNX Runtime, Candle, or tract depending on later benchmarks and maintenance needs.

Models are untrusted data:

- verify signatures and metadata
- enforce compatibility
- cap CPU/memory/thread use
- provide inference budgets
- sandbox loading where practical
- support adaptive/event-driven scheduling

Resource modes can be exposed as Minimal, Standard, and Advanced.

Target philosophy: CPU-first, negligible normal idle overhead, event-driven ML, and a practical memory footprint for ordinary Linux systems.

---

# 16. Dovetail integration

Dendrite can use **Dovetail**, but it should be used in the **Python tooling/research plane**, not inserted into the trusted Rust action path.

Dendrite is Rust-first, so embedding Python into `dendrited` purely to use Dovetail would add unnecessary complexity and expand the trusted computing base.

Good uses inside `python/` include:

- dataset processing
- telemetry replay
- experiment orchestration
- model-training pipelines
- threat-intelligence ingestion
- offline Memory Graph analysis
- regression/security test orchestration
- bounded background work
- rate-limited external lookups
- bridging synchronous and asynchronous Python tools
- lifecycle/retry/observability support for research utilities

Conceptually:

```text
                 DENDRITE
                    │
              IPC / API / MCP
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
    Python tooling      Python research
          │                   │
       Dovetail             Dovetail
          │                   │
   replay / datasets    training / experiments
```

Do **not** make Dovetail part of:

```text
dendrite-action
dendrite-guard
```

and do not route privileged security decisions through a Python/Dovetail worker pipeline.

Correct boundary:

```text
Dovetail-backed tooling
        ↓
produces data / evidence / analysis
        ↓
Dendrite protocol/API
        ↓
normal Dendrite trust + policy boundaries
```

This lets Dendrite dogfood Dovetail for the workloads Dovetail is designed for without making it a security authority.

---

# 17. Updater and vulnerability remediation

`dendrite-updater` should abstract Linux package managers rather than hard-code one distribution.

```text
PackageManager
├── detect
├── inventory
├── check_updates
├── check_security_updates
├── resolve_transaction
├── prepare
├── apply
├── verify
└── rollback
```

Likely backends:

```text
apt
dnf
pacman
zypper
apk
flatpak
snap
```

Package manager selection can be auto-detected on install, user-overridden, and periodically re-detected.

Evaluate the **whole transaction**, including:

- dependencies
- packages added/removed
- config changes
- service restarts
- workloads
- containers/Kubernetes
- maintenance windows

Vulnerability intelligence should map:

```text
CVE ↔ package ↔ installed version ↔ fixed version ↔ severity ↔ exploitability
```

Distinguish "a CVE exists" from "this host is actually exposed."

Candidate patch generation may assist a human, but Dendrite should not autonomously perform arbitrary source-code modification or execute generated repair scripts as privileged actions.

---

# 18. Vaccination and threat-knowledge sharing

Vaccination means **pre-deploying signed, validated threat knowledge** before a host sees the threat.

Share threat knowledge broadly; keep host normality local.

```text
GLOBAL
├── threat antibodies
├── malware intelligence
├── attack-chain knowledge
├── global reputation
└── generic malicious behaviour

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
└── normal process relationships
```

Antibody maturity:

```text
CANDIDATE → LOCAL → VALIDATED → TRUSTED → GLOBAL
```

A local candidate must not automatically gain destructive authority.

Global threat antibodies should be signed and distributable. Shared benign/negative knowledge must be treated more conservatively than known-malicious knowledge because "normal" is highly host-specific.

---

# 19. Optional MCP server

`dendrite-mcp` is a separate repository/process:

```text
AI agent → dendrite-mcp → dendrited
```

Default posture: **read-only**.

Good MCP tools include:

```text
incident.explain
memory.recall
memory.related
self.explain_deviation
attack_chain.trace
entity.history
incident/process/network/vulnerability reads
```

Rules:

- no direct database access
- no direct action-executor access
- no arbitrary command execution
- authenticated and auditable
- mutations enter the normal auth/quorum/policy/action pipeline

An external AI is an investigator/operator, not root.

---

# 20. CLI and GUI

## CLI

Initial useful commands:

```bash
dendrite status
dendrite health
dendrite scan <path>
dendrite watch
dendrite process list
dendrite process show <pid>
dendrite incident list
dendrite incident show <id>
dendrite incident explain <id>
dendrite quarantine list
dendrite quarantine inspect <id>
dendrite quarantine restore <id>
dendrite quarantine delete <id>
dendrite rules list
dendrite config show
dendrite config get <key>
dendrite logs
dendrite doctor
```

Public names should remain conventional even when internal components use immune-system or MAGI terminology.

## GUI

`dendrite-ui` is an optional client, not part of the protection boundary.

Useful views:

- Overview
- Memory Graph
- Self
- Threats
- Incidents
- Attack Chains
- Activity
- Relationships
- topology
- MAGI/quorum
- action history
- system health

The Memory Graph UI is a projection of real STM/LTM state. It must not own memory logic or invent state.

Operational animation is acceptable when it represents real events:

```text
NGINX ─────────► APP
       request
APP ───────────► POSTGRES
       query
APP ───────────► INTERNET
       outbound
```

The Memory Graph itself should remain a clear, force-directed/Obsidian-like graph. Avoid fake neural animation or AI theatre.

Potential visual semantics:

```text
thick edge    = strong relationship
thin edge     = weak relationship
dotted edge   = nearly expired
faded node    = low current relevance
badge/icon    = state / priority / confirmed threat
```

Visual fading and graph removal must reflect real memory state, not arbitrary animation.

---

# 21. Human immune system ↔ Dendrite mapping

| Biology | Dendrite |
|---|---|
| Organism | Linux host |
| Immune system | Dendrite |
| Self | Known/normal host state |
| Non-self | Unknown/suspicious behaviour |
| Pathogen | Malware/malicious activity |
| Antigen | Observable suspicious characteristic |
| PAMP | Known malicious behavioural indicator |
| Danger signal | Contextual risk |
| Innate immunity | Rules/heuristics |
| Adaptive immunity | Learned behaviour |
| Antibody | Detection signature/model |
| B cell | Detection generator/learner |
| T cell | Investigation/coordination |
| Helper T | Coordinator |
| Cytotoxic T | Process termination |
| Regulatory T | False-positive/tolerance control |
| Memory B/T | Threat memory |
| Macrophage | Quarantine/remediation |
| Neutrophil | Rapid response |
| NK cell | Anomaly detector |
| Dendritic cell | Event/antigen processor |
| Complement | Response/evidence amplification |
| Cytokines | Internal event signals |
| Lymphatic system | Telemetry/event pipeline |
| Bone marrow | Rule/model generation |
| Thymus | Training/validation |
| Clonal expansion | Detection reinforcement |
| Somatic hypermutation | Detection mutation/generalisation |
| Affinity maturation | Detection refinement |
| Immune tolerance | Allowlisting/Self |
| Autoimmunity | False positive |
| Immunosuppression | Dendrite impairment/tampering |
| Inflammation | Elevated monitoring |
| Fever | Resource/sensitivity escalation |
| Sepsis | Cascading defensive failure |
| Vaccination | Pre-trained/shared threat memory |
| Antigen presentation | Feature extraction |
| Immune memory | Persistent Memory Graph knowledge |
| Immune exhaustion | Resource-exhaustion protection |
| Barrier immunity | File/exec/network controls |
| Skin/mucous membranes | Kernel/filesystem/network boundaries |

The MAGI/quorum system is a Dendrite-specific extension rather than a literal biological mapping.

---

# 22. Complete Dendrite system map

```text
                         DENDRITE
                            │
                  ┌─────────┴─────────┐
                  │                   │
                SELF              NON-SELF
                  │                   │
                  │              Threat / anomaly
                  │                   │
                  └───────┬───────────┘
                          │
                    SURVEILLANCE
                          │
              kernel / eBPF / fanotify
                          │
                          ▼
                    DENDRITIC CELL
                   event processing
                          │
                          ▼
                       ANTIGEN
                          │
              ┌───────────┼───────────┐
              │           │           │
           INNATE       MEMORY        ML
          DETECTION     GRAPH       DETECTION
              │           │           │
              └───────────┼───────────┘
                          │
                       EVIDENCE
                          │
                          ▼
                    HELPER T-CELL
                     coordination
                          │
                          ▼
                       INCIDENT
                          │
             ┌────────────┼────────────┐
             │            │            │
          BALTHASAR     CASPER      MELCHIOR
            HOST         USER      ENVIRONMENT
             │            │            │
             └────────────┼────────────┘
                          │
                        QUORUM
                          │
                          ▼
                    ACTION PROPOSAL
                          │
                    dendrite-action
                          │
             ┌────────────┼────────────┐
             │            │            │
         NEUTROPHIL   MACROPHAGE   CYTOTOXIC
         rapid       quarantine      T-CELL
         response                   termination
             │            │            │
             └────────────┼────────────┘
                          │
                       RESPONSE
                          │
                          ▼
                   IMMUNE MEMORY
                          │
                    Memory Graph
                          │
                          ▼
                    FUTURE THREATS
```

Guard:

```text
                    ┌───────────────────┐
                    │   DENDRITE-GUARD  │
                    │                   │
                    │ Trust / integrity │
                    │ anti-tampering    │
                    │ recovery          │
                    └─────────┬─────────┘
                              │
                 protects the immune system itself
```

---

# 23. Development roadmap

```text
0.  dendrite-memory
1.  dendrited foundation
2.  observation / collectors
3.  Self model
4.  basic detection
5.  incidents / attack chains
6.  dendrite-action
7.  dendrite-guard
8.  MAGI / quorum
9.  eBPF expansion
10. vulnerability / updater
11. ML
12. GUI expansion
13. containers / Kubernetes
14. MCP
15. federation
```

The GUI can begin around Stages 0–3 as a development/inspection tool.

Recommended implementation loop:

```text
Memory Graph
   ↓
real Linux observations
   ↓
Self
   ↓
what context is missing?
   ↓
improve Memory Graph
   ↓
detection
   ↓
what context is missing?
   ↓
improve Memory Graph
   ↓
incidents / response / learning
```

---

# 24. Design summary

Dendrite is not intended to be "a neural network antivirus." Its distinguishing architecture is the combination of:

- host-specific Self
- cheap deterministic detection first
- selective ML evidence
- temporal Memory Graph
- short-term and long-term memory with consolidation/decay
- graph-based contextual reasoning
- strict separation between evidence and authority
- MAGI-style independent action evaluation
- capability-limited transactional remediation
- independent trust/anti-tamper guard
- signed shared threat knowledge
- conventional CLI/GUI/MCP interfaces
- Rust-first trusted core with Python/Dovetail supporting research and tooling

The intended question is not merely:

> **"Have I seen this file before?"**

It is:

> **"Does this belong here, what is it doing, what is it connected to, what does that mean for this host, and what have I learned from similar behaviour?"**
