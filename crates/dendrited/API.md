# Dendrite HTTP API

The operator UI uses the localhost Dendrite HTTP API, which defaults to `127.0.0.1:8766`. It is a presentation/control surface over daemon state; the UI is not a security authority.

The API is currently development-oriented. Packaging must preserve localhost/protected access and should not expose it remotely without an explicit authenticated design.

## Core

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/status` | Daemon, instance identity and signing-key status |
| GET | `/api/v1/health` | Health check — see "Health check semantics" below |
| GET | `/api/v1/incidents` | Incident list |
| GET | `/api/v1/incidents/:id` | Incident detail/evidence |

## Health check semantics

`GET /api/v1/health` returns `{"daemon": "...", "memory": "...", "guard": "..."}`.

- `memory`: `"ok"` or `"error"`, from a direct ping of the Memory Graph database.
- `guard`: the real current Guard trust state (`trusted`, `degraded`, `suspected`, `quarantined`, `compromised`, `recovering`).
- `daemon`: a timed liveness probe of the self-store and incidents databases (the latter also backs the vulnerability/CVE/behaviour-knowledge tables — see `docs/CONFIGURATION.md`). `"ok"` if both respond within the timeout, `"degraded"` if they respond but too slowly, `"error"` if either query fails outright.

The `daemon` timeout is currently a placeholder (`DaemonCore::HEALTH_CHECK_TIMEOUT`, 200ms) and has not been benchmarked against representative load — see `docs/TODO.md` and the "Benchmarking" item in `docs/ROADMAP.md`. Don't treat `"degraded"` as calibrated yet; treat `"error"` as meaningful (it means a query genuinely failed).

## Memory Graph

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/memory/nodes` | Nodes; optional kind filter |
| GET | `/api/v1/memory/recent` | Recent nodes |
| GET | `/api/v1/memory/graph` | Renderable graph DTO |
| GET | `/api/v1/memory/neighbours` | Adjacent node IDs |
| GET | `/api/v1/memory/path` | Filtered path query |

Memory node DTOs include host-local canonical IDs, provenance, and derived `correlation_keys`. Canonical `object_id`s are observations and remain host-scoped; correlation keys are the cross-host equivalence/correlation layer.

## Guard and telemetry

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/guard` | Current Guard state |
| GET | `/api/v1/guard/findings` | Integrity/trust findings |
| GET | `/api/v1/telemetry/status` | Collector status/fallback state |
| GET | `/api/v1/telemetry/recent` | Recent normalised events |

## Actions

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/actions` | Action proposals |
| POST | `/api/v1/actions` | Create proposal |
| GET | `/api/v1/actions/:id` | Proposal/evaluations/transaction detail |
| POST | `/api/v1/actions/:id/evaluate` | Evaluate a proposal |
| POST | `/api/v1/actions/:id/reevaluate` | Re-evaluate against current authority/context |

A request through this API does not bypass the MAGI → policy → Guard → transaction boundary.

## Vulnerabilities and remediation

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/vulnerabilities/status` | Inventory/knowledge status |
| GET | `/api/v1/vulnerabilities/inventory` | Installed package inventory |
| GET | `/api/v1/vulnerabilities` | Exposure list |
| GET | `/api/v1/vulnerabilities/:id` | Exposure detail |
| POST | `/api/v1/vulnerabilities/refresh` | Refresh inventory/exposures |
| POST | `/api/v1/vulnerabilities/:id/manual` | Create manual remediation proposal |
| POST | `/api/v1/vulnerabilities/:id/authorise` | Explicitly authorise remediation |
| POST | `/api/v1/vulnerabilities/:id/update` | Execute authorised update transaction |

Known CVE records can carry Dendrite enrichment such as display names and associated behaviour IDs. Official CVE source data remains distinguishable from host-derived enrichment.

## Analysis and Antiserum

The Analysis workspace separates **Import Package** from **Accept Knowledge**. Importing verifies, replay-checks and stores evidence only. Accept Knowledge is a separate explicit operator action that merges supported semantic knowledge into the active stores. Successful verification alone is never execution authority.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/analysis/packages` | On-device Antiserum package index |
| POST | `/api/v1/analysis/import` | **Import Package**: verify/replay-check/store a `.danti` without merging active knowledge |
| POST | `/api/v1/analysis/export` | Create a signed Antiserum package |
| GET | `/api/v1/analysis/packages/:antiserum_id` | Package metadata/detail |
| GET | `/api/v1/analysis/packages/:antiserum_id/graph` | Parsed graph DTO for Review renderer |
| GET | `/api/v1/analysis/packages/:antiserum_id/download` | Download original `.danti` artifact |
| POST | `/api/v1/analysis/packages/:antiserum_id/accept` | **Accept Knowledge** from an imported package into supported local knowledge stores |
| GET | `/api/v1/analysis/chains` | Attack-chain knowledge including classification enrichment |
| GET | `/api/v1/analysis/cves` | CVE knowledge for export/selection |
| GET | `/api/v1/analysis/behaviours` | Reusable behaviour definitions |

### Review sessions

Reviews are server-persisted and plural. Multiple operators/tabs can keep different reviews open; unloading a review does not delete its underlying package.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/analysis/reviews` | Active review sessions |
| POST | `/api/v1/analysis/reviews` | Create a review session |
| POST | `/api/v1/analysis/reviews/:review_id/open` | Mark/open a review |
| DELETE | `/api/v1/analysis/reviews/:review_id` | Unload the review only |

### Vulnerability Candidates

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/analysis/vulnerability-candidates` | List Dendrite Vulnerability Candidates |
| POST | `/api/v1/analysis/vulnerability-candidates` | Manually create a candidate |
| GET | `/api/v1/analysis/vulnerability-candidates/:candidate_id` | Candidate detail |

A Dendrite Vulnerability Candidate is research knowledge, not an assigned CVE. It can carry affected products/versions, candidate weaknesses/CWEs, CVSS estimate, associated behaviours/attack chains/indicators/evidence/Antiserum packages, reproduction and mitigation notes, confidence, and optionally a later assigned CVE ID.

## Antiserum export scopes

`Create Antiserum` selects semantic knowledge classes. Provenance is mandatory and therefore has no UI selector. The v1 physical package still contains all nine canonical payload files; unselected/empty classes are authenticated as `status: "empty"`.

Memory Graph scopes:

- **Complete Graph** — all selected live graph knowledge;
- **Best Path** — from one starting node, repeatedly follow the strongest outgoing relationship (effective strength, confidence, recency, deterministic ID tie-break);
- **Reachable Graph** — cycle-safe traversal of all reachable outgoing relationships from the starting node.

Best Path and Reachable Graph support a finite maximum depth or Unlimited.

## Validation

Use [`docs/DEVELOPMENT.md`](../../docs/DEVELOPMENT.md) as the canonical API validation plan rather than duplicating curl examples here.