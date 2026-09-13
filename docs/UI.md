# Dendrite Operator UI

The web UI renders daemon state and must not invent security state or bypass daemon authority checks.

## Main knowledge/security surfaces

Current pages include Overview, Activity, Incidents, Threats, Attack Chains, Vulnerabilities, Memory Graph, Relationships, Analysis, MAGI & Response, Self & Trust, and System Health.

## Memory Graph

The Memory Graph renderer is shared as a reusable rendering backend/component, but pages keep separate data sources and workflows.

The normal Memory Graph page renders live Dendrite Memory only. It does **not** import or load Antiserum packages. Its graph controls include host-origin filtering based primarily on `origin_instance_id`; node inspection shows canonical IDs, provenance and correlation keys.

## Analysis

Analysis is tabbed:

```text
Review
Import Package
Create Antiserum
Create Vulnerability Candidate
```

### Review

Review sessions are persisted server-side and multiple reviews may coexist. A browser/tab can select which review it is displaying. Navigation/reload/daemon restart does not implicitly unload server-side reviews; **Unload Review** removes only that review session and does not delete the underlying Antiserum package.

A Review exposes package Overview, Graph, Payloads, Provenance and Verification. Its graph uses the same renderer implementation as the Memory Graph with a package-derived graph DTO.

### Import Package

Import Package parses, strictly validates, cryptographically verifies, replay-checks and stores a `.danti` package on-device. **It does not merge package knowledge into the active Dendrite databases.** The package can be reviewed indefinitely in this state.

### Accept Knowledge

For a foreign imported package, Review exposes an explicit **Accept Knowledge** control. This re-verifies the package and then merges the currently supported semantic classes:

- graph nodes and relationships, preserving origin and recording the immediate exporter in `imported_from_instance_id`;
- correlation keys attached to accepted graph objects;
- reusable behaviour knowledge;
- CVE knowledge/enrichment;
- Dendrite Vulnerability Candidates.

Foreign attack-chain history remains review evidence and is not injected as a local incident. Indicator payloads remain review-only until first-class local indicator stores exist. Acceptance is recorded server-side and is idempotent. Packages issued by the local Dendrite instance are treated as source knowledge and cannot be re-accepted into the same host.

### Create Antiserum

The user selects semantic payload classes. Provenance is mandatory and has no selector.

Memory Graph scope options:

- Complete Graph;
- Best Path;
- Reachable Graph;
- optional maximum depth for trace modes.

Attack chains, CVEs/candidates, indicators and behaviours expose class-appropriate selectors. The physical v1 package always contains all nine authenticated payload files.

### Create Vulnerability Candidate

Manual candidate creation supports vulnerability description, affected products/versions, candidate weaknesses, CVSS/severity, associated behaviours/attack chains, reproduction/mitigation notes and confidence. A currently reviewed Antiserum can be recorded as source provenance.

## Attack Chains and Vulnerabilities

Attack Chains render canonical chain identity plus classification enrichment such as original/display title, matched vulnerability IDs, behaviour IDs/fingerprint and confidence. Vulnerability detail renders associated activity/behaviour knowledge when available.

## Privilege model

The UI may request actions or remediation but cannot bypass MAGI, policy, Guard or transaction verification. UI state is not authority.
