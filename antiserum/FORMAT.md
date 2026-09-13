# Dendrite Antiserum package format — v1

A `.danti` file is a signed Dendrite Antiserum package. The package carries a fixed set of authenticated security-intelligence payload files plus its signed envelope and Guard attestation.

## Logical layout

```text
package.danti
├── envelope.json
├── envelope.sig
├── attestation.json
├── payloads/
│   ├── vulnerabilities/vulnerabilities.json
│   ├── indicators/hashes.json
│   ├── indicators/domains.json
│   ├── indicators/ips.json
│   ├── indicators/urls.json
│   ├── behaviours/behaviours.json
│   └── graph/
│       ├── graph-fragment.json
│       └── attack-chains.json
└── provenance/sources.json
```

The physical `.danti` container is deterministic POSIX ustar. Only the exact standard paths documented below are allowed; unknown, duplicate, absolute, parent-traversal, or backslash paths are rejected.


## Terminology and package identity

The portable artifact is an **Antiserum package**. The canonical package identifier
is `antiserum_id`; `bundle_id` is not part of v1. The package itself remains
evidence and never carries execution authority.

The exact physical members are:

```text
package.danti
├── envelope.json
├── envelope.sig
├── attestation.json
├── payloads/vulnerabilities/vulnerabilities.json
├── payloads/indicators/hashes.json
├── payloads/indicators/domains.json
├── payloads/indicators/ips.json
├── payloads/indicators/urls.json
├── payloads/behaviours/behaviours.json
├── payloads/graph/graph-fragment.json
├── payloads/graph/attack-chains.json
└── provenance/sources.json
```

## Canonical JSON

`envelope.json` and `attestation.json` are signed/hashed in deterministic JSON:
object keys sorted lexicographically, no insignificant whitespace, array order
preserved, and ordinary JSON scalar encoding.

## Instance-bound signatures

The Ed25519 signature preimage is:

```text
DENDRITE-SIGNATURE-V1\0
<instance_id>\0
<key_id>\0
antiserum-envelope-v1\0
<canonical envelope bytes>
```

`envelope.sig` contains:

```text
ed25519:<128 lowercase hex characters>
```

The envelope also carries the immediate exporter's instance ID, key ID, public key, and key fingerprint. The included public key lets a receiver verify cryptographic authenticity to that key; it does not itself establish local trust. A receiver authenticates the immediate exporter only. Historical
origin/lineage inside payloads remains signed provenance asserted by that
exporter; it is not recursively authenticated.

## Attestation

`attestation.json` is not separately signed. Its canonical SHA-256 digest is
committed by the signed envelope, and the attestation is also included in the
content Merkle root.

The attestation must have been observed no more than 30 seconds before package
creation. Guard state is evidence/provenance only and never execution authority.

## Content root: `sha256-merkle-v1`

Files committed by the content root are `attestation.json` plus every declared
payload/provenance file. `envelope.json` and `envelope.sig` are excluded.

Files are sorted by canonical path. Each leaf is:

```text
SHA256(
  "DENDRITE-ANTISERUM-LEAF-V1\\0" ||
  path || 0x00 || SHA256(file_bytes)
)
```

Parent nodes are:

```text
SHA256(
  "DENDRITE-ANTISERUM-NODE-V1\\0" ||
  left_digest || right_digest
)
```

If a level has an odd number of nodes, its final node is duplicated for that
pair. The final digest is encoded as `sha256:<64 lowercase hex>`.

## Sequence / replay protection

Outgoing sequence numbers are monotonically increasing per local stream. v1
uses the `default` stream. Receivers persist the highest accepted sequence by:

```text
(immediate issuer instance ID, immediate key fingerprint, stream)
```

A sequence equal to or lower than the recorded value is rejected. Sequence
acceptance occurs only after cryptographic/content verification succeeds.

## Trust boundary

Cryptographic validity does not imply local trust and does not grant authority.
Antiserum remains evidence. Any privileged action continues through Dendrite's
MAGI → policy → Guard → transaction boundary.

## V1 payload presence and status

Every v1 package contains all nine canonical payload files. Empty payloads are
valid schema documents with empty record arrays; they are never zero-byte files.

`envelope.json` lists all nine payloads and marks each declaration with:

- `status: "populated"` when the payload contains one or more semantic records.
- `status: "empty"` when the canonical payload document contains no records.

All payload files, including those marked `empty`, are committed by the
`sha256-merkle-v1` content root. Receivers may skip semantic processing of an
`empty` payload, but must still authenticate and content-verify it.

The envelope status is not trusted as a hint: verification recomputes payload
emptiness from the authenticated JSON and rejects a status mismatch.

## Graph identity and correlation

`object_id` / canonical graph node IDs remain observation identities scoped to the originating Dendrite instance. Two hosts observing the same infection do not need identical object IDs.

Graph node `properties` may include `correlation_keys`, derived stable keys/fingerprints that allow equivalent observations across hosts to be related without collapsing provenance. Correlation keys are evidence and may vary in confidence/semantics by key type.

## Behaviour payload

`payloads/behaviours/behaviours.json` contains reusable semantic behaviour definitions rather than raw host observations or executable logic. Behaviour conditions may include graph-relation constraints describing expected source kind, relationship kind and target kind. Behaviours can carry a stable fingerprint plus provenance/lineage.

A behaviour definition must never contain arbitrary executable remediation code, scripts or SQL. It is detection/classification knowledge.

## Attack-chain enrichment

Attack-chain records preserve their canonical chain identity while allowing later classification enrichment, including:

- original title and enriched display title;
- classification confidence;
- matched vulnerability/CVE IDs;
- behaviour IDs;
- a derived behaviour fingerprint.

A later classification does not rewrite the historical identity or imply Dendrite knew the classification before it was derived.

## Vulnerability knowledge and candidates

The vulnerability payload may carry both:

- known/official CVE knowledge (`record_type: "cve"`); and
- Dendrite Vulnerability Candidates (`record_type: "candidate"`).

A candidate is research evidence and does not claim an official CVE assignment. Candidate records may carry status, description, behaviour associations and provenance. If a CVE is later assigned, that relationship should enrich the candidate without erasing its earlier research lineage.

Official/source vulnerability data and Dendrite-derived enrichment must remain distinguishable.

## Lifetime and freshness

Antiserum package lifetime and Guard-attestation freshness are deliberately separate.

- `created_at` is mandatory.
- `expires_at` is optional. Dendrite-created manual and automatic packages do not expire by default.
- A producer may explicitly set `expires_at`; receivers must reject the package after that signed timestamp.
- `attestation.observed_at` remains freshness-checked against package creation time. A package can therefore remain valid historical/research intelligence long after the export-time Guard attestation is no longer fresh for a new export.

This allows air-gapped and archival Antiserum packages to remain reviewable/importable without weakening the requirement that the exporter attest its state at export time.
