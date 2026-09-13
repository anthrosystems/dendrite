# Vulnerabilities, Remediation and Updates

## Package inventory and CVE knowledge

Dendrite inventories installed packages and stores version-aware vulnerability knowledge in the incidents database. A CVE record can be enriched with a display name and reusable behaviour IDs so an observed attack chain can be correlated with known vulnerability activity rather than matching only by package/version metadata.

Official CVE source material and Dendrite-derived enrichment remain distinct.

## Behaviour-aware classification

A CVE knowledge import may define reusable behaviour patterns and associate them with one or more CVEs/packages. Live attack chains can derive behaviour fingerprints and match behaviour definitions. A successful match can enrich the existing chain/incident presentation, for example changing an unknown display name to a known vulnerability/attack name while preserving canonical IDs and the historical action timeline.

This is classification evidence, not privileged authority.

## Dendrite Vulnerability Candidates

A **Dendrite Vulnerability Candidate** is a first-class research record for a possible vulnerability that does not yet have to be an official CVE.

Candidates can be created manually from **Analysis → Create Vulnerability Candidate** and can carry:

- title/description;
- affected products and versions;
- candidate CWE/weakness identifiers;
- severity/CVSS estimate;
- associated behaviour IDs;
- attack-chain, indicator and evidence references;
- source Antiserum IDs;
- reproduction and mitigation notes;
- discovery origin and confidence;
- optional later `cve_id`;
- lifecycle status such as draft/researching/ready/submitted/assigned.

An unofficial candidate remains useful shareable/learnable security knowledge. If an official CVE is later assigned, Dendrite should associate/promote the candidate without erasing its research history/provenance.

## Remediation boundary

Package remediation requires explicit authority and remains inside:

```text
proposal → MAGI → policy → Guard → PREPARE → REVALIDATE → COMMIT → VERIFY
```

Dendrite does not provide a generic privileged shell primitive.

## Self-update boundary

The independent updater foundation verifies signed release metadata/artifacts, hashes, revocation state and anti-downgrade constraints, and is designed around staging/rollback/service verification. The complete packaged self-update workflow is a Batch 7 / Checkpoint B goal; see [`ROADMAP.md`](ROADMAP.md).
