# Dendrite Identity, Correlation and Provenance

## Instance identity

Every Dendrite installation has a persistent installation identity (`instance_id`) and an Ed25519 signing identity. This is a Dendrite installation identity, not a claim about immutable physical hardware.

Private signing material is filesystem-backed with strict permissions and is never stored as raw key material in SQLite. Public-key metadata/fingerprint/lifecycle state is stored in Self.

## Canonical object identity

Memory/evidence object IDs are observation identities and are host-scoped:

```text
<instance-id>::<local-node-id>
```

The same infection/artifact observed independently on Host A and Host B should not normally get the same `object_id`. Preserving distinct IDs preserves the fact that two hosts made independent observations.

## Correlation identity

Cross-host equivalence is represented separately through correlation keys, fingerprints and reusable behaviours. Examples include:

- SHA-256 artifact identity;
- normalised domain/IP/URL;
- process/executable semantic fingerprint;
- package/ecosystem/version identity;
- CVE identity;
- derived behaviour fingerprints/pattern IDs.

Thus:

```text
Host A observation ─┐
                    ├─ correlates-to → shared fingerprint/behaviour
Host B observation ─┘
```

Correlation never rewrites either observation's provenance.

## Memory provenance standard

Relevant persisted knowledge records carry:

- `origin_instance_id` — where the knowledge/object originated;
- `imported_from_instance_id` — immediate Dendrite instance from which it was imported, or SQL `NULL` when not imported;
- `derived_by_instance_id` — instance that derived the relationship/knowledge, or `NULL` when not derived;
- `lineage` — ordered recent host lineage, capped at the most recent 10 hosts. Verified end-to-end across 12 real hops (`scripts/test_lineage_cap.sh`), not just unit-tested: the array correctly caps at 10 and the origin host ages out of it as expected past that point, while `origin_instance_id` (above) remains the correct source of truth for who originated the object regardless of how far it's since travelled.

The original source remains separately preserved by `origin_instance_id`. Unused values are real SQL `NULL`, not placeholder strings.

## Antiserum trust rule

A receiver authenticates only the **immediate exporter** of an Antiserum package. It does not recursively re-authenticate historical origin hosts in provenance/lineage. Historical origin and lineage are signed assertions made by the immediate exporter.

Imported knowledge can become the receiver's accepted evidence without rewriting its origin. Evidence is never execution authority.

## Attack-chain enrichment

Attack chains keep a stable canonical chain ID. Classification may later enrich that same identity with a display name, matched CVEs, reusable behaviours and classification confidence. Existing action proposals/transactions remain linked to their original incident/chain identity, preserving the timeline of what Dendrite knew when an action occurred.