# Dendrite Antiserum

An **Antiserum package** (`.danti`) is Dendrite's signed portable security-intelligence artifact. It can carry vulnerability knowledge/candidates, indicators, reusable behaviours, graph fragments, attack chains and mandatory provenance while preserving the rule that **evidence is never authority**.

The canonical v1 specification is [`FORMAT.md`](FORMAT.md). Dendrite-owned JSON Schemas are under [`schema/`](schema/). Receivers must use those trusted schemas rather than schemas supplied inside a package.

Every v1 package has one fixed physical/logical layout and contains all nine canonical payload/provenance files. Empty classes remain valid authenticated JSON payloads and are declared `status: "empty"`; files are not omitted merely because they contain no records.

The package identifier is `antiserum_id`. Historical `bundle` terminology is not part of v1.
