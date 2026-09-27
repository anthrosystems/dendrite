# Dendrite CLI

`dendrite-cli` is the local Unix-socket client for `dendrited`. `DENDRITE_SOCKET` always overrides the default when set; otherwise it checks `/run/dendrite/dendrited.sock` (a packaged install's socket) first, falling back to the local-dev default `/tmp/dendrited.sock` if that's not there — see `crates/dendrite-cli/README.md`.

The CLI is an operator/debugging client; privileged response still requires the daemon's normal MAGI, policy, Guard and transaction checks.

## Getting help

Only `--help`/`-h` trigger help output — the bare word `help` is not a recognised command at any level. Typing it (alone or as a subcommand) is treated like any other unrecognised input and falls back to the same general help.

- `dendrite-cli --help` (or `-h`, or no arguments at all) shows general help: the full command list below, plus a pointer to per-command help.
- Multi-form commands — `incidents`, `memory`, `actions`, `guard`, `vulnerabilities`, `vulnerability`, `telemetry`, `debug` — each support their own `dendrite-cli <command> --help`, showing that command's full usage (including forms not obvious from the general list, like `incidents <ID>` or `memory nodes --kind <KIND>`). `--help`/`-h` is recognised anywhere in the arguments, not just immediately after the command.
- Argument-less commands — `status`, `health`, `http-token`, `version` — have no dedicated help screen. A stray `--help`/`-h` passed to one of these is ignored and the command runs normally, rather than being rejected or explained.
- Any unrecognised or malformed input under a known command family falls back to that family's own help (not the general list) where possible — e.g. `memory nodes --kind` (missing value) shows `memory --help`'s output.

`dendrite-cli --help` is the executable source of truth if this document diverges from it.

## Commands

```text
status
health
http-token
version
incidents
incidents <id>
memory nodes [--kind <kind>] [limit]
memory recent [limit]
memory neighbours <node-id>
memory path <source-id> <target-id>
actions
actions <id>
actions propose <incident-id> <action> <target>
actions evaluate <proposal-id>
guard
guard findings
guard baseline
guard verify
telemetry
telemetry recent [limit]
vulnerabilities [--all]
vulnerability <exposure-id>
vulnerability status
vulnerability inventory
vulnerability refresh
vulnerability import <path>
vulnerability manual <exposure-id>
vulnerability authorise <exposure-id>
vulnerability update <exposure-id>
```

Debug commands (development-only, not a production operator API; disabled entirely in release builds):

```text
debug seed-incident [label]
debug guard-state <state>
debug guard-finding <target> <severity> <description>
```

## Important semantics

- `status` exposes the persistent Dendrite instance ID plus active signing key/fingerprint. `observations` in its output is a per-process-lifetime counter — it resets to `0` on every daemon restart by design; it is not a persistent lifetime total, so a drop after restart is not data loss. Instance ID, signing key, and Memory Graph state persist across restarts independently of this counter.
- Memory canonical IDs are host-scoped; equivalent observations across hosts correlate through fingerprints/correlation keys/behaviour knowledge rather than by forcing identical `object_id`s.
- `vulnerability manual` creates the remediation proposal path; it does not directly mutate the package manager.
- `vulnerability authorise` records explicit user authority; stale authority must not be reusable for a changed target/state.
- `vulnerability update` remains transactional and policy/Guard-gated.
- `vulnerability import` validates behaviour conditions strictly and rejects the whole import on the first invalid one (see "CVE knowledge bundle format" below) rather than importing partial/best-effort data.
- Debug commands are development-only surfaces and should not be treated as production operator APIs.
- `http-token` prints the bearer token that gates `dendrited`'s HTTP API and `/ws` WebSocket upgrade (see `docs/CONFIGURATION.md`'s "HTTP API authentication" section). It's deliberately the only way to retrieve it — the HTTP API never serves it over itself. The local dev UI (`npm run dev`) never needs this pasted in by hand; it's only for the packaged UI's one-time token-entry prompt, or for a manual `curl`/script against the HTTP API.
- `memory nodes` caps what it prints to the terminal at 20 by default (the daemon's own `MemoryNodes` query is unbounded, since it also backs the HTTP API's node listing, which the UI paginates/searches itself) — pass an explicit `[limit]` to see more, or `0` for no limit at all.
- `guard baseline`/`guard verify` hash the paths `dendrite-guard` is itself configured to watch (its own `DENDRITE_GUARD_WATCH_PATHS`, never anything supplied by this command) and compare against a signed baseline it stores and verifies itself — see `crates/dendrite-guard/README.md`'s "Integrity manifest" section. `guard verify` triggers the same verification pass `dendrite-guard` also runs automatically in the background (every `DENDRITE_GUARD_VERIFY_INTERVAL_SECONDS`, default 300s): a detected mismatch is recorded as an `IntegrityFinding` (deduplicated across repeated checks) and escalates trust state, via a monotonic rule that never auto-improves trust back toward `trusted`.

Analysis/Antiserum and Vulnerability Candidate management currently live in the HTTP/UI surface rather than the CLI. A later CLI update should add feature parity deliberately rather than exposing raw file/database primitives.

## Guard trust states and integrity severities

Used by `dendrite-cli guard`, and by `debug guard-state`/`debug guard-finding` (development builds only).

Trust states (`debug guard-state <state>`):

```text
trusted
degraded
suspected
quarantined
compromised
recovering
```

Integrity severities (`debug guard-finding <target> <severity> <description>`):

```text
informational
warning
high
critical
```

An invalid value for either is rejected with an error listing the valid options, rather than the daemon's generic error format.

## CVE knowledge bundle format (`vulnerability import`)

`vulnerability import <path>` reads a JSON file with this shape (schema version 1):

```json
{
  "schema_version": 1,
  "generated_at": 1700000000,
  "source": "example-source",
  "behaviours": [
    {
      "id": "behaviour:example-id",
      "name": "Example behaviour",
      "description": "...",
      "confidence": 85,
      "severity": "high",
      "techniques": ["T1071"],
      "conditions": [
        { "kind": "graph-relation", "source_kind": "process", "relationship": "connected_to", "target_kind": "network_endpoint" }
      ],
      "ordered": true,
      "max_interval_seconds": 3600,
      "source_refs": ["example-source"]
    }
  ],
  "records": [
    {
      "id": "CVE-0000-00000",
      "package": "example-package",
      "affected_before": "1.2.3",
      "fixed_version": "1.2.4",
      "severity": "high",
      "description": "...",
      "provenance": "example-source",
      "behaviour_ids": ["behaviour:example-id"]
    }
  ]
}
```

`behaviours` is optional (defaults to empty) and lets a bundle carry reusable behaviour/attack-chain-classification knowledge alongside CVE records. `records[].behaviour_ids` associates a CVE with one or more of the bundle's (or already-known) behaviour IDs.

**Every behaviour condition object must include `"kind": "graph-relation"` explicitly.** This is the only condition kind currently supported, and it is required rather than assumed: the matcher that classifies attack chains against behaviour knowledge only considers conditions carrying this exact tag, so it can be extended to other condition kinds later without ambiguity. A condition missing `"kind"`, or carrying any other value, is rejected — the whole import fails rather than silently storing a condition that would never match anything. Each `graph-relation` condition also requires non-empty `source_kind`, `relationship`, and `target_kind` strings.

Importing new behaviour/CVE knowledge re-evaluates all existing attack chains against it (not just chains created afterward), without changing any chain's or incident's canonical ID.

## Development socket permissions

A typical development configuration is:

```bash
DENDRITE_SOCKET_GROUP=dendrite \
DENDRITE_SOCKET_MODE=0660 \
target/debug/dendrited
```

The invoking shell must actually have membership in the `dendrite` group. A packaged install now does this for you (`packaging/postinst` best-effort adds the invoking `sudo` user to the `dendrite` group on install — effective after the next login/`newgrp dendrite`); `scripts/bootstrap.sh` does the equivalent for local dev.

See [`docs/DEVELOPMENT.md`](../../docs/DEVELOPMENT.md) for the current CLI smoke/regression sequence.