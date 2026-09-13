# TODO

Running list of small items found while working through `TESTS.md` and the
Checkpoint A review. This is a scratch tracking file, not a design document —
each item should end up either fixed, folded into `ROADMAP.md`/other docs, or
explicitly dropped, and then removed from this list. Nothing here should
still be open when Checkpoint A is signed off.

## Done

- [x] `dendrite-cli --help` was missing `guard`, `guard findings`, and all
  `debug` subcommands; stale line claimed privileged actions were
  "policy-denied until Guard integration" despite Guard already existing.
  Fixed.
- [x] `debug guard-state`/`debug guard-finding` gave a raw Rust `Debug`-
  formatted error on an invalid value instead of listing valid options.
  Fixed in `runtime.rs` (validates before calling into `GuardService`).
- [x] No command had contextual `--help`; multi-form commands (`incidents`,
  `memory`, `actions`, `guard`, `vulnerabilities`, `vulnerability`,
  `telemetry`, `debug`) now support `--help`/`-h` anywhere in their
  arguments; argument-less commands (`status`, `health`, `version`) ignore
  a stray `--help`/`-h` rather than erroring.
- [x] Unrecognised forms of a known family (`memory nodes --kind` with no
  value, bare `vulnerability`, `guard extra-garbage`) fell through to the
  generic top-level help instead of that family's own help. Fixed: the
  catch-all now checks `HelpTopic::for_family` first.
- [x] `actions propose`/`actions evaluate` typed without their required
  arguments silently matched the generic `actions <ID>` pattern (e.g.
  looked up an action literally named "propose") instead of surfacing a
  missing-arguments error. Fixed by excluding those two reserved words from
  the generic ID-lookup match arm.
- [x] Attack-chain classification (`observe_attack_chain`) only ran once, at
  the moment a chain's evidence was first created — importing new
  behaviour/CVE knowledge afterward never reached chains that already
  existed, contradicting `architecture.md`'s stated intent that chains "can
  later be enriched/classified." Fixed: added
  `DaemonCore::reclassify_all_attack_chains`, called after every
  `vulnerability import`, which re-runs classification against all current
  chains without changing canonical chain/incident identity.
- [x] Behaviour conditions imported via `vulnerability import` silently
  never matched anything: the matcher in `knowledge.rs` only considers
  conditions tagged `"kind": "graph-relation"`, but hand-authored CVE
  bundles (per the documented `source_kind`/`relationship`/`target_kind`
  triple) had no reason to know that internal tag was required. Fixed in
  `vulnerability.rs`: `validate_behaviour_condition` now explicitly rejects
  (fails the whole import) any condition missing `"kind": "graph-relation"`
  or a required field, rather than silently defaulting it. Documented the
  full bundle schema, including this requirement, in `docs/CLI.md`.
- [x] `docs/CLI.md`'s `status` semantics section now notes that
  `observations` is a per-process-lifetime counter that resets to 0 on
  every daemon restart (by design), not a persistent lifetime total.
- [x] `docs/CLI.md` rewritten: per-family `--help` behaviour, the full
  `debug` subcommand list, Guard trust-state values and integrity
  severities, and the CVE knowledge bundle format (including the
  `"kind": "graph-relation"` condition requirement above).
- [x] UI inconsistency: the Incidents/Attack Chains pages appeared to always
  show the generic incident summary instead of anything
  classification-derived. Turned out not to be a UI bug at all — no chain
  had a matched CVE yet to display. Confirmed in the actual UI (not just
  the API) that once `inc_00000001` got a real CVE match via the
  retroactive-classification path, both the Incidents page and the Attack
  Chains page correctly render "Example remote code execution"; the Threat
  Knowledge page is unaffected (it shows the raw node label, a different
  thing entirely).
- [x] Automatic Antiserum export had no deduplication at all: every
  reinforcement of an ongoing attack chain creates a new evidence row (and
  therefore a fresh literal `chain_id`, which embeds that evidence ID), and
  `auto_export_attack_chain` had no check against re-exporting the same
  underlying chain shape — so a persistently reinforced real attack chain
  would have generated an unbounded number of signed packages, one per
  reinforcement. Fixed: added a new `automatic_chain_exports` table
  (`knowledge.rs`, keyed on `(incident_id, behaviour_fingerprint)` — the
  fingerprint is a stable structural hash, unlike the literal chain_id) and
  a check in `auto_export_attack_chain` that skips creating another package
  once one already exists for that incident/shape combination.
- [x] `dendrite-cli actions`/`actions <ID>` showed the wrong field on the
  `guard:` line: it printed `ActionDetailDto.guard_requirement`, which is a
  hardcoded constant (`"required_for_execution"`, always, regardless of
  action type or Guard state) — not the actual per-evaluation Guard verdict.
  So the CLI never actually showed whether Guard allowed or denied a given
  evaluation; `quorum:`/`policy:` were already correct (they read
  `proposal.quorum`/`proposal.policy`). Fixed: `render_action` now reads
  `proposal.guard` instead, matching the same pattern as quorum/policy.
  `guard_requirement` itself is unchanged in the backend/HTTP DTO (still a
  placeholder, still potentially read by the UI — worth checking whether
  the UI has the same display bug, separately from this CLI fix).
- [x] `HealthDto.daemon` was hardcoded to `"ok"` in both `runtime.rs` and
  `http.rs`, performing no actual liveness check. Fixed: added `ping()` to
  `SelfStore` and `IncidentService`, and a new shared
  `DaemonCore::health_check()` (used by both the IPC and HTTP handlers) that
  times both pings and reports `"ok"` within timeout, `"degraded"` if slow,
  `"error"` if either query fails. The timeout itself
  (`DaemonCore::HEALTH_CHECK_TIMEOUT`, 200ms) is an explicitly-flagged
  placeholder, not a measured value — see the new "Batch 10: Benchmarking"
  in `ROADMAP.md`, which is where it (and anything similar added before
  then) should get a real number.
- [x] Fanotify was opt-in-and-restrictive (`DENDRITE_FANOTIFY` default off,
  `DENDRITE_WATCH_PATHS` an arbitrary include-list, per-directory marks
  capped at 4,096). Redesigned to match a real EDR/AV default posture:
  `DENDRITE_FANOTIFY` now defaults **on** (opt-out via `DENDRITE_FANOTIFY=0`),
  `DENDRITE_WATCH_PATHS` removed entirely in favour of `DENDRITE_WATCH_MOUNTS`
  (a restrict-list, not an include-list — empty means "every real mount,
  auto-discovered from `/proc/self/mountinfo`, minus a hardcoded
  pseudo-filesystem skip-list"), and `DENDRITE_WATCH_EXCLUDE_PATHS` added as
  the userspace opt-out filter on reported events. Every mount is marked
  with a single `FAN_MARK_FILESYSTEM` call instead of walking a directory
  tree — replaces the old cap-prone per-directory approach entirely.
  Periodic re-scan (piggybacked on `DENDRITE_TELEMETRY_INTERVAL_SECONDS`)
  picks up mounts that appear after startup (USB drives, container overlay
  mounts) — deliberately just coverage maintenance, not its own security
  signal yet. Full design/rationale in `CONFIGURATION.md`.
  **Caveat, not yet verified**: needs a real `cargo check`/`cargo test` pass
  on your end — I can't run either in this sandbox, and while writing this
  I introduced (and then caught, via a manual brace-balance check, since a
  naive line-count check gave a false negative) one real dangling-brace bug
  from deleting the old per-directory-walk function. Everything here has
  been carefully re-read but never actually compiled.
- [x] Renamed `AdaptiveAnalysisError/Sources/Campaign/Manager` -> `Culture*`
  and `adaptive_analysis.rs` -> `culture.rs` (mechanical rename, per the
  user settling on "Culture" as the name). Confirmed zero remaining
  references to the old symbol names anywhere in `crates/`.
- [x] Added `DENDRITE_WATCH_INCLUDE_PATHS` (the counterpart to
  `DENDRITE_WATCH_EXCLUDE_PATHS`) for marking specific extra paths whose
  mount isn't otherwise covered, using the same directory-by-directory
  approach the old `DENDRITE_WATCH_PATHS` design used (brought back
  specifically for this, capped at 4,096 directories). Startup now
  explicitly rejects (falls back to polling, doesn't crash) any
  include/exclude path pair that's equal or one contains the other, rather
  than silently picking a winner — `find_watch_path_collision` in
  `telemetry.rs`. Also caught and fixed a second dangling-brace bug this
  time while writing it (a proper tokenizing brace/paren balance check,
  not a naive count, is what actually caught both this and last turn's
  bug — worth remembering as the right verification tool given I can't
  run `cargo check` myself).
  **Still unverified**: same caveat as above, needs a real `cargo check`.
- [x] UI fixes from the user-feedback backlog (`ROADMAP.md`): button
  relabels ("Import/Create Antiserum Package"), the Dashboard's always-
  visible Guard exposition sentence moved to a hover `.info-hint` badge
  (Guard/Health pages' own dedicated explanatory text left alone — those
  pages exist specifically to explain status in detail), Memory Graph
  focus/drag distinction (dragging away from the focused node unfocuses
  it, dragging the node itself never does), 3D camera pitch inversion
  fixed, user-node color changed to match the yellow already defined
  elsewhere (`Memory.tsx`), Live Event Stream search added matching the
  Memory Graph's search UX. Verified with a real `npx tsc --noEmit`
  pass (zero errors) after a proper `npm install` — not just read-through.
- [x] CVE/exposure lifecycle implemented: `ignore_exposure` (only from
  `open`/`awaiting_revalidation`, records the version at time of ignoring),
  `delete_exposure` (unrestricted, hard delete), `unignore_if_matched`
  (re-raises an ignored exposure when a fresh attack-chain/behaviour
  reclassification matches its CVE — wired into the `vulnerability import`
  path via `reclassify_all_attack_chains` now also returning matched CVE
  IDs), and `refresh_inventory`'s CASE logic auto-re-raising an ignored
  exposure if the installed version changes while still matching (a
  package update revealing the same CVE again). New `ignored_version`/
  `ignored_at` columns and DTO fields. Deliberately scoped to the
  import-triggered reclassification path, not live per-observation
  ingestion — the latter would need deeper `IngestionOutcome` plumbing
  across many callers; logged as a known limitation, not silently dropped.
  HTTP routes (`POST .../ignore`, `POST .../delete` — deliberately *not*
  the `DELETE` verb, since this server has no CORS preflight/OPTIONS
  handling and `DELETE` always triggers one in real browsers, unlike
  `GET`/`POST`), CLI commands (`vulnerability ignore/delete`), and UI
  wiring (`Vulnerabilities.tsx`, `window.confirm`-gated delete) all added.
  Five new backend unit tests (ignore validation, hiding-from-default-list,
  selective re-raise, delete). While adding the CLI commands, found and
  fixed a latent pre-existing bug from before this session: typing
  `vulnerability manual`/`authorise`/`update` without the required ID
  silently misparsed as an ID lookup — same bug class already fixed for
  `actions propose`/`evaluate` earlier, never caught for these three.
  Fixed all five (including the two new subcommands) with one guard.
  **Still unverified**: no `cargo check`/`cargo test` run against any of
  this — only a manual brace/paren balance check (real compiler errors,
  type mismatches, and match-exhaustiveness issues would not be caught by
  that). The UI side did get a real `tsc` pass; the Rust side did not get
  an equivalent.

## Open

- [ ] Make `DENDRITE_EBPF` opt-out, like `DENDRITE_FANOTIFY` now is, rather
  than opt-in. Currently still defaults to `false` in
  `RuntimeConfig::development_defaults()` (`runtime.rs`) — only fanotify
  was flipped so far.
- [ ] Provenance lineage's 10-host cap (`MemoryProvenance::new` /
  `append_lineage_host` in `model.rs`) is unit-tested but not exercised
  end-to-end. `scripts/test_lineage_cap.sh` now exists to do exactly this —
  spins up a chain of N independent hosts, relays a seeded object through
  all of them via Antiserum export/import/accept, and checks the final
  host's lineage array caps at 10 rather than growing unbounded. Written
  but not yet run (no live daemon available while writing it) — explicitly
  not being tested until the user moves testing to a physical machine, per
  their own notes. A direct SQLite edit wouldn't have been a substitute
  test either way, since the cap lives in the model layer, not the
  read/decode path.
- [x] Ingestion pipeline saturation, found via real numbers on the physical
  Proxmox host (`/` watched, EBPF off): routine lane 57,258/57,344 with
  2,263 dropped, `Max combined wait: 721,143 ms`, yet only 68 Memory Graph
  nodes/44 relationships — confirming most received telemetry was still
  backlogged, not "healthily deduplicated." Root cause: a single shared
  worker thread for both lanes (only turn-order weighted, not actually
  parallel), plus no batching at all (every `save_node`/`save_relationship`/
  correlation-key write autocommits individually, despite WAL +
  `synchronous=NORMAL` already being configured correctly). Considered and
  rejected an external queue (Redis/etc.) for this — it doesn't address the
  actual bottleneck (SQLite write throughput on this host), adds a new
  unauthenticated network service on top of the already-tracked HTTP/WS gap,
  and conflicts with "raw telemetry is short-lived" as a design principle.
  Fixed instead: priority and routine now have fully separate dedicated
  worker threads (`spawn_priority_worker`/`spawn_routine_worker` in
  `runtime.rs`) — this directly addresses "a genuine attack could saturate
  priority the same way," since a routine flood can no longer occupy
  priority's only processing slot the way a shared thread did. Routine
  additionally batches up to `ROUTINE_BATCH_SIZE` (200) jobs into one
  transaction (`MemoryStore::begin_batch`/`commit_batch`/`rollback_batch` in
  `dendrite-memory`, delegated via `DaemonCore`) instead of autocommitting
  per statement — no changes needed to `ingest_observation` itself, since
  SQLite transactions are connection-scoped, so its existing individual
  writes automatically join whatever transaction is open. Also fixed a
  separate, unconditional cost found while reading this code:
  `LiveBroadcaster::publish` was JSON-serializing every event even with zero
  WebSocket subscribers connected — now skipped entirely when nobody's
  listening.
  **Still open, deliberately not attempted this pass**: if batching alone
  doesn't clear the backlog under real sustained load, the next step within
  this same architecture (not a new queue technology) is splitting routine
  further into parallel CPU-bound prep threads feeding one dedicated SQLite
  writer thread — respects the single-writer constraint while still
  parallelizing the part that can be. Needs real load data first to know if
  it's actually necessary.
  **Unverified, as always for a live daemon this session couldn't run**: no
  `cargo check`/`cargo test` against this — brace/paren balance checked
  manually across all four touched files (`runtime.rs`, `core.rs`,
  `dendrite-memory/storage.rs`, `live.rs`), which catches structural
  corruption but not type errors or borrow-checker issues.