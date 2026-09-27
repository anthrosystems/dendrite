# Dendrite Roadmap

This file is the canonical implementation roadmap. Historical patch/batch notes are intentionally consolidated into topical documentation rather than kept as separate patch documents.

## Current pre-packaging state

The deterministic/pre-ML Dendrite foundation now includes the Memory Graph, incident/evidence correlation, MAGI/policy/Guard action gating, eBPF/fanotify telemetry with fallbacks, package/CVE exposure knowledge, authorised package remediation, signed self-update foundations, instance signing identity, Antiserum packages and Analysis review tooling, cross-host correlation keys, reusable behaviour knowledge, attack-chain classification/enrichment, and Dendrite Vulnerability Candidates.

A low-level **Culture** (working name, formerly "Adaptive Malware Analysis"/AMA) skeleton also exists. It can create isolated campaign workspaces by snapshotting the active Self, Memory, Incidents, and Guard SQLite databases into campaign-local copies. It is deliberately not yet a malware-execution or automatic-counter system and never mutates the active databases. Full campaign orchestration belongs after the deterministic baseline is proven stable.

## Batch 7: Packaging

Nothing outstanding. Checkpoint A (CLI/docs/validation-matrix pass) and `dendrite-guard`'s decision-logic hardening (privilege separation, signed integrity manifest, automatic + on-demand verification, severity-based trust escalation, host-authenticated recovery) are both done — see `crates/dendrite-guard/README.md` for the design. Build/packaging mechanics (dev bootstrap, the `.deb`, what it installs, required capabilities) live in `docs/DEVELOPMENT.md`.

## CHECKPOINT B

**IF CURRENT PRE-ML VERSION IS IN A WORKING STATE, TEST ON A LIVE, LOW-RISK SYSTEM.**

Packaged-build testing on a real host is done: `apt install`, all four systemd units (enable/disable/fail-closed independence between `dendrited`/`dendrite-ui`/`dendrite-magi`/`dendrite-guard`), a full reboot, and a real version-bump upgrade (instance identity, signing key, Memory Graph, and Guard's own trust state/findings all correctly survived; both system accounts came back with the same ownership; the reordered CLI help and packaged UI fix both held) have all been verified — see `docs/DEVELOPMENT.md`'s "Manual validation matrix" step 8. Two real bugs turned up and were fixed along the way: `packaging/postrm` wasn't purging the `dendrite-guard` account/state on `apt purge` (only the original `dendrite` account), and the packaged UI shipped with `DENDRITE_UI_API_ORIGIN` unset, which on the stock two-fixed-port install meant the UI could never actually reach `dendrited` at all (see `packaging/dendrite-ui.env.example`'s comment for the mechanism).

Complete the packaged Dendrite self-update path:

- expose installed Dendrite version;
- expose available signed release information;
- signature verification status;
- SHA-256/artifact verification status;
- revocation status;
- anti-downgrade status;
- rollback availability/status;
- service-health verification;
- allow an explicitly authorised Dendrite self-update through the independent updater;
- verify the full sequence:

```text
VERIFY
STAGE
PREPARE ROLLBACK
INSTALL
RESTART
VERIFY INSTALLED VERSION
VERIFY SERVICE HEALTH
ROLLBACK ON FAILURE
```

Wire packaged updater state into the UI:

- installed version;
- available verified release;
- signature/hash/revocation/downgrade checks;
- staging state;
- rollback state;
- last updater result;
- service health;
- explicit **Install verified update** control once the packaged updater path is proven safe.

Wire packaged/service state into the UI:

- `dendrited.service` status;
- installed package version;
- effective service capabilities;
- package/repository source where useful;
- updater health;
- daemon restart/reconnect state.

Live low-risk-system validation:

- confirm telemetry remains stable over an extended runtime;
- confirm eBPF/fanotify do not create excessive CPU, memory, I/O or event volume;
- confirm fallback collectors activate correctly if privileged telemetry fails;
- confirm normal user activity does not generate excessive false positives;
- confirm Memory Graph growth/decay behaviour is sane over real activity;
- confirm node/relationship lifecycle and garbage collection behave as intended;
- confirm vulnerability inventory/CVE matching remains accurate as packages change;
- confirm remediation transactions remain safe under real package-manager state changes;
- confirm stale authority cannot be reused;
- confirm daemon crashes/restarts do not corrupt databases or transaction state;
- confirm Guard remains independent and correctly blocks invalid privileged actions;
- confirm WebSocket/HTTP/UI reconnect cleanly after daemon restart;
- confirm logs remain useful without leaking unnecessary sensitive information.

Gather real-world baseline data for Batch 8:

- normal process execution patterns;
- normal filesystem activity;
- normal outbound network behaviour;
- typical event rates;
- common benign process/package relationships;
- normal user/session behaviour where appropriate;
- sources of false positives/noise;
- collector reliability/fallback frequency;
- performance impact;
- Memory Graph growth characteristics.

Record any pre-ML tuning required before branching for Batch 8:

- detection thresholds;
- event filtering;
- telemetry suppression/deduplication;
- Memory Graph TTL/decay defaults;
- incident correlation behaviour;
- package/CVE matching edge cases;
- MAGI/policy/Guard edge cases;
- UI/API inconsistencies discovered during live use.

**Do NOT begin adaptive/ML enforcement until the deterministic/statistical pre-ML system is stable enough that its baseline behaviour is understood.**

Anything discovered during this checkpoint that changes core deterministic behaviour should be fixed before creating the Batch 8 ML branch.

### Second-instance Antiserum validation

Batch 7/Checkpoint B is also the point to install a second real Dendrite instance and exercise the intended cross-host trust boundary:

1. Host A creates a signed `.danti` Antiserum package.
2. Transfer it out-of-band to Host B.
3. Host B authenticates the immediate exporter, verifies Merkle/signature/attestation/schema/replay state, and stores it as evidence.
4. Confirm host-scoped `object_id`s remain distinct while correlation keys/behaviour identities allow equivalent observations to be related.
5. Confirm historical origin/lineage remains provenance asserted by Host A and does not become execution authority on Host B.

"Host B" does not require a second physical machine or VM. Instance identity is a random `Uuid::new_v4()` generated once per fresh, empty self-store (`self_store.rs`) — it has no dependency on hostname, MAC address, or any other host-derived value. Two `dendrited` processes on the same machine, each pointed at a fully separate set of `DENDRITE_*_DB`/`DENDRITE_SOCKET`/`DENDRITE_HTTP_ADDR` values (see `CONFIGURATION.md`; `DENDRITE_HTTP_ADDR` alone covers both HTTP and WebSocket, which share one listener), get genuinely distinct instance IDs and behave as distinct hosts for every purpose this validation cares about. A literal second machine only starts to matter once real host-level differences (actual separate telemetry, actual separate package inventory, network reachability between the two) become relevant — not for exercising the Antiserum trust boundary itself.

`scripts/launch_host_a.sh` and `scripts/launch_host_XYZ.sh [HOST_NAME]` automate exactly this setup — the latter can be run repeatedly with different `HOST_NAME`s (each requiring its own explicit `DENDRITE_HOST_HTTP_PORT`, which covers both HTTP and the `/ws` WebSocket upgrade — see `docs/CONFIGURATION.md`) to stand up as many additional same-machine hosts as needed, each fully isolated under its own folder outside the repository. Both scripts support `--cleanup` to reset a host's data; `launch_host_XYZ.sh` additionally supports `--remove-host` to delete a disposable host entirely.

## Batch 8: ML / adaptive detection update

- new repo branch;
- tweaks based on data gathered from live test;
- CPU-first bounded statistical/ML detection;
- behavioural/sequence and graph-context models where justified by real baseline data;
- model signing, compatibility/resource budgets, and explicit explainable evidence surfaces;
- ML remains evidence and never direct privileged authority;
- a dedicated `EntityKind::Package`/`Software` variant (from the User feedback backlog) — installed packages currently map to `EntityKind::Service` as the closest fit (`core.rs`), which is why e.g. curl shows up as a "service" in the Memory Graph even though nothing about it is a running service. Touches the graph model and the export schema, so scope it properly rather than a quick patch;
- local-instance Antiserum accept (from the User feedback backlog) — a user should be able to load a `.danti` file the *local* instance itself issued (e.g. output from a Culture sandbox run) and accept it back in. On accept, deduplicate exact matches (same host, same node/process/etc., identical) by skipping them, but update them with any *new* relationships present in the package. Explicitly do **not** touch lineage on this path. This directly enables the Culture sandbox-findings use case and needs real accept-logic changes (currently no same-instance-specific handling exists at all in `accept_antiserum_knowledge`).

### Daemon agency — what this batch is and isn't for

"When does the daemon get to make its own decisions" is really two separate questions that shouldn't be conflated:

1. **Autonomous proposal generation** — something originating an action proposal without a human typing a command. This does *not* require ML: the existing policy system is already capable of a fixed rule like "if an exposure matches these conditions, auto-propose `observe`" today, with no changes to this batch's scope.
2. **Learned pattern recognition** — generalising from a specific past incident to a new situation that's *similar but not identical*, rather than only exact behaviour-fingerprint matches. This is what ML actually buys that fixed rules can't: the deterministic behaviour/fingerprint matching that exists today is exact-shape matching (same `source_kind`/`relationship`/`target_kind` sequence), not similarity — it can't currently look at a new pattern and conclude "this resembles that bad incident from before" unless the structural shape is identical. That's squarely this batch's job, not something to bolt onto the deterministic baseline.

Concretely, the goal this batch is aiming at: given either this host's own history or knowledge merged in from other hosts via Antiserum, recognise that a new observation *resembles* a past confirmed-bad incident closely enough to be worth raised suspicion (tightened observation, a proposal, elevated priority) even though it isn't an exact match — and have that resemblance itself be something the system can act on, not just something a human has to notice by eye. Whatever surfaces from this (a similarity score, a nearest-neighbour incident reference, a learned embedding) needs an explainable evidence surface per the bullets above — the same "ML is evidence, never authority" rule applies here as much as anywhere else in the pipeline.

## CHECKPOINT C

**IF CURRENT POST-ML VERSION IS IN A WORKING STATE, TEST ON A LIVE, LOW-RISK SYSTEM.**

Repeat the relevant Checkpoint B safety/performance/false-positive validation with ML enabled and compare against the recorded deterministic baseline.

## Batch 9: UI work

Started ahead of Batch 8 (ML), by explicit operator choice, directly on `dev`.

- richer fleet/multi-system views without weakening host-local trust boundaries — not started;

**CLI shell autocompletion — done.** `dendrite-cli` is a hand-rolled parser, not `clap`-based, so there's no free completion generator. Added a `--list-commands` introspection flag (`Command::ListCommands`, handled in `execute()` without touching the daemon socket, same as `--version`/`--help`) backed by `Command::command_paths()`, a hand-maintained, doc-commented, test-guarded flat list of every literal token path `parse()` recognises. `packaging/completions/dendrite-cli.bash` and `packaging/completions/_dendrite-cli` (bash and zsh) both work by calling `dendrite-cli --list-commands` and prefix-filtering the result client-side, rather than hardcoding a copy of the command tree — so neither script can silently drift from the parser as commands are added or removed. A regression test (`every_listed_command_path_is_recognised_by_parse`) fails the build if `command_paths()` ever lists something `parse()` no longer recognises. Both scripts are wired into the `.deb`'s `[package.metadata.deb]` assets (`usr/share/bash-completion/completions/dendrite-cli`, `usr/share/zsh/vendor-completions/_dendrite-cli`). Building this surfaced and fixed a real pre-existing parser bug: `vulnerability import` (missing its required path argument) was silently misparsing as an ID lookup for an exposure literally named "import", the same bug class an existing test already guarded against for `manual`/`authorise`/`update`/`ignore`/`delete` — `import` was just missing from that exclusion list.

**Zoraxy-style reskin/typography pass — partially done.** Before touching anything, `ui/src/styles.css` (9,462 lines) turned out to hold **six stacked full-page redesign attempts**, each one just redefining `:root` and re-styling components on top of the last without removing it — including one already labelled "Zoraxy-inspired" that didn't actually match Zoraxy's real dashboard (no gradients, no rounded cards, no shadows) and was found via a real bug it caused: the Memory Graph's rendered background was `#020403` via a stray `!important` in that block, not the `#050807` the dataviz-validated palette was checked against. Consolidated app-shell/shared-primitive styling (sidebar, nav, topbar, hero banner, stat tiles, cards, buttons, status pills, tables) into the one remaining pass, matching real Zoraxy reference screenshots (gradient hero card, gradient active-nav pill, rounded soft-shadowed cards, icon-accent stat tiles) — verified with Playwright screenshots across Overview/Memory/Vulnerabilities/System Health. The Memory Graph page is now full-bleed (the whole page is the canvas, title/stats/refresh float over it in a HUD bar) rather than the graph sitting inside a padded page column — the settings panel was already an absolute-positioned overlay, it just wasn't given the room to act like one.

**Not done, and explicitly scoped out for now rather than attempted at risk:** the five now-superseded passes (`grep` this file's git history for "operator UI", "scientific-control", "consolidation refinement", "Black/white operator theme") are still the *only* styling for roughly 400 more selectors covering System Map, the MAGI console, Analysis's graph canvas, attack-chain/threat/vulnerability detail cards, and the WebGL Memory Graph's internal HUD chrome (confirmed via a selector-coverage diff against the new pass, and visually — System Map still renders in the old monospace/orange "scientific-console" style, chrome apart, screenshotted for comparison). Deleting those five passes now would break all of that; consolidating them into the new design language is real, separate follow-up work, not a quick pass.

Memory Graph clustering (the earlier backlog item — behaviour/fingerprint-derived named clusters with a "magnetic" pull) is dropped from this batch: the artificial per-kind clustering was removed in favour of pure link+repel+centre physics (see the WebGLMemoryGraph rework earlier this branch), and the operator is satisfied with that result over building a new clustering feature.

To be explicit about what "fleet" does and doesn't mean here: the underlying exchange mechanism (Antiserum export/import/accept, one signed `.danti` package at a time, each acceptance an explicit operator action) already exists and is validated — see "Second-instance Antiserum validation" above. What's genuinely undesigned is any *live*, ongoing, multi-host aggregation: a UI/CLI surface that shows several hosts' state together in real time, without an explicit accept step per exchange. The README's "later federation" phrase points at this same undesigned territory. Nothing in the codebase today does live cross-host querying or in-flight merging; don't assume "fleet" means that already exists just because Antiserum exchange does.

## Batch 10: Benchmarking

Timeouts and other numeric thresholds introduced during Checkpoint A were placeholders, chosen for plausibility rather than measurement, and are explicitly flagged wherever they appear (search for "placeholder"/"not tuned"/"not benchmarked" in code comments and `docs/TODO.md`). This batch is where those get real numbers, on representative hardware and load, instead of guesses:

- `DaemonCore::HEALTH_CHECK_TIMEOUT` (currently 200ms) — the `daemon` field of `GET /api/v1/health`'s "ok vs degraded" threshold for the self-store/incidents liveness probe. Needs measurement of normal-case latency for these two `SELECT 1` pings under realistic load (busy telemetry ingestion, large Memory Graph, concurrent CLI/HTTP/WebSocket clients) before the threshold means anything.
- Routine-lane throughput: real-hardware root causes already found and fixed (confirmed by design and unit tests) still need **re-verification against the live hardware/workload that originally surfaced them** — `dendrite-cli telemetry`/`top` under the same FileFlows/ffmpeg contention. `MAX_RELATIONSHIPS_PER_NODE_FOR_REASONING = 200` (the hub-node cap) is itself a reasoned-but-unbenchmarked placeholder, same as the other constants this batch exists to replace with measured numbers. Full root-cause history and the fixes already made: `docs/PERFORMANCE.md`.
- Any other timeout/threshold constants added between now and this batch should be flagged the same way when introduced, so this list doesn't need to be reconstructed by searching the whole codebase later.

## Future: Culture

Working name: **Culture** (formerly "Adaptive Malware Analysis"/AMA — code symbols renamed accordingly: `culture.rs`, `Culture{Error,Sources,Campaign,Manager}`).

A low-level campaign snapshot skeleton exists now, but the full feature is future research work. Intended architecture:

```text
active Dendrite databases
        │ snapshot only
        ▼
contained campaign workspace
├── self.sqlite3
├── stm.sqlite3
├── ltm.sqlite3
├── incidents.sqlite3
├── guard.sqlite3
└── artifacts/
```

Rules:

- experimental campaigns never mutate active Dendrite databases;
- campaign STM/LTM/Self/incident state is isolated from production state;
- malware/sample execution must occur in an explicitly contained environment;
- counters still flow through the normal MAGI → policy → Guard → transaction pipeline inside the contained environment;
- repeat runs may reinforce, weaken, contradict, or branch behaviour knowledge;
- convergence must be measured, not claimed as perfect immunity;
- resulting behaviours, vulnerability candidates, graph knowledge, counter evidence, and Antiserum packages require explicit review/promotion/export rather than silent production mutation.

Possible future stopping criteria include no novel behaviour for N runs, no newly reachable attack-path nodes, no observed counter bypass, graph convergence above a threshold, campaign budget exhaustion, or explicit operator stop.

**Snapshotting / "recording" an action** (from the User feedback backlog): a lighter-weight version of the campaign-snapshot mechanism above — record Memory Graph changes resulting from a specific, user-chosen action (targeting a specific process/node), rather than a full campaign. A natural fit here specifically because Culture already has the isolation/permissions/workspace story worked out; a general-purpose snapshot button without that containment would be a materially bigger safety surface. Also useful more generally for: verifying a remediation only changed what it claimed to, forensic point-in-time capture before decay/reinforcement moves state, and generating labelled before/after data for the ML batch.

## Future: Obsidian plugin

Export-only, deliberately: a plugin/script that exports selected Dendrite knowledge into an Obsidian vault as Markdown notes. No live sync is planned — each export is a one-shot snapshot the operator re-runs by hand (or schedules themselves), not an ongoing background connection Dendrite maintains to Obsidian.

This must remain an observation/export integration and must not grant Obsidian execution authority over Dendrite.

**Realistic beyond novelty even scoped this way.** Dendrite already has the raw material a plugin like this would need — persistent incidents/evidence, a Memory Graph with real relationships, correlation keys, and the existing Antiserum export format as a template for "here is a consistent, signed snapshot of what I know." An export that writes one Markdown note per incident/node, cross-linked via `[[wikilinks]]` from the graph's own relationships, would give an operator a genuinely useful, searchable, linkable security journal inside a tool they already use for notes. Lower priority than Batch 7/8 core work either way.

## Future: project website

From the User feedback backlog: consider a project website, potentially hosting the apt repository once the `.deb`/apt distribution target in `docs/DEVELOPMENT.md` is real. A live, publicly-interactive Memory Graph demo is a good idea, confirmed worth keeping — but it must not run on the same machine hosting the website/anything real, must obviously limit what it actually shows (a live demo of a real running host's telemetry is not something to expose unfiltered to the public internet), and needs its own explicit demo-scoped token/access story (a token baked into a public demo page is not meaningfully different from no auth at all — see `docs/CONFIGURATION.md`'s "HTTP API authentication" section for the auth mechanism itself) if it's ever reachable beyond localhost. A public Memory Graph endpoint is reconnaissance material if pointed at something that matters — treat "what does the public demo actually reveal" as its own design question, not an afterthought.

## Future: eBPF pre-filtering for file events

Deliberately deferred — worth doing once Dendrite is a more mature/functional AV, not now. The current file-touch cache (`FanotifyCollector::file_touch_cache`, `telemetry.rs`) filters repeat noise in userspace: the kernel still generates and delivers the event, and Dendrite still pays the syscall/context-switch/read cost before discarding it. A genuine next tier of optimisation would move that decision into the kernel itself.

This is *not* a tweak to the existing fanotify path — fanotify and eBPF are separate kernel subsystems, and there's no hook point to attach custom eBPF logic to fanotify's own event pipeline. Getting real kernel-side filtering for file events means replacing fanotify's role for this purpose with a new eBPF program attached to a kprobe/LSM hook (e.g. on `vfs_open`), doing the (device, inode, program) lookup against a `BPF_MAP_TYPE_LRU_HASH` map *inside the kernel* — a cache hit means Dendrite never wakes up for that event at all, no ring-buffer write, no userspace processing. `BPF_MAP_TYPE_LRU_HASH` would also handle eviction automatically, more elegantly than the current cache's clear-on-overflow approach.

Real costs to weigh before attempting it: kprobes on internal kernel functions are less stable across kernel versions than fanotify's own purpose-built, stable API — a real portability trade. The eBPF verifier is a genuine constraint (no unbounded loops, careful stack/map access) — harder to write and debug than the equivalent Rust. And the marginal benefit is narrower than it first sounds, given what's already fixed: `FAN_MARK_FILESYSTEM` already makes "watch a whole mount" one cheap kernel call rather than per-file registration, and the userspace cache already eliminates the expensive downstream cost (the threat-path search) for repeat noise. What this would additionally save is specifically the small per-event kernel-to-userspace transfer for cache hits — real at very high event rates, but smaller in magnitude than the fixes already in place.