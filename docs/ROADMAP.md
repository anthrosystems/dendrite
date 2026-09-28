# Dendrite Roadmap

This file is the canonical implementation roadmap. Historical patch/batch notes are intentionally consolidated into topical documentation rather than kept as separate patch documents.

## Current pre-packaging state

The deterministic/pre-ML Dendrite foundation now includes the Memory Graph, incident/evidence correlation, MAGI/policy/Guard action gating, eBPF/fanotify telemetry with fallbacks, package/CVE exposure knowledge, authorised package remediation, signed self-update foundations, instance signing identity, Antiserum packages and Analysis review tooling, cross-host correlation keys, reusable behaviour knowledge, attack-chain classification/enrichment, and Dendrite Vulnerability Candidates.

A low-level **Culture** (working name, formerly "Adaptive Malware Analysis"/AMA) skeleton also exists, now with `dendrite culture` CLI/IPC surfacing (Batch 9). It can create isolated campaign workspaces by snapshotting the active Self/Memory/Incidents SQLite databases into campaign-local copies — Guard's own database is no longer included in that snapshot, since the Guard privilege-separation split means `dendrited` can't read it any more (see Batch 9 below). It is deliberately not yet a malware-execution or automatic-counter system and never mutates the active databases. Full campaign orchestration belongs after the deterministic baseline is proven stable.

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

**"Herd" (renamed from "fleet") — skeleton done.** No leader and no election anywhere — nothing in the codebase does host-to-host consensus, and a real one (Raft/corosync-style) is a separate, much larger undertaking than a first skeleton warrants. Instead `crates/dendrited/src/herd.rs` automates the *existing, already-validated* Antiserum export/import/verify pipeline on a timer (`DENDRITE_HERD_PUSH_INTERVAL_SECONDS`, default 120s) between a statically configured, full-mesh peer list (`DENDRITE_HERD_CONFIG` → `packaging/herd.json.example`) — the same way a Proxmox cluster's config is fully replicated to every node rather than funnelled through one. Deliberately does **not** auto-accept: a pushed package is verified/deduplicated/stored on the receiving peer exactly as a manual `.danti` import is, but merging into that peer's live graph/vulnerability data stays an explicit operator action (`accept_antiserum_knowledge`), matching Antiserum's existing trust model — a per-peer `auto_accept` config field exists for a future opt-in but nothing acts on it yet. Also push-only, not pull; an unreachable peer just fails that tick and retries next interval. `dendrite herd status` reports per-peer last-attempt/last-success/last-error/packages-pushed, the same shape as `docker node ls`/`pvecm status`. Verified live end-to-end in this session: two real `dendrited` processes, one pushing every 3s, the other's `/api/v1/analysis/packages` showing the imported package with a valid signature/content-root/attestation and `knowledge_status: "not_accepted"` — confirming the no-auto-accept boundary holds in practice, not just in the type signature. Followed up with an HTTP API (`GET /api/v1/herd/status`, mirroring the CLI/IPC handler) and a Herd page in the UI (nav: System → Herd) showing the same per-peer attempt/success/error/pushed-count table `dendrite herd status` prints, plus the design disclosure above — this was the first UI surface added for Herd; there was previously no HTTP route or UI page for it at all, only the CLI.

**"Culture" — CLI/IPC surfacing done, execution/enforcement still stubbed.** The campaign-snapshot mechanism (see "Current pre-packaging state" and "Future: Culture" above) existed already but had no CLI, no IPC, and a dead duplicate module (`adaptive_analysis.rs`, an unwired leftover from the AMA→Culture rename — deleted). Added `dendrite culture` / `culture list` / `culture create [LABEL]` / `culture discard <ID>`, wired through new `IpcRequest`/`IpcResponse` variants into `DaemonCore`. Answering the operator's question directly: no, real enforcement does not exist yet either — `dendrite_protocol::ActionType` (`TerminateProcess`, `QuarantineObject`, etc.) is a decision taxonomy the MAGI→policy→Guard→transaction pipeline can approve, but nothing calls `kill()`/moves a file/touches `iptables` today. `crates/dendrited/src/containment.rs` now models both real gaps this depends on — an `ActionExecutor` (approved decision → actual host effect) and a `CampaignSandbox` (actual execution isolation for whatever a campaign runs) — as traits with a logging-only, `NotImplemented`-returning default (`NoopActionExecutor`/`NoopCampaignSandbox`), so there's a real interface to build against later instead of nothing to call or a silently-faked success. Building neither of these was in scope for this pass. Also followed up with an HTTP API (`GET`/`POST /api/v1/culture/campaigns`, `POST .../{id}/discard` — `POST`, not `DELETE`, matching the existing `/api/v1/vulnerabilities/*/delete` convention, since this server has no CORS preflight handling for non-"simple" methods) and a Culture page in the UI (nav: Knowledge → Culture) that creates/lists/discards campaigns and states the enforcement gap above directly on the page rather than only in this document.

**CLI shell autocompletion — done.** `dendrite-cli` is a hand-rolled parser, not `clap`-based, so there's no free completion generator. Added a `--list-commands` introspection flag (`Command::ListCommands`, handled in `execute()` without touching the daemon socket, same as `--version`/`--help`) backed by `Command::command_paths()`, a hand-maintained, doc-commented, test-guarded flat list of every literal token path `parse()` recognises. `packaging/completions/dendrite-cli.bash` and `packaging/completions/_dendrite-cli` (bash and zsh) both work by calling `dendrite-cli --list-commands` and prefix-filtering the result client-side, rather than hardcoding a copy of the command tree — so neither script can silently drift from the parser as commands are added or removed. A regression test (`every_listed_command_path_is_recognised_by_parse`) fails the build if `command_paths()` ever lists something `parse()` no longer recognises. Both scripts are wired into the `.deb`'s `[package.metadata.deb]` assets (`usr/share/bash-completion/completions/dendrite-cli`, `usr/share/zsh/vendor-completions/_dendrite-cli`). Building this surfaced and fixed a real pre-existing parser bug: `vulnerability import` (missing its required path argument) was silently misparsing as an ID lookup for an exposure literally named "import", the same bug class an existing test already guarded against for `manual`/`authorise`/`update`/`ignore`/`delete` — `import` was just missing from that exclusion list.

**Zoraxy-style reskin/typography pass — partially done.** Before touching anything, `ui/src/styles.css` (9,462 lines) turned out to hold **six stacked full-page redesign attempts**, each one just redefining `:root` and re-styling components on top of the last without removing it — including one already labelled "Zoraxy-inspired" that didn't actually match Zoraxy's real dashboard (no gradients, no rounded cards, no shadows) and was found via a real bug it caused: the Memory Graph's rendered background was `#020403` via a stray `!important` in that block, not the `#050807` the dataviz-validated palette was checked against. Consolidated app-shell/shared-primitive styling (sidebar, nav, topbar, hero banner, stat tiles, cards, buttons, status pills, tables) into the one remaining pass, matching real Zoraxy reference screenshots (gradient hero card, gradient active-nav pill, rounded soft-shadowed cards, icon-accent stat tiles) — verified with Playwright screenshots across Overview/Memory/Vulnerabilities/System Health. The Memory Graph page is now full-bleed (the whole page is the canvas, title/stats/refresh float over it in a HUD bar) rather than the graph sitting inside a padded page column — the settings panel was already an absolute-positioned overlay, it just wasn't given the room to act like one.

**System Map rewritten onto the current pass.** It was the worst offender of the pre-Zoraxy debt below — a bespoke "MAGI console" retro sci-fi treatment (`instrument-node`, `magi-console-*`, `sys-rail`, `core-reactor-v2`, etc.) with its own animated "moving dot" traveling along rail connectors between zones to represent live signal flow. Rebuilt `SystemMap.tsx` from scratch using the same `surface`/`compact-list`/`source-list`/`StatusPill` primitives the rest of the app (Dashboard, Guard, Vulnerabilities) already uses, at the operator's explicit request to make it match and to remove the moving-dot animation — it no longer references any of the old system-map-only CSS classes. The old CSS for that page (both the original "scientific-console" pass and the later "-v2" instrument/rail pass) was left in `styles.css` rather than deleted in the same pass, since it's tangled with unrelated shared selectors in places and a careful removal is exactly the "consolidation" work described below, not a quick follow-on to a UI-wiring task; it is confirmed dead (no `.tsx` file references it) but not yet deleted.

**Not done, and explicitly scoped out for now rather than attempted at risk:** the five now-superseded passes (`grep` this file's git history for "operator UI", "scientific-control", "consolidation refinement", "Black/white operator theme") are still the *only* styling for roughly 400 more selectors covering the (now-dead) old System Map rules above, the MAGI console on the Actions/"MAGI & Response" page, Analysis's graph canvas, attack-chain/threat/vulnerability detail cards, and the WebGL Memory Graph's internal HUD chrome (confirmed via a selector-coverage diff against the new pass). Deleting those five passes now would break the pages still actively using them (Actions, Analysis, etc.); consolidating them into the new design language is real, separate follow-up work, not a quick pass.

Memory Graph clustering (the earlier backlog item — behaviour/fingerprint-derived named clusters with a "magnetic" pull) is dropped from this batch: the artificial per-kind clustering was removed in favour of pure link+repel+centre physics (see the WebGLMemoryGraph rework earlier this branch), and the operator is satisfied with that result over building a new clustering feature.

**Not started, still open:** richer fleet/multi-system *views* — a UI surface that shows several hosts' Herd-known state together — without weakening host-local trust boundaries. Herd (above) gives every host a local copy of what its peers have pushed (via the ordinary Antiserum package store, still per-host and still requiring explicit accept), but there is no cross-host UI aggregation view yet, and no live in-flight querying of another host on demand.

**Live-connection file-descriptor leak — found and fixed.** Reported from a real deployment: `dendrited` failing every HTTP/WebSocket request with `Too many open files (os error 24)` after a couple of hours of normal use, recovering only on `systemctl restart`. Root cause: `LiveBroadcaster` (`live.rs`) spawns one dedicated thread + holds one `TcpStream` per `/ws` client, and only detects a dead client when a *write* to it fails — there was no TCP keepalive on the accepted socket, so a peer that vanished without a clean close (a client machine sleeping, roaming Wi-Fi, or a NAT mapping timing out — all routine for a laptop running the UI) could leave that write blocked at the kernel level for a long time before ever failing, holding the fd and thread open indefinitely in the meantime. Fixed by enabling TCP keepalive (`SO_KEEPALIVE` + `TCP_KEEPIDLE`/`TCP_KEEPINTVL`/`TCP_KEEPCNT` via `libc::setsockopt`, already a dependency) on every accepted connection in the HTTP/WS listener's accept loop (`http::enable_tcp_keepalive`, called from `runtime.rs`) — bounds detection of a vanished peer to roughly 60 seconds (30s idle + 3×10s probes) instead of an effectively unbounded kernel retransmission timeout, so `LiveBroadcaster`'s existing reactive cleanup (on the next failed write) now actually runs promptly.

## Batch 10: Benchmarking

Timeouts and other numeric thresholds introduced during Checkpoint A were placeholders, chosen for plausibility rather than measurement, and are explicitly flagged wherever they appear (search for "placeholder"/"not tuned"/"not benchmarked" in code comments and `docs/TODO.md`). This batch is where those get real numbers, on representative hardware and load, instead of guesses:

- `DaemonCore::HEALTH_CHECK_TIMEOUT` (currently 200ms) — the `daemon` field of `GET /api/v1/health`'s "ok vs degraded" threshold for the self-store/incidents liveness probe. Needs measurement of normal-case latency for these two `SELECT 1` pings under realistic load (busy telemetry ingestion, large Memory Graph, concurrent CLI/HTTP/WebSocket clients) before the threshold means anything.
- Routine-lane throughput: real-hardware root causes already found and fixed (confirmed by design and unit tests) still need **re-verification against the live hardware/workload that originally surfaced them** — `dendrite-cli telemetry`/`top` under the same FileFlows/ffmpeg contention. `MAX_RELATIONSHIPS_PER_NODE_FOR_REASONING = 200` (the hub-node cap) is itself a reasoned-but-unbenchmarked placeholder, same as the other constants this batch exists to replace with measured numbers. Full root-cause history and the fixes already made: `docs/PERFORMANCE.md`.
- Any other timeout/threshold constants added between now and this batch should be flagged the same way when introduced, so this list doesn't need to be reconstructed by searching the whole codebase later.

## Future: Culture

Working name: **Culture** (formerly "Adaptive Malware Analysis"/AMA — code symbols renamed accordingly: `culture.rs`, `Culture{Error,Sources,Campaign,Manager}`).

A low-level campaign snapshot skeleton exists now, with `dendrite culture` CLI/IPC surfacing added in Batch 9, but the full feature is future research work. Intended architecture:

```text
active Dendrite databases
        │ snapshot only
        ▼
contained campaign workspace
├── self.sqlite3
├── stm.sqlite3
├── ltm.sqlite3
├── incidents.sqlite3
├── guard.sqlite3 (only if dendrited can read it — see below)
└── artifacts/
```

`guard.sqlite3` is optional now (`CultureSources::guard_db: Option<PathBuf>`), not because it stopped mattering, but because it moved out of reach: since Guard's privilege-separation split, `dendrite-guard` owns that database under its own system account and `dendrited` has no read access to it at all on a real deployment. A campaign still carries Guard's live trust state as of creation time via the same Antiserum-attestation path a manual export uses; it just isn't a raw file copy any more. Reuniting the two (a deliberately-granted read path, or running Culture as part of a process that does have access) is real follow-up work, not done here.

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

## Future: artificial immune systems — what to borrow, what not to

Prompted by a direct comparison against the academic "artificial immune systems" (AIS) field, given Dendrite's naming is already immunological (Antiserum, Culture, Herd, Guard, MAGI). AIS splits into four main algorithm families — negative selection (train detectors on "self," flag whatever they don't recognise), clonal selection (iteratively mutate/select the best-matching detectors, keep memory of winners), immune network theory (detectors interact with each other), and danger theory / the dendritic cell algorithm (fuse several contextual signals into a verdict instead of a binary self/non-self call). The field peaked in the early 2000s and has settled into a niche within intrusion detection rather than displacing conventional ML — worth knowing going in, so this isn't approached as an underexploited goldmine.

**Already doing the right thing, unintentionally.** MAGI's Host/User/Environment quorum is structurally closer to danger theory than to self/non-self classification — several independent contextual signals fused into a verdict, not "have I seen this exact thing before." Guard's baseline-hash integrity check does what a negative-selection detector population would do, but deterministically (hash mismatch against a stored baseline) rather than probabilistically — which sidesteps that field's worst-known failure mode (see below) rather than reimplementing it. Memory Graph's tiered short/long-term retention is already, functionally, immunological memory; no change indicated.

**Two concrete extensions worth building:**

- **Culture as clonal selection.** Culture is snapshot-only today (see "Future: Culture" above) — no execution, no iteration. Clonal selection's actual mechanism (replay against a sample, generate variant detectors, score against both the malicious sample and known-good traffic, keep only variants that improve affinity without raising false positives) maps directly onto a Culture campaign once containment/execution exist: promote surviving variants into permanent Memory Graph correlations ("memory cells") rather than discarding a campaign's findings at review time.
- **Herd as idiotypic/herd-immunity signal sharing.** Herd today pushes Antiserum packages and reports per-peer push *status*; a peer's own Guard/Culture findings still have to be independently rediscovered by every other host (see Batch 9's "richer fleet/multi-system views" open item, above). The AIS-faithful reading of "herd immunity" is a confirmed finding propagating as a ready-made detector, not just a status row — this is a natural fit for the existing accept/no-auto-accept trust boundary Herd already enforces, not a new mechanism.

**Deliberately not adopting:**

- **The literal negative selection algorithm as a core detector.** Its two documented failure modes — detector-population coverage collapsing in high-dimensional space ("curse of dimensionality"), and "generator holes" producing excessive false alarms — are exactly what modelling a real endpoint's behaviour space would hit. Guard's deterministic hash comparison is already the better answer to the same problem; there is no reason to add a probabilistic detector population alongside it.
- **A bespoke "danger theory"/dendritic-cell-algorithm subsystem.** A published theoretical analysis found a prominent DCA variant (ltDCA) reduces to "simply an ensemble linear classifier" — the biological framing adds no algorithmic benefit over a plain multi-signal statistical model. If MAGI's quorum voting is ever found too coarse (weak-but-concordant signals should sometimes outweigh one strong dissent), the fix is an ordinary weighted/statistical fusion model, not an "immune" abstraction layer around it.
- **Immune network (idiotypic) algorithms for clustering/visualisation.** The most dated corner of AIS research, superseded by clustering/embedding techniques already available for anything Memory Graph or Culture would need.
- **Any design that leans on a hard "self" baseline for a real endpoint.** The field's persistent, unsolved problem is that "normal" drifts constantly (new processes, users, environment), degrading any self/non-self model over time. Dendrite's hybrid approach (correlation + quorum + explicit CVE/vulnerability data, rather than pure anomaly detection) is already less brittle than a from-scratch AIS system would be — nothing here argues for moving toward a purer anomaly-detection model.

Sources: [Artificial immune system (Wikipedia)](https://en.wikipedia.org/wiki/Artificial_immune_system); [Artificial Immune Systems for Industrial Intrusion Detection: A Systematic Review and Conceptual Framework, Journal of Engineering 2025](https://onlinelibrary.wiley.com/doi/full/10.1155/je/8408209); [A New Intrusion Detection System Using the Improved Dendritic Cell Algorithm, The Computer Journal](https://academic.oup.com/comjnl/article/64/8/1193/6015901).

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

## Planned patch: Memory Graph identity fixes + telemetry collector overhaul

Surfaced while designing the "Threats" (.danti signature-based detection) feature — working through exactly how `ObjectId`/`MemoryNodeId`/correlation keys are derived turned up several real, independent gaps. All of the below ships as one patch, not staged separately, since the collector changes are what make the identity fixes actually load-bearing (no content hash to key on until the eBPF side captures a stable file reference).

**1. Memory Graph import fix.** `build_graph_payload()` (`analysis.rs:789`) currently exports the full host-prefixed `node.id` (a pre-joined `MemoryNodeId`) verbatim; `accept_antiserum_graph()` (`core.rs:774`) stores it back verbatim with no recomputation. Change: export the bare `ObjectId` plus `origin_instance_id` (both already present in the payload) instead of the pre-joined string, and have every importer compute `MemoryNodeId = format!("{origin_instance_id}::{object_id}")` itself — using the *origin's* instance_id from the archive, never the importing host's own. Produces the identical value to today's happy path, but closes a real integrity gap: nothing currently verifies that a shipped `id` string's prefix actually matches its accompanying `origin_instance_id` field, so a malformed or malicious exporter can claim mismatched provenance today.

**2. New content-hash correlation key, purely additive.** Add a `content_hash: Option<String>` field, populated once a collector can actually hash a file, and derive a dedicated `sha256` correlation key (weight 100) straight from it — no more relying on `derive_correlation_keys()`'s existing prefix-stripping/shape-sniffing heuristics on `id`/`label` to notice a hash was present. `ObjectId`, `MemoryNodeId`, `process-identity key` (weight 90, name-based), and `semantic-fingerprint` (weight 50, weakest fallback) all stay exactly as they are today — the hash is a new, independent, stronger signal sitting alongside them in the correlation-key set, not a replacement for any of them. Keeping `process-identity` name-based and separate from the hash is deliberate: a name-match with no hash-match is itself a meaningful signal (masquerading — a process claiming a trusted name without the bytes to back it up), and folding the hash into the `process_identity:` prefix would both lose that signal and silently downgrade hash-certainty to name-only confidence (confirmed: the dedicated bare-sha256 correlation-key scan doesn't match a prefixed string, so it wouldn't even fire twice).

**3. Extend eBPF capture at `sched_process_exec`.** Currently only `comm` is captured at the tracepoint (`ebpf/dendrite-ebpf/src/main.rs:41-53`); `ParentPid`/`StartTicks`/`UserId`/executable identity are all deferred to a separate, later `/proc/<pid>/...` read that races the process's own exit (`read_process()`, `telemetry.rs:686`) and silently produces nothing — no field, no marker, just absent data — when it loses. Fix: capture `parent_pid`, `start_ticks`, and `uid` directly from `task_struct` at the same tracepoint (all reachable synchronously, same technique as the fix below), and capture the executable's **(device, inode)** rather than its path. `(dev, inode)` identifies the file on disk, not the process, so hashing it can happen asynchronously/lazily, fully decoupled from whether the process is still alive by the time the hash job runs — this is what actually supplies `content_hash` from (2) above without racing anything. Cache hashes by `(dev, inode)` so repeat execs of the same binary aren't rehashed.

Two residual gaps this does not close, deliberately accepted rather than chased further: a file deleted from disk before the async hasher reaches it (rare, and itself a weak signal worth logging — "backing file vanished before it could be fingerprinted" — even though the fingerprint itself is lost), and fully fileless execution (`memfd_create` + exec, no backing file to reference at all — a hard limit, not a racing problem, and rare/suspicious enough on its own to be worth flagging when seen).

**5. Fix the fanotify fd leak (confirmed root cause of the "too many open files" crash under heavy activity bursts).** `FanotifyCollector::collect()` (`telemetry.rs:1174-1254`) closes each raw fanotify record's fd inside the per-buffer parsing loop, but that loop's exit condition (`offset + size_of::<FanotifyEventMetadata>() <= bytes && observations.len() < MAX_EVENTS_PER_COLLECTION`) is coupled to the *observation* cap, not the *parse* cap. A 64KB `read()` can return 2,700+ raw records; once `observations.len()` hits `MAX_EVENTS_PER_COLLECTION` (4096) partway through a buffer — easy under a heavy burst, since the outer `loop` keeps re-reading — the `while` exits immediately and every still-unparsed record in that buffer never reaches its `libc::close(event_fd)` call. Fanotify hands out the fd at read time, not close time, so those fds leak permanently, until the process hits its ulimit and every subsystem needing a new fd (subprocess spawns, outbound HTTP, the control socket) starts failing at once — exactly the reported symptom, and exactly why it only clears on a full daemon restart. Fix: decouple draining/closing every record in a buffer from capping how many become `Observation`s — keep closing fds for every record parsed regardless of whether the cap has been hit.

Secondary, contributing rather than causal, worth fixing in the same pass: `herd_push_tick` (`herd.rs`, invoked synchronously from the main loop in `runtime.rs`) calls `ureq::post(...)` with no configured timeout — a slow/unreachable Herd peer can stall the whole daemon, plausibly explaining the reported "freezes, then unfreezes" lead-in before the fd errors surface.

**6. Give connector-node expiry a real answer instead of silent orphaning.** For a chain `A(LTM) — B(STM) — C(LTM)`, `mark_expired()` (`storage.rs:2058`) expires nodes and relationships independently, purely by each row's own `expires_at`; there is no rewiring logic anywhere. `preserve_short_term_connectors()` (`core.rs:2392`) is the only existing mitigation — it can extend a connector STM node's own expiry, but only up to `REINFORCED_STM_HARD_LIFETIME_SECONDS`, and only when one of its own active relationships already outlives it; the comment is explicit that this is deliberately bounded, not a fix for orphaning generally. So today, once B expires, A and C simply lose their only path to each other — confirmed by reading the expiry path directly, not inferred.

Neither obvious option is right: synthesizing `A > C` directly fabricates a fact that was never observed (the real relationship was A-via-B-to-C, and collapsing it erases how they were connected); doing nothing loses the fact a connection ever existed, with no trace. Loosening TTLs generally only delays the same cliff and undermines the reason an STM tier (bounded, short-lived) exists at all.

Considered and rejected: writing the collapse reason into `lineage` — checked the type directly (`model.rs:373-376`, `core.rs:37-48`) and it's structurally a host-id trail (`Vec<String>` of `instance_id`s, even a purely local node seeds it with `[instance_id]`, and `imported_lineage()`'s dedup logic assumes every entry is a host) — not a general-purpose reason field, and writing a non-host string into it would break that invariant. `derived_by_instance_id` is a closer fit (already exists to mark "derived, not directly observed") and is fine to set on a collapsed edge, but it only carries a host id, not which node it was collapsed from or why.

Also considered and rejected on a second pass: `MemoryRelationship.reinforcement: Option<ReinforcementProvenance>` (`{ reason: ReinforcementReason, incident_id, evidence_ids }`, `model.rs:337-341`). Its three existing variants (`ConfirmedHighRisk`, `RepeatedObservation`, `OperatorConfirmed`, `model.rs:307-311`) are all reasons something *already observed* got promoted/strengthened — a collapsed connector edge isn't reinforcement, it's a relationship being created fresh as a downgraded substitute for a lost direct path, not an existing fact gaining confidence. Wrong scope, same mistake as `lineage` one field over.

The properly-scoped fix, checked against the actual convention: `MemoryRelationshipKind` (`model.rs:110-118` — `Spawned`/`Executed`/`Read`/`Wrote`/`ConnectedTo`/`BelongsTo`/`AssociatedWith`) is built exhaustively from `ObservationKind` via `map_relationship_kind()` (`core.rs:2720-2731`) — every existing variant, with no exception, means "this exact action was directly observed." A collapsed edge is the first relationship in the system that wouldn't be a direct observation, so it needs its own new variant (e.g. `MemoryRelationshipKind::Inferred`) to keep that invariant intact for every other kind, rather than overloading `AssociatedWith` and quietly making it mean two different things. `derived_by_instance_id = Some(self.instance_id)` (already exists, already means "derived, not observed") carries the provenance half; `reinforcement` stays untouched. "Connector" itself has no existing stored type to match — `preserve_short_term_connectors()` computes it ad hoc from `relationships_for()` each time rather than persisting a role, and the collapse check should do the same rather than introducing a new persisted flag.

**4. Stop treating polling as a disabled-by-default backup.** `TelemetryManager::collect()` currently runs `/proc` polling only when eBPF is unavailable, and filesystem polling only when fanotify is unavailable (`telemetry.rs:233-244`, a strict either/or). This undersells both pollers — their real value isn't "same job, worse," it's a genuinely different job: `/proc` polling's job is cold-start inventory of processes that existed before `dendrited` attached (eBPF only sees exec events from attach-time onward) plus a backstop if the eBPF ring buffer ever overflows and drops events; filesystem polling's job is the same kind of backstop for anything fanotify's own event queue drops or misses across a restart. Fix: run both halves of each pair concurrently — event-driven (eBPF/fanotify) and periodic-reconciliation (`/proc`/filesystem polling) — rather than switching one off the instant the other is available, with downstream dedup extending the `known`/`seen` diffing `FilesystemCollector`/`ProcessCollector` already do.