# Dendrite Roadmap

This file is the canonical implementation roadmap. Historical patch/batch notes are intentionally consolidated into topical documentation rather than kept as separate patch documents.

## Current pre-packaging state

The deterministic/pre-ML Dendrite foundation now includes the Memory Graph, incident/evidence correlation, MAGI/policy/Guard action gating, eBPF/fanotify telemetry with fallbacks, package/CVE exposure knowledge, authorised package remediation, signed self-update foundations, instance signing identity, Antiserum packages and Analysis review tooling, cross-host correlation keys, reusable behaviour knowledge, attack-chain classification/enrichment, and Dendrite Vulnerability Candidates.

A low-level **Culture** (working name, formerly "Adaptive Malware Analysis"/AMA) skeleton also exists. It can create isolated campaign workspaces by snapshotting the active Self, Memory, Incidents, and Guard SQLite databases into campaign-local copies. It is deliberately not yet a malware-execution or automatic-counter system and never mutates the active databases. Full campaign orchestration belongs after the deterministic baseline is proven stable.

## Batch 7: Packaging

Checkpoint A (testing the current version against README/docs, updating and testing the CLI, updating docs, and running the full `DEVELOPMENT.md` validation matrix) is complete — the fixes that came out of it are already reflected in the current state of the CLI, `architecture.md`, and `CONFIGURATION.md`; `TODO.md` only tracks what's still open.

Findings from the external code review pass that preceded Checkpoint A, carried forward here since they're genuinely packaging-scoped rather than resolved:

- **`dendrite-guard`'s decision logic is still a stub.** A trust-state enum and an allow/deny match on `evaluate_authority`. No integrity manifests, anti-tamper, attestation, or recovery isolation yet, despite being the architecture's central authority-removal boundary. Given how much the invariants lean on Guard surviving compromise, hardening it should be prioritised ahead of enabling any destructive action executor (`SUSPEND_PROCESS`, `TERMINATE_PROCESS`, `QUARANTINE_OBJECT`, `BLOCK_NETWORK_DESTINATION`, `ISOLATE_HOST`). Confirmed as its own batch: every call site outside `dendrite-guard` only calls `evaluate_authority()`, `trust_state()`, `status()`, and `findings()` (`core.rs`, `actions.rs`, `adaptive_analysis.rs`) — as long as hardening work stays behind that same four-method surface, it should require no changes elsewhere in the codebase. (Process separation itself — the IPC protocol, reconnect behaviour, fail-closed semantics — is done; see `crates/dendrite-guard/README.md`. What's left is the decision logic.)

  Ordered plan for this work, agreed before starting:
  1. **Privilege separation — done.** `dendrite-guard` now runs as its own dedicated `dendrite-guard` system user, with its own `StateDirectory=` (mode `0700`, no group access at all) instead of sharing `dendrited`'s `/var/lib/dendrite`. Until this, a compromised `dendrited` (same user, same writable state directory) could edit `guard.sqlite3` directly — bypassing the socket, the process boundary, and every fail-closed check in `dendrite_guard`'s own code entirely, making "compromise can remove authority but not create it" true only for in-memory/IPC access, not for the actual on-disk state. See `crates/dendrite-guard/README.md`'s "Privilege separation" section for the full design (why `Group=dendrite` at the unit level, the socket's own explicit chmod/chown, `RuntimeDirectory=dendrite-guard` being safe to declare directly now that nothing else references that name).
  2. **Integrity manifest — done.** `dendrite-guard` hashes a configured set of paths (`DENDRITE_GUARD_WATCH_PATHS`, its own env var, never accepted over the `GuardRequest` wire from `dendrited` — a compromised `dendrited` must not be able to redirect what gets hashed) with SHA-256, signs the resulting deterministic manifest with its own ed25519 keypair (generated and stored the same way `self_store.rs`'s `InstanceKeyRecord` stores `dendrited`'s — but a genuinely separate key Guard owns itself, never `dendrited`'s: Guard verifies `dendrited`, so `dendrited` must never hold a key that could re-sign a tampered manifest as trusted), and stores it in its own now-isolated `StateDirectory=`. `GuardRequest::EstablishBaseline`/`VerifyIntegrity` (`dendrite guard baseline`/`guard verify`) trigger it on demand today. See `crates/dendrite-guard/README.md`'s "Integrity manifest" section for the full design.
  3. **A real verification pass inside `dendrite-guard` itself — done.** `GuardStore::verify_integrity` is now the single real implementation, called identically by a background thread (spawned at startup whenever `DENDRITE_GUARD_WATCH_PATHS` is non-empty; runs immediately, then every `DENDRITE_GUARD_VERIFY_INTERVAL_SECONDS`, default 300s) and by `GuardRequest::VerifyIntegrity` (`dendrite guard verify`) on demand — so verification happens automatically *and* can be triggered manually, sharing one code path rather than two. A mismatch now turns into a real `IntegrityFinding` instead of the dev-only `debug_record_finding` path, deduplicated via a `guard_open_mismatches` table so a persistent, unresolved mismatch records exactly one finding across arbitrarily many ticks (until its digest changes again, or `establish_baseline` clears the table).
  4. **Severity → trust-state transition rules — done.** A built-in severity heuristic keyed on path basename (`dendrited`/`dendrite-guard` binaries → `Critical` → `Compromised`; any `*.service` unit → `High` → `Suspected`; everything else → `Warning` → `Degraded`), plus an unconditional `Critical`/`Compromised` finding if the baseline's own signature fails to verify. Trust escalation (`escalate_trust_state`) is monotonic — it only moves to a candidate state strictly worse than the current one, by rank (`Trusted < Degraded < Suspected < Quarantined < Compromised < Recovering`) — so a verification pass can never automatically improve trust state; re-baselining clears the dedup table but does not restore trust, consistent with the recovery-path note below. See `crates/dendrite-guard/README.md`'s "Integrity manifest" section for the full design.
  5. **Recovery path — done.** An explicit, two-phase path back to `Trusted`, authenticated by proof of real host access rather than IPC reachability: `GuardRequest::BeginRecovery` (`dendrite guard recover begin`) writes a one-time token into Guard's own privilege-separated `StateDirectory=` (never returning the token itself over the wire, since that travels through `dendrited`'s relay) and moves trust to `Recovering`; an operator retrieves the token by reading the file directly on the host; `GuardRequest::CompleteRecovery` (`dendrite guard recover complete <TOKEN>`) requires a matching token, then re-baselines against current content and restores `Trusted`. A compromised `dendrited` can relay either request but cannot read the token file, so it cannot self-authorize its own recovery — the one deliberate, explicit bypass of `escalate_trust_state`'s monotonic rule. See `crates/dendrite-guard/README.md`'s "Recovery" section for the full design.

Build/packaging mechanics (dev bootstrap, the `.deb`, what it installs, required capabilities) now live in `docs/DEVELOPMENT.md`.

## CHECKPOINT B

**IF CURRENT PRE-ML VERSION IS IN A WORKING STATE, TEST ON A LIVE, LOW-RISK SYSTEM.**

Test the packaged/installable Dendrite build rather than the development `target/debug` workflow:

```bash
sudo apt install dendrite
sudo systemctl enable --now dendrited
```

Verify:

- dedicated `dendrite` user/group; **done** — real `.deb` install on an Ubuntu laptop, confirmed via `getent passwd`/`getent group dendrite`.
- socket ownership/permissions; **done** — confirmed `0660`/group-`dendrite` ownership, and the group-membership requirement is now handled by `packaging/postinst` (adds the invoking `sudo` user automatically).
- systemd service hardening/capabilities; **done** — all four units active with their configured hardening; no manual `setcap` needed.
- eBPF and fanotify work without manual `setcap`; **done** — confirmed via `dendrite-cli telemetry` showing both `active` (real `bpf-linker`-built object, not a stub) with the `/proc`/filesystem-polling fallbacks correctly in `standby`.
- service restart/reboot behaviour; **partially done** — individual-service restart resilience is verified, including a real shared-`RuntimeDirectory=` teardown bug found by restarting `dendrite-guard` alone and confirmed fixed by restarting `dendrited` alone afterward with no ill effect (see `docs/CONFIGURATION.md`'s "IPC and network" section for the fix); a full machine reboot hasn't specifically been exercised yet.
- package upgrades preserve configuration/data correctly; **partially done** — remove-then-reinstall-same-version was verified to preserve `/var/lib/dendrite` and `/etc/dendrite` and resume the *same* instance (matching `instance id` across the round-trip); an actual version-bump upgrade path hasn't been exercised yet (there's only one released version so far).
- uninstall/reinstall behaviour where safe. **done** — `apt remove` leaves state/conffiles/account alone (confirmed), `apt purge` removes all of it cleanly (confirmed), matching `packaging/postrm`.

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

This full validation sequence (steps 1–5 above) was already run once ahead of schedule, during Checkpoint A, using this same-machine approach — it passed cleanly, including cross-host correlation keys linking equivalent objects without merging their identities. It's included here as the canonical repeatable procedure, not because it's still unverified.

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

- new repo branch — preferably **after** ML work is done;
- UI/UX changes informed by data gathered from live testing;
- richer fleet/multi-system views without weakening host-local trust boundaries;
- the broader Zoraxy-style reskin/typography pass (from the User feedback backlog — the smaller items originally filed alongside it: button relabels, Dashboard exposition text, Memory Graph focus/drag distinction, 3D camera inversion, user-node colour, Live Event Stream search, have already been implemented directly against `ui/src` and verified with a `tsc` type-check);
- Memory Graph clustering (from the User feedback backlog) — behaviour/fingerprint-derived named clusters with a "magnetic" pull between clusters sharing nodes;
- CLI shell autocompletion (from the User feedback backlog) — `dendrite-cli` is a hand-rolled parser, not `clap`-based, so there's no free completion generator. Best approach is likely a completion script that shells out to a small introspection subcommand (`--list-commands`-style) rather than a static/hardcoded completion list, so it can't silently drift from the real command set as new commands are added.

To be explicit about what "fleet" does and doesn't mean here: the underlying exchange mechanism (Antiserum export/import/accept, one signed `.danti` package at a time, each acceptance an explicit operator action) already exists and is validated — see "Second-instance Antiserum validation" above. What's genuinely undesigned is any *live*, ongoing, multi-host aggregation: a UI/CLI surface that shows several hosts' state together in real time, without an explicit accept step per exchange. The README's "later federation" phrase points at this same undesigned territory. Nothing in the codebase today does live cross-host querying or in-flight merging; don't assume "fleet" means that already exists just because Antiserum exchange does.

## Batch 10: Benchmarking

Timeouts and other numeric thresholds introduced during Checkpoint A were placeholders, chosen for plausibility rather than measurement, and are explicitly flagged wherever they appear (search for "placeholder"/"not tuned"/"not benchmarked" in code comments and `docs/TODO.md`). This batch is where those get real numbers, on representative hardware and load, instead of guesses:

- `DaemonCore::HEALTH_CHECK_TIMEOUT` (currently 200ms) — the `daemon` field of `GET /api/v1/health`'s "ok vs degraded" threshold for the self-store/incidents liveness probe. Needs measurement of normal-case latency for these two `SELECT 1` pings under realistic load (busy telemetry ingestion, large Memory Graph, concurrent CLI/HTTP/WebSocket clients) before the threshold means anything.
- Routine-lane throughput: two real-hardware root causes found and fixed so far (`read_process()` running before the file-touch cache; an unbounded-width hub-node search), plus a batching redesign to cut per-item overhead. Both fixes are confirmed by design and unit tests but **not yet re-verified against the live hardware/workload that originally surfaced them** — that re-verification (`dendrite-cli telemetry`, `top`, under the same FileFlows/ffmpeg contention) is the remaining open step. `MAX_RELATIONSHIPS_PER_NODE_FOR_REASONING = 200` (the hub-node cap) is itself a reasoned-but-unbenchmarked placeholder, same as the other constants this batch exists to replace with measured numbers. Full root-cause history, real numbers, and the exact fixes: `docs/PERFORMANCE.md`.
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