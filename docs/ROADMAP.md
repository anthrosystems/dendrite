# Dendrite Roadmap

This file is the canonical implementation roadmap. Historical patch/batch notes are intentionally consolidated into topical documentation rather than kept as separate patch documents.

## Current pre-packaging state

The deterministic/pre-ML Dendrite foundation now includes the Memory Graph, incident/evidence correlation, MAGI/policy/Guard action gating, eBPF/fanotify telemetry with fallbacks, package/CVE exposure knowledge, authorised package remediation, signed self-update foundations, instance signing identity, Antiserum packages and Analysis review tooling, cross-host correlation keys, reusable behaviour knowledge, attack-chain classification/enrichment, and Dendrite Vulnerability Candidates.

A low-level **Culture** (working name, formerly "Adaptive Malware Analysis"/AMA) skeleton also exists. It can create isolated campaign workspaces by snapshotting the active Self, Memory, Incidents, and Guard SQLite databases into campaign-local copies. It is deliberately not yet a malware-execution or automatic-counter system and never mutates the active databases. Full campaign orchestration belongs after the deterministic baseline is proven stable.

## Batch 7: Packaging

Checkpoint A (testing the current version against README/docs, updating and testing the CLI, updating docs, and running the full `TESTS.md` validation matrix) is complete — the fixes that came out of it are already reflected in the current state of the CLI, `architecture.md`, and `CONFIGURATION.md`; `TODO.md` only tracks what's still open.

Findings from the external code review pass that preceded Checkpoint A, carried forward here since they're genuinely packaging-scoped rather than resolved:

- **`dendrite-guard`'s decision logic is still a stub.** A trust-state enum and an allow/deny match on `evaluate_authority`. No integrity manifests, anti-tamper, attestation, or recovery isolation yet, despite being the architecture's central authority-removal boundary. Given how much the invariants lean on Guard surviving compromise, hardening it should be prioritised ahead of enabling any destructive action executor (`SUSPEND_PROCESS`, `TERMINATE_PROCESS`, `QUARANTINE_OBJECT`, `BLOCK_NETWORK_DESTINATION`, `ISOLATE_HOST`). Confirmed as its own batch: every call site outside `dendrite-guard` only calls `evaluate_authority()`, `trust_state()`, `status()`, and `findings()` (`core.rs`, `actions.rs`, `adaptive_analysis.rs`) — as long as hardening work stays behind that same four-method surface, it should require no changes elsewhere in the codebase. (Process separation itself — the IPC protocol, reconnect behaviour, fail-closed semantics — is done; see `crates/dendrite-guard/README.md`. What's left is the decision logic.)
- **`.unwrap()`/`.expect()` audit in `dendrited`.** An ongoing, periodic pass distinguishing genuinely infallible cases (see `CLAUDE.md`'s note on the validated-newtype pattern — `Confidence`, `MemoryStrength`, `MemoryConfidence`, `DecayRate`) from ones that could take the daemon down on unexpected input (e.g. odd filesystem metadata, malformed telemetry). Re-run this whenever a batch of new I/O-adjacent code lands rather than treating it as a one-time count, since raw call counts drift with every change and aren't themselves meaningful.
- **There is no `tests/` directory at the repo root.** It once held a single placeholder script (`tests/test-dendrite.sh`), removed when `docs/TESTS.md` took over as the canonical manual validation matrix. Inline `#[cfg(test)]` coverage exists across ~20 modules, but there's still no automated integration/end-to-end harness matching what `TESTS.md` describes — that file is executed by hand, once per checkpoint so far. Whether it's worth automating into a real harness (vs. continuing to re-run it manually before each future checkpoint) is an open question for this batch.
- **Docs-to-code ratio.** `architecture.md` documents a very ambitious end-state (CVE intelligence, federation, ML, Culture/AMA sandbox, cross-host correlation) against ~20k lines of code concentrated almost entirely in one crate (`dendrited`, ~12.9k lines). Not a problem in itself this early, but a reason to hold off documenting further ahead of implementation until packaging closes more of the gap.

The current development binary needs:

```text
CAP_DAC_READ_SEARCH
CAP_SYS_ADMIN
CAP_PERFMON
CAP_BPF
```

Current development capability set:

```text
cap_bpf,cap_perfmon,cap_sys_admin,cap_dac_read_search+ep
```

Packaging goals:

- eBPF + the UI are compiled during release/build and bundled with Dendrite;
- create/use a dedicated `dendrite` service user and `dendrite` group with appropriate ownership/permissions;
- install service files, default configuration, state directories, UI assets, eBPF assets, CLI and daemon binaries;
- configure systemd hardening and only the capabilities that the packaged collectors actually require;
- provide safe package upgrades that preserve configuration and state;
- make installation require minimal faff, ideally:

```bash
sudo apt install dendrite
sudo systemctl enable --now dendrited
```

The intended native layout should converge on `/usr/bin`, `/usr/lib/dendrite`, `/usr/share/dendrite`, `/etc/dendrite`, and `/var/lib/dendrite`, with an Anthrosystems-owned signed APT repository as the long-term distribution target.

### Local packaging (done) vs. distribution packaging (skeleton, later)

These are two different things and shouldn't be conflated:

- **Local packaging** — getting a fresh clone to a runnable state with one command, for dev work across machines. Done: `scripts/bootstrap.sh` builds `dendrited`/`dendrite-cli`, the eBPF object, and the UI, and sets up the dev `dendrite` group/capabilities — idempotent (skips anything already built, `--force` to override), and each step degrades gracefully rather than aborting the others if a toolchain piece (bpf-linker, nightly, npm) is missing, since eBPF and the UI are both optional at runtime. `scripts/launch_host_a.sh` calls it automatically on a fresh clone (no `target/debug/dendrited` yet) and skips straight to launching once built. For a dev who wants to rebuild just one piece, `scripts/bootstrap.sh` takes `--skip-ebpf`/`--skip-ui`/`--skip-capabilities`/`--force` directly.
- **Distribution packaging** — the actual `.deb`, for real installs on machines that aren't a dev clone. **Implemented** via `cargo-deb` (chosen over hand-rolled `debian/` control files — version/metadata stays in `Cargo.toml` next to the code it describes, no separate changelog-version-sync step, and it has built-in systemd-unit install support that maps directly onto `packaging/dendrited.service`). `scripts/build-deb.sh` wraps the whole sequence (`build-ebpf.sh` → `npm run build` in `ui/` → `cargo deb -p dendrited`) into one command, since `cargo build`/`cargo deb` only packages what already exists on disk and won't run the eBPF or UI builds itself — matching the same "wraps, doesn't replace, `bootstrap.sh`'s steps" relationship called out here previously. Installing the result is exactly the two commands the packaging goals at the top of this batch call for:
    ```bash
    sudo apt install ./dendrited_0.1.0-1_amd64.deb
    systemctl status dendrited
    ```
    with no separate `enable --now` step needed — see the "auto-starts on install" point below.
  - **Done:** the WebSocket port merged onto the same HTTP listener (no more `DENDRITE_WS_ADDR`), the UI split into its own process (`dendrite-ui-server`), MAGI split into its own process (`dendrite-magi`), Guard split into its own process (`dendrite-guard`), and the HTTP API/WebSocket bearer-token requirement (`dendrite-cli http-token`) — each verified end to end with real running processes. Current design/configuration lives in `docs/CONFIGURATION.md` and each crate's own README (`crates/dendrite-ui-server/README.md`, `crates/dendrite-magi/README.md`, `crates/dendrite-guard/README.md`); the process-separation and fail-closed design rationale (why MAGI/Guard are separate units, ABSTAIN vs. DENY/VETO, the MCP client/server split) now lives in `docs/architecture.md` rather than here.
  - **Closed:** the real-hardware run this used to wait on happened (see CHECKPOINT B below) — real `bpf-linker`-built eBPF object, real systemd host, full install/remove/purge/reinstall cycle. Two real bugs surfaced and were fixed as a direct result, not sandbox-only findings: `dendrited`, `dendrite-magi`, and `dendrite-guard` sharing one `RuntimeDirectory=dendrite` meant restarting any single one of them deleted the others' still-listening sockets out from under them (systemd removes a `RuntimeDirectory=` when the first referencing unit stops, even while siblings sharing the name are still running — [systemd/systemd#5394](https://github.com/systemd/systemd/issues/5394)); fixed by provisioning `/run/dendrite` via a tmpfiles.d snippet instead (`packaging/dendrite.tmpfiles`) with `RuntimeDirectory=` removed from all three units. Separately, `dendrite-cli` hardcoded `/tmp/dendrited.sock` as its fallback, which never matches a packaged install (`dendrited.service` sets `DENDRITE_SOCKET` via its own `Environment=`, invisible to an interactive shell) — fixed by checking the packaged path first. See `docs/CONFIGURATION.md`'s "IPC and network" section and `crates/dendrite-cli/README.md` for the current behaviour.
  - Website/distribution (from the User feedback backlog): consider a project website, potentially hosting the apt repository once this batch's `.deb`/apt distribution target is real (see the "long-term distribution target" note at the top of this batch). A live, publicly-interactive Memory Graph demo is a good idea, confirmed worth keeping — but it must not run on the same machine hosting the website/anything real, must obviously limit what it actually shows (a live demo of a real running host's telemetry is not something to expose unfiltered to the public internet), and, now that the HTTP/WebSocket bearer-token requirement above is in place, still needs its own explicit demo-scoped token/access story (a token baked into a public demo page is not meaningfully different from no auth at all) if it's ever reachable beyond localhost. A public Memory Graph endpoint is reconnaissance material if pointed at something that matters — treat "what does the public demo actually reveal" as its own design question, not an afterthought.

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
- service restart/reboot behaviour; **partially done** — individual-service restart resilience is verified (including the `RuntimeDirectory=` bug above, found by restarting `dendrite-guard` alone and confirmed fixed by restarting `dendrited` alone afterward with no ill effect); a full machine reboot hasn't specifically been exercised yet.
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

"Host B" does not require a second physical machine or VM. Instance identity is a random `Uuid::new_v4()` generated once per fresh, empty self-store (`self_store.rs`) — it has no dependency on hostname, MAC address, or any other host-derived value. Two `dendrited` processes on the same machine, each pointed at a fully separate set of `DENDRITE_*_DB`/`DENDRITE_SOCKET`/`DENDRITE_HTTP_ADDR` values (see `CONFIGURATION.md`; `DENDRITE_HTTP_ADDR` alone now covers both HTTP and WebSocket, per the port-merge note above), get genuinely distinct instance IDs and behave as distinct hosts for every purpose this validation cares about. A literal second machine only starts to matter once real host-level differences (actual separate telemetry, actual separate package inventory, network reachability between the two) become relevant — not for exercising the Antiserum trust boundary itself.

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

## Future: eBPF pre-filtering for file events

Deliberately deferred — worth doing once Dendrite is a more mature/functional AV, not now. The current file-touch cache (`FanotifyCollector::file_touch_cache`, `telemetry.rs`) filters repeat noise in userspace: the kernel still generates and delivers the event, and Dendrite still pays the syscall/context-switch/read cost before discarding it. A genuine next tier of optimisation would move that decision into the kernel itself.

This is *not* a tweak to the existing fanotify path — fanotify and eBPF are separate kernel subsystems, and there's no hook point to attach custom eBPF logic to fanotify's own event pipeline. Getting real kernel-side filtering for file events means replacing fanotify's role for this purpose with a new eBPF program attached to a kprobe/LSM hook (e.g. on `vfs_open`), doing the (device, inode, program) lookup against a `BPF_MAP_TYPE_LRU_HASH` map *inside the kernel* — a cache hit means Dendrite never wakes up for that event at all, no ring-buffer write, no userspace processing. `BPF_MAP_TYPE_LRU_HASH` would also handle eviction automatically, more elegantly than the current cache's clear-on-overflow approach.

Real costs to weigh before attempting it: kprobes on internal kernel functions are less stable across kernel versions than fanotify's own purpose-built, stable API — a real portability trade. The eBPF verifier is a genuine constraint (no unbounded loops, careful stack/map access) — harder to write and debug than the equivalent Rust. And the marginal benefit is narrower than it first sounds, given what's already fixed: `FAN_MARK_FILESYSTEM` already makes "watch a whole mount" one cheap kernel call rather than per-file registration, and the userspace cache already eliminates the expensive downstream cost (the threat-path search) for repeat noise. What this would additionally save is specifically the small per-event kernel-to-userspace transfer for cache hits — real at very high event rates, but smaller in magnitude than the fixes already in place.