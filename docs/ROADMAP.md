# Dendrite Roadmap

This file is the canonical implementation roadmap. Historical patch/batch notes are intentionally consolidated into topical documentation rather than kept as separate patch documents.

## Current pre-packaging state

The deterministic/pre-ML Dendrite foundation now includes the Memory Graph, incident/evidence correlation, MAGI/policy/Guard action gating, eBPF/fanotify telemetry with fallbacks, package/CVE exposure knowledge, authorised package remediation, signed self-update foundations, instance signing identity, Antiserum packages and Analysis review tooling, cross-host correlation keys, reusable behaviour knowledge, attack-chain classification/enrichment, and Dendrite Vulnerability Candidates.

A low-level **Culture** (working name, formerly "Adaptive Malware Analysis"/AMA) skeleton also exists. It can create isolated campaign workspaces by snapshotting the active Self, Memory, Incidents, and Guard SQLite databases into campaign-local copies. It is deliberately not yet a malware-execution or automatic-counter system and never mutates the active databases. Full campaign orchestration belongs after the deterministic baseline is proven stable.

## Batch 7: Packaging

Checkpoint A (testing the current version against README/docs, updating and testing the CLI, updating docs, and running the full `TESTS.md` validation matrix) is complete — the fixes that came out of it are already reflected in the current state of the CLI, `architecture.md`, and `CONFIGURATION.md`; `TODO.md` only tracks what's still open.

Findings from the external code review pass that preceded Checkpoint A, carried forward here since they're genuinely packaging-scoped rather than resolved:

- **`dendrite-guard`'s decision logic is still a stub.** A trust-state enum and an allow/deny match on `evaluate_authority`. No integrity manifests, anti-tamper, attestation, or recovery isolation yet, despite being the architecture's central authority-removal boundary. Given how much the invariants lean on Guard surviving compromise, hardening it should be prioritised ahead of enabling any destructive action executor (`SUSPEND_PROCESS`, `TERMINATE_PROCESS`, `QUARANTINE_OBJECT`, `BLOCK_NETWORK_DESTINATION`, `ISOLATE_HOST`). Confirmed as its own batch: every call site outside `dendrite-guard` only calls `evaluate_authority()`, `trust_state()`, `status()`, and `findings()` (`core.rs`, `actions.rs`, `adaptive_analysis.rs`) — as long as hardening work stays behind that same four-method surface, it should require no changes elsewhere in the codebase.
  - **Process separation: done — see `crates/dendrite-guard/README.md` and `docs/CONFIGURATION.md`'s "Guard, and its own process" section.** The IPC protocol, reconnect behaviour, and fail-closed semantics this section used to call out as still needed are all now built; what's left in this bullet is the decision logic itself (integrity manifests, anti-tamper, attestation, recovery isolation), not the process boundary around it.
- **The localhost HTTP API and WebSocket (both now `127.0.0.1:8766`, the WebSocket at `/ws` — merged onto the same port, see `docs/CONFIGURATION.md`) have no authentication.** Only a CORS origin allowlist (`http://127.0.0.1:5173`, `http://localhost:5173`) protects either — the `/ws` upgrade handshake in `http.rs` checks the same `Origin` header the rest of the HTTP API does, but that's still just an allowlist, not real auth. The Unix socket (CLI↔daemon) is out of scope here — its access control is already the OS-level file permissions/group ownership set up in `runtime.rs`, which is a legitimate boundary on its own. Deliberately deferred: revisit before MCP integration or any fleet/multi-host feature. When it's picked up, both need a real token/session mechanism (the WebSocket upgrade via query-string token, upgrade-header, or first-message auth frame); the UI itself is just a client of both and doesn't need separate treatment.
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
  - **Done:** the WebSocket port merged onto the same HTTP listener (no more `DENDRITE_WS_ADDR`), the UI split into its own process (`dendrite-ui-server`), MAGI split into its own process (`dendrite-magi`), and Guard split into its own process (`dendrite-guard`) — each verified end to end with real running processes. Current design/configuration for all four lives in `docs/CONFIGURATION.md` and each crate's own README (`crates/dendrite-ui-server/README.md`, `crates/dendrite-magi/README.md`, `crates/dendrite-guard/README.md`) rather than here; what's kept below is the design rationale that isn't just "what exists today" and is still worth having on record.

    **Why `dendrite-magi` keeps its own systemd unit rather than being spawned/supervised by `dendrited`.** Raised directly as a simplification: four systemd units for one conceptual daemon is real operational overhead. But "compromise can remove authority, but cannot create authority" only holds if `dendrited` can't influence what `dendrite-magi` actually is — if `dendrited` spawned/supervised it as a child process, a compromised `dendrited` would control what gets spawned (binary path, args, a substituted replacement), and the process boundary would become cosmetic. What makes the boundary real is that the unit file is root-owned and not writable by `dendrited`, and systemd (PID 1), not `dendrited`, decides what runs. So this stays its own unit — the ergonomic cost is already low, since an unreachable `dendrite-magi` just means every seat abstains (below) and `dendrited` keeps running, degraded rather than down.

    **Fail-closed behaviour, and why ABSTAIN rather than DENY/VETO (MAGI).** `Abstain` is the one verdict that can never itself manufacture an approval, and doesn't turn "is `dendrite-magi` reachable" into a lever that unilaterally denies every action, the way a hardcoded DENY-on-unreachable would. Under the default quorum policy (2 approvals required) an unreachable `dendrite-magi` still blocks everything in practice — the same outcome DENY would give — but without redefining "didn't answer" as "said no," which matters once a seat (especially an MCP-backed one) can be legitimately slow. Genuinely open to reconsideration if real-world operation surfaces a reason DENY/VETO's harder semantics are actually needed.

    **MCP integration, resolved: client (done) vs. server (stub only).** The MCP *client* side is built: `dendrite-magi`'s `SeatSource::Mcp` spawns a configured command, talks to it over stdio via `rmcp`, and fully replaces a seat's internal evaluator when configured — any spawn/handshake/tool-call/parse failure resolves to `Abstain`, same fail-closed philosophy as above. See `crates/dendrite-magi/README.md` for the configuration reference. The MCP *server* side — exposing Dendrite's own capabilities to external agents — is a fundamentally different, inbound/additive privileged surface, and was confirmed to never belong inside `dendrite-magi`: any such tool call is a caller of the ordinary proposal → MAGI → policy → Guard → transaction pipeline, not a shortcut around it. It now exists as its own process, `dendrite-mcp`, deliberately kept a stub (real MCP handshake, zero tools) until the HTTP API auth gap noted at the top of this batch is closed — see `crates/dendrite-mcp/README.md`.

    **Fail-closed behaviour: `Compromised`/`Deny`, not abstain (Guard).** A deliberate departure from MAGI's abstain-on-unreachable choice: MAGI is a three-way vote where silence from one seat shouldn't drown out the other two, but Guard has exactly one voice on trust, so there's no quorum for "unreachable" to defer to — collapsing straight to the same denial a real detected compromise produces is the only fail-closed answer available. `status()`/`findings()` stay genuinely fallible rather than joining that fallback, since they feed signed Antiserum attestations and a fabricated status could misrepresent host integrity in an exported package.
  - Known gaps, not yet closed: the eBPF asset (`usr/lib/dendrite/dendrite-ebpf`) has only been packaging-tested with a stub file, since this sandbox has no `bpf-linker`/nightly toolchain to produce the real object — the full `scripts/build-deb.sh` sequence needs one real run wherever that toolchain is available. The `.deb` maintainer-scripts/upgrade-safety work is done but has likewise only been exercised in a sandboxed non-systemd container — a real run on an actual systemd host is still the final confirmation needed.
  - Website/distribution (from the User feedback backlog): consider a project website, potentially hosting the apt repository once this batch's `.deb`/apt distribution target is real (see the "long-term distribution target" note at the top of this batch). A live, publicly-interactive Memory Graph demo is a good idea, confirmed worth keeping — but it must not run on the same machine hosting the website/anything real, must obviously limit what it actually shows (a live demo of a real running host's telemetry is not something to expose unfiltered to the public internet), and needs the HTTP/WebSocket auth gap (the second finding at the top of this batch) closed first if it's ever reachable beyond localhost. A public Memory Graph endpoint is reconnaissance material if pointed at something that matters — treat "what does the public demo actually reveal" as its own design question, not an afterthought.

## CHECKPOINT B

**IF CURRENT PRE-ML VERSION IS IN A WORKING STATE, TEST ON A LIVE, LOW-RISK SYSTEM.**

Test the packaged/installable Dendrite build rather than the development `target/debug` workflow:

```bash
sudo apt install dendrite
sudo systemctl enable --now dendrited
```

Verify:

- dedicated `dendrite` user/group;
- socket ownership/permissions;
- systemd service hardening/capabilities;
- eBPF and fanotify work without manual `setcap`;
- service restart/reboot behaviour;
- package upgrades preserve configuration/data correctly;
- uninstall/reinstall behaviour where safe.

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
- Priority and routine are now fully separate dedicated worker threads (not a shared thread with weighted turns — that design was replaced; `scheduler_priority_weight`/`scheduler_routine_weight` in the telemetry DTO are vestigial leftovers from it and no longer control anything real). Confirmed live on real hardware: priority stays fast and isolated regardless of routine's queue depth.

  Routine's own throughput ceiling — real numbers from a busy Proxmox host initially showed routine backlogged into the tens of thousands, with per-batch processing up to 62 seconds. Root-caused to two things, in order of actual impact: (1) `read_process()` — a three-syscall `/proc` resolution (`stat`, `exe` readlink, `status`) — ran unconditionally on *every* fanotify event, before the file-touch cache was ever consulted, meaning a cache hit paid the full cost anyway and got none of the benefit the cache existing was supposed to provide; reordering so a cheap single-syscall executable lookup gates the cache check first, with the full resolution only paid on an actual miss or write, dropped max per-batch processing from 62,633ms to 623ms and eliminated the backlog entirely (queue returned to and stayed at 0) in isolated testing. (2) The unconditional, uncapped threat-path search on every observation, already addressed separately with a file-touch cache and a depth cap for routine's search specifically.

  **Confirmed still needed under full real-world load** — re-tested with the FileFlows/ffmpeg transcode job running again: queue climbed steadily (30,561 → 32,032 across three checks a minute apart), wait times past 5 minutes for the oldest items, never draining. `top` during this run showed `dendrited` independently pegged at 92.3% CPU — its own dedicated share, not scheduler starvation from ffmpeg (which was separately also at ~92%, with `wa: 0.0` confirming this is real compute, not I/O stalling). The arithmetic roughly closes: sustained arrival around 10–15 items/sec, at today's improved but still real per-item cost (~20–100ms), works out to close to a full core continuously busy — consistent with what's observed. This isn't one more hiding inefficiency; it's genuine per-item cost times genuine sustained volume, on weak hardware sharing a core with another real workload.

  **Follow-up re-test, after the hub-node relationship cap fix below: confirmed non-monotonic, not a one-way backlog.** A further live check (queue climbing 1,502 → 1,960 → 2,191 → 2,750 across four checks, wait times past 20s, `dendrited` steady at 100% CPU sharing a core with `ffmpeg` at ~287%) also showed the queue draining somewhat when the competing CPU-bound job's load eased momentarily, then growing again when it didn't — consistent with two workloads genuinely trading time on one core, not a fixed processing ceiling Dendrite can never clear on its own. Open question, lower urgency than the hub-node hang (which is resolved): whether routine's per-item cost or batch sizing should be tightened further for sustained contention, or whether this variability is simply expected on weak shared hardware and should be left as-is.

  **Implemented** ("Direction 2": reasoning and persistence running inside one writer-owned transaction, chosen over a read-once-upfront mutation plan because the latter can't see a same-batch observation's own earlier effects). `MemoryStore::run_stm_batch` (`dendrite-memory/src/storage.rs`) sends a whole batch as one closure to the STM writer actor via a new `WriterCommand::RunBatch`, wrapped in `BEGIN IMMEDIATE`/`COMMIT`; the closure gets both the raw connection (for direct STM-tier writes via `execute_node_upsert`/`execute_relationship_upsert`, skipping the per-item writer-actor round trip) and a `GraphReader` over that same connection (so later jobs in the batch see earlier jobs' writes — the STM writer's connection now has LTM attached `mode=ro` specifically so a write mistakenly aimed at the wrong tier fails loudly instead of silently corrupting anything). `DaemonCore::ingest_routine_batch` (`dendrited/src/core.rs`) is the batched counterpart to `ingest_observation_with_max_depth`: it persists nodes/relationships and runs the threat-path search for every job in one `run_stm_batch` call, deferring anything whose merged retention resolves to LongTerm/Persistent to the ordinary post-batch `save_node`/`save_relationship` (unchanged cross-tier promotion logic — batching never touches that). The rare "found a threat path" tail (incident/evidence creation, reinforcement, knowledge correlation) is unchanged and still runs per job, outside the batch, via the shared `finish_ingestion` helper — it's hit on a near-zero fraction of routine traffic and touches subsystems (incidents, knowledge) outside the memory graph, so batching it too would add real complexity for a cost that isn't the one driving routine-lane load. `spawn_routine_worker` (`dendrited/src/runtime.rs`) now flattens a batch's jobs (including each job's `related_observations`) into one flat list, calls `ingest_routine_batch` once, and regroups the per-observation results back into each job's `TelemetryEventDto`. Covered by two new tests (`core::tests::routine_batch_consolidates_repeated_observations_within_one_batch`, `core::tests::routine_batch_results_line_up_one_to_one_with_input_jobs`) exercising exactly the same-batch read-your-own-write property and per-job result ordering. Not yet re-verified against a live full-load run on real hardware — the fix that's confirmed by design and unit tests still needs the same kind of real-world telemetry check (`dendrite-cli telemetry`, `top`) that caught the original regression, before trusting it the way the read_process/cache fix was trusted.

  **Second real-hardware regression found during that re-verification, root-caused and fixed.** The first live re-test of the batching redesign (FileFlows/ffmpeg running again) showed the routine worker stall completely: `telemetry`'s routine counters (`processed`, `queue wait`, `processing`) froze at the same values across multiple checks a minute apart while the queue climbed without bound (9,598 → 10,923 → 11,750, heading for the 57,344 cap), and `top` showed `dendrited` pegged at a steady 100.0% CPU the whole time — no crash, no panic, not scheduler starvation (`ffmpeg` was separately busy at 215%, consistent with two real workloads sharing weak hardware). Diagnosis (via `dendrite-cli status`, `memory nodes --kind threat | wc -l`, and a targeted SQL query counting relationships per node) found the actual cause: `host:local` — the `MemoryNodeId` used for observations whose process couldn't be resolved to a real host/process identity — had accumulated 2,272 relationships. `PathQuery::max_depth` only bounds threat-path search *depth*; nothing bounded per-node *width*, so a single degenerate hub node turned a supposedly depth-2-bounded routine-lane BFS into effectively unbounded combinatorial work per batch. This is a genuine algorithmic blowup, not a regression introduced by the batching redesign itself — the same unbounded-width search existed before Direction 2 — but batching's coarser "count as processed once per whole batch" telemetry granularity (already true pre-batching, not new) made a stall against one pathological node look, and actually last, much worse.

  Fixed with `PathQuery::max_relationships_per_node: Option<usize>` (`dendrite-memory/src/storage.rs`): when set, `reasoning_relationships` truncates each node's relationship set to the strongest edges (by effective strength) before expanding further, via a new `cap_relationships_by_strength` helper. `DaemonCore` wires this to a new `MAX_RELATIONSHIPS_PER_NODE_FOR_REASONING = 200` constant (`dendrited/src/core.rs`), applied to both the single-item (`ingest_observation_with_max_depth`) and batched (`ingest_routine_batch`/`run_batched_job`) threat-path `PathQuery` construction sites, so a hub node can no longer stall either path. `200` is a reasoned-but-unbenchmarked choice, same status as the other placeholders this batch exists to replace with measured numbers — revisit if a real hub node's fan-out ever approaches it. Covered by a new test, `storage::tests::max_relationships_per_node_keeps_the_strongest_edges_at_a_hub_node`, which builds a 500-edge hub node plus one strong direct threat-relevant edge and confirms the cap still finds the threat (correctness preserved, only breadth reduced) alongside an uncapped control. Passes the full workspace `cargo fmt`/`cargo test`/`cargo clippy -- -D warnings` gate. Like the batching redesign above, this fix is confirmed by design and unit tests only — it has not yet been re-run against the live hardware and workload that surfaced the original stall.
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

Either:

- export selected Dendrite knowledge to Obsidian; or
- provide a live **one-way** Dendrite → Obsidian connection.

This must remain an observation/export integration and must not grant Obsidian execution authority over Dendrite.

**Realistic beyond novelty, if scoped as a living export rather than a one-off dump.** Dendrite already has the raw material a plugin like this would need — persistent incidents/evidence, a Memory Graph with real relationships, correlation keys, and the existing Antiserum export format as a template for "here is a consistent, signed snapshot of what I know." A plugin that periodically (or on `/ws` events) writes one Markdown note per incident/node, cross-linked via `[[wikilinks]]` from the graph's own relationships, would give an operator a genuinely useful, searchable, linkable security journal inside a tool they already use for notes — closer to a read-only mirror than a gimmick. What would make it a novelty instead: trying to replicate the Memory Graph's live interactivity inside Obsidian (fighting the tool rather than using it), or scoping it as a one-time export rather than an ongoing sync. Lower priority than Batch 7/8 core work either way.

## Future: eBPF pre-filtering for file events

Deliberately deferred — worth doing once Dendrite is a more mature/functional AV, not now. The current file-touch cache (`FanotifyCollector::file_touch_cache`, `telemetry.rs`) filters repeat noise in userspace: the kernel still generates and delivers the event, and Dendrite still pays the syscall/context-switch/read cost before discarding it. A genuine next tier of optimisation would move that decision into the kernel itself.

This is *not* a tweak to the existing fanotify path — fanotify and eBPF are separate kernel subsystems, and there's no hook point to attach custom eBPF logic to fanotify's own event pipeline. Getting real kernel-side filtering for file events means replacing fanotify's role for this purpose with a new eBPF program attached to a kprobe/LSM hook (e.g. on `vfs_open`), doing the (device, inode, program) lookup against a `BPF_MAP_TYPE_LRU_HASH` map *inside the kernel* — a cache hit means Dendrite never wakes up for that event at all, no ring-buffer write, no userspace processing. `BPF_MAP_TYPE_LRU_HASH` would also handle eviction automatically, more elegantly than the current cache's clear-on-overflow approach.

Real costs to weigh before attempting it: kprobes on internal kernel functions are less stable across kernel versions than fanotify's own purpose-built, stable API — a real portability trade. The eBPF verifier is a genuine constraint (no unbounded loops, careful stack/map access) — harder to write and debug than the equivalent Rust. And the marginal benefit is narrower than it first sounds, given what's already fixed: `FAN_MARK_FILESYSTEM` already makes "watch a whole mount" one cheap kernel call rather than per-file registration, and the userspace cache already eliminates the expensive downstream cost (the threat-path search) for repeat noise. What this would additionally save is specifically the small per-event kernel-to-userspace transfer for cache hits — real at very high event rates, but smaller in magnitude than the fixes already in place.