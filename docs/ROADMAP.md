# Dendrite Roadmap

This file is the canonical implementation roadmap. Historical patch/batch notes are intentionally consolidated into topical documentation rather than kept as separate patch documents.

## Current pre-packaging state

The deterministic/pre-ML Dendrite foundation now includes the Memory Graph, incident/evidence correlation, MAGI/policy/Guard action gating, eBPF/fanotify telemetry with fallbacks, package/CVE exposure knowledge, authorised package remediation, signed self-update foundations, instance signing identity, Antiserum packages and Analysis review tooling, cross-host correlation keys, reusable behaviour knowledge, attack-chain classification/enrichment, and Dendrite Vulnerability Candidates.

A low-level **Culture** (working name, formerly "Adaptive Malware Analysis"/AMA) skeleton also exists. It can create isolated campaign workspaces by snapshotting the active Self, Memory, Incidents, and Guard SQLite databases into campaign-local copies. It is deliberately not yet a malware-execution or automatic-counter system and never mutates the active databases. Full campaign orchestration belongs after the deterministic baseline is proven stable.

## Batch 7: Packaging

Checkpoint A (testing the current version against README/docs, updating and testing the CLI, updating docs, and running the full `TESTS.md` validation matrix) is complete — see `TODO.md` for the specific fixes that came out of it.

Findings from the external code review pass that preceded Checkpoint A, carried forward here since they're genuinely packaging-scoped rather than resolved:

- **`dendrite-guard` is a stub.** Currently ~74 lines: a trust-state enum and an allow/deny match on `evaluate_authority`. No integrity manifests, anti-tamper, attestation, or recovery isolation yet, despite being the architecture's central authority-removal boundary. Given how much the invariants lean on Guard surviving compromise, hardening it should be prioritised ahead of enabling any destructive action executor (`SUSPEND_PROCESS`, `TERMINATE_PROCESS`, `QUARANTINE_OBJECT`, `BLOCK_NETWORK_DESTINATION`, `ISOLATE_HOST`). Confirmed as its own batch: every call site outside `dendrite-guard`/`guard.rs` only calls `evaluate_authority()`, `trust_state()`, `status()`, and `findings()` (`core.rs`, `actions.rs`, `adaptive_analysis.rs`) — as long as hardening work stays behind that same four-method surface, it should require no changes elsewhere in the codebase.
  - **Process separation, raised during Batch 7 planning.** `dendrite-guard` is currently a library linked directly into `dendrited` — a memory-corruption compromise of the main daemon has direct in-process access to Guard's state and logic, no real boundary beyond a logical one in the same address space. That undermines "compromise can remove authority, but cannot create authority" more than almost anything else in the current architecture: the invariant only really holds if compromising `dendrited` can't reach Guard directly. Splitting Guard into its own OS process (a second systemd service, `dendrite-guard`), talking to `dendrited` over a narrow, purpose-built IPC channel (a separate Unix socket from the CLI one), would make that boundary real — the same privilege-separation pattern OpenSSH uses between its unprivileged post-auth child and its privileged monitor process. The four-method call surface identified above (`evaluate_authority`/`trust_state`/`status`/`findings`) is exactly what that IPC channel would need to carry, so the existing call-site discipline already sets this up well. Real work still needed before attempting it: the IPC protocol itself, reconnect behaviour if `dendrite-guard` restarts independently of `dendrited`, and — most importantly — defined fail-closed semantics for "what happens if `dendrited` can't reach Guard at all" (must deny privileged actions, matching "evidence is not authority," never silently degrade to allow). Treat this as part of the Guard-hardening batch itself, not something to fold into packaging.
- **The localhost HTTP API (`127.0.0.1:8766`) and WebSocket (`127.0.0.1:8767`) have no authentication.** Only a CORS origin allowlist (`http://127.0.0.1:5173`, `http://localhost:5173`) protects the HTTP API; the WebSocket listener in `live.rs` has no handshake auth at all. The Unix socket (CLI↔daemon) is out of scope here — its access control is already the OS-level file permissions/group ownership set up in `runtime.rs`, which is a legitimate boundary on its own. Deliberately deferred: revisit before MCP integration or any fleet/multi-host feature. When it's picked up, both the HTTP API and the WebSocket need a token/session mechanism (WebSocket via query-string token, upgrade-header, or first-message auth frame); the UI itself is just a client of both and doesn't need separate treatment.
- **148 `.unwrap()` and 24 `.expect()` calls in `dendrited`.** Worth an audit pass distinguishing genuinely infallible cases from ones that could take the daemon down on unexpected input (e.g. odd filesystem metadata, malformed telemetry).
- **`tests/` at the repo root is empty (`.gitkeep` only).** Inline `#[cfg(test)]` coverage exists across ~20 modules, but there's no automated integration/end-to-end harness matching what `TESTS.md`'s validation matrix described — that file was a manual test plan, now executed once by hand for Checkpoint A. Whether it's worth automating into a real harness (vs. re-running it manually before each future checkpoint) is an open question for this batch.
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
- **Distribution packaging** — the actual `.deb`, for real installs on machines that aren't a dev clone. Not started; skeleton only, via `cargo-deb` (chosen over hand-rolled `debian/` control files — version/metadata stays in `Cargo.toml` next to the code it describes, no separate changelog-version-sync step, and it has built-in systemd-unit install support that maps directly onto the already-drafted `packaging/dendrited.service`). This is where the real design differences from local dev live, and they're real engineering, not just config:
  - The target machine won't have Node.js/npm at runtime, so `dendrited` needs to serve the *built* UI (`ui/dist`, from `npm run build`) itself, from a static-file route alongside its existing API routes — not rely on a separate dev server.
  - For that to actually mean "one address, just works" (the same requirement that drove this decision), WebSocket should merge onto the same listener/port as HTTP rather than staying a separate `DENDRITE_WS_ADDR` — currently a genuinely separate `TcpListener` in `live.rs` (via the `tungstenite` crate, ~80 lines, no existing WS-upgrade-detection-on-a-shared-port logic). Real protocol-adjacent code, not something to build without the ability to test it live.
  - `cargo build`/`cargo deb` only packages what already exists on disk — the UI and eBPF build steps still need to run first, so distribution packaging will end up wrapping (not replacing) the same build steps `bootstrap.sh` already does for local dev.
  - Dedicated `dendrite` service user/group creation via `.deb` maintainer scripts (`postinst`), replacing local dev's `sudo groupadd`/`usermod` bootstrap step with the real packaged equivalent.
  - Safe upgrade behaviour (preserve `/var/lib/dendrite` state and `/etc/dendrite` config across a package update).

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

"Host B" does not require a second physical machine or VM. Instance identity is a random `Uuid::new_v4()` generated once per fresh, empty self-store (`self_store.rs`) — it has no dependency on hostname, MAC address, or any other host-derived value. Two `dendrited` processes on the same machine, each pointed at a fully separate set of `DENDRITE_*_DB`/`DENDRITE_SOCKET`/`DENDRITE_HTTP_ADDR`/`DENDRITE_WS_ADDR` values (see `CONFIGURATION.md`), get genuinely distinct instance IDs and behave as distinct hosts for every purpose this validation cares about. A literal second machine only starts to matter once real host-level differences (actual separate telemetry, actual separate package inventory, network reachability between the two) become relevant — not for exercising the Antiserum trust boundary itself.

`scripts/launch_host_a.sh` and `scripts/launch_host_b.sh [HOST_NAME]` automate exactly this setup — the latter can be run repeatedly with different `HOST_NAME`s (each requiring its own explicit `DENDRITE_HOST_HTTP_PORT`/`DENDRITE_HOST_WS_PORT`) to stand up as many additional same-machine hosts as needed, each fully isolated under its own folder outside the repository. Both scripts support `--cleanup` to reset a host's data; `launch_host_b.sh` additionally supports `--remove-host` to delete a disposable host entirely.

This full validation sequence (steps 1–5 above) was already run once ahead of schedule, during Checkpoint A, using this same-machine approach — it passed cleanly, including cross-host correlation keys linking equivalent objects without merging their identities. It's included here as the canonical repeatable procedure, not because it's still unverified.

## Batch 8: ML / adaptive detection update

- new repo branch;
- tweaks based on data gathered from live test;
- CPU-first bounded statistical/ML detection;
- behavioural/sequence and graph-context models where justified by real baseline data;
- model signing, compatibility/resource budgets, and explicit explainable evidence surfaces;
- ML remains evidence and never direct privileged authority.

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
- richer fleet/multi-system views without weakening host-local trust boundaries.

To be explicit about what "fleet" does and doesn't mean here: the underlying exchange mechanism (Antiserum export/import/accept, one signed `.danti` package at a time, each acceptance an explicit operator action) already exists and is validated — see "Second-instance Antiserum validation" above. What's genuinely undesigned is any *live*, ongoing, multi-host aggregation: a UI/CLI surface that shows several hosts' state together in real time, without an explicit accept step per exchange. The README's "later federation" phrase points at this same undesigned territory. Nothing in the codebase today does live cross-host querying or in-flight merging; don't assume "fleet" means that already exists just because Antiserum exchange does.

## Batch 10: Benchmarking

Timeouts and other numeric thresholds introduced during Checkpoint A were placeholders, chosen for plausibility rather than measurement, and are explicitly flagged wherever they appear (search for "placeholder"/"not tuned"/"not benchmarked" in code comments and `docs/TODO.md`). This batch is where those get real numbers, on representative hardware and load, instead of guesses:

- `DaemonCore::HEALTH_CHECK_TIMEOUT` (currently 200ms) — the `daemon` field of `GET /api/v1/health`'s "ok vs degraded" threshold for the self-store/incidents liveness probe. Needs measurement of normal-case latency for these two `SELECT 1` pings under realistic load (busy telemetry ingestion, large Memory Graph, concurrent CLI/HTTP/WebSocket clients) before the threshold means anything.
- The ingestion scheduler's priority:routine weighting (`runtime.rs`, currently a hardcoded 4:1 — `priority_budget = 4usize`, refilled after 4 priority jobs or an empty priority queue) doesn't adjust to queue pressure at all today. Needs real load testing (not just correctness testing) before trusting it under sustained priority traffic or a large routine burst (e.g. a big file operation) — a dev-VM report of the routine queue struggling at ~3k is the kind of signal this batch should chase down properly, on real hardware, rather than guessing at a fix.
- Any other timeout/threshold constants added between now and this batch should be flagged the same way when introduced, so this list doesn't need to be reconstructed by searching the whole codebase later.

## User feedback backlog (post-Checkpoint A)

Raised during/after Checkpoint A manual testing. Filed here rather than lost.

### UI
The items originally filed here (button relabels, Dashboard exposition text, Memory Graph focus/drag distinction, 3D camera inversion, user-node color, Live Event Stream search) have been implemented directly against the real `ui/src` and verified with a `tsc` type-check — see `TODO.md`. Still outstanding, not yet started: the broader Zoraxy-style reskin/typography pass, and the Memory Graph clustering feature (behaviour/fingerprint-derived named clusters with a "magnetic" pull between clusters sharing nodes) — both real, well-specified design threads, just bigger than a single-pass fix.

### Data model
- No dedicated `EntityKind::Package`/`Software` exists — installed packages currently map to `EntityKind::Service` as the closest fit (`core.rs`), which is why e.g. curl shows up as a "service" in the Memory Graph even though nothing about it is a running service. Worth a real `Package` variant at some point; touches the graph model and the export schema, so scope it properly rather than a quick patch.
- Local-instance Antiserum accept: revised design (supersedes any earlier assumption that a same-instance import should just be refused/no-op) — a user should be able to load a `.danti` file the *local* instance itself issued (e.g. output from a Culture sandbox run) and accept it back in. On accept, deduplicate exact matches (same host, same node/process/etc., identical) by skipping them, but update them with any *new* relationships present in the package. Explicitly do **not** touch lineage on this path. This directly enables the Culture sandbox-findings use case and needs real accept-logic changes (currently no same-instance-specific handling exists at all in `accept_antiserum_knowledge`).

### CLI
- Shell autocompletion — `dendrite-cli` is a hand-rolled parser, not `clap`-based, so there's no free completion generator. Best approach is likely a completion script that shells out to a small introspection subcommand (`--list-commands`-style) rather than a static/hardcoded completion list, so it can't silently drift from the real command set as new commands are added.

### Website / distribution
- Consider a project website, potentially hosting the apt repository once packaging (Batch 7) is real. A live, publicly-interactive Memory Graph demo is a good idea, confirmed worth keeping — but it must not run on the same machine hosting the website/anything real, must obviously limit what it actually shows (a live demo of a real running host's telemetry is not something to expose unfiltered to the public internet), and needs the HTTP/WebSocket auth gap (see the Batch 7 findings above) closed first if it's ever reachable beyond localhost. A public Memory Graph endpoint is reconnaissance material if pointed at something that matters — treat "what does the public demo actually reveal" as its own design question, not an afterthought.

### Snapshotting / "recording" an action
- A lighter-weight version of Culture's existing campaign-snapshot mechanism: record Memory Graph changes resulting from a specific, user-chosen action (targeting a specific process/node), rather than a full campaign. Natural fit as a Culture-scoped feature specifically because Culture already has the isolation/permissions/workspace story worked out (see "Future: Culture" below) — a general-purpose snapshot button without that containment would be a materially bigger safety surface. Also useful more generally for: verifying a remediation only changed what it claimed to, forensic point-in-time capture before decay/reinforcement moves state, and generating labeled before/after data for the ML batch.

## Future: Culture

Working name: **Culture** (formerly "Adaptive Malware Analysis"/AMA — code symbols renamed accordingly: `culture.rs`, `Culture{Error,Sources,Campaign,Manager}`).

A low-level campaign snapshot skeleton exists now, but the full feature is future research work. Intended architecture:

```text
active Dendrite databases
        │ snapshot only
        ▼
contained campaign workspace
├── self.sqlite3
├── memory.sqlite3
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

## Future: Obsidian plugin

Either:

- export selected Dendrite knowledge to Obsidian; or
- provide a live **one-way** Dendrite → Obsidian connection.

This must remain an observation/export integration and must not grant Obsidian execution authority over Dendrite.