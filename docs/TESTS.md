# Manual validation matrix

A repeatable, by-hand checklist for confirming a build actually works end to
end — beyond `cargo test`. Useful after a change that touches daemon
startup, telemetry, the HTTP/WebSocket surface, the UI, or packaging, and
before cutting a checkpoint. Each section names the commands to run and
what a pass looks like; none of it is automated yet (see `docs/ROADMAP.md`'s
Batch 7 notes on whether that's worth building).

## 1. Build and unit tests

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

All four should pass cleanly with no warnings. If your toolchain can't reach
`static.rust-lang.org` for the pinned version in `rust-toolchain.toml`, use
`cargo +stable` instead (see `CLAUDE.md`).

## 2. Single-instance daemon smoke test

Start the daemon against a scratch data directory and confirm the core
surfaces respond:

```bash
mkdir -p /tmp/dendrite-smoke && cd /tmp/dendrite-smoke
/path/to/target/debug/dendrite-guard &
# "dendrite-guard: listening on /tmp/dendrite-guard.sock (data/guard.sqlite3)"

DENDRITE_SELF_DB=self.sqlite3 DENDRITE_STM_DB=stm.sqlite3 \
DENDRITE_LTM_DB=ltm.sqlite3 DENDRITE_INCIDENT_DB=incidents.sqlite3 \
  /path/to/target/debug/dendrited &

/path/to/target/debug/dendrite-cli status
curl -s http://127.0.0.1:8766/api/v1/health
```

Expect a healthy status from both, and `dendrited` to still be running
(check `dendrite-cli status` again) rather than having exited.

For real kernel telemetry rather than the `/proc`-polling fallback, follow
the eBPF quick functional test in `ebpf/README.md` (build the object,
`setcap`, enable with `DENDRITE_EBPF=1`, generate a process/network event,
inspect with `dendrite-cli telemetry recent 50`).

## 3. UI, including the merged HTTP/WebSocket port

```bash
cd ui && npm install && npm run dev
```

Open `http://127.0.0.1:5173` against a running `dendrited` (from step 2).
Confirm:

- the Overview/Activity pages populate from the HTTP API;
- the Live Event Stream view actually receives events over `/ws` (trigger a
  telemetry event, e.g. `/bin/true`, and watch it arrive live) — this is the
  one path not covered by `cargo test`, since it needs a real browser
  WebSocket client talking to the daemon's real upgrade handshake, not a
  raw socket script.

For a packaged-style build (the UI's own separate process), build it with
an absolute `dendrited` origin baked in, then run `dendrite-ui-server`
against the result:

```bash
cd ui && VITE_DENDRITE_API_BASE="http://127.0.0.1:8766/api/v1" \
  VITE_DENDRITE_WS_URL="ws://127.0.0.1:8766/ws" npm run build
DENDRITE_UI_DIR=ui/dist DENDRITE_UI_ADDR=127.0.0.1:8767 \
  /path/to/target/debug/dendrite-ui-server
```

Open `http://127.0.0.1:8767` and confirm the same things as above, plus that
this is genuinely a separate process from `dendrited` — stopping
`dendrite-ui-server` should leave `dendrited`'s API/CLI/telemetry entirely
unaffected, and vice versa.

## 4. MAGI, as its own process

Confirms `dendrited` actually reaches a separate `dendrite-magi` process
over its Unix socket for real evaluations, and correctly fails closed
(every seat abstains) when it can't.

```bash
# terminal 1: the MAGI evaluation process
/path/to/target/debug/dendrite-magi
# "dendrite-magi: listening on /tmp/dendrite-magi.sock"

# terminal 2: dendrited, pointed at it (defaults to the same path if unset)
DENDRITE_SELF_DB=/tmp/dendrite-smoke/self.sqlite3 \
DENDRITE_STM_DB=/tmp/dendrite-smoke/stm.sqlite3 \
DENDRITE_LTM_DB=/tmp/dendrite-smoke/ltm.sqlite3 \
DENDRITE_INCIDENT_DB=/tmp/dendrite-smoke/incidents.sqlite3 \
DENDRITE_MAGI_SOCKET=/tmp/dendrite-magi.sock \
  /path/to/target/debug/dendrited
# also start terminal 0: /path/to/target/debug/dendrite-guard, or every
# proposal below will read guard: deny/not_authorised regardless of MAGI —
# see step 5 for exercising Guard on its own

# terminal 3: propose and evaluate a real action through the CLI
dendrite debug seed-incident e2e-test
dendrite actions propose <INCIDENT_ID> observe <PROCESS_OBJECT_ID>
dendrite actions evaluate <PROPOSAL_ID>
```

A pass shows real, non-abstain evaluations in the `MAGI:` section (Host and
Environment `approve`, User `abstain` for a bare `observe` — matching
`dendrite-magi`'s rule-based evaluator) and `quorum: approved`/
`[completed]`.

Then kill the `dendrite-magi` process (terminal 1) and propose/evaluate a
second action the same way. Confirm the fallback: every seat now reads
`abstain` with a `dendrite-magi is unreachable: ...` reason, `quorum:
denied`, and the proposal ends `[not_authorised]` — not a hang, and not a
silent approval.

## 5. Guard, as its own process

Confirms `dendrited` actually reaches a separate `dendrite-guard` process
over its Unix socket for trust-state/authority checks, that changes made
through `dendrite-guard`'s own persistent state are visible to `dendrited`,
and that an unreachable `dendrite-guard` correctly fails closed to
`Compromised`/`Deny` (not MAGI's abstain — Guard has only one voice on
trust, so there's no quorum for "unreachable" to defer to).

```bash
# terminal 1: the Guard process (owns guard.sqlite3 itself now, not dendrited)
/path/to/target/debug/dendrite-guard
# "dendrite-guard: listening on /tmp/dendrite-guard.sock (data/guard.sqlite3)"

# terminal 2: dendrited, pointed at it (defaults to the same path if unset)
DENDRITE_SELF_DB=/tmp/dendrite-smoke/self.sqlite3 \
DENDRITE_STM_DB=/tmp/dendrite-smoke/stm.sqlite3 \
DENDRITE_LTM_DB=/tmp/dendrite-smoke/ltm.sqlite3 \
DENDRITE_INCIDENT_DB=/tmp/dendrite-smoke/incidents.sqlite3 \
DENDRITE_GUARD_SOCKET=/tmp/dendrite-guard.sock \
  /path/to/target/debug/dendrited

# terminal 3: read trust state and propose/evaluate a real action
dendrite guard
dendrite debug seed-incident e2e-test
dendrite actions propose <INCIDENT_ID> observe <PROCESS_OBJECT_ID>
dendrite actions evaluate <PROPOSAL_ID>
```

A pass shows `trust_state: trusted` from `dendrite guard`, and the proposal
completes (`guard: allow`, `[completed]`, assuming MAGI also approves).

Now exercise the persistent-state path: `dendrite debug guard-state
compromised` (a debug-only surface, refused outright in a release build —
see `crates/dendrite-guard/README.md`), then `dendrite guard` again from
the same or a fresh terminal. Confirm it now reads `trust_state:
compromised` — this is `dendrite-guard`'s own SQLite state persisting the
change, not something `dendrited` computed. Propose/evaluate a new action
and confirm it's denied (`guard: deny`, `[not_authorised]`).

Reset with `dendrite debug guard-state trusted`, confirm a fresh proposal
completes again, then kill the `dendrite-guard` process (terminal 1) and
propose/evaluate one more action. Confirm the fallback: `guard: deny`,
`[not_authorised]` — and, separately, that `dendrite guard` itself now
*errors* (rather than printing a fabricated status) because `status()`/
`findings()` are kept genuinely fallible, not defaulted, since they feed
signed Antiserum attestations (step 6).

## 6. Antiserum export pipeline

```bash
cargo run -p dendrited --example antiserum_smoke -- /tmp/dendrite-smoke/antiserum-out
```

Point the same `DENDRITE_*_DB` env vars as step 2 at a data directory with
some real incidents/graph data in it for a non-trivial run. A pass prints
`Antiserum live-data smoke test PASSED` and confirms signature verification,
`.danti` encode/decode, replay rejection, and payload/envelope tamper
rejection all succeeded. See `crates/dendrited/README.md`'s Testing section
for what this covers and where it reads/writes.

## 7. Second-instance Antiserum trust-boundary validation

Exercises cross-host export/import without needing a second physical
machine — see `docs/ROADMAP.md`'s "Second-instance Antiserum validation"
section (under Batch 7/Checkpoint B) for the full five-step procedure and
what each step should confirm. `scripts/launch_host_a.sh` and
`scripts/launch_host_XYZ.sh [HOST_NAME]` automate standing up an isolated
second instance on the same machine for this.

## 8. Packaging (`.deb`)

```bash
./scripts/build-deb.sh
```

Then, in a disposable container or VM (not your main dev machine — this
installs a system user and four systemd services):

```bash
sudo dpkg -i target/debian/dendrite_*.deb
systemctl status dendrited
systemctl status dendrite-ui
systemctl status dendrite-magi
systemctl status dendrite-guard
sudo systemctl disable --now dendrite-ui     # confirm dendrited is unaffected
sudo systemctl disable --now dendrite-magi   # confirm dendrited fails closed (see step 4), not down
sudo systemctl disable --now dendrite-guard  # confirm dendrited fails closed (see step 5), not down
sudo dpkg -r dendrite   # confirm /var/lib/dendrite and /etc/dendrite survive
sudo dpkg -P dendrite   # confirm purge removes them
```

Confirm all four services start (four independent systemd units, one
package — see `crates/dendrite-ui-server/README.md` for why the UI is
split out, and `crates/dendrite-magi/README.md`/`crates/dendrite-guard/README.md`
for MAGI/Guard), that disabling `dendrite-ui`/`dendrite-magi`/
`dendrite-guard` doesn't affect `dendrited` or vice versa, the
user/group exist, `/etc/dendrite/dendrited.env` is preserved across a plain
removal and only deleted on purge, and (if your
test environment has a real `bpf-linker`/nightly toolchain, unlike a sandbox
without one) that the packaged eBPF object actually loads rather than
falling back to `/proc` polling.

## Known load-testing findings

For what happens under sustained real-world load rather than a quick smoke
test (routine-lane throughput ceilings, hub-node relationship blowups, CPU
contention with another workload on the same core), see `docs/ROADMAP.md`'s
Batch 10 section — those are live-hardware findings, not something to
re-derive from scratch here.
