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
DENDRITE_SELF_DB=self.sqlite3 DENDRITE_STM_DB=stm.sqlite3 \
DENDRITE_LTM_DB=ltm.sqlite3 DENDRITE_INCIDENT_DB=incidents.sqlite3 \
DENDRITE_GUARD_DB=guard.sqlite3 \
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

## 4. Antiserum export pipeline

```bash
cargo run -p dendrited --example antiserum_smoke -- /tmp/dendrite-smoke/antiserum-out
```

Point the same `DENDRITE_*_DB` env vars as step 2 at a data directory with
some real incidents/graph data in it for a non-trivial run. A pass prints
`Antiserum live-data smoke test PASSED` and confirms signature verification,
`.danti` encode/decode, replay rejection, and payload/envelope tamper
rejection all succeeded. See `crates/dendrited/README.md`'s Testing section
for what this covers and where it reads/writes.

## 5. Second-instance Antiserum trust-boundary validation

Exercises cross-host export/import without needing a second physical
machine — see `docs/ROADMAP.md`'s "Second-instance Antiserum validation"
section (under Batch 7/Checkpoint B) for the full five-step procedure and
what each step should confirm. `scripts/launch_host_a.sh` and
`scripts/launch_host_XYZ.sh [HOST_NAME]` automate standing up an isolated
second instance on the same machine for this.

## 6. Packaging (`.deb`)

```bash
./scripts/build-deb.sh
```

Then, in a disposable container or VM (not your main dev machine — this
installs a system user and two systemd services):

```bash
sudo dpkg -i target/debian/dendrite_*.deb
systemctl status dendrited
systemctl status dendrite-ui
sudo systemctl disable --now dendrite-ui   # confirm dendrited is unaffected
sudo dpkg -r dendrite   # confirm /var/lib/dendrite and /etc/dendrite survive
sudo dpkg -P dendrite   # confirm purge removes them
```

Confirm both services start (two independent systemd units, one package —
see `crates/dendrite-ui-server/README.md` for why the UI is split out), that
disabling `dendrite-ui` doesn't affect `dendrited` or vice versa, the
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
