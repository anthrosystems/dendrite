# CLAUDE.md

Guidance for Claude Code (or any AI assistant) working in this repository.

## What this is

Dendrite is a Linux-native endpoint security platform: a Rust workspace
(`dendrited` daemon + supporting crates) plus a TypeScript/React UI
(`ui/`), developed under the Anthrosystems project umbrella. It combines
eBPF/fanotify telemetry, a Memory Graph for behavioural correlation,
incident/evidence tracking, policy-gated response actions, and CVE/package
vulnerability tracking.

`docs/ROADMAP.md` is the canonical implementation roadmap (organised into
numbered batches) — read it before starting non-trivial work to see what
batch is active and what's already been decided. `docs/TODO.md` is a
scratch tracking list, not a design doc; items should get resolved,
folded into `ROADMAP.md`/`architecture.md`, or dropped, not left open
indefinitely. `docs/architecture.md` documents the long-term vision and
is intentionally ahead of the current implementation in places.

## Workspace layout

```
crates/dendrited          - the daemon: HTTP/WS API, Memory Graph, telemetry,
                             guard/action gating, vulnerability tracking
crates/dendrite-cli       - CLI client (talks to dendrited over its Unix socket)
crates/dendrite-memory    - Memory Graph storage (SQLite-backed STM/LTM)
crates/dendrite-protocol  - shared DTOs/IPC types between daemon and CLI/UI
crates/dendrite-guard     - authority/trust-state gating (currently a stub,
                             see ROADMAP.md's Batch 7 findings)
crates/dendrite-action    - response action execution
crates/dendrite-updater   - self-update foundations
crates/dendrite-ebpf-common - shared types for the eBPF collector
ebpf/dendrite-ebpf        - the actual eBPF program (excluded from the main
                             workspace; needs bpf-linker + a nightly toolchain)
ui/                       - TypeScript/React operator UI
packaging/                - systemd unit, postinst/postrm, env file for the .deb
scripts/                  - bootstrap.sh (dev setup), build-deb.sh (distribution
                             packaging), launch_host_*.sh (dev launch scripts)
```

## Toolchain

`rust-toolchain.toml` pins `1.98.0`. Some sandboxed dev environments can't
reach `static.rust-lang.org` to fetch a pinned toolchain and only have
`stable` available — in that case run cargo commands as `cargo +stable
...` rather than fighting the pin. The eBPF crate additionally needs
`bpf-linker` and a nightly toolchain; where those aren't available, eBPF
work can be tested with a stub object file at
`ebpf/dendrite-ebpf/target/bpfel-unknown-none/release/dendrite-ebpf` to
exercise everything else (packaging, asset resolution) without a real
build — always flag this clearly (e.g. in `docs/TODO.md`) rather than
treating a stub as a real verification.

## Local dev vs. distribution packaging

Two different things, don't conflate them (see `docs/ROADMAP.md`'s Batch 7):

- **Local dev**: `scripts/bootstrap.sh` gets a fresh clone runnable (builds
  `dendrited`/`dendrite-cli`, the eBPF object, the UI; sets up the dev
  `dendrite` group/capabilities). `scripts/launch_host_a.sh` calls it
  automatically on a fresh clone. The UI runs via `npm run dev` (Vite),
  proxying `/api`/`/ws` to a locally-running `dendrited`.
- **Distribution packaging**: `scripts/build-deb.sh` builds the eBPF
  object, builds the UI (`ui/dist`, baked with an absolute `dendrited`
  origin — see `docs/CONFIGURATION.md`), then runs `cargo deb -p dendrited`.
  The resulting `.deb` installs a dedicated `dendrite` system user/group and
  **three** independent systemd units: `dendrited.service` (the daemon),
  `dendrite-ui.service` (`dendrite-ui-server`, a minimal unprivileged
  static-file server for the UI — see `crates/dendrite-ui-server/README.md`
  for why it's a separate process/unit rather than something `dendrited`
  serves itself), and `dendrite-magi.service` (`dendrite-magi`, the MAGI
  quorum-evaluation process `dendrited` reaches over a Unix socket — see
  `crates/dendrite-magi/README.md`). Each unit can be enabled/disabled
  independently (`systemctl disable --now dendrite-ui`/`dendrite-magi`);
  `dendrited` treats an unreachable `dendrite-magi` as fail-closed (every
  MAGI seat abstains, so nothing can complete) rather than hanging or
  silently allowing. Config lives in `/etc/dendrite/dendrited.env`/
  `dendrite-magi.env` (conffiles — survive upgrades/removal, only `purge`
  deletes them), state in `/var/lib/dendrite` (via systemd's
  `StateDirectory=`, same survival rules).

## Testing

Inline `#[cfg(test)]` modules exist across most `dendrited` source files —
run with `cargo +stable test --workspace`. `docs/TESTS.md` is a manual
validation matrix, currently run by hand rather than automated — there is
no `tests/` directory at the repo root (it never held more than a
placeholder script, later removed); see `docs/ROADMAP.md`'s Batch 7 open
questions on whether an automated integration harness is worth building.

When auditing `.unwrap()`/`.expect()` calls (a recurring roadmap item):
count only production code, not inline test modules — test-assertion
`.unwrap()`s are normal and not part of that audit's scope. Several
validated newtypes in this codebase (`Confidence`, `MemoryStrength`,
`MemoryConfidence`, `DecayRate` — all private-field `u8` wrappers whose
only public constructor validates a `0..=100` range) make many
`.expect()` calls provably safe: re-deriving one from an already-validated
value of the same type, or from a literal in-range constant, can never
fail. Look for the ones that break that pattern (fetch something back
after a mutation and assume it's still there, parse untrusted input
without validating first, etc.) rather than treating every `.expect()`
as suspect.

## Dev/test workflow

Development and testing are meant to happen on different machines:
development on whichever machine is convenient (needs a real Linux kernel
for eBPF/fanotify work — WSL2 if on Windows), testing on a real Linux host
via the built `.deb` (`sudo apt install ./dendrited_*.deb`, `systemctl
status dendrited`).

**Use normal git push/pull against this repo for that, not hand-copied
patch files or pasted file contents.** Development machine commits and
pushes (a branch + PR, or directly to `dev` if that's the agreed flow);
the test machine pulls and rebuilds the `.deb`. Falling back to manually
reconstructing diffs against a guessed copy of a file's content is
fragile and error-prone (variable names, line offsets, and interleaved
unrelated local changes all cause silent mismatches) — always prefer an
actual `git fetch`/`pull` from `origin` when a git remote is available.
