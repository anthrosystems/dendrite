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
batch is active and what's already been decided. It's a task list, not a
changelog or a debugging journal: a fully-resolved item gets removed
outright rather than annotated "done" in place, and design rationale or
engineering history that's still worth keeping moves to a more fitting
doc — `docs/architecture.md` for design decisions, `docs/DEVELOPMENT.md` for
build/packaging mechanics, `docs/PERFORMANCE.md` for load-testing history.
`docs/TODO.md` is a scratch tracking list, not a design doc; items should
get resolved, folded into `ROADMAP.md`/`architecture.md`, or dropped, not
left open indefinitely. `docs/architecture.md` documents the long-term
vision and is intentionally ahead of the current implementation in places.

## Workspace layout

```
crates/dendrited          - the daemon: HTTP/WS API, Memory Graph, telemetry,
                             action proposals; talks to MAGI/Guard as a client
                             over their own Unix sockets, never in-process
crates/dendrite-cli       - CLI client (talks to dendrited over its Unix socket)
crates/dendrite-memory    - Memory Graph storage (SQLite-backed STM/LTM)
crates/dendrite-protocol  - shared DTOs/IPC types between daemon/CLI/UI/MAGI/Guard
crates/dendrite-magi      - MAGI quorum evaluation, its own process/systemd unit
                             (internal rule-based evaluators, or an MCP client
                             per seat — see its own README)
crates/dendrite-guard     - trust/integrity boundary, its own process/systemd
                             unit; the decision logic itself (integrity
                             manifests, anti-tamper, attestation) is still a
                             stub, see ROADMAP.md's Batch 7 findings
crates/dendrite-action    - response action execution
crates/dendrite-updater   - self-update foundations
crates/dendrite-ebpf-common - shared types for the eBPF collector
crates/dendrite-ui-server - serves the built UI, its own process/systemd unit
crates/dendrite-mcp       - inbound MCP server, deliberately a stub for now
                             (see its own README)
ebpf/dendrite-ebpf        - the actual eBPF program (excluded from the main
                             workspace; needs bpf-linker + a nightly toolchain)
ui/                       - TypeScript/React operator UI
packaging/                - systemd units, postinst/postrm, env files for the .deb
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

Two different things, don't conflate them — full mechanics in
`docs/DEVELOPMENT.md`:

- **Local dev**: `scripts/bootstrap.sh` gets a fresh clone runnable. The UI
  runs via `npm run dev` (Vite), proxying `/api`/`/ws` to a locally-running
  `dendrited` and injecting its HTTP API bearer token automatically (see
  `docs/CONFIGURATION.md`'s "HTTP API authentication" section) — dev never
  needs the token pasted in by hand.
- **Distribution packaging**: `scripts/build-deb.sh` produces the real
  `.deb`, which installs a dedicated `dendrite` system user/group and
  **four** independent systemd units (`dendrited`, `dendrite-ui`,
  `dendrite-magi`, `dendrite-guard` — see each crate's own README for its
  fail-closed behaviour when another is unreachable).

## Keeping scripts compatible with code changes

`scripts/` (`bootstrap.sh`, `build-deb.sh`, `build-ebpf.sh`, `launch_host_a.sh`,
`launch_host_XYZ.sh`) and the packaging maintainer scripts (`packaging/postinst`,
`postrm`, the `.service` units) are real consumers of this codebase's env vars,
paths, socket names, and binary/build layout, not just docs. Whenever a code
change touches any of those — a new `DENDRITE_*` env var, a renamed/moved
default path, a new build artifact or output directory, a changed CLI
subcommand or flag one of these scripts calls, a new systemd unit or
capability requirement — check every script/unit file that could reference
the old shape and update it in the same change, not as a follow-up. A script
that silently drifts out of sync fails at run time on someone else's machine,
often long after the code change that broke it, which is much more expensive
to debug than fixing it while the change is still in front of you.

## Testing

Inline `#[cfg(test)]` modules exist across most `dendrited` source files —
run with `cargo +stable test --workspace`. `docs/DEVELOPMENT.md`'s "Manual
validation matrix" section is run by hand rather than automated — there is
no `tests/` directory at the repo root (it never held more than a
placeholder script, later removed). See that doc's "Open question"
section on whether/when an automated integration harness is worth building.

### `.unwrap()`/`.expect()` audit

An ongoing, periodic pass over `dendrited`, distinguishing genuinely
infallible cases from ones that could take the daemon down on unexpected
input (odd filesystem metadata, malformed telemetry, etc.). Re-run this
whenever a batch of new I/O-adjacent code lands rather than treating it as
a one-time count, since raw call counts drift with every change and aren't
themselves meaningful on their own.

Count only production code, not inline test modules — test-assertion
`.unwrap()`s are normal and not part of this audit's scope. Several
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
