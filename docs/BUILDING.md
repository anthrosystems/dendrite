# Building and packaging Dendrite

Reference for how Dendrite gets from source to a runnable install — both the
local dev path and the real `.deb`. See `docs/CONFIGURATION.md` for runtime
environment variables once something is actually running, and `docs/TESTS.md`
for validating the result.

## Local dev vs. distribution packaging

Two different things, don't conflate them:

- **Local packaging** — getting a fresh clone to a runnable state with one
  command, for dev work across machines. `scripts/bootstrap.sh` builds
  `dendrited`/`dendrite-cli`, the eBPF object, and the UI, and sets up the dev
  `dendrite` group/capabilities — idempotent (skips anything already built,
  `--force` to override), and each step degrades gracefully rather than
  aborting the others if a toolchain piece (bpf-linker, nightly, npm) is
  missing, since eBPF and the UI are both optional at runtime.
  `scripts/launch_host_a.sh` calls it automatically on a fresh clone (no
  `target/debug/dendrited` yet) and skips straight to launching once built.
  For a dev who wants to rebuild just one piece, `scripts/bootstrap.sh` takes
  `--skip-ebpf`/`--skip-ui`/`--skip-capabilities`/`--force` directly.
- **Distribution packaging** — the actual `.deb`, for real installs on
  machines that aren't a dev clone. Built via `cargo-deb` (chosen over
  hand-rolled `debian/` control files — version/metadata stays in
  `Cargo.toml` next to the code it describes, no separate
  changelog-version-sync step, and it has built-in systemd-unit install
  support that maps directly onto `packaging/dendrited.service`).
  `scripts/build-deb.sh` wraps the whole sequence (`build-ebpf.sh` →
  `npm run build` in `ui/` → `cargo deb -p dendrited`) into one command,
  since `cargo build`/`cargo deb` only packages what already exists on disk
  and won't run the eBPF or UI builds itself. Installing the result:

  ```bash
  sudo apt install ./dendrited_0.1.0-1_amd64.deb
  systemctl status dendrited
  ```

  with no separate `enable --now` step needed — the package's postinst
  enables and starts the units itself.

## What the package installs

A dedicated `dendrite` system user/group, and four independent systemd
units: `dendrited.service` (the daemon), `dendrite-ui.service`
(`dendrite-ui-server`, a minimal unprivileged static-file server for the UI
— see `crates/dendrite-ui-server/README.md`), `dendrite-magi.service`
(`dendrite-magi`, MAGI quorum evaluation — see `crates/dendrite-magi/README.md`),
and `dendrite-guard.service` (`dendrite-guard`, the trust/integrity process —
see `crates/dendrite-guard/README.md`). Each unit can be enabled/disabled
independently (`systemctl disable --now dendrite-ui`/`dendrite-magi`/
`dendrite-guard`) — see each crate's own README for what happens to
`dendrited` when one of the other three is unreachable.

Config lives in `/etc/dendrite/dendrited.env`/`dendrite-magi.env`/
`dendrite-guard.env` (conffiles — survive upgrades/removal, only `purge`
deletes them), state in `/var/lib/dendrite` (via systemd's
`StateDirectory=`, same survival rules). The intended native layout
converges on `/usr/bin`, `/usr/lib/dendrite`, `/usr/share/dendrite`,
`/etc/dendrite`, and `/var/lib/dendrite`, with an Anthrosystems-owned
signed APT repository as the long-term distribution target.

## What packaging is expected to provide

- eBPF + the UI compiled during release/build and bundled with Dendrite;
- a dedicated `dendrite` service user and `dendrite` group with appropriate
  ownership/permissions;
- service files, default configuration, state directories, UI assets, eBPF
  assets, CLI and daemon binaries all installed by the package;
- systemd hardening, with only the capabilities the packaged collectors
  actually require;
- safe package upgrades that preserve configuration and state;
- installation this simple:

  ```bash
  sudo apt install dendrite
  sudo systemctl enable --now dendrited
  ```

## Development binary capabilities

The current development binary needs:

```text
CAP_DAC_READ_SEARCH
CAP_SYS_ADMIN
CAP_PERFMON
CAP_BPF
```

Current development capability set (as applied by `scripts/bootstrap.sh`):

```text
cap_bpf,cap_perfmon,cap_sys_admin,cap_dac_read_search+ep
```
