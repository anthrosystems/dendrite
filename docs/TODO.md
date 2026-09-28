# TODO

Running list of small items found while working through the codebase. This is
a scratch tracking file, not a design document or a historical log — each
item should end up either fixed, folded into `ROADMAP.md`/`architecture.md`/
other docs, or explicitly dropped, and then removed from this list once it's
captured wherever it actually belongs. Nothing here should stay open
indefinitely without a reason.

## Open

- Rename the `dendrite-cli` binary to `dendrite`. Current name is verbose for
  an interactive tool typed constantly at the terminal (`dendrite-cli guard
  recover complete <TOKEN>`, etc.). Touches the crate's `[[bin]]` name in
  `Cargo.toml`, `packaging/postinst`/`dendrited.service` if either shells out
  to it, `docs/CONFIGURATION.md`, `crates/dendrite-guard/README.md`,
  `crates/dendrite-cli/CLI.md`, and any user-facing strings in
  `crates/dendrite-cli/src/lib.rs` that hardcode the binary name (e.g. the
  `GuardRecoverBegin` response message). Not started — do not push until
  explicitly asked.
