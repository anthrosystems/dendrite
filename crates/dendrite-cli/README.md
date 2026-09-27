# dendrite-cli

The `dendrite` command-line client, talking to a running `dendrited` over its Unix socket. `DENDRITE_SOCKET` always overrides the default when set; otherwise the CLI checks for a packaged install's socket (`/run/dendrite/dendrited.sock`) first, falling back to the local-dev default (`/tmp/dendrited.sock`) if that's not there — see `crates/dendrite-cli/src/main.rs`. This matters because `dendrited.service` sets `DENDRITE_SOCKET` itself via a systemd-unit-scoped `Environment=` line, invisible to an interactive shell — without the packaged-path check, a bare `dendrite-cli status` against a real install would always look in the wrong place.

The CLI should not contain privileged security logic itself — it's a client of `dendrited`'s IPC surface, same as the UI is a client of its HTTP/WebSocket surface.

See `CLI.md` (in this crate) for the full current command reference (status, incidents, memory graph queries, actions, guard/trust health, vulnerability/updater commands, and the `debug` subcommands, which are disabled in release builds).

## Testing

```bash
cargo test -p dendrite-cli
cargo clippy -p dendrite-cli --all-targets -- -D warnings
```
