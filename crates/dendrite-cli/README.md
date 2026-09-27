# dendrite-cli

The `dendrite` command-line client, talking to a running `dendrited` over its Unix socket (default `/tmp/dendrited.sock`, override with `DENDRITE_SOCKET`).

The CLI should not contain privileged security logic itself — it's a client of `dendrited`'s IPC surface, same as the UI is a client of its HTTP/WebSocket surface.

See `CLI.md` (in this crate) for the full current command reference (status, incidents, memory graph queries, actions, guard/trust health, vulnerability/updater commands, and the `debug` subcommands, which are disabled in release builds).

## Testing

```bash
cargo test -p dendrite-cli
cargo clippy -p dendrite-cli --all-targets -- -D warnings
```
