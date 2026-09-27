# dendrite-magi

The MAGI quorum-evaluation process: it decides whether an action proposal gets the Host/User/Environment votes it needs before `dendrited` will execute it. It exists as its own binary/systemd unit (`dendrite-magi.service`), reached only over a Unix socket, for the same reason `dendrite-guard` is planned to become one — see `docs/ROADMAP.md`'s Batch 7 process-separation notes: action authority (here, the quorum vote itself) shouldn't be reachable in-process from wherever a compromise of the main daemon might land. "Compromise can remove authority, but cannot create authority" only really holds if compromising `dendrited` can't reach the thing that grants authority directly.

`dendrited` never links this crate's evaluation logic in production; it talks to a running `dendrite-magi` process only over the socket protocol in `dendrite_protocol::magi_ipc` (newline-delimited JSON, one request per connection — the same convention as the existing CLI IPC protocol, kept as its own separate request/response pair since this is a distinct process boundary with its own fail-closed semantics, not just another CLI command). `dendrited`'s own test suite depends on this crate as a dev-dependency purely to keep one rule-based reference implementation instead of duplicating the same logic twice — that does not create an in-process link in the shipped binary.

## Fail-closed behaviour

If `dendrite-magi` is unreachable, times out, or isn't running, `dendrited`'s client (`MagiIpcClient`, in `crates/dendrited/src/actions.rs`) reports every seat as **abstain**, not deny/veto and not a hang. Under the default quorum policy (2 approvals required, an abstain counting toward neither approval nor denial) this means an action can never complete while `dendrite-magi` is down — denied, not silently allowed, and not stuck waiting either. See `docs/ROADMAP.md`'s "Fail-closed behaviour, and why ABSTAIN rather than DENY/VETO" note for the full reasoning (short version: abstain is the one verdict that can never itself manufacture approval, and it doesn't conflate an evaluator's real reasoned denial with the evaluator simply not being reachable, which matters once a seat's answer can legitimately be slow — see the MCP note below).

## Configuration

| Variable | Default | Description |
|---|---|---|
| `DENDRITE_MAGI_SOCKET` | `/tmp/dendrite-magi.sock` | Unix socket path this process listens on |
| `DENDRITE_MAGI_HOST_SOURCE` | `internal` | Which evaluator backs the Host seat: `internal` or `mcp` |
| `DENDRITE_MAGI_USER_SOURCE` | `internal` | Which evaluator backs the User seat: `internal` or `mcp` |
| `DENDRITE_MAGI_ENVIRONMENT_SOURCE` | `internal` | Which evaluator backs the Environment seat: `internal` or `mcp` |
| `DENDRITE_MAGI_<SEAT>_MCP_COMMAND` | *(none)* | Required when `<SEAT>_SOURCE=mcp`: the command to spawn as that seat's MCP server |
| `DENDRITE_MAGI_<SEAT>_MCP_ARGS` | *(empty)* | Optional, whitespace-split arguments to the command above (no quoting support — use a wrapper script for an argument that needs an embedded space) |
| `DENDRITE_MAGI_<SEAT>_MCP_TOOL` | `evaluate_action` | Optional: the MCP tool name to call on that server |

`dendrite-magi` refuses to start, on purpose, if a `_SOURCE` variable is set to anything other than `internal`/`mcp`, or if `mcp` is set without a matching `_MCP_COMMAND` — rather than silently falling back to the internal evaluator for that seat.

## MCP-backed seats

Connecting an external MCP-connected AI agent to a seat — letting a company hook up an AI that actually understands their own infrastructure to act as that seat's MAGI vote — is a per-seat configuration change: set `DENDRITE_MAGI_<SEAT>_SOURCE=mcp` plus the `_MCP_COMMAND`/`_MCP_ARGS`/`_MCP_TOOL` variables above. Per the confirmed design, an MCP-backed evaluator is a **full replacement** for that seat's internal evaluator, not an advisor running alongside it: the seat's vote comes entirely from the external agent.

The server is spawned as a local child process and talked to over stdio (via `rmcp`'s `TokioChildProcess` transport) — no network reachability or auth story is needed for a process `dendrite-magi` itself spawns and owns the lifetime of. Per evaluation, `dendrite-magi` calls the configured tool with `{"seat": "host"|"user"|"environment", "action": <action name>, "user_authorised": bool}` and expects back either structured tool content or JSON-in-text content shaped like `{"verdict": "approve"|"deny"|"abstain", "reason": "..."}` (`reason` is optional).

If the process won't spawn, the MCP handshake fails, the tool call errors, or the response can't be parsed, that seat resolves to **abstain** with a reason describing what went wrong — the same fail-closed philosophy as a wholly-unreachable `dendrite-magi` process: an unreachable evaluator must not manufacture an approval.

This is the MAGI-side half of Dendrite's MCP integration — `dendrite-magi` only ever acts as an MCP *client*, connecting out to a seat's external agent. A separate, inbound MCP *server* exposing Dendrite's own capabilities to external agents is a different, additive privileged surface, and lives in its own crate (`dendrite-mcp`, currently a stub) rather than here — see that crate's README and `docs/ROADMAP.md`'s MCP scope note for why the two are kept apart.

## Testing

```bash
cargo test -p dendrite-magi
cargo clippy -p dendrite-magi --all-targets -- -D warnings
```

See `docs/TESTS.md` for an end-to-end exercise (running `dendrite-magi` and `dendrited` as two real processes and confirming both the normal round-trip and the abstain-on-unreachable fallback).
