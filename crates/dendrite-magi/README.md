# dendrite-magi

The MAGI quorum-evaluation process: it decides whether an action proposal gets the Host/User/Environment votes it needs before `dendrited` will execute it. It exists as its own binary/systemd unit (`dendrite-magi.service`), reached only over a Unix socket, for the same reason `dendrite-guard` is planned to become one — see `docs/ROADMAP.md`'s Batch 7 process-separation notes: action authority (here, the quorum vote itself) shouldn't be reachable in-process from wherever a compromise of the main daemon might land. "Compromise can remove authority, but cannot create authority" only really holds if compromising `dendrited` can't reach the thing that grants authority directly.

`dendrited` never links this crate's evaluation logic in production; it talks to a running `dendrite-magi` process only over the socket protocol in `dendrite_protocol::magi_ipc` (newline-delimited JSON, one request per connection — the same convention as the existing CLI IPC protocol, kept as its own separate request/response pair since this is a distinct process boundary with its own fail-closed semantics, not just another CLI command). `dendrited`'s own test suite depends on this crate as a dev-dependency purely to keep one rule-based reference implementation instead of duplicating the same logic twice — that does not create an in-process link in the shipped binary.

## Fail-closed behaviour

If `dendrite-magi` is unreachable, times out, or isn't running, `dendrited`'s client (`MagiIpcClient`, in `crates/dendrited/src/actions.rs`) reports every seat as **abstain**, not deny/veto and not a hang. Under the default quorum policy (2 approvals required, an abstain counting toward neither approval nor denial) this means an action can never complete while `dendrite-magi` is down — denied, not silently allowed, and not stuck waiting either. See `docs/ROADMAP.md`'s "Fail-closed behaviour, and why ABSTAIN rather than DENY/VETO" note for the full reasoning (short version: abstain is the one verdict that can never itself manufacture approval, and it doesn't conflate an evaluator's real reasoned denial with the evaluator simply not being reachable, which matters once a seat's answer can legitimately be slow — see the MCP note below).

## Configuration

| Variable | Default | Description |
|---|---|---|
| `DENDRITE_MAGI_SOCKET` | `/tmp/dendrite-magi.sock` | Unix socket path this process listens on |
| `DENDRITE_MAGI_HOST_SOURCE` | `internal` | Which evaluator backs the Host seat |
| `DENDRITE_MAGI_USER_SOURCE` | `internal` | Which evaluator backs the User seat |
| `DENDRITE_MAGI_ENVIRONMENT_SOURCE` | `internal` | Which evaluator backs the Environment seat |

`internal` (the built-in rule-based evaluator, the only thing implemented today) is the only value these three `_SOURCE` variables currently accept — `dendrite-magi` refuses to start, on purpose, if any of them is set to anything else, rather than silently falling back to the internal evaluator for that seat.

## MCP-backed seats: designed for, not built

The `_SOURCE` variables and the `SeatSource` enum they're read into exist now so that connecting an external MCP-connected AI agent to a seat — letting a company hook up an AI that actually understands their own infrastructure to act as that seat's MAGI vote — is a configuration change later, not a code change today. Per the confirmed design, an MCP-backed evaluator is meant to be a **full replacement** for a seat's internal evaluator, not an advisor running alongside it: the seat's vote would come entirely from the external agent. None of the actual MCP client/server plumbing exists yet. `SeatSource::Unimplemented` is a real, deliberate placeholder, not a stub pretending to work — it fails loudly at startup rather than quietly doing the wrong thing.

## Testing

```bash
cargo test -p dendrite-magi
cargo clippy -p dendrite-magi --all-targets -- -D warnings
```

See `docs/TESTS.md` for an end-to-end exercise (running `dendrite-magi` and `dendrited` as two real processes and confirming both the normal round-trip and the abstain-on-unreachable fallback).
