# dendrite-guard

Dendrite's trust, integrity and recovery boundary — the single voice that decides whether `dendrited` currently has authority to act at all.

```text
TRUSTED -> DEGRADED -> SUSPECTED -> QUARANTINED -> COMPROMISED -> RECOVERING
```

Action authority is only granted while Guard considers the system trusted. A degraded or compromised state must never increase privileges — it fails closed by design.

> Compromise can remove authority, but cannot create authority.

It exists as its own binary and systemd unit (`dendrite-guard.service`), reached only over a Unix socket, for exactly that reason (see `docs/architecture.md`'s "Why `dendrite-magi` keeps its own systemd unit" note, and the MAGI split this one followed): Guard's whole job *is* deciding whether `dendrited` still has authority, so that decision needs to live somewhere a compromise of `dendrited` itself cannot reach.

`dendrited` never links this crate's `Guard`/`GuardStore` logic in production; it talks to a running `dendrite-guard` process only over the socket protocol in `dendrite_protocol::guard_ipc` (newline-delimited JSON, one request per connection — the same convention as `dendrite-magi` and the CLI's own IPC protocol). Unlike MAGI (a stateless per-request vote), Guard owns real persistent state: the trust state and integrity findings live in `dendrite-guard`'s own `guard.sqlite3`, not `dendrited`'s.

## Fail-closed behaviour

If `dendrite-guard` is unreachable, times out, or isn't running, `dendrited`'s client (`GuardIpcClient`, in `crates/dendrited/src/guard.rs`) reports the trust state as **`Compromised`** and every authority check as **`Deny`** — not a hang, and not `Trusted`. This intentionally differs from MAGI's abstain-on-unreachable choice: MAGI is a three-way vote where silence from one seat shouldn't drown out the other two, but Guard has exactly one voice on trust, so there's no quorum for "unreachable" to defer to. Collapsing straight to the same denial a real detected compromise produces is the only fail-closed answer available here.

`status()` and `findings()` behave differently again: they stay genuinely fallible rather than fabricating a result, because they feed `antiserum_attestation` (see `crates/dendrited/src/core.rs`), which signs and can export what it's given. A made-up "unreachable"-flavoured status or an empty findings list could end up misrepresenting host integrity in a signed, exported package — so an unreachable `dendrite-guard` fails the request instead.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `DENDRITE_GUARD_DB` | `data/guard.sqlite3` | `dendrite-guard`'s own trust-state/integrity-findings database |
| `DENDRITE_GUARD_SOCKET` | `/tmp/dendrite-guard.sock` | Unix socket path this process listens on, and `dendrited` connects to |

## Development-only surfaces

`dendrite-cli debug guard-state`/`debug guard-finding` reach `dendrite-guard` over the same socket (`GuardRequest::DebugSetState`/`DebugRecordFinding`). `dendrite-guard` refuses both outright — a real, honest rejection, not a silent no-op — in a release build (`#[cfg(not(debug_assertions))]`), matching `dendrited`'s own existing debug-command gating. A packaged `dendrite-guard` should never let anything but its own real integrity checks move trust state.

## Testing

```bash
cargo test -p dendrite-guard
cargo clippy -p dendrite-guard --all-targets -- -D warnings
```

See `docs/TESTS.md` for an end-to-end exercise (running `dendrite-guard` and `dendrited` as two real processes, changing trust state through the CLI, and confirming both the normal round-trip and the deny-on-unreachable fallback).
