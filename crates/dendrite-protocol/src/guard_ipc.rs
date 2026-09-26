//! Wire protocol between `dendrited` and the separate `dendrite-guard`
//! process. One JSON request per line over a Unix socket, one JSON response
//! back — the same convention as `magi_ipc.rs` and the CLI's `IpcRequest`/
//! `IpcResponse` in `ipc.rs`, kept as its own enum pair for the same reason:
//! this is a distinct process boundary with its own fail-closed semantics.
//!
//! Unlike MAGI (a stateless per-request vote), Guard owns real persistent
//! state — the trust state and integrity findings live in `dendrite-guard`'s
//! own database, not `dendrited`'s — so this protocol also carries the
//! read/write operations `dendrited`'s CLI-facing `guard status`/`guard
//! findings` commands and the debug-only `debug guard-state`/`guard-finding`
//! commands need, not just the authority check on the action-evaluation
//! path.

use crate::{ActionProposal, GuardDecision, GuardStatusDto, IntegrityFindingDto, TrustState};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum GuardRequest {
    EvaluateAuthority {
        proposal: ActionProposal,
    },
    TrustState,
    Status,
    Findings,
    /// Development-only, mirrors `dendrite-cli debug guard-state`.
    /// `dendrite-guard` refuses this request in a release build (see
    /// `crates/dendrite-guard/README.md`) — it is not gated on the wire,
    /// only on the server, so the error is a real, honest rejection rather
    /// than the request silently vanishing.
    DebugSetState {
        state: String,
    },
    /// Development-only, mirrors `dendrite-cli debug guard-finding`. Same
    /// release-build rejection as `DebugSetState`.
    DebugRecordFinding {
        target: String,
        severity: String,
        description: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum GuardResponse {
    Authority { decision: GuardDecision },
    TrustState { trust_state: TrustState },
    Info { guard_status: GuardStatusDto },
    Findings { findings: Vec<IntegrityFindingDto> },
    Ack,
    Error { message: String },
}
