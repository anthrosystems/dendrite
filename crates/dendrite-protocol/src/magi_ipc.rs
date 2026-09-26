//! Wire protocol between `dendrited` and the separate `dendrite-magi`
//! process. One JSON request per line over a Unix socket, one JSON
//! response back — the same convention as the CLI's `IpcRequest`/
//! `IpcResponse` in `ipc.rs`, kept as its own enum pair rather than folded
//! into that one because this is a distinct process boundary with its own
//! fail-closed semantics (see `MagiResponse::Error` and `dendrited`'s
//! caller, which treats an unreachable/erroring `dendrite-magi` as every
//! seat abstaining, never as an approval).

use crate::{ActionType, Evaluator, EvaluatorVerdict};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum MagiRequest {
    Evaluate {
        action: ActionType,
        user_authorised: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MagiEvaluation {
    pub evaluator: Evaluator,
    pub verdict: EvaluatorVerdict,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum MagiResponse {
    Evaluations { evaluations: Vec<MagiEvaluation> },
    Error { message: String },
}
