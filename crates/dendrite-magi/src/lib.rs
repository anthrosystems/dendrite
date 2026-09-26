//! MAGI evaluation logic, split out of `dendrited` into its own process
//! (`dendrite-magi`) for the same reason `dendrite-guard` is planned to
//! become one — action authority (here, the quorum vote itself) shouldn't
//! be reachable in-process from wherever a compromise of the main daemon
//! might land. See `docs/ROADMAP.md`'s MAGI/MCP process-separation notes.
//!
//! `dendrited` never links this crate in production; it talks to a running
//! `dendrite-magi` process only over the Unix-socket protocol in
//! `dendrite_protocol::magi_ipc`. `dendrited`'s own test suite depends on
//! this crate (dev-only) purely to keep one rule-based reference
//! implementation instead of duplicating it — that does not create an
//! in-process link in the shipped binary.

use dendrite_protocol::{ActionType, Evaluation, Evaluator, EvaluatorVerdict};

/// Which seats are backed by today: the built-in rule-based engine. A seat
/// backed by an external MCP-connected agent (see `docs/ROADMAP.md`) is a
/// real, separate piece of work — not yet implemented — so `SeatSource`
/// exists now only to make that a configuration decision later, not a code
/// change, and to fail loudly rather than silently if selected before it's
/// built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeatSource {
    Internal,
    /// Reserved for the MCP-backed evaluator. Carries the raw configured
    /// value so a clear error can name what was asked for.
    Unimplemented(String),
}

impl SeatSource {
    pub fn from_env_value(value: &str) -> Self {
        if value.eq_ignore_ascii_case("internal") {
            Self::Internal
        } else {
            Self::Unimplemented(value.to_owned())
        }
    }
}

/// One seat's evaluation, plus the reasoning string `dendrited` stores
/// alongside the verdict (`action_evaluations.reason`).
pub fn evaluate(action: ActionType, user_authorised: bool) -> Vec<(Evaluation, String)> {
    let safe = action.is_safe_non_privileged();
    let package_update = action == ActionType::UpdatePackage;

    vec![
        (
            Evaluation {
                evaluator: Evaluator::Host,
                verdict: if safe || package_update {
                    EvaluatorVerdict::Approve
                } else {
                    EvaluatorVerdict::Abstain
                },
            },
            if safe {
                "BALTHASAR-2: Action is non-privileged and does not mutate protected host state"
            } else if package_update {
                "BALTHASAR-2: Native package update is scoped to a verified vulnerability exposure"
            } else {
                "BALTHASAR-2: Privileged host mutation has no specialised executor policy"
            }
            .into(),
        ),
        (
            Evaluation {
                evaluator: Evaluator::User,
                verdict: if package_update && user_authorised {
                    EvaluatorVerdict::Approve
                } else if package_update {
                    EvaluatorVerdict::Deny
                } else {
                    EvaluatorVerdict::Abstain
                },
            },
            if package_update && user_authorised {
                "CASPER-3: Operator explicitly authorised this package update through Dendrite"
            } else if package_update {
                "CASPER-3: Package mutation requires explicit operator authority"
            } else {
                "CASPER-3: No interactive user authority applies to this action"
            }
            .into(),
        ),
        (
            Evaluation {
                evaluator: Evaluator::Environment,
                verdict: if safe || package_update {
                    EvaluatorVerdict::Approve
                } else {
                    EvaluatorVerdict::Abstain
                },
            },
            if safe {
                "MELCHIOR-1: Action is safe for the current environment"
            } else if package_update {
                "MELCHIOR-1: Remediation uses the native APT/dpkg package state and revalidation path"
            } else {
                "MELCHIOR-1: No environment-specific privileged executor is enabled"
            }
            .into(),
        ),
    ]
}

/// Reads `DENDRITE_MAGI_<SEAT>_SOURCE` for the three seats and returns an
/// error naming any seat that asked for something other than `internal` —
/// called once at startup so a misconfiguration is a clear, immediate
/// failure to start rather than a silently-ignored setting.
pub fn read_seat_sources_from_env() -> Result<(), String> {
    for (env_var, seat_name) in [
        ("DENDRITE_MAGI_HOST_SOURCE", "host"),
        ("DENDRITE_MAGI_USER_SOURCE", "user"),
        ("DENDRITE_MAGI_ENVIRONMENT_SOURCE", "environment"),
    ] {
        if let Ok(value) = std::env::var(env_var)
            && let SeatSource::Unimplemented(requested) = SeatSource::from_env_value(&value)
        {
            return Err(format!(
                "{env_var} requested '{requested}', but only 'internal' is implemented today \
                 (MCP-backed MAGI seats are planned, not yet built — see docs/ROADMAP.md); \
                 refusing to start with an unmet configuration rather than silently falling \
                 back to the internal evaluator for the {seat_name} seat"
            ));
        }
    }
    Ok(())
}
