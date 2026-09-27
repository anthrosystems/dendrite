//! MAGI evaluation logic, split out of `dendrited` into its own process
//! (`dendrite-magi`) for the same reason `dendrite-guard` became one —
//! action authority (here, the quorum vote itself) shouldn't be reachable
//! in-process from wherever a compromise of the main daemon might land.
//! See `docs/ROADMAP.md`'s MAGI/MCP process-separation notes.
//!
//! `dendrited` never links this crate in production; it talks to a running
//! `dendrite-magi` process only over the Unix-socket protocol in
//! `dendrite_protocol::magi_ipc`.

use dendrite_protocol::{ActionType, Evaluation, Evaluator, EvaluatorVerdict};
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use rmcp::transport::TokioChildProcess;

/// Where a single seat's vote comes from: the built-in rule-based engine,
/// or an external MCP-connected agent that fully replaces this seat's
/// internal evaluator (not an advisor alongside it — see the confirmed
/// design decision in `docs/ROADMAP.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeatSource {
    Internal,
    Mcp(McpSeatConfig),
}

/// How to reach an MCP-backed seat's server: spawned as a local child
/// process, talked to over stdio (the same transport most MCP clients use
/// for a locally-installed server) rather than a network endpoint — no
/// network reachability or auth story is needed for a process `dendrite-magi`
/// itself spawns and owns the lifetime of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpSeatConfig {
    pub command: String,
    pub args: Vec<String>,
    pub tool: String,
}

/// Every seat resolved for this `dendrite-magi` instance, read once at
/// startup so a misconfiguration is a clear, immediate failure to start
/// rather than a silently-ignored setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatSources {
    pub host: SeatSource,
    pub user: SeatSource,
    pub environment: SeatSource,
}

const DEFAULT_MCP_TOOL: &str = "evaluate_action";

impl SeatSources {
    /// Reads `DENDRITE_MAGI_<SEAT>_SOURCE` (`internal`, the default, or
    /// `mcp`) for each of the three seats, plus, for any seat configured as
    /// `mcp`, `DENDRITE_MAGI_<SEAT>_MCP_COMMAND` (required),
    /// `DENDRITE_MAGI_<SEAT>_MCP_ARGS` (optional, whitespace-split — no
    /// quoting support; use a wrapper script if an argument needs an
    /// embedded space) and `DENDRITE_MAGI_<SEAT>_MCP_TOOL` (optional,
    /// defaults to `"evaluate_action"`).
    pub fn from_env() -> Result<Self, String> {
        Ok(Self {
            host: seat_source_from_env("HOST", "host")?,
            user: seat_source_from_env("USER", "user")?,
            environment: seat_source_from_env("ENVIRONMENT", "environment")?,
        })
    }
}

fn seat_source_from_env(env_prefix: &str, seat_name: &str) -> Result<SeatSource, String> {
    let source_var = format!("DENDRITE_MAGI_{env_prefix}_SOURCE");
    let source_value = std::env::var(&source_var).unwrap_or_else(|_| "internal".into());

    if source_value.eq_ignore_ascii_case("internal") {
        return Ok(SeatSource::Internal);
    }
    if !source_value.eq_ignore_ascii_case("mcp") {
        return Err(format!(
            "{source_var} requested '{source_value}', but only 'internal' or 'mcp' is \
             recognised; refusing to start with an unmet configuration rather than silently \
             falling back to the internal evaluator for the {seat_name} seat"
        ));
    }

    let command_var = format!("DENDRITE_MAGI_{env_prefix}_MCP_COMMAND");
    let command = std::env::var(&command_var).map_err(|_| {
        format!(
            "{source_var}=mcp for the {seat_name} seat, but {command_var} is not set — an \
             MCP-backed seat needs a command to spawn as its MCP server"
        )
    })?;

    let args = std::env::var(format!("DENDRITE_MAGI_{env_prefix}_MCP_ARGS"))
        .ok()
        .map(|value| {
            value
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let tool = std::env::var(format!("DENDRITE_MAGI_{env_prefix}_MCP_TOOL"))
        .unwrap_or_else(|_| DEFAULT_MCP_TOOL.into());

    Ok(SeatSource::Mcp(McpSeatConfig {
        command,
        args,
        tool,
    }))
}

fn evaluate_host_internal(
    action: ActionType,
    _user_authorised: bool,
) -> (EvaluatorVerdict, String) {
    let safe = action.is_safe_non_privileged();
    let package_update = action == ActionType::UpdatePackage;
    let verdict = if safe || package_update {
        EvaluatorVerdict::Approve
    } else {
        EvaluatorVerdict::Abstain
    };
    let reason = if safe {
        "BALTHASAR-2: Action is non-privileged and does not mutate protected host state"
    } else if package_update {
        "BALTHASAR-2: Native package update is scoped to a verified vulnerability exposure"
    } else {
        "BALTHASAR-2: Privileged host mutation has no specialised executor policy"
    };
    (verdict, reason.into())
}

fn evaluate_user_internal(action: ActionType, user_authorised: bool) -> (EvaluatorVerdict, String) {
    let package_update = action == ActionType::UpdatePackage;
    let verdict = if package_update && user_authorised {
        EvaluatorVerdict::Approve
    } else if package_update {
        EvaluatorVerdict::Deny
    } else {
        EvaluatorVerdict::Abstain
    };
    let reason = if package_update && user_authorised {
        "CASPER-3: Operator explicitly authorised this package update through Dendrite"
    } else if package_update {
        "CASPER-3: Package mutation requires explicit operator authority"
    } else {
        "CASPER-3: No interactive user authority applies to this action"
    };
    (verdict, reason.into())
}

fn evaluate_environment_internal(
    action: ActionType,
    _user_authorised: bool,
) -> (EvaluatorVerdict, String) {
    let safe = action.is_safe_non_privileged();
    let package_update = action == ActionType::UpdatePackage;
    let verdict = if safe || package_update {
        EvaluatorVerdict::Approve
    } else {
        EvaluatorVerdict::Abstain
    };
    let reason = if safe {
        "MELCHIOR-1: Action is safe for the current environment"
    } else if package_update {
        "MELCHIOR-1: Remediation uses the native APT/dpkg package state and revalidation path"
    } else {
        "MELCHIOR-1: No environment-specific privileged executor is enabled"
    };
    (verdict, reason.into())
}

/// All three seats' internal-evaluator verdicts, computed together. Kept as
/// a convenience for callers that only ever use the internal evaluator
/// (e.g. deterministic test fixtures) — real seat dispatch (honouring a
/// per-seat `SeatSource`) goes through [`evaluate_seat`].
pub fn evaluate(action: ActionType, user_authorised: bool) -> Vec<(Evaluation, String)> {
    let (host_verdict, host_reason) = evaluate_host_internal(action, user_authorised);
    let (user_verdict, user_reason) = evaluate_user_internal(action, user_authorised);
    let (env_verdict, env_reason) = evaluate_environment_internal(action, user_authorised);
    vec![
        (
            Evaluation {
                evaluator: Evaluator::Host,
                verdict: host_verdict,
            },
            host_reason,
        ),
        (
            Evaluation {
                evaluator: Evaluator::User,
                verdict: user_verdict,
            },
            user_reason,
        ),
        (
            Evaluation {
                evaluator: Evaluator::Environment,
                verdict: env_verdict,
            },
            env_reason,
        ),
    ]
}

/// Resolves one seat's vote according to its configured [`SeatSource`] —
/// the internal rule-based engine, or a full replacement by an external
/// MCP-connected agent.
///
/// An MCP-backed seat that fails (the process won't spawn, the handshake
/// fails, the tool call errors, or the response can't be parsed) resolves
/// to `Abstain` with a reason naming what went wrong, the same fail-closed
/// philosophy already applied when the whole `dendrite-magi` process is
/// unreachable from `dendrited`'s side: an unreachable evaluator must not
/// manufacture an approval, and must not silently collapse into a harder
/// verdict than the evaluator itself ever actually gave.
pub async fn evaluate_seat(
    seat: Evaluator,
    source: &SeatSource,
    action: ActionType,
    user_authorised: bool,
) -> (EvaluatorVerdict, String) {
    match source {
        SeatSource::Internal => match seat {
            Evaluator::Host => evaluate_host_internal(action, user_authorised),
            Evaluator::User => evaluate_user_internal(action, user_authorised),
            Evaluator::Environment => evaluate_environment_internal(action, user_authorised),
        },
        SeatSource::Mcp(config) => {
            match evaluate_via_mcp(seat, config, action, user_authorised).await {
                Ok(result) => result,
                Err(message) => (
                    EvaluatorVerdict::Abstain,
                    format!("{} MCP seat abstaining: {message}", seat.as_str()),
                ),
            }
        }
    }
}

async fn evaluate_via_mcp(
    seat: Evaluator,
    config: &McpSeatConfig,
    action: ActionType,
    user_authorised: bool,
) -> Result<(EvaluatorVerdict, String), String> {
    let mut command = tokio::process::Command::new(&config.command);
    command.args(&config.args);

    let transport = TokioChildProcess::new(command)
        .map_err(|error| format!("failed to spawn '{}': {error}", config.command))?;

    let client = ()
        .serve(transport)
        .await
        .map_err(|error| format!("MCP handshake with '{}' failed: {error}", config.command))?;

    let arguments = serde_json::json!({
        "seat": seat.as_str(),
        "action": action.as_str(),
        "user_authorised": user_authorised,
    });
    let arguments = arguments
        .as_object()
        .cloned()
        .expect("object literal always serialises to a JSON object");

    let call_result = client
        .call_tool(CallToolRequestParams::new(config.tool.clone()).with_arguments(arguments))
        .await
        .map_err(|error| format!("tool '{}' call failed: {error}", config.tool));

    // Best-effort: a failure to cleanly shut down the child process/session
    // doesn't change whether the tool call itself succeeded.
    let _ = client.cancel().await;

    let result = call_result?;

    if result.is_error.unwrap_or(false) {
        return Err(format!("tool '{}' reported an error result", config.tool));
    }

    let value = result.structured_content.clone().or_else(|| {
        result.content.iter().find_map(|block| match block {
            rmcp::model::ContentBlock::Text(text) => {
                serde_json::from_str::<serde_json::Value>(&text.text).ok()
            }
            _ => None,
        })
    });
    let Some(value) = value else {
        return Err(format!(
            "tool '{}' returned no structured or JSON-text content",
            config.tool
        ));
    };

    let verdict_value = value
        .get("verdict")
        .cloned()
        .ok_or_else(|| "response missing 'verdict' field".to_string())?;
    let verdict: EvaluatorVerdict = serde_json::from_value(verdict_value)
        .map_err(|error| format!("invalid 'verdict' field: {error}"))?;
    let reason = value
        .get("reason")
        .and_then(|reason| reason.as_str())
        .unwrap_or("(MCP evaluator gave no reason)")
        .to_string();

    Ok((verdict, reason))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clear_seat_env(prefix: &str) {
        for suffix in ["SOURCE", "MCP_COMMAND", "MCP_ARGS", "MCP_TOOL"] {
            // SAFETY: these tests run with `--test-threads=1` semantics for
            // this module in spirit (each test clears only its own seat's
            // vars and restores them before returning), and `std::env` var
            // mutation is inherently process-global; see the guard in each
            // test below.
            unsafe { std::env::remove_var(format!("DENDRITE_MAGI_{prefix}_{suffix}")) };
        }
    }

    // These tests mutate process-wide environment variables, so they must
    // not run concurrently with each other (or with anything else that
    // reads `DENDRITE_MAGI_*`). A single lock, held for the duration of
    // each test, keeps them serialised regardless of the test harness's
    // thread pool.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn seat_source_defaults_to_internal_when_unset() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_seat_env("HOST");
        assert_eq!(
            seat_source_from_env("HOST", "host").unwrap(),
            SeatSource::Internal
        );
    }

    #[test]
    fn seat_source_rejects_unrecognised_value() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_seat_env("HOST");
        unsafe { std::env::set_var("DENDRITE_MAGI_HOST_SOURCE", "nonsense") };
        let error = seat_source_from_env("HOST", "host").unwrap_err();
        assert!(error.contains("only 'internal' or 'mcp' is recognised"));
        clear_seat_env("HOST");
    }

    #[test]
    fn seat_source_mcp_requires_command() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_seat_env("HOST");
        unsafe { std::env::set_var("DENDRITE_MAGI_HOST_SOURCE", "mcp") };
        let error = seat_source_from_env("HOST", "host").unwrap_err();
        assert!(error.contains("MCP_COMMAND is not set"));
        clear_seat_env("HOST");
    }

    #[test]
    fn seat_source_mcp_reads_full_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_seat_env("HOST");
        unsafe {
            std::env::set_var("DENDRITE_MAGI_HOST_SOURCE", "MCP");
            std::env::set_var("DENDRITE_MAGI_HOST_MCP_COMMAND", "/usr/bin/example-agent");
            std::env::set_var("DENDRITE_MAGI_HOST_MCP_ARGS", "--stdio  --verbose");
            std::env::set_var("DENDRITE_MAGI_HOST_MCP_TOOL", "custom_tool");
        }
        let source = seat_source_from_env("HOST", "host").unwrap();
        assert_eq!(
            source,
            SeatSource::Mcp(McpSeatConfig {
                command: "/usr/bin/example-agent".into(),
                args: vec!["--stdio".into(), "--verbose".into()],
                tool: "custom_tool".into(),
            })
        );
        clear_seat_env("HOST");
    }

    #[test]
    fn seat_source_mcp_defaults_tool_and_args() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_seat_env("HOST");
        unsafe {
            std::env::set_var("DENDRITE_MAGI_HOST_SOURCE", "mcp");
            std::env::set_var("DENDRITE_MAGI_HOST_MCP_COMMAND", "/usr/bin/example-agent");
        }
        let source = seat_source_from_env("HOST", "host").unwrap();
        assert_eq!(
            source,
            SeatSource::Mcp(McpSeatConfig {
                command: "/usr/bin/example-agent".into(),
                args: vec![],
                tool: DEFAULT_MCP_TOOL.into(),
            })
        );
        clear_seat_env("HOST");
    }

    #[test]
    fn evaluate_matches_internal_evaluators_for_a_safe_action() {
        let evaluations = evaluate(ActionType::Observe, false);
        assert_eq!(evaluations.len(), 3);
        for (evaluation, _reason) in &evaluations {
            // A safe, non-privileged action is approved by the Host and
            // Environment seats regardless of user authority, but the User
            // seat (CASPER-3) only ever has an opinion on package updates —
            // for anything else it abstains rather than manufacturing a
            // verdict about authority that was never asked about.
            let expected = if evaluation.evaluator == Evaluator::User {
                EvaluatorVerdict::Abstain
            } else {
                EvaluatorVerdict::Approve
            };
            assert_eq!(
                evaluation.verdict, expected,
                "seat: {:?}",
                evaluation.evaluator
            );
        }
    }

    #[test]
    fn evaluate_seat_internal_dispatches_to_the_matching_evaluator() {
        let futures_executed = futures_lite_block_on(async {
            evaluate_seat(
                Evaluator::User,
                &SeatSource::Internal,
                ActionType::UpdatePackage,
                true,
            )
            .await
        });
        assert_eq!(futures_executed.0, EvaluatorVerdict::Approve);
        assert!(futures_executed.1.contains("CASPER-3"));
    }

    #[test]
    fn evaluate_seat_mcp_abstains_when_the_command_cannot_spawn() {
        let config = McpSeatConfig {
            command: "/nonexistent/dendrite-mcp-test-agent-does-not-exist".into(),
            args: vec![],
            tool: DEFAULT_MCP_TOOL.into(),
        };
        let (verdict, reason) = futures_lite_block_on(async {
            evaluate_seat(
                Evaluator::Host,
                &SeatSource::Mcp(config),
                ActionType::UpdatePackage,
                true,
            )
            .await
        });
        assert_eq!(verdict, EvaluatorVerdict::Abstain);
        assert!(reason.contains("abstaining"), "reason was: {reason}");
    }

    /// A minimal single-threaded async block-on, avoiding the need to pull
    /// in `tokio`'s own test macros (or a full runtime) just for these unit
    /// tests — the async functions under test never actually need a
    /// multi-thread runtime or IO driver except in the MCP-spawn path, which
    /// `tokio::process::Command`/`TokioChildProcess` register with whatever
    /// runtime is current, so a real (if minimal) `tokio` runtime is what we
    /// build here rather than a hand-rolled executor.
    fn futures_lite_block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("building a current-thread runtime for a unit test")
            .block_on(future)
    }
}
