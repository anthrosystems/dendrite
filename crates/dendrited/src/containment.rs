//! Stubbed containment interfaces.
//!
//! Two real gaps exist in Dendrite today, and this module keeps both visible
//! rather than papering over either:
//!
//! 1. **No action executor.** `dendrite_protocol::action::ActionType` (
//!    `TerminateProcess`, `SuspendProcess`, `RestrictProcess`,
//!    `QuarantineObject`, `BlockNetworkDestination`, `IsolateHost`,
//!    `UpdatePackage`) is a decision taxonomy only: the MAGI → policy →
//!    Guard → transaction pipeline can *approve* one of these, but nothing
//!    in the codebase calls `kill()`, moves a file into quarantine, or
//!    touches `iptables`/`nft`. Dendrite detects and decides; it does not
//!    yet act.
//! 2. **No execution sandbox.** Culture (`crate::culture`) can snapshot the
//!    active databases into an isolated campaign workspace, but nothing
//!    isolates the actual execution of anything found in that workspace —
//!    there is no VM, container, or namespace jail anywhere in this
//!    workspace.
//!
//! These are related but separate: a real Culture campaign that runs
//! untrusted samples needs (1) to already exist so it has something to call
//! when a stop-criterion trips. Both are modelled here as traits with a
//! logging-only default implementation, so callers have a real interface to
//! code against today and a single seam to fill in when the actual
//! enforcement/isolation work is scoped and built — rather than leaving
//! call sites with nothing to call at all, or quietly faking success.

use dendrite_protocol::ActionType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionOutcome {
    /// No executor is wired up yet; the action was neither performed nor
    /// denied — it simply has no implementation behind it. Callers must
    /// treat this the same as "did not happen", never as tacit approval.
    NotImplemented,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxRunOutcome {
    /// No sandbox is wired up yet; nothing was executed.
    NotImplemented,
}

#[derive(Debug)]
pub enum ContainmentError {
    Unsupported(String),
}

/// Performs the real, host-affecting side of an approved `ActionType` —
/// actually terminating a process, actually quarantining a file, actually
/// blocking a network destination. See the module doc comment: this does
/// not exist as a real capability anywhere in Dendrite today.
pub trait ActionExecutor: Send + Sync {
    fn execute(
        &self,
        action_type: ActionType,
        target_summary: &str,
        now: u64,
    ) -> Result<ExecutionOutcome, ContainmentError>;
}

/// Logs the request and reports `NotImplemented` rather than silently
/// succeeding or panicking. This is the default `ActionExecutor` until a
/// real one (calling `kill()`, moving a file, applying an nftables rule,
/// etc.) is built and wired in.
pub struct NoopActionExecutor;

impl ActionExecutor for NoopActionExecutor {
    fn execute(
        &self,
        action_type: ActionType,
        target_summary: &str,
        now: u64,
    ) -> Result<ExecutionOutcome, ContainmentError> {
        eprintln!(
            "containment: NoopActionExecutor received {} against {target_summary} at {now} — \
             no real executor is configured, so nothing happened on the host",
            action_type.as_str(),
        );
        Ok(ExecutionOutcome::NotImplemented)
    }
}

/// Isolates and runs whatever a Culture campaign needs to execute (a
/// sample, a script, anything captured into the campaign workspace). See
/// the module doc comment: no such isolation (VM, container, or namespace
/// jail) exists in this codebase yet.
pub trait CampaignSandbox: Send + Sync {
    fn run(
        &self,
        campaign_id: &str,
        artifact_path: &str,
        now: u64,
    ) -> Result<SandboxRunOutcome, ContainmentError>;
}

/// Logs the request and reports `NotImplemented` rather than actually
/// running anything. This is the default `CampaignSandbox` until a real
/// isolation mechanism is chosen and built.
pub struct NoopCampaignSandbox;

impl CampaignSandbox for NoopCampaignSandbox {
    fn run(
        &self,
        campaign_id: &str,
        artifact_path: &str,
        now: u64,
    ) -> Result<SandboxRunOutcome, ContainmentError> {
        eprintln!(
            "containment: NoopCampaignSandbox asked to run {artifact_path} for campaign \
             {campaign_id} at {now} — no real sandbox is configured, so nothing was executed",
        );
        Ok(SandboxRunOutcome::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_action_executor_reports_not_implemented_rather_than_success() {
        let executor = NoopActionExecutor;
        let outcome = executor
            .execute(ActionType::TerminateProcess, "process:1234", 10)
            .unwrap();
        assert_eq!(outcome, ExecutionOutcome::NotImplemented);
    }

    #[test]
    fn noop_campaign_sandbox_reports_not_implemented_rather_than_success() {
        let sandbox = NoopCampaignSandbox;
        let outcome = sandbox.run("ama-test", "/tmp/sample.bin", 10).unwrap();
        assert_eq!(outcome, SandboxRunOutcome::NotImplemented);
    }
}
