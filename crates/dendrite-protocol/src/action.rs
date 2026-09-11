use crate::{ActionProposalId, IncidentId, ObjectId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    Observe,
    Warn,
    RestrictProcess,
    SuspendProcess,
    TerminateProcess,
    QuarantineObject,
    BlockNetworkDestination,
    IsolateHost,
}

impl ActionType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Warn => "warn",
            Self::RestrictProcess => "restrict_process",
            Self::SuspendProcess => "suspend_process",
            Self::TerminateProcess => "terminate_process",
            Self::QuarantineObject => "quarantine_object",
            Self::BlockNetworkDestination => "block_network_destination",
            Self::IsolateHost => "isolate_host",
        }
    }

    pub fn is_safe_non_privileged(self) -> bool {
        matches!(self, Self::Observe | Self::Warn)
    }
}

impl std::str::FromStr for ActionType {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "observe" => Ok(Self::Observe),
            "warn" => Ok(Self::Warn),
            "restrict_process" => Ok(Self::RestrictProcess),
            "suspend_process" => Ok(Self::SuspendProcess),
            "terminate_process" => Ok(Self::TerminateProcess),
            "quarantine_object" => Ok(Self::QuarantineObject),
            "block_network_destination" => Ok(Self::BlockNetworkDestination),
            "isolate_host" => Ok(Self::IsolateHost),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionProposal {
    pub id: ActionProposalId,
    pub incident_id: IncidentId,
    pub action: ActionType,
    pub target: ObjectId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Evaluator {
    Host,
    User,
    Environment,
}

impl Evaluator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::User => "user",
            Self::Environment => "environment",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluatorVerdict {
    Approve,
    Deny,
    Abstain,
    Veto,
}

impl EvaluatorVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
            Self::Abstain => "abstain",
            Self::Veto => "veto",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evaluation {
    pub evaluator: Evaluator,
    pub verdict: EvaluatorVerdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuorumDecision {
    Approved,
    Denied,
    Blocked,
}

impl QuorumDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumPolicy {
    pub approvals_required: usize,
    pub deny_blocks: bool,
    pub veto_blocks: bool,
}

impl Default for QuorumPolicy {
    fn default() -> Self {
        Self {
            approvals_required: 2,
            deny_blocks: true,
            veto_blocks: true,
        }
    }
}

impl QuorumPolicy {
    pub fn evaluate(self, evaluations: &[Evaluation]) -> QuorumDecision {
        if self.veto_blocks
            && evaluations
                .iter()
                .any(|evaluation| evaluation.verdict == EvaluatorVerdict::Veto)
        {
            return QuorumDecision::Blocked;
        }

        if self.deny_blocks
            && evaluations
                .iter()
                .any(|evaluation| evaluation.verdict == EvaluatorVerdict::Deny)
        {
            return QuorumDecision::Denied;
        }

        let approvals = evaluations
            .iter()
            .filter(|evaluation| evaluation.verdict == EvaluatorVerdict::Approve)
            .count();

        if approvals >= self.approvals_required {
            QuorumDecision::Approved
        } else {
            QuorumDecision::Denied
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Deny,
}

impl PolicyDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionTransactionState {
    Proposal,
    Prepared,
    Revalidated,
    Committed,
    Verified,
    Failed,
}

impl ActionTransactionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposal => "proposal",
            Self::Prepared => "prepared",
            Self::Revalidated => "revalidated",
            Self::Committed => "committed",
            Self::Verified => "verified",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionExecutionStatus {
    NotAuthorised,
    Completed,
    Failed,
}

impl ActionExecutionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotAuthorised => "not_authorised",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionAuthorization {
    pub quorum: QuorumDecision,
    pub policy: PolicyDecision,
    pub guard: crate::GuardDecision,
}

impl ActionAuthorization {
    pub fn is_authorised(self) -> bool {
        self.quorum == QuorumDecision::Approved
            && self.policy == PolicyDecision::Allow
            && self.guard == crate::GuardDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GuardDecision;

    #[test]
    fn quorum_requires_configured_approvals() {
        let policy = QuorumPolicy::default();
        let evaluations = [
            Evaluation {
                evaluator: Evaluator::Host,
                verdict: EvaluatorVerdict::Approve,
            },
            Evaluation {
                evaluator: Evaluator::Environment,
                verdict: EvaluatorVerdict::Approve,
            },
        ];

        assert_eq!(policy.evaluate(&evaluations), QuorumDecision::Approved);
    }

    #[test]
    fn veto_blocks_quorum() {
        let policy = QuorumPolicy::default();
        let evaluations = [
            Evaluation {
                evaluator: Evaluator::Host,
                verdict: EvaluatorVerdict::Approve,
            },
            Evaluation {
                evaluator: Evaluator::User,
                verdict: EvaluatorVerdict::Veto,
            },
            Evaluation {
                evaluator: Evaluator::Environment,
                verdict: EvaluatorVerdict::Approve,
            },
        ];

        assert_eq!(policy.evaluate(&evaluations), QuorumDecision::Blocked);
    }

    #[test]
    fn authorization_requires_all_three_gates() {
        let authorization = ActionAuthorization {
            quorum: QuorumDecision::Approved,
            policy: PolicyDecision::Allow,
            guard: GuardDecision::Allow,
        };

        assert!(authorization.is_authorised());

        let denied = ActionAuthorization {
            guard: GuardDecision::Deny,
            ..authorization
        };

        assert!(!denied.is_authorised());
    }

    #[test]
    fn only_observe_and_warn_are_safe_non_privileged_actions() {
        assert!(ActionType::Observe.is_safe_non_privileged());
        assert!(ActionType::Warn.is_safe_non_privileged());
        assert!(!ActionType::TerminateProcess.is_safe_non_privileged());
    }
}
