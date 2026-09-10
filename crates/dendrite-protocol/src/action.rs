use crate::{ActionProposalId, IncidentId, ObjectId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionProposal {
    pub id: ActionProposalId,
    pub incident_id: IncidentId,
    pub action: ActionType,
    pub target: ObjectId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evaluator {
    Host,
    User,
    Environment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluatorVerdict {
    Approve,
    Deny,
    Abstain,
    Veto,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub evaluator: Evaluator,
    pub verdict: EvaluatorVerdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuorumDecision {
    Approved,
    Denied,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionTransactionState {
    Proposal,
    Prepared,
    Revalidated,
    Committed,
    Verified,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionExecutionStatus {
    NotAuthorised,
    Completed,
    Failed,
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
}
