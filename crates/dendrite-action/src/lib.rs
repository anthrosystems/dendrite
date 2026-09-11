//! Privileged and non-privileged action coordination.
//!
//! Batch 3 only executes the explicitly non-privileged `Observe` and `Warn` actions.
//! Privileged actions continue to require the full guard-gated authorisation path.

use dendrite_protocol::{
    ActionAuthorization, ActionExecutionStatus, ActionProposal, ActionTransactionState,
    PolicyDecision, QuorumDecision,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionReport {
    pub state: ActionTransactionState,
    pub status: ActionExecutionStatus,
    pub message: Option<String>,
    pub transitions: Vec<ActionTransactionState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutorError {
    Prepare(String),
    Revalidate(String),
    Commit(String),
    Verify(String),
}

pub trait ActionExecutor {
    type Prepared;

    fn prepare(&mut self, proposal: &ActionProposal) -> Result<Self::Prepared, ExecutorError>;

    fn revalidate(
        &mut self,
        proposal: &ActionProposal,
        prepared: &Self::Prepared,
    ) -> Result<(), ExecutorError>;

    fn commit(
        &mut self,
        proposal: &ActionProposal,
        prepared: &Self::Prepared,
    ) -> Result<(), ExecutorError>;

    fn verify(
        &mut self,
        proposal: &ActionProposal,
        prepared: &Self::Prepared,
    ) -> Result<(), ExecutorError>;
}

pub struct ActionCoordinator<E> {
    executor: E,
}

impl<E> ActionCoordinator<E>
where
    E: ActionExecutor,
{
    pub fn new(executor: E) -> Self {
        Self { executor }
    }

    pub fn execute(
        &mut self,
        proposal: &ActionProposal,
        authorization: ActionAuthorization,
    ) -> TransactionReport {
        if !authorization.is_authorised() {
            return not_authorised("action proposal did not pass every authorisation gate");
        }

        execute_transaction(&mut self.executor, proposal)
    }

    pub fn execute_safe(
        &mut self,
        proposal: &ActionProposal,
        quorum: QuorumDecision,
        policy: PolicyDecision,
    ) -> TransactionReport {
        if !proposal.action.is_safe_non_privileged() {
            return not_authorised("privileged actions require dendrite-guard integration");
        }

        if quorum != QuorumDecision::Approved || policy != PolicyDecision::Allow {
            return not_authorised("safe action did not pass MAGI quorum and policy");
        }

        execute_transaction(&mut self.executor, proposal)
    }
}

fn execute_transaction<E: ActionExecutor>(
    executor: &mut E,
    proposal: &ActionProposal,
) -> TransactionReport {
    let mut transitions = vec![ActionTransactionState::Proposal];

    let prepared = match executor.prepare(proposal) {
        Ok(prepared) => {
            transitions.push(ActionTransactionState::Prepared);
            prepared
        }
        Err(error) => return failed_report(error, transitions),
    };

    if let Err(error) = executor.revalidate(proposal, &prepared) {
        return failed_report(error, transitions);
    }
    transitions.push(ActionTransactionState::Revalidated);

    if let Err(error) = executor.commit(proposal, &prepared) {
        return failed_report(error, transitions);
    }
    transitions.push(ActionTransactionState::Committed);

    if let Err(error) = executor.verify(proposal, &prepared) {
        return failed_report(error, transitions);
    }
    transitions.push(ActionTransactionState::Verified);

    TransactionReport {
        state: ActionTransactionState::Verified,
        status: ActionExecutionStatus::Completed,
        message: None,
        transitions,
    }
}

fn not_authorised(message: &str) -> TransactionReport {
    TransactionReport {
        state: ActionTransactionState::Proposal,
        status: ActionExecutionStatus::NotAuthorised,
        message: Some(message.into()),
        transitions: vec![ActionTransactionState::Proposal],
    }
}

fn failed_report(
    error: ExecutorError,
    mut transitions: Vec<ActionTransactionState>,
) -> TransactionReport {
    transitions.push(ActionTransactionState::Failed);
    TransactionReport {
        state: ActionTransactionState::Failed,
        status: ActionExecutionStatus::Failed,
        message: Some(format!("{error:?}")),
        transitions,
    }
}

#[derive(Default)]
pub struct SafeExecutor {
    last_warning: Option<String>,
}

impl SafeExecutor {
    pub fn last_warning(&self) -> Option<&str> {
        self.last_warning.as_deref()
    }
}

impl ActionExecutor for SafeExecutor {
    type Prepared = ();

    fn prepare(&mut self, proposal: &ActionProposal) -> Result<Self::Prepared, ExecutorError> {
        if proposal.action.is_safe_non_privileged() {
            Ok(())
        } else {
            Err(ExecutorError::Prepare(
                "safe executor refuses privileged action".into(),
            ))
        }
    }

    fn revalidate(
        &mut self,
        proposal: &ActionProposal,
        _: &Self::Prepared,
    ) -> Result<(), ExecutorError> {
        if proposal.action.is_safe_non_privileged() {
            Ok(())
        } else {
            Err(ExecutorError::Revalidate(
                "action is no longer safe for this executor".into(),
            ))
        }
    }

    fn commit(
        &mut self,
        proposal: &ActionProposal,
        _: &Self::Prepared,
    ) -> Result<(), ExecutorError> {
        if proposal.action == dendrite_protocol::ActionType::Warn {
            self.last_warning = Some(format!(
                "Dendrite warning for {} from {}",
                proposal.target.0, proposal.incident_id.0
            ));
        }
        Ok(())
    }

    fn verify(&mut self, _: &ActionProposal, _: &Self::Prepared) -> Result<(), ExecutorError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dendrite_protocol::{ActionProposalId, ActionType, GuardDecision, IncidentId, ObjectId};

    #[derive(Default)]
    struct RecordingExecutor {
        calls: Vec<&'static str>,
    }

    impl ActionExecutor for RecordingExecutor {
        type Prepared = ();

        fn prepare(&mut self, _: &ActionProposal) -> Result<Self::Prepared, ExecutorError> {
            self.calls.push("prepare");
            Ok(())
        }

        fn revalidate(&mut self, _: &ActionProposal, _: &()) -> Result<(), ExecutorError> {
            self.calls.push("revalidate");
            Ok(())
        }

        fn commit(&mut self, _: &ActionProposal, _: &()) -> Result<(), ExecutorError> {
            self.calls.push("commit");
            Ok(())
        }

        fn verify(&mut self, _: &ActionProposal, _: &()) -> Result<(), ExecutorError> {
            self.calls.push("verify");
            Ok(())
        }
    }

    fn proposal(action: ActionType) -> ActionProposal {
        ActionProposal {
            id: ActionProposalId("act_test".into()),
            incident_id: IncidentId("inc_test".into()),
            action,
            target: ObjectId("obj_test".into()),
        }
    }

    #[test]
    fn unauthorised_action_never_reaches_executor() {
        let executor = RecordingExecutor::default();
        let mut coordinator = ActionCoordinator::new(executor);

        let report = coordinator.execute(
            &proposal(ActionType::Observe),
            ActionAuthorization {
                quorum: QuorumDecision::Denied,
                policy: PolicyDecision::Allow,
                guard: GuardDecision::Allow,
            },
        );

        assert_eq!(report.status, ActionExecutionStatus::NotAuthorised);
        assert!(coordinator.executor.calls.is_empty());
    }

    #[test]
    fn authorised_action_uses_transaction_order() {
        let executor = RecordingExecutor::default();
        let mut coordinator = ActionCoordinator::new(executor);

        let report = coordinator.execute(
            &proposal(ActionType::Observe),
            ActionAuthorization {
                quorum: QuorumDecision::Approved,
                policy: PolicyDecision::Allow,
                guard: GuardDecision::Allow,
            },
        );

        assert_eq!(report.status, ActionExecutionStatus::Completed);
        assert_eq!(
            coordinator.executor.calls,
            vec!["prepare", "revalidate", "commit", "verify"]
        );
        assert_eq!(
            report.transitions,
            vec![
                ActionTransactionState::Proposal,
                ActionTransactionState::Prepared,
                ActionTransactionState::Revalidated,
                ActionTransactionState::Committed,
                ActionTransactionState::Verified,
            ]
        );
    }

    #[test]
    fn safe_path_refuses_privileged_actions_without_guard() {
        let executor = RecordingExecutor::default();
        let mut coordinator = ActionCoordinator::new(executor);

        let report = coordinator.execute_safe(
            &proposal(ActionType::TerminateProcess),
            QuorumDecision::Approved,
            PolicyDecision::Allow,
        );

        assert_eq!(report.status, ActionExecutionStatus::NotAuthorised);
        assert!(coordinator.executor.calls.is_empty());
    }
}
