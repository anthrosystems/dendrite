//! Privileged action coordination.
//!
//! This crate contains the authorisation and transaction boundaries. It deliberately
//! provides no production destructive executor yet.

use dendrite_protocol::{
    ActionAuthorization, ActionExecutionStatus, ActionProposal, ActionTransactionState,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionReport {
    pub state: ActionTransactionState,
    pub status: ActionExecutionStatus,
    pub message: Option<String>,
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
            return TransactionReport {
                state: ActionTransactionState::Proposal,
                status: ActionExecutionStatus::NotAuthorised,
                message: Some("action proposal did not pass every authorisation gate".into()),
            };
        }

        let prepared = match self.executor.prepare(proposal) {
            Ok(prepared) => prepared,
            Err(error) => return failed_report(error),
        };

        if let Err(error) = self.executor.revalidate(proposal, &prepared) {
            return failed_report(error);
        }

        if let Err(error) = self.executor.commit(proposal, &prepared) {
            return failed_report(error);
        }

        if let Err(error) = self.executor.verify(proposal, &prepared) {
            return failed_report(error);
        }

        TransactionReport {
            state: ActionTransactionState::Verified,
            status: ActionExecutionStatus::Completed,
            message: None,
        }
    }
}

fn failed_report(error: ExecutorError) -> TransactionReport {
    TransactionReport {
        state: ActionTransactionState::Failed,
        status: ActionExecutionStatus::Failed,
        message: Some(format!("{error:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dendrite_protocol::{
        ActionProposalId, ActionType, GuardDecision, IncidentId, ObjectId, PolicyDecision,
        QuorumDecision,
    };

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

    fn proposal() -> ActionProposal {
        ActionProposal {
            id: ActionProposalId("act_test".into()),
            incident_id: IncidentId("inc_test".into()),
            action: ActionType::Observe,
            target: ObjectId("obj_test".into()),
        }
    }

    #[test]
    fn unauthorised_action_never_reaches_executor() {
        let executor = RecordingExecutor::default();
        let mut coordinator = ActionCoordinator::new(executor);

        let report = coordinator.execute(
            &proposal(),
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
            &proposal(),
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
    }
}
