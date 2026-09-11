use dendrite_action::{ActionCoordinator, SafeExecutor};
use dendrite_protocol::{
    ActionAuthorization, ActionDetailDto, ActionExecutionStatus, ActionProposal, ActionProposalId,
    ActionSummaryDto, ActionTransactionState, ActionType, Evaluation, EvaluationDto, Evaluator,
    EvaluatorVerdict, GuardDecision, IncidentId, ObjectId, PolicyDecision, QuorumPolicy,
    TransactionEventDto, TrustState,
};
use rusqlite::{Connection, OptionalExtension, params};
use std::str::FromStr;

#[derive(Debug)]
pub enum ActionStoreError {
    Database(rusqlite::Error),
    InvalidAction(String),
    InvalidProposal(String),
}

impl From<rusqlite::Error> for ActionStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

pub struct ActionService {
    connection: Connection,
    next_proposal: u64,
}

impl ActionService {
    pub fn open(path: &str) -> Result<Self, ActionStoreError> {
        let connection = Connection::open(path)?;
        let mut service = Self {
            connection,
            next_proposal: 1,
        };
        service.initialise()?;
        service.load_counter()?;
        Ok(service)
    }

    fn initialise(&self) -> Result<(), ActionStoreError> {
        self.connection.execute_batch(
            "
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS action_proposals (
                id          TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                action      TEXT NOT NULL,
                target      TEXT NOT NULL,
                status      TEXT NOT NULL,
                quorum      TEXT,
                policy      TEXT,
                created_at  INTEGER NOT NULL,
                updated_at  INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_action_proposals_incident
                ON action_proposals(incident_id);

            CREATE TABLE IF NOT EXISTS action_evaluations (
                proposal_id  TEXT NOT NULL,
                evaluator    TEXT NOT NULL,
                verdict      TEXT NOT NULL,
                reason       TEXT NOT NULL,
                evaluated_at INTEGER NOT NULL,
                PRIMARY KEY(proposal_id, evaluator),
                FOREIGN KEY(proposal_id) REFERENCES action_proposals(id)
            );

            CREATE TABLE IF NOT EXISTS action_transactions (
                sequence    INTEGER PRIMARY KEY AUTOINCREMENT,
                proposal_id TEXT NOT NULL,
                state       TEXT NOT NULL,
                status      TEXT NOT NULL,
                message     TEXT,
                recorded_at INTEGER NOT NULL,
                FOREIGN KEY(proposal_id) REFERENCES action_proposals(id)
            );
            ",
        )?;

        let _ = self
            .connection
            .execute("ALTER TABLE action_proposals ADD COLUMN guard TEXT", []);
        let _ = self.connection.execute(
            "ALTER TABLE action_proposals ADD COLUMN trust_state TEXT",
            [],
        );

        Ok(())
    }

    fn load_counter(&mut self) -> Result<(), ActionStoreError> {
        self.next_proposal = self.connection.query_row(
            "SELECT COALESCE(MAX(rowid), 0) + 1 FROM action_proposals",
            [],
            |row| row.get(0),
        )?;
        Ok(())
    }

    pub fn create(
        &mut self,
        incident_id: &str,
        action: &str,
        target: &str,
        now: u64,
    ) -> Result<ActionDetailDto, ActionStoreError> {
        let action_type = ActionType::from_str(action)
            .map_err(|_| ActionStoreError::InvalidAction(action.into()))?;
        let id = format!("act_{:08}", self.next_proposal);
        self.next_proposal = self.next_proposal.saturating_add(1);
        self.connection.execute(
            "INSERT INTO action_proposals
             (id, incident_id, action, target, status, quorum, policy, guard, trust_state, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 'proposed', NULL, NULL, NULL, NULL, ?5, ?5)",
            params![&id, incident_id, action_type.as_str(), target, now],
        )?;
        self.record_transaction(&id, ActionTransactionState::Proposal, "pending", None, now)?;

        self.detail(&id)?
            .ok_or_else(|| ActionStoreError::InvalidProposal(id))
    }

    pub fn list(&self) -> Result<Vec<ActionSummaryDto>, ActionStoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, incident_id, action, target, status, quorum, policy, guard, trust_state, created_at, updated_at
             FROM action_proposals
             ORDER BY updated_at DESC, id ASC",
        )?;
        let rows = statement.query_map([], action_summary_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn detail(&self, id: &str) -> Result<Option<ActionDetailDto>, ActionStoreError> {
        let proposal = self
            .connection
            .query_row(
                "SELECT id, incident_id, action, target, status, quorum, policy, guard, trust_state, created_at, updated_at
                 FROM action_proposals WHERE id = ?1",
                [id],
                action_summary_from_row,
            )
            .optional()?;
        let Some(proposal) = proposal else {
            return Ok(None);
        };

        let mut eval_statement = self.connection.prepare(
            "SELECT evaluator, verdict, reason, evaluated_at
             FROM action_evaluations
             WHERE proposal_id = ?1
             ORDER BY CASE evaluator
                 WHEN 'host' THEN 1
                 WHEN 'user' THEN 2
                 WHEN 'environment' THEN 3
                 ELSE 4 END",
        )?;
        let evaluations = eval_statement
            .query_map([id], |row| {
                Ok(EvaluationDto {
                    evaluator: row.get(0)?,
                    verdict: row.get(1)?,
                    reason: row.get(2)?,
                    evaluated_at: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut tx_statement = self.connection.prepare(
            "SELECT state, status, message, recorded_at
             FROM action_transactions
             WHERE proposal_id = ?1
             ORDER BY sequence ASC",
        )?;
        let transactions = tx_statement
            .query_map([id], |row| {
                Ok(TransactionEventDto {
                    state: row.get(0)?,
                    status: row.get(1)?,
                    message: row.get(2)?,
                    recorded_at: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let guard_requirement = "required_for_execution";

        Ok(Some(ActionDetailDto {
            proposal,
            evaluations,
            transactions,
            guard_requirement: guard_requirement.into(),
        }))
    }

    pub fn evaluate_and_execute(
        &mut self,
        id: &str,
        guard_decision: GuardDecision,
        trust_state: TrustState,
        now: u64,
    ) -> Result<ActionDetailDto, ActionStoreError> {
        let detail = self
            .detail(id)?
            .ok_or_else(|| ActionStoreError::InvalidProposal(format!("proposal {id} not found")))?;

        let action = ActionType::from_str(&detail.proposal.action)
            .map_err(|_| ActionStoreError::InvalidAction(detail.proposal.action.clone()))?;

        let proposal = ActionProposal {
            id: ActionProposalId(detail.proposal.id.clone()),
            incident_id: IncidentId(detail.proposal.incident_id.clone()),
            action,
            target: ObjectId(detail.proposal.target.clone()),
        };

        let evaluations = evaluate_magi(action);
        for (evaluation, reason) in &evaluations {
            self.connection.execute(
                "INSERT INTO action_evaluations
                 (proposal_id, evaluator, verdict, reason, evaluated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(proposal_id, evaluator) DO UPDATE SET
                    verdict = excluded.verdict,
                    reason = excluded.reason,
                    evaluated_at = excluded.evaluated_at",
                params![
                    id,
                    evaluation.evaluator.as_str(),
                    evaluation.verdict.as_str(),
                    reason,
                    now
                ],
            )?;
        }

        let plain_evaluations = evaluations
            .iter()
            .map(|(evaluation, _)| evaluation.clone())
            .collect::<Vec<_>>();
        let quorum = QuorumPolicy::default().evaluate(&plain_evaluations);
        let policy = evaluate_policy(action);

        let mut coordinator = ActionCoordinator::new(SafeExecutor::default());
        let report = coordinator.execute(
            &proposal,
            ActionAuthorization {
                quorum,
                policy,
                guard: guard_decision,
            },
        );

        let status = match report.status {
            ActionExecutionStatus::Completed => "completed",
            ActionExecutionStatus::NotAuthorised => "not_authorised",
            ActionExecutionStatus::Failed => "failed",
        };

        self.connection.execute(
            "UPDATE action_proposals
             SET status = ?1, quorum = ?2, policy = ?3, guard = ?4, trust_state = ?5, updated_at = ?6
             WHERE id = ?7",
            params![
                status,
                quorum.as_str(),
                policy.as_str(),
                guard_decision.as_str(),
                trust_state.as_str(),
                now,
                id
            ],
        )?;

        self.connection.execute(
            "DELETE FROM action_transactions WHERE proposal_id = ?1",
            [id],
        )?;

        for state in &report.transitions {
            let event_status = match state {
                ActionTransactionState::Proposal
                    if report.status == ActionExecutionStatus::NotAuthorised =>
                {
                    "not_authorised"
                }
                ActionTransactionState::Proposal
                    if report.status == ActionExecutionStatus::Completed =>
                {
                    "accepted"
                }
                ActionTransactionState::Proposal => "pending",
                ActionTransactionState::Failed => "failed",
                ActionTransactionState::Verified => status,
                _ => "ok",
            };
            let message = if *state == report.state {
                report.message.as_deref()
            } else {
                None
            };
            self.record_transaction(id, *state, event_status, message, now)?;
        }

        self.detail(id)?
            .ok_or_else(|| ActionStoreError::InvalidProposal(id.into()))
    }

    fn record_transaction(
        &self,
        proposal_id: &str,
        state: ActionTransactionState,
        status: &str,
        message: Option<&str>,
        now: u64,
    ) -> Result<(), ActionStoreError> {
        self.connection.execute(
            "INSERT INTO action_transactions
             (proposal_id, state, status, message, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![proposal_id, state.as_str(), status, message, now],
        )?;
        Ok(())
    }
}

fn action_summary_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ActionSummaryDto> {
    Ok(ActionSummaryDto {
        id: row.get(0)?,
        incident_id: row.get(1)?,
        action: row.get(2)?,
        target: row.get(3)?,
        status: row.get(4)?,
        quorum: row.get(5)?,
        policy: row.get(6)?,
        guard: row.get(7)?,
        trust_state: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

fn evaluate_magi(action: ActionType) -> Vec<(Evaluation, String)> {
    let safe = action.is_safe_non_privileged();

    vec![
        (
            Evaluation {
                evaluator: Evaluator::Host,
                verdict: if safe {
                    EvaluatorVerdict::Approve
                } else {
                    EvaluatorVerdict::Abstain
                },
            },
            if safe {
                "Balthasar: action is non-privileged and does not mutate protected host state"
            } else {
                "Balthasar: privileged host mutation is deferred until Guard integration"
            }
            .into(),
        ),
        (
            Evaluation {
                evaluator: Evaluator::User,
                verdict: EvaluatorVerdict::Abstain,
            },
            "Casper: no interactive user preference source is connected yet".into(),
        ),
        (
            Evaluation {
                evaluator: Evaluator::Environment,
                verdict: if safe {
                    EvaluatorVerdict::Approve
                } else {
                    EvaluatorVerdict::Abstain
                },
            },
            if safe {
                "Melchior: action is safe for the current development environment"
            } else {
                "Melchior: privileged environmental action is not enabled in Batch 3"
            }
            .into(),
        ),
    ]
}

fn evaluate_policy(action: ActionType) -> PolicyDecision {
    if action.is_safe_non_privileged() {
        PolicyDecision::Allow
    } else {
        PolicyDecision::Deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn service_with_incident() -> ActionService {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        let service = ActionService {
            connection,
            next_proposal: 1,
        };
        service.initialise().unwrap();
        service
    }

    #[test]
    fn safe_action_reaches_verified_state() {
        let mut service = service_with_incident();
        let proposal = service
            .create("inc_00000001", "observe", "process:1", 10)
            .unwrap();
        let detail = service
            .evaluate_and_execute(
                &proposal.proposal.id,
                GuardDecision::Allow,
                TrustState::Trusted,
                20,
            )
            .unwrap();

        assert_eq!(detail.proposal.status, "completed");
        assert_eq!(detail.proposal.quorum.as_deref(), Some("approved"));
        assert_eq!(detail.proposal.policy.as_deref(), Some("allow"));
        assert_eq!(detail.evaluations.len(), 3);
        assert!(
            detail
                .transactions
                .iter()
                .any(|event| event.state == "verified")
        );
    }

    #[test]
    fn compromised_guard_blocks_otherwise_safe_action_before_prepare() {
        let mut service = service_with_incident();
        let proposal = service
            .create("inc_00000001", "observe", "process:1", 10)
            .unwrap();
        let detail = service
            .evaluate_and_execute(
                &proposal.proposal.id,
                GuardDecision::Deny,
                TrustState::Compromised,
                20,
            )
            .unwrap();

        assert_eq!(detail.proposal.status, "not_authorised");
        assert_eq!(detail.proposal.quorum.as_deref(), Some("approved"));
        assert_eq!(detail.proposal.policy.as_deref(), Some("allow"));
        assert_eq!(detail.proposal.guard.as_deref(), Some("deny"));
        assert_eq!(detail.proposal.trust_state.as_deref(), Some("compromised"));
        assert!(
            !detail
                .transactions
                .iter()
                .any(|event| event.state == "prepared")
        );
    }

    #[test]
    fn privileged_action_is_policy_denied_and_never_committed() {
        let mut service = service_with_incident();
        let proposal = service
            .create("inc_00000001", "terminate_process", "process:1", 10)
            .unwrap();
        let detail = service
            .evaluate_and_execute(
                &proposal.proposal.id,
                GuardDecision::Allow,
                TrustState::Trusted,
                20,
            )
            .unwrap();

        assert_eq!(detail.proposal.status, "not_authorised");
        assert_eq!(detail.proposal.policy.as_deref(), Some("deny"));
        assert!(
            !detail
                .transactions
                .iter()
                .any(|event| event.state == "committed")
        );
    }
}
