use dendrite_action::{ActionCoordinator, ActionExecutor, ExecutorError, SafeExecutor};
use dendrite_protocol::{
    ActionAuthorization, ActionDetailDto, ActionExecutionStatus, ActionProposal, ActionProposalId,
    ActionSummaryDto, ActionTransactionState, ActionType, Evaluation, EvaluationDto, Evaluator,
    EvaluatorVerdict, GuardDecision, IncidentId, MagiRequest, MagiResponse, ObjectId,
    PolicyDecision, QuorumPolicy, TransactionEventDto, TrustState, VulnerabilityExposureDto,
};
use dendrite_updater::{AptPackageManager, UpdatePlan, Updater};
use rusqlite::{Connection, OptionalExtension, params};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

/// Talks to the separate `dendrite-magi` process for MAGI evaluation. This
/// is a real OS-process boundary, not an in-process call, for the same
/// reason Guard is planned to become one (see `docs/ROADMAP.md`'s Batch 7
/// process-separation note): action authority should not be reachable
/// in-process from wherever a compromise might land.
pub trait MagiEvaluator: Send {
    fn evaluate(&self, action: ActionType, user_authorised: bool) -> Vec<(Evaluation, String)>;
}

/// Default `dendrite-magi` socket path for local dev — matches the
/// `/tmp/dendrited.sock` convention used for the CLI socket. Packaged
/// installs override this via `DENDRITE_MAGI_SOCKET`
/// (`/run/dendrite/dendrite-magi.sock`, set in `packaging/dendrited.service`).
pub const DEFAULT_MAGI_SOCKET_PATH: &str = "/tmp/dendrite-magi.sock";

/// Short — this call sits on the request-handling path, and an unreachable
/// `dendrite-magi` must not hang the whole daemon waiting for it.
const MAGI_CALL_TIMEOUT: Duration = Duration::from_secs(2);

pub struct MagiIpcClient {
    socket_path: PathBuf,
}

impl MagiIpcClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    fn call(&self, request: &MagiRequest) -> Result<MagiResponse, String> {
        let mut stream =
            UnixStream::connect(&self.socket_path).map_err(|error| format!("{error}"))?;
        stream
            .set_read_timeout(Some(MAGI_CALL_TIMEOUT))
            .map_err(|error| format!("{error}"))?;
        stream
            .set_write_timeout(Some(MAGI_CALL_TIMEOUT))
            .map_err(|error| format!("{error}"))?;

        let mut line = serde_json::to_string(request).map_err(|error| format!("{error}"))?;
        line.push('\n');
        stream
            .write_all(line.as_bytes())
            .map_err(|error| format!("{error}"))?;

        let mut response_line = String::new();
        BufReader::new(stream)
            .read_line(&mut response_line)
            .map_err(|error| format!("{error}"))?;
        serde_json::from_str(response_line.trim()).map_err(|error| format!("{error}"))
    }
}

/// An evaluator that abstains on every seat — the fail-closed fallback used
/// whenever `dendrite-magi` can't be reached at all. Abstaining (rather than
/// denying/vetoing) matches how the quorum policy already treats a silent
/// evaluator: it can never by itself cause an approval (so an unreachable
/// `dendrite-magi` can't create authority), but it also doesn't block an
/// action the *remaining* reachable evaluators would still unanimously
/// approve — unlike a hardcoded deny/veto, which would turn "the MAGI
/// process happens to be restarting" into a denial-of-service against every
/// containment/remediation action host-wide, including during a real
/// incident where Dendrite most needs to still be able to act. See
/// `docs/ROADMAP.md`'s MAGI/MCP process-separation notes for the full
/// reasoning.
fn abstain_all(reason: &str) -> Vec<(Evaluation, String)> {
    [Evaluator::Host, Evaluator::User, Evaluator::Environment]
        .into_iter()
        .map(|evaluator| {
            (
                Evaluation {
                    evaluator,
                    verdict: EvaluatorVerdict::Abstain,
                },
                reason.to_owned(),
            )
        })
        .collect()
}

impl MagiEvaluator for MagiIpcClient {
    fn evaluate(&self, action: ActionType, user_authorised: bool) -> Vec<(Evaluation, String)> {
        let request = MagiRequest::Evaluate {
            action,
            user_authorised,
        };
        match self.call(&request) {
            Ok(MagiResponse::Evaluations { evaluations }) => evaluations
                .into_iter()
                .map(|evaluation| {
                    (
                        Evaluation {
                            evaluator: evaluation.evaluator,
                            verdict: evaluation.verdict,
                        },
                        evaluation.reason,
                    )
                })
                .collect(),
            Ok(MagiResponse::Error { message }) => {
                abstain_all(&format!("dendrite-magi returned an error: {message}"))
            }
            Err(error) => abstain_all(&format!("dendrite-magi is unreachable: {error}")),
        }
    }
}

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
    magi: Box<dyn MagiEvaluator>,
}

impl ActionService {
    pub fn open(path: &str) -> Result<Self, ActionStoreError> {
        let connection = Connection::open(path)?;
        let mut service = Self {
            connection,
            next_proposal: 1,
            magi: Box::new(MagiIpcClient::new(PathBuf::from(DEFAULT_MAGI_SOCKET_PATH))),
        };
        service.initialise()?;
        service.load_counter()?;
        Ok(service)
    }

    /// Overrides the default `dendrite-magi` socket path (see
    /// `DEFAULT_MAGI_SOCKET_PATH`) — used by `DaemonRuntime::open` to wire in
    /// the configured `DENDRITE_MAGI_SOCKET` path, and by tests to inject a
    /// fake evaluator instead of talking to a real socket.
    pub fn set_magi_evaluator(&mut self, magi: Box<dyn MagiEvaluator>) {
        self.magi = magi;
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
        self.evaluate_and_execute_with(
            id,
            guard_decision,
            trust_state,
            false,
            SafeExecutor::default(),
            now,
        )
    }

    pub fn evaluate_and_execute_package_update(
        &mut self,
        id: &str,
        guard_decision: GuardDecision,
        trust_state: TrustState,
        exposure: VulnerabilityExposureDto,
        now: u64,
    ) -> Result<ActionDetailDto, ActionStoreError> {
        let user_authorised = exposure.authorised_at.is_some() && exposure.status == "authorised";
        self.evaluate_and_execute_with(
            id,
            guard_decision,
            trust_state,
            user_authorised,
            PackageUpdateExecutor::new(exposure),
            now,
        )
    }

    fn evaluate_and_execute_with<E>(
        &mut self,
        id: &str,
        guard_decision: GuardDecision,
        trust_state: TrustState,
        user_authorised: bool,
        executor: E,
        now: u64,
    ) -> Result<ActionDetailDto, ActionStoreError>
    where
        E: ActionExecutor,
    {
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

        let evaluations = self.magi.evaluate(action, user_authorised);
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
        let policy = evaluate_policy(action, user_authorised);

        let mut coordinator = ActionCoordinator::new(executor);
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

fn evaluate_policy(action: ActionType, user_authorised: bool) -> PolicyDecision {
    if action.is_safe_non_privileged() || (action == ActionType::UpdatePackage && user_authorised) {
        PolicyDecision::Allow
    } else {
        PolicyDecision::Deny
    }
}

pub struct PackageUpdateExecutor {
    exposure: VulnerabilityExposureDto,
    package_manager: AptPackageManager,
}

impl PackageUpdateExecutor {
    pub fn new(exposure: VulnerabilityExposureDto) -> Self {
        Self {
            exposure,
            package_manager: AptPackageManager,
        }
    }
}

impl ActionExecutor for PackageUpdateExecutor {
    type Prepared = UpdatePlan;

    fn prepare(&mut self, proposal: &ActionProposal) -> Result<Self::Prepared, ExecutorError> {
        if proposal.action != ActionType::UpdatePackage {
            return Err(ExecutorError::Prepare(
                "package executor received the wrong action type".into(),
            ));
        }
        self.package_manager
            .prepare(
                &self.exposure.package,
                &self.exposure.architecture,
                &self.exposure.installed_version,
                self.exposure.fixed_version.as_deref(),
            )
            .map_err(|error| ExecutorError::Prepare(format!("{error:?}")))
    }

    fn revalidate(
        &mut self,
        _: &ActionProposal,
        plan: &Self::Prepared,
    ) -> Result<(), ExecutorError> {
        self.package_manager
            .revalidate(plan)
            .map_err(|error| ExecutorError::Revalidate(format!("{error:?}")))
    }

    fn commit(&mut self, _: &ActionProposal, plan: &Self::Prepared) -> Result<(), ExecutorError> {
        let mut updater = Updater::new(self.package_manager);
        updater
            .apply_verified(plan)
            .map_err(|error| ExecutorError::Commit(format!("{error:?}")))
    }

    fn verify(&mut self, _: &ActionProposal, plan: &Self::Prepared) -> Result<(), ExecutorError> {
        if let Err(error) = self.package_manager.verify_fixed(plan) {
            let mut updater = Updater::new(self.package_manager);
            let rollback = updater.rollback(&plan.candidate);
            return Err(ExecutorError::Verify(match rollback {
                Ok(()) => format!("verification failed and package rollback completed: {error:?}"),
                Err(rollback_error) => format!(
                    "verification failed: {error:?}; rollback also failed: {rollback_error:?}"
                ),
            }));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reproduces `dendrite-magi`'s rule-based evaluator in-process, purely
    /// so these tests don't need a real socket/process — production
    /// `ActionService::open` always defaults to the real `MagiIpcClient`
    /// instead. Keep this in sync with `dendrite-magi`'s own evaluator if
    /// that logic changes.
    struct TestRuleMagiEvaluator;

    impl MagiEvaluator for TestRuleMagiEvaluator {
        fn evaluate(&self, action: ActionType, user_authorised: bool) -> Vec<(Evaluation, String)> {
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
                    "BALTHASAR-2: test evaluator".into(),
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
                    "CASPER-3: test evaluator".into(),
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
                    "MELCHIOR-1: test evaluator".into(),
                ),
            ]
        }
    }

    fn service_with_incident() -> ActionService {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        let service = ActionService {
            connection,
            next_proposal: 1,
            magi: Box::new(TestRuleMagiEvaluator),
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
    #[test]
    fn package_update_requires_explicit_user_authority() {
        let evaluator = TestRuleMagiEvaluator;
        let denied = evaluator.evaluate(ActionType::UpdatePackage, false);
        assert!(
            denied
                .iter()
                .any(|(evaluation, _)| evaluation.evaluator == Evaluator::User
                    && evaluation.verdict == EvaluatorVerdict::Deny)
        );
        assert_eq!(
            evaluate_policy(ActionType::UpdatePackage, false),
            PolicyDecision::Deny
        );

        let approved = evaluator.evaluate(ActionType::UpdatePackage, true);
        assert!(
            approved
                .iter()
                .any(|(evaluation, _)| evaluation.evaluator == Evaluator::User
                    && evaluation.verdict == EvaluatorVerdict::Approve)
        );
        assert_eq!(
            evaluate_policy(ActionType::UpdatePackage, true),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn magi_ipc_client_abstains_all_seats_when_dendrite_magi_is_unreachable() {
        let client = MagiIpcClient::new(PathBuf::from(
            "/tmp/dendrite-magi-test-socket-that-does-not-exist.sock",
        ));
        let evaluations = client.evaluate(ActionType::IsolateHost, false);
        assert_eq!(evaluations.len(), 3);
        assert!(
            evaluations
                .iter()
                .all(|(evaluation, _)| evaluation.verdict == EvaluatorVerdict::Abstain)
        );
    }
}
