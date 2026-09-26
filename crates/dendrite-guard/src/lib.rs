//! Independent trust, integrity, and recovery boundary.
//!
//! `Guard` is the pure in-memory decision logic (unchanged from before the
//! process split). `GuardStore` wraps it with the persistent state
//! (`guard.sqlite3`) that used to live in `dendrited`'s own `guard.rs` —
//! moved here, verbatim in behaviour, now that this crate is a standalone
//! process (`dendrite-guard`/`dendrite-guard.service`) rather than a library
//! linked directly into `dendrited`. See `README.md` for why: the same
//! "compromise can remove authority, but cannot create authority" reasoning
//! that motivated the MAGI split applies here too, and more directly —
//! Guard's whole job is deciding whether `dendrited` still has authority to
//! act, so it should be the one place a compromise of `dendrited` itself
//! cannot reach.

use dendrite_protocol::{
    ActionProposal, GuardDecision, GuardStatusDto, IntegrityFinding, IntegrityFindingDto,
    IntegritySeverity, ObjectId, TrustState,
};
use rusqlite::{Connection, params};
use std::str::FromStr;
use std::time::Duration;

pub struct Guard {
    trust_state: TrustState,
    findings: Vec<IntegrityFinding>,
}

impl Guard {
    pub fn new(trust_state: TrustState) -> Self {
        Self {
            trust_state,
            findings: Vec::new(),
        }
    }

    pub fn trust_state(&self) -> TrustState {
        self.trust_state
    }

    pub fn set_trust_state(&mut self, state: TrustState) {
        self.trust_state = state;
    }

    pub fn record_finding(&mut self, finding: IntegrityFinding) {
        self.findings.push(finding);
    }

    pub fn findings(&self) -> &[IntegrityFinding] {
        &self.findings
    }

    pub fn evaluate_authority(&self, _proposal: &ActionProposal) -> GuardDecision {
        match self.trust_state {
            TrustState::Trusted => GuardDecision::Allow,
            TrustState::Degraded
            | TrustState::Suspected
            | TrustState::Quarantined
            | TrustState::Compromised
            | TrustState::Recovering => GuardDecision::Deny,
        }
    }
}

#[derive(Debug)]
pub enum GuardStoreError {
    Database(rusqlite::Error),
    InvalidTrustState(String),
    InvalidSeverity(String),
}

impl std::fmt::Display for GuardStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "database error: {error}"),
            Self::InvalidTrustState(state) => write!(formatter, "invalid trust state: {state}"),
            Self::InvalidSeverity(severity) => write!(formatter, "invalid severity: {severity}"),
        }
    }
}

impl From<rusqlite::Error> for GuardStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

fn configure_connection(connection: &Connection, path: &str) -> rusqlite::Result<()> {
    connection.busy_timeout(Duration::from_secs(5))?;
    if path != ":memory:" {
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
    }
    connection.pragma_update(None, "foreign_keys", "ON")?;
    Ok(())
}

/// Owns `guard.sqlite3` and the one live `Guard` instance backed by it.
/// `dendrite-guard`'s `main.rs` holds exactly one of these and serves every
/// request against it — there is deliberately no per-connection state,
/// since trust state and integrity findings are process-wide, not
/// per-caller.
pub struct GuardStore {
    connection: Connection,
    guard: Guard,
}

impl GuardStore {
    pub fn open(path: &str) -> Result<Self, GuardStoreError> {
        let connection = Connection::open(path)?;
        configure_connection(&connection, path)?;
        connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS guard_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                trust_state TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS integrity_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                recorded_at INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO guard_state(singleton, trust_state, updated_at)
            VALUES (1, 'trusted', 0);
            ",
        )?;

        let state: String = connection.query_row(
            "SELECT trust_state FROM guard_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let trust_state =
            TrustState::from_str(&state).map_err(|_| GuardStoreError::InvalidTrustState(state))?;

        Ok(Self {
            connection,
            guard: Guard::new(trust_state),
        })
    }

    pub fn trust_state(&self) -> TrustState {
        self.guard.trust_state()
    }

    pub fn evaluate_authority(&self, proposal: &ActionProposal) -> GuardDecision {
        self.guard.evaluate_authority(proposal)
    }

    pub fn status(&self) -> Result<GuardStatusDto, GuardStoreError> {
        let findings_count =
            self.connection
                .query_row("SELECT COUNT(*) FROM integrity_findings", [], |row| {
                    row.get(0)
                })?;
        let decision = match self.guard.trust_state() {
            TrustState::Trusted => "available",
            _ => "removed",
        };
        Ok(GuardStatusDto {
            trust_state: self.guard.trust_state().as_str().into(),
            authority: decision.into(),
            findings_count,
        })
    }

    pub fn findings(&self) -> Result<Vec<IntegrityFindingDto>, GuardStoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, target, severity, description, recorded_at
             FROM integrity_findings ORDER BY id DESC",
        )?;
        Ok(statement
            .query_map([], |row| {
                Ok(IntegrityFindingDto {
                    id: row.get(0)?,
                    target: row.get(1)?,
                    severity: row.get(2)?,
                    description: row.get(3)?,
                    recorded_at: row.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Development-only, mirrored by `dendrite-guard`'s `main.rs` refusing
    /// `GuardRequest::DebugSetState` outright in a release build rather than
    /// gating this method itself — see `README.md`.
    pub fn debug_set_state(&mut self, state: &str, now: u64) -> Result<(), GuardStoreError> {
        let state = TrustState::from_str(state)
            .map_err(|_| GuardStoreError::InvalidTrustState(state.into()))?;
        self.guard.set_trust_state(state);
        self.connection.execute(
            "UPDATE guard_state SET trust_state = ?1, updated_at = ?2 WHERE singleton = 1",
            params![state.as_str(), now],
        )?;
        Ok(())
    }

    /// Development-only — see `debug_set_state`.
    pub fn debug_record_finding(
        &mut self,
        target: &str,
        severity: &str,
        description: &str,
        now: u64,
    ) -> Result<(), GuardStoreError> {
        let severity = IntegritySeverity::from_str(severity)
            .map_err(|_| GuardStoreError::InvalidSeverity(severity.into()))?;
        let finding = IntegrityFinding {
            target: ObjectId(target.into()),
            severity,
            description: description.into(),
        };
        self.guard.record_finding(finding);
        self.connection.execute(
            "INSERT INTO integrity_findings(target, severity, description, recorded_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![target, severity.as_str(), description, now],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dendrite_protocol::{ActionProposalId, ActionType, IncidentId};

    fn proposal() -> ActionProposal {
        ActionProposal {
            id: ActionProposalId("act_test".into()),
            incident_id: IncidentId("inc_test".into()),
            action: ActionType::Observe,
            target: ObjectId("target".into()),
        }
    }

    #[test]
    fn trusted_guard_allows_authority() {
        let guard = Guard::new(TrustState::Trusted);
        assert_eq!(guard.evaluate_authority(&proposal()), GuardDecision::Allow);
    }

    #[test]
    fn compromised_guard_removes_authority() {
        let guard = Guard::new(TrustState::Compromised);
        assert_eq!(guard.evaluate_authority(&proposal()), GuardDecision::Deny);
    }

    #[test]
    fn compromised_state_removes_authority_and_persists() {
        let path = std::env::temp_dir().join(format!(
            "dendrite-guard-store-test-{}-{}.sqlite3",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_file(&path);

        {
            let mut store = GuardStore::open(path.to_str().unwrap()).unwrap();
            store.debug_set_state("compromised", 1).unwrap();
            assert_eq!(store.evaluate_authority(&proposal()), GuardDecision::Deny);
        }

        let store = GuardStore::open(path.to_str().unwrap()).unwrap();
        assert_eq!(store.trust_state(), TrustState::Compromised);
        assert_eq!(store.evaluate_authority(&proposal()), GuardDecision::Deny);
        let _ = std::fs::remove_file(path);
    }
}
