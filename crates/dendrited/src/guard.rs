use dendrite_guard::Guard;
use dendrite_protocol::{
    ActionProposal, GuardDecision, GuardStatusDto, IntegrityFinding, IntegrityFindingDto,
    IntegritySeverity, ObjectId, TrustState,
};
use rusqlite::{Connection, params};
use std::str::FromStr;

#[derive(Debug)]
pub enum GuardStoreError {
    Database(rusqlite::Error),
    InvalidTrustState(String),
    InvalidSeverity(String),
}

impl From<rusqlite::Error> for GuardStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

pub struct GuardService {
    connection: Connection,
    guard: Guard,
}

impl GuardService {
    pub fn open(path: &str) -> Result<Self, GuardStoreError> {
        let connection = Connection::open(path)?;
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

    #[cfg(debug_assertions)]
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

    #[cfg(debug_assertions)]
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
    fn compromised_state_removes_authority_and_persists() {
        let path = std::env::temp_dir().join(format!(
            "dendrite-guard-test-{}-{}.sqlite3",
            std::process::id(),
            1
        ));
        let _ = std::fs::remove_file(&path);

        {
            let mut service = GuardService::open(path.to_str().unwrap()).unwrap();
            service.debug_set_state("compromised", 1).unwrap();
            assert_eq!(service.evaluate_authority(&proposal()), GuardDecision::Deny);
        }

        let service = GuardService::open(path.to_str().unwrap()).unwrap();
        assert_eq!(service.trust_state(), TrustState::Compromised);
        assert_eq!(service.evaluate_authority(&proposal()), GuardDecision::Deny);
        let _ = std::fs::remove_file(path);
    }
}
