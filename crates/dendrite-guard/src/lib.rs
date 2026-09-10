//! Independent trust, integrity, and recovery boundary.

use dendrite_protocol::{ActionProposal, GuardDecision, IntegrityFinding, TrustState};

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

#[cfg(test)]
mod tests {
    use super::*;
    use dendrite_protocol::{ActionProposalId, ActionType, IncidentId, ObjectId};

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
}
