use dendrite_protocol::{
    ActionProposal, ActionProposalId, ActionType, Evidence, EvidenceCandidate, EvidenceId,
    Incident, IncidentId, ObjectId,
};
use std::collections::HashMap;

pub struct IncidentService {
    incidents: HashMap<IncidentId, Incident>,
    evidence: HashMap<EvidenceId, Evidence>,
    next_incident: u64,
    next_evidence: u64,
}

impl Default for IncidentService {
    fn default() -> Self {
        Self::new()
    }
}

impl IncidentService {
    pub fn new() -> Self {
        Self {
            incidents: HashMap::new(),
            evidence: HashMap::new(),
            next_incident: 1,
            next_evidence: 1,
        }
    }

    pub fn record_candidate(&mut self, candidate: EvidenceCandidate) -> (IncidentId, EvidenceId) {
        let evidence_id = EvidenceId(format!("evi_{:08}", self.next_evidence));
        self.next_evidence = self.next_evidence.saturating_add(1);

        let incident_id = IncidentId(format!("inc_{:08}", self.next_incident));
        self.next_incident = self.next_incident.saturating_add(1);

        let evidence = Evidence {
            id: evidence_id.clone(),
            source: candidate.source,
            description: candidate.description,
            confidence: candidate.confidence,
        };

        let incident = Incident {
            id: incident_id.clone(),
            severity: candidate.severity,
            summary: candidate.summary,
            evidence: vec![evidence_id.clone()],
        };

        self.evidence.insert(evidence_id.clone(), evidence);
        self.incidents.insert(incident_id.clone(), incident);

        (incident_id, evidence_id)
    }

    pub fn incident(&self, id: &IncidentId) -> Option<&Incident> {
        self.incidents.get(id)
    }

    pub fn evidence(&self, id: &EvidenceId) -> Option<&Evidence> {
        self.evidence.get(id)
    }

    pub fn incidents(&self) -> Vec<&Incident> {
        let mut incidents = self.incidents.values().collect::<Vec<_>>();
        incidents.sort_by(|left, right| left.id.cmp(&right.id));
        incidents
    }
}

pub struct ProposalService {
    next_proposal: u64,
}

impl Default for ProposalService {
    fn default() -> Self {
        Self::new()
    }
}

impl ProposalService {
    pub fn new() -> Self {
        Self { next_proposal: 1 }
    }

    pub fn propose(
        &mut self,
        incident_id: IncidentId,
        action: ActionType,
        target: ObjectId,
    ) -> ActionProposal {
        let id = ActionProposalId(format!("act_{:08}", self.next_proposal));
        self.next_proposal = self.next_proposal.saturating_add(1);

        ActionProposal {
            id,
            incident_id,
            action,
            target,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dendrite_protocol::{Confidence, EvidenceSource, Severity};

    #[test]
    fn candidate_creates_evidence_and_incident() {
        let mut service = IncidentService::new();
        let candidate = EvidenceCandidate {
            source: EvidenceSource::MemoryGraph,
            summary: "Threat path found".into(),
            description: "process -> threat".into(),
            severity: Severity::High,
            confidence: Confidence::new(90).unwrap(),
            related_objects: Vec::new(),
        };

        let (incident_id, evidence_id) = service.record_candidate(candidate);

        assert!(service.incident(&incident_id).is_some());
        assert!(service.evidence(&evidence_id).is_some());
    }
}
