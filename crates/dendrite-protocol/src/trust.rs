use crate::ObjectId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustState {
    Trusted,
    Degraded,
    Suspected,
    Quarantined,
    Compromised,
    Recovering,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntegritySeverity {
    Informational,
    Warning,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityFinding {
    pub target: ObjectId,
    pub severity: IntegritySeverity,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardDecision {
    Allow,
    Deny,
}
