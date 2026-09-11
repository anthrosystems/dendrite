use crate::ObjectId;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustState {
    Trusted,
    Degraded,
    Suspected,
    Quarantined,
    Compromised,
    Recovering,
}

impl TrustState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Degraded => "degraded",
            Self::Suspected => "suspected",
            Self::Quarantined => "quarantined",
            Self::Compromised => "compromised",
            Self::Recovering => "recovering",
        }
    }
}

impl FromStr for TrustState {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "trusted" => Ok(Self::Trusted),
            "degraded" => Ok(Self::Degraded),
            "suspected" => Ok(Self::Suspected),
            "quarantined" => Ok(Self::Quarantined),
            "compromised" => Ok(Self::Compromised),
            "recovering" => Ok(Self::Recovering),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegritySeverity {
    Informational,
    Warning,
    High,
    Critical,
}

impl IntegritySeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Warning => "warning",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl FromStr for IntegritySeverity {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "informational" => Ok(Self::Informational),
            "warning" => Ok(Self::Warning),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityFinding {
    pub target: ObjectId,
    pub severity: IntegritySeverity,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardDecision {
    Allow,
    Deny,
}

impl GuardDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}
