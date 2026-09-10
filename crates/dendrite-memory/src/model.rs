use dendrite_protocol::{EvidenceId, IncidentId};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemoryNodeId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemoryRelationshipId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MemoryStrength(u8);

impl MemoryStrength {
    pub fn new(value: u8) -> Option<Self> {
        if value <= 100 {
            Some(Self(value))
        } else {
            None
        }
    }

    pub fn value(self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MemoryConfidence(u8);

impl MemoryConfidence {
    pub fn new(value: u8) -> Option<Self> {
        if value <= 100 {
            Some(Self(value))
        } else {
            None
        }
    }

    pub fn value(self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DecayRate(u8);

impl DecayRate {
    pub fn new(value: u8) -> Option<Self> {
        if value <= 100 {
            Some(Self(value))
        } else {
            None
        }
    }

    pub fn value(self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryNodeKind {
    Process,
    File,
    User,
    Host,
    NetworkEndpoint,
    Service,
    Container,
    Incident,
    Threat,
}

impl MemoryNodeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::File => "file",
            Self::User => "user",
            Self::Host => "host",
            Self::NetworkEndpoint => "network_endpoint",
            Self::Service => "service",
            Self::Container => "container",
            Self::Incident => "incident",
            Self::Threat => "threat",
        }
    }
}

impl FromStr for MemoryNodeKind {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "process" => Ok(Self::Process),
            "file" => Ok(Self::File),
            "user" => Ok(Self::User),
            "host" => Ok(Self::Host),
            "network_endpoint" => Ok(Self::NetworkEndpoint),
            "service" => Ok(Self::Service),
            "container" => Ok(Self::Container),
            "incident" => Ok(Self::Incident),
            "threat" => Ok(Self::Threat),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRelationshipKind {
    Spawned,
    Executed,
    Read,
    Wrote,
    ConnectedTo,
    BelongsTo,
    AssociatedWith,
}

impl MemoryRelationshipKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Spawned => "spawned",
            Self::Executed => "executed",
            Self::Read => "read",
            Self::Wrote => "wrote",
            Self::ConnectedTo => "connected_to",
            Self::BelongsTo => "belongs_to",
            Self::AssociatedWith => "associated_with",
        }
    }
}

impl FromStr for MemoryRelationshipKind {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "spawned" => Ok(Self::Spawned),
            "executed" => Ok(Self::Executed),
            "read" => Ok(Self::Read),
            "wrote" => Ok(Self::Wrote),
            "connected_to" => Ok(Self::ConnectedTo),
            "belongs_to" => Ok(Self::BelongsTo),
            "associated_with" => Ok(Self::AssociatedWith),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryState {
    Observed,
    Correlated,
    Supported,
    Established,
    Contradicted,
    Superseded,
    Expired,
    Revoked,
}

impl MemoryState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Correlated => "correlated",
            Self::Supported => "supported",
            Self::Established => "established",
            Self::Contradicted => "contradicted",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn is_active_for_reasoning(self) -> bool {
        matches!(
            self,
            Self::Observed | Self::Correlated | Self::Supported | Self::Established
        )
    }
}

impl FromStr for MemoryState {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "observed" => Ok(Self::Observed),
            "correlated" => Ok(Self::Correlated),
            "supported" => Ok(Self::Supported),
            "established" => Ok(Self::Established),
            "contradicted" => Ok(Self::Contradicted),
            "superseded" => Ok(Self::Superseded),
            "expired" => Ok(Self::Expired),
            "revoked" => Ok(Self::Revoked),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemoryPriority {
    Low,
    Normal,
    Elevated,
    High,
    Critical,
}

impl MemoryPriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Normal => "normal",
            Self::Elevated => "elevated",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl FromStr for MemoryPriority {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "low" => Ok(Self::Low),
            "normal" => Ok(Self::Normal),
            "elevated" => Ok(Self::Elevated),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionClass {
    ShortTerm,
    LongTerm,
    Persistent,
}

impl RetentionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShortTerm => "short_term",
            Self::LongTerm => "long_term",
            Self::Persistent => "persistent",
        }
    }
}

impl FromStr for RetentionClass {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "short_term" => Ok(Self::ShortTerm),
            "long_term" => Ok(Self::LongTerm),
            "persistent" => Ok(Self::Persistent),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecayPolicy {
    None,
    Linear { rate: DecayRate },
    Exponential { rate: DecayRate },
}

impl DecayPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Linear { .. } => "linear",
            Self::Exponential { .. } => "exponential",
        }
    }

    pub fn from_parts(kind: &str, rate: Option<u8>) -> Option<Self> {
        match kind {
            "none" => Some(Self::None),
            "linear" => Some(Self::Linear {
                rate: DecayRate::new(rate?)?,
            }),
            "exponential" => Some(Self::Exponential {
                rate: DecayRate::new(rate?)?,
            }),
            _ => None,
        }
    }

    pub fn rate(self) -> Option<DecayRate> {
        match self {
            Self::None => None,
            Self::Linear { rate } | Self::Exponential { rate } => Some(rate),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReinforcementReason {
    ConfirmedHighRisk,
    RepeatedObservation,
    OperatorConfirmed,
}

impl ReinforcementReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfirmedHighRisk => "confirmed_high_risk",
            Self::RepeatedObservation => "repeated_observation",
            Self::OperatorConfirmed => "operator_confirmed",
        }
    }
}

impl FromStr for ReinforcementReason {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "confirmed_high_risk" => Ok(Self::ConfirmedHighRisk),
            "repeated_observation" => Ok(Self::RepeatedObservation),
            "operator_confirmed" => Ok(Self::OperatorConfirmed),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReinforcementProvenance {
    pub reason: ReinforcementReason,
    pub incident_id: Option<IncidentId>,
    pub evidence_ids: Vec<EvidenceId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryNode {
    pub id: MemoryNodeId,
    pub kind: MemoryNodeKind,
    pub label: String,
    pub created_at: u64,
    pub last_seen_at: u64,
    pub expires_at: Option<u64>,
    pub state: MemoryState,
    pub priority: MemoryPriority,
    pub retention: RetentionClass,
    pub decay_policy: DecayPolicy,
}

impl MemoryNode {
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|expires_at| now >= expires_at)
    }

    pub fn is_purge_eligible(&self, now: u64, grace_period: u64) -> bool {
        if self.retention == RetentionClass::Persistent || self.state != MemoryState::Expired {
            return false;
        }

        self.expires_at
            .is_some_and(|expires_at| now >= expires_at.saturating_add(grace_period))
    }

    pub fn record_observation(&mut self, observed_at: u64) {
        self.last_seen_at = self.last_seen_at.max(observed_at);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRelationship {
    pub id: MemoryRelationshipId,
    pub kind: MemoryRelationshipKind,
    pub source: MemoryNodeId,
    pub target: MemoryNodeId,
    pub created_at: u64,
    pub last_seen_at: u64,
    pub observation_count: u64,
    pub expires_at: Option<u64>,
    pub state: MemoryState,
    pub priority: MemoryPriority,
    pub retention: RetentionClass,
    pub decay_policy: DecayPolicy,
    pub strength: MemoryStrength,
    pub confidence: MemoryConfidence,
    pub reinforcement: Option<ReinforcementProvenance>,
}

impl MemoryRelationship {
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|expires_at| now >= expires_at)
    }

    pub fn is_purge_eligible(&self, now: u64, grace_period: u64) -> bool {
        if self.retention == RetentionClass::Persistent || self.state != MemoryState::Expired {
            return false;
        }

        self.expires_at
            .is_some_and(|expires_at| now >= expires_at.saturating_add(grace_period))
    }

    pub fn elapsed_percent(&self, now: u64) -> u8 {
        let Some(expires_at) = self.expires_at else {
            return 0;
        };

        if expires_at <= self.created_at || now >= expires_at {
            return 100;
        }

        if now <= self.created_at {
            return 0;
        }

        let elapsed = now - self.created_at;
        let lifetime = expires_at - self.created_at;
        ((elapsed.saturating_mul(100) / lifetime).min(100)) as u8
    }

    pub fn effective_strength(&self, now: u64) -> MemoryStrength {
        self.decayed_strength(self.elapsed_percent(now))
    }

    pub fn decayed_strength(&self, elapsed_percent: u8) -> MemoryStrength {
        let elapsed_percent = elapsed_percent.min(100);

        if self.reinforcement.is_some() {
            return self.strength;
        }

        match self.decay_policy {
            DecayPolicy::None => self.strength,

            DecayPolicy::Linear { rate } => {
                let reduction =
                    (self.strength.value() as u32 * rate.value() as u32 * elapsed_percent as u32)
                        / 10_000;

                let value = self.strength.value().saturating_sub(reduction as u8);

                MemoryStrength::new(value).expect("decayed strength must remain within 0..=100")
            }

            DecayPolicy::Exponential { rate } => {
                let remaining_fraction = 1.0 - f64::from(rate.value()) / 100.0;
                let elapsed_fraction = f64::from(elapsed_percent) / 100.0;
                let value =
                    f64::from(self.strength.value()) * remaining_fraction.powf(elapsed_fraction);
                let value = value.round().clamp(0.0, 100.0) as u8;

                MemoryStrength::new(value).expect("decayed strength must remain within 0..=100")
            }
        }
    }

    pub fn record_observation(&mut self, observed_at: u64) {
        self.observation_count = self.observation_count.saturating_add(1);
        self.last_seen_at = self.last_seen_at.max(observed_at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_strength_accepts_valid_values() {
        assert_eq!(MemoryStrength::new(0).unwrap().value(), 0);
        assert_eq!(MemoryStrength::new(100).unwrap().value(), 100);
    }

    #[test]
    fn memory_strength_rejects_values_above_100() {
        assert_eq!(MemoryStrength::new(101), None);
    }

    #[test]
    fn memory_confidence_accepts_valid_values() {
        assert_eq!(MemoryConfidence::new(0).unwrap().value(), 0);
        assert_eq!(MemoryConfidence::new(100).unwrap().value(), 100);
    }

    #[test]
    fn memory_confidence_rejects_values_above_100() {
        assert_eq!(MemoryConfidence::new(101), None);
    }

    #[test]
    fn decay_rate_accepts_valid_values() {
        assert_eq!(DecayRate::new(0).unwrap().value(), 0);
        assert_eq!(DecayRate::new(100).unwrap().value(), 100);
    }

    #[test]
    fn decay_rate_rejects_values_above_100() {
        assert_eq!(DecayRate::new(101), None);
    }

    #[test]
    fn memory_node_kind_round_trips_through_string() {
        let kinds = [
            MemoryNodeKind::Process,
            MemoryNodeKind::File,
            MemoryNodeKind::User,
            MemoryNodeKind::Host,
            MemoryNodeKind::NetworkEndpoint,
            MemoryNodeKind::Service,
            MemoryNodeKind::Container,
            MemoryNodeKind::Incident,
            MemoryNodeKind::Threat,
        ];

        for kind in kinds {
            assert_eq!(MemoryNodeKind::from_str(kind.as_str()), Ok(kind));
        }
    }

    #[test]
    fn memory_relationship_kind_round_trips_through_string() {
        let kinds = [
            MemoryRelationshipKind::Spawned,
            MemoryRelationshipKind::Executed,
            MemoryRelationshipKind::Read,
            MemoryRelationshipKind::Wrote,
            MemoryRelationshipKind::ConnectedTo,
            MemoryRelationshipKind::BelongsTo,
            MemoryRelationshipKind::AssociatedWith,
        ];

        for kind in kinds {
            assert_eq!(MemoryRelationshipKind::from_str(kind.as_str()), Ok(kind));
        }
    }

    #[test]
    fn memory_state_round_trips_through_string() {
        let states = [
            MemoryState::Observed,
            MemoryState::Correlated,
            MemoryState::Supported,
            MemoryState::Established,
            MemoryState::Contradicted,
            MemoryState::Superseded,
            MemoryState::Expired,
            MemoryState::Revoked,
        ];

        for state in states {
            assert_eq!(MemoryState::from_str(state.as_str()), Ok(state));
        }
    }

    #[test]
    fn decay_policy_reconstructs_from_stored_parts() {
        let linear = DecayPolicy::from_parts("linear", Some(25)).unwrap();

        assert_eq!(
            linear,
            DecayPolicy::Linear {
                rate: DecayRate::new(25).unwrap(),
            }
        );

        let exponential = DecayPolicy::from_parts("exponential", Some(40)).unwrap();

        assert_eq!(
            exponential,
            DecayPolicy::Exponential {
                rate: DecayRate::new(40).unwrap(),
            }
        );

        assert_eq!(
            DecayPolicy::from_parts("none", None),
            Some(DecayPolicy::None),
        );

        assert_eq!(DecayPolicy::from_parts("linear", None), None);
        assert_eq!(DecayPolicy::from_parts("unknown", Some(10)), None);
    }

    #[test]
    fn memory_node_expiry_uses_expires_at() {
        let node = MemoryNode {
            id: MemoryNodeId("node-1".into()),
            kind: MemoryNodeKind::Process,
            label: "nginx".into(),
            created_at: 100,
            last_seen_at: 200,
            expires_at: Some(300),
            state: MemoryState::Observed,
            priority: MemoryPriority::Normal,
            retention: RetentionClass::ShortTerm,
            decay_policy: DecayPolicy::None,
        };

        assert!(!node.is_expired(299));
        assert!(node.is_expired(300));
        assert!(node.is_expired(301));
    }

    #[test]
    fn memory_node_without_expiry_does_not_expire() {
        let node = MemoryNode {
            id: MemoryNodeId("node-1".into()),
            kind: MemoryNodeKind::Process,
            label: "nginx".into(),
            created_at: 100,
            last_seen_at: 200,
            expires_at: None,
            state: MemoryState::Established,
            priority: MemoryPriority::High,
            retention: RetentionClass::Persistent,
            decay_policy: DecayPolicy::None,
        };

        assert!(!node.is_expired(u64::MAX));
    }

    #[test]
    fn memory_node_record_observation_updates_last_seen() {
        let mut node = MemoryNode {
            id: MemoryNodeId("node-1".into()),
            kind: MemoryNodeKind::Process,
            label: "nginx".into(),
            created_at: 100,
            last_seen_at: 200,
            expires_at: Some(500),
            state: MemoryState::Observed,
            priority: MemoryPriority::Normal,
            retention: RetentionClass::ShortTerm,
            decay_policy: DecayPolicy::None,
        };

        node.record_observation(250);
        assert_eq!(node.last_seen_at, 250);

        node.record_observation(150);
        assert_eq!(node.last_seen_at, 250);
    }

    #[test]
    fn memory_relationship_expiry_uses_expires_at() {
        let relationship = MemoryRelationship {
            id: MemoryRelationshipId("rel-1".into()),
            kind: MemoryRelationshipKind::Spawned,
            source: MemoryNodeId("node-1".into()),
            target: MemoryNodeId("node-2".into()),
            created_at: 100,
            last_seen_at: 200,
            observation_count: 1,
            expires_at: Some(300),
            state: MemoryState::Observed,
            priority: MemoryPriority::Normal,
            retention: RetentionClass::ShortTerm,
            decay_policy: DecayPolicy::None,
            strength: MemoryStrength::new(50).unwrap(),
            confidence: MemoryConfidence::new(50).unwrap(),
            reinforcement: None,
        };

        assert!(!relationship.is_expired(299));
        assert!(relationship.is_expired(300));
        assert!(relationship.is_expired(301));
    }

    #[test]
    fn memory_relationship_without_expiry_does_not_expire() {
        let relationship = MemoryRelationship {
            id: MemoryRelationshipId("rel-1".into()),
            kind: MemoryRelationshipKind::AssociatedWith,
            source: MemoryNodeId("node-1".into()),
            target: MemoryNodeId("node-2".into()),
            created_at: 100,
            last_seen_at: 200,
            observation_count: 10,
            expires_at: None,
            state: MemoryState::Established,
            priority: MemoryPriority::High,
            retention: RetentionClass::Persistent,
            decay_policy: DecayPolicy::None,
            strength: MemoryStrength::new(90).unwrap(),
            confidence: MemoryConfidence::new(95).unwrap(),
            reinforcement: None,
        };

        assert!(!relationship.is_expired(u64::MAX));
    }

    #[test]
    fn record_observation_updates_count_and_last_seen() {
        let mut relationship = MemoryRelationship {
            id: MemoryRelationshipId("rel-1".into()),
            kind: MemoryRelationshipKind::ConnectedTo,
            source: MemoryNodeId("node-1".into()),
            target: MemoryNodeId("node-2".into()),
            created_at: 100,
            last_seen_at: 200,
            observation_count: 5,
            expires_at: Some(500),
            state: MemoryState::Observed,
            priority: MemoryPriority::Normal,
            retention: RetentionClass::ShortTerm,
            decay_policy: DecayPolicy::None,
            strength: MemoryStrength::new(50).unwrap(),
            confidence: MemoryConfidence::new(50).unwrap(),
            reinforcement: None,
        };

        relationship.record_observation(250);

        assert_eq!(relationship.observation_count, 6);
        assert_eq!(relationship.last_seen_at, 250);

        relationship.record_observation(150);

        assert_eq!(relationship.observation_count, 7);
        assert_eq!(relationship.last_seen_at, 250);
    }

    #[test]
    fn linear_decay_reduces_relationship_strength() {
        let relationship = MemoryRelationship {
            id: MemoryRelationshipId("rel-1".into()),
            kind: MemoryRelationshipKind::AssociatedWith,
            source: MemoryNodeId("node-1".into()),
            target: MemoryNodeId("node-2".into()),
            created_at: 100,
            last_seen_at: 200,
            observation_count: 1,
            expires_at: Some(300),
            state: MemoryState::Observed,
            priority: MemoryPriority::Normal,
            retention: RetentionClass::ShortTerm,
            decay_policy: DecayPolicy::Linear {
                rate: DecayRate::new(50).unwrap(),
            },
            strength: MemoryStrength::new(100).unwrap(),
            confidence: MemoryConfidence::new(50).unwrap(),
            reinforcement: None,
        };

        assert_eq!(relationship.decayed_strength(0).value(), 100);
        assert_eq!(relationship.decayed_strength(50).value(), 75);
        assert_eq!(relationship.decayed_strength(100).value(), 50);
    }

    #[test]
    fn linear_decay_clamps_elapsed_percent_to_100() {
        let relationship = MemoryRelationship {
            id: MemoryRelationshipId("rel-1".into()),
            kind: MemoryRelationshipKind::AssociatedWith,
            source: MemoryNodeId("node-1".into()),
            target: MemoryNodeId("node-2".into()),
            created_at: 100,
            last_seen_at: 200,
            observation_count: 1,
            expires_at: Some(300),
            state: MemoryState::Observed,
            priority: MemoryPriority::Normal,
            retention: RetentionClass::ShortTerm,
            decay_policy: DecayPolicy::Linear {
                rate: DecayRate::new(50).unwrap(),
            },
            strength: MemoryStrength::new(100).unwrap(),
            confidence: MemoryConfidence::new(50).unwrap(),
            reinforcement: None,
        };

        assert_eq!(relationship.decayed_strength(200).value(), 50);
    }

    #[test]
    fn reinforced_relationship_does_not_decay() {
        let relationship = MemoryRelationship {
            id: MemoryRelationshipId("rel-1".into()),
            kind: MemoryRelationshipKind::AssociatedWith,
            source: MemoryNodeId("node-1".into()),
            target: MemoryNodeId("node-2".into()),
            created_at: 100,
            last_seen_at: 200,
            observation_count: 1,
            expires_at: Some(300),
            state: MemoryState::Established,
            priority: MemoryPriority::High,
            retention: RetentionClass::LongTerm,
            decay_policy: DecayPolicy::Linear {
                rate: DecayRate::new(50).unwrap(),
            },
            strength: MemoryStrength::new(100).unwrap(),
            confidence: MemoryConfidence::new(95).unwrap(),
            reinforcement: Some(ReinforcementProvenance {
                reason: ReinforcementReason::ConfirmedHighRisk,
                incident_id: None,
                evidence_ids: Vec::new(),
            }),
        };

        assert_eq!(relationship.decayed_strength(100).value(), 100);
    }

    #[test]
    fn memory_state_identifies_reasoning_active_states() {
        for state in [
            MemoryState::Observed,
            MemoryState::Correlated,
            MemoryState::Supported,
            MemoryState::Established,
        ] {
            assert!(state.is_active_for_reasoning());
        }

        for state in [
            MemoryState::Contradicted,
            MemoryState::Superseded,
            MemoryState::Expired,
            MemoryState::Revoked,
        ] {
            assert!(!state.is_active_for_reasoning());
        }
    }

    #[test]
    fn exponential_decay_reduces_relationship_strength() {
        let relationship = MemoryRelationship {
            id: MemoryRelationshipId("rel-exp".into()),
            kind: MemoryRelationshipKind::AssociatedWith,
            source: MemoryNodeId("node-1".into()),
            target: MemoryNodeId("node-2".into()),
            created_at: 100,
            last_seen_at: 200,
            observation_count: 1,
            expires_at: Some(300),
            state: MemoryState::Observed,
            priority: MemoryPriority::Normal,
            retention: RetentionClass::ShortTerm,
            decay_policy: DecayPolicy::Exponential {
                rate: DecayRate::new(50).unwrap(),
            },
            strength: MemoryStrength::new(100).unwrap(),
            confidence: MemoryConfidence::new(50).unwrap(),
            reinforcement: None,
        };

        assert_eq!(relationship.decayed_strength(0).value(), 100);
        assert_eq!(relationship.decayed_strength(50).value(), 71);
        assert_eq!(relationship.decayed_strength(100).value(), 50);
    }

    #[test]
    fn expired_non_persistent_node_becomes_purge_eligible_after_grace_period() {
        let node = MemoryNode {
            id: MemoryNodeId("node-purge".into()),
            kind: MemoryNodeKind::File,
            label: "old file".into(),
            created_at: 10,
            last_seen_at: 20,
            expires_at: Some(100),
            state: MemoryState::Expired,
            priority: MemoryPriority::Low,
            retention: RetentionClass::ShortTerm,
            decay_policy: DecayPolicy::None,
        };

        assert!(!node.is_purge_eligible(149, 50));
        assert!(node.is_purge_eligible(150, 50));
    }

    #[test]
    fn persistent_node_is_never_purge_eligible() {
        let node = MemoryNode {
            id: MemoryNodeId("node-persistent".into()),
            kind: MemoryNodeKind::Host,
            label: "host".into(),
            created_at: 10,
            last_seen_at: 20,
            expires_at: Some(100),
            state: MemoryState::Expired,
            priority: MemoryPriority::High,
            retention: RetentionClass::Persistent,
            decay_policy: DecayPolicy::None,
        };

        assert!(!node.is_purge_eligible(u64::MAX, 0));
    }

    #[test]
    fn relationship_elapsed_percent_tracks_lifetime() {
        let mut relationship = MemoryRelationship {
            id: MemoryRelationshipId("rel-time".into()),
            kind: MemoryRelationshipKind::AssociatedWith,
            source: MemoryNodeId("node-1".into()),
            target: MemoryNodeId("node-2".into()),
            created_at: 100,
            last_seen_at: 100,
            observation_count: 1,
            expires_at: Some(200),
            state: MemoryState::Observed,
            priority: MemoryPriority::Normal,
            retention: RetentionClass::ShortTerm,
            decay_policy: DecayPolicy::None,
            strength: MemoryStrength::new(100).unwrap(),
            confidence: MemoryConfidence::new(50).unwrap(),
            reinforcement: None,
        };

        assert_eq!(relationship.elapsed_percent(50), 0);
        assert_eq!(relationship.elapsed_percent(150), 50);
        assert_eq!(relationship.elapsed_percent(200), 100);

        relationship.expires_at = None;
        assert_eq!(relationship.elapsed_percent(u64::MAX), 0);
    }

    #[test]
    fn effective_strength_uses_elapsed_lifetime_and_resumes_after_reinforcement_is_removed() {
        let mut relationship = MemoryRelationship {
            id: MemoryRelationshipId("rel-effective".into()),
            kind: MemoryRelationshipKind::AssociatedWith,
            source: MemoryNodeId("node-1".into()),
            target: MemoryNodeId("node-2".into()),
            created_at: 100,
            last_seen_at: 100,
            observation_count: 1,
            expires_at: Some(200),
            state: MemoryState::Observed,
            priority: MemoryPriority::Normal,
            retention: RetentionClass::ShortTerm,
            decay_policy: DecayPolicy::Linear {
                rate: DecayRate::new(50).unwrap(),
            },
            strength: MemoryStrength::new(100).unwrap(),
            confidence: MemoryConfidence::new(50).unwrap(),
            reinforcement: Some(ReinforcementProvenance {
                reason: ReinforcementReason::ConfirmedHighRisk,
                incident_id: None,
                evidence_ids: Vec::new(),
            }),
        };

        assert_eq!(relationship.effective_strength(200).value(), 100);
        relationship.reinforcement = None;
        assert_eq!(relationship.effective_strength(200).value(), 50);
    }
}
