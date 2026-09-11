use crate::model::{
    DecayPolicy, MemoryConfidence, MemoryNode, MemoryNodeId, MemoryNodeKind, MemoryPriority,
    MemoryRelationship, MemoryRelationshipId, MemoryRelationshipKind, MemoryState, MemoryStrength,
    ReinforcementProvenance, ReinforcementReason, RetentionClass,
};
use dendrite_protocol::{EvidenceId, IncidentId};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::{HashSet, VecDeque};
use std::str::FromStr;

#[derive(Debug)]
pub enum StorageError {
    Database(rusqlite::Error),
    InvalidNodeKind(String),
    InvalidRelationshipKind(String),
    InvalidMemoryState(String),
    InvalidPriority(String),
    InvalidRetentionClass(String),
    InvalidDecayPolicy { kind: String, rate: Option<u8> },
    InvalidStrength(u8),
    InvalidConfidence(u8),
    InvalidReinforcementReason(String),
    InvalidReinforcementEvidenceJson(serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraversalVisit {
    pub node_id: MemoryNodeId,
    pub depth: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraversalDirection {
    Any,
    Outgoing,
    Incoming,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathQuery {
    pub max_depth: usize,
    pub direction: TraversalDirection,
    pub relationship_kinds: Vec<MemoryRelationshipKind>,
    pub minimum_strength: Option<MemoryStrength>,
    pub minimum_confidence: Option<MemoryConfidence>,
    pub evaluation_time: Option<u64>,
}

impl Default for PathQuery {
    fn default() -> Self {
        Self {
            max_depth: 8,
            direction: TraversalDirection::Any,
            relationship_kinds: Vec::new(),
            minimum_strength: None,
            minimum_confidence: None,
            evaluation_time: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryPath {
    pub nodes: Vec<MemoryNodeId>,
    pub relationships: Vec<MemoryRelationshipId>,
    pub weakest_strength: MemoryStrength,
    pub weakest_confidence: MemoryConfidence,
}

impl MemoryPath {
    pub fn score(&self) -> u8 {
        self.weakest_strength
            .value()
            .min(self.weakest_confidence.value())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatPath {
    pub threat: MemoryNodeId,
    pub path: MemoryPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleUpdate {
    pub relationships_expired: usize,
    pub nodes_expired: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationshipDecayEvaluation {
    pub relationship_id: MemoryRelationshipId,
    pub stored_strength: MemoryStrength,
    pub effective_strength: MemoryStrength,
}

impl From<rusqlite::Error> for StorageError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

fn decode_node_kind(value: String) -> Result<MemoryNodeKind, StorageError> {
    MemoryNodeKind::from_str(&value).map_err(|_| StorageError::InvalidNodeKind(value))
}

fn decode_relationship_kind(value: String) -> Result<MemoryRelationshipKind, StorageError> {
    MemoryRelationshipKind::from_str(&value)
        .map_err(|_| StorageError::InvalidRelationshipKind(value))
}

fn decode_memory_state(value: String) -> Result<MemoryState, StorageError> {
    MemoryState::from_str(&value).map_err(|_| StorageError::InvalidMemoryState(value))
}

fn decode_priority(value: String) -> Result<MemoryPriority, StorageError> {
    MemoryPriority::from_str(&value).map_err(|_| StorageError::InvalidPriority(value))
}

fn decode_retention_class(value: String) -> Result<RetentionClass, StorageError> {
    RetentionClass::from_str(&value).map_err(|_| StorageError::InvalidRetentionClass(value))
}

fn decode_decay_policy(kind: String, rate: Option<u8>) -> Result<DecayPolicy, StorageError> {
    DecayPolicy::from_parts(&kind, rate).ok_or(StorageError::InvalidDecayPolicy { kind, rate })
}

fn decode_strength(value: u8) -> Result<MemoryStrength, StorageError> {
    MemoryStrength::new(value).ok_or(StorageError::InvalidStrength(value))
}

fn decode_confidence(value: u8) -> Result<MemoryConfidence, StorageError> {
    MemoryConfidence::new(value).ok_or(StorageError::InvalidConfidence(value))
}

fn decode_reinforcement(
    reason: Option<String>,
    incident_id: Option<String>,
    evidence_ids_json: Option<String>,
) -> Result<Option<ReinforcementProvenance>, StorageError> {
    let Some(reason) = reason else {
        return Ok(None);
    };

    let evidence_ids = evidence_ids_json
        .map(|json| serde_json::from_str::<Vec<String>>(&json))
        .transpose()
        .map_err(StorageError::InvalidReinforcementEvidenceJson)?
        .unwrap_or_default()
        .into_iter()
        .map(EvidenceId)
        .collect();

    Ok(Some(ReinforcementProvenance {
        reason: ReinforcementReason::from_str(&reason)
            .map_err(|_| StorageError::InvalidReinforcementReason(reason))?,
        incident_id: incident_id.map(IncidentId),
        evidence_ids,
    }))
}

pub struct MemoryStore {
    connection: Connection,
}

impl MemoryStore {
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let connection = Connection::open(path)?;

        Ok(Self { connection })
    }

    pub fn ping(&self) -> rusqlite::Result<()> {
        self.connection.execute_batch("SELECT 1;")?;
        Ok(())
    }

    pub fn node_count(&self) -> rusqlite::Result<u64> {
        self.connection
            .query_row("SELECT COUNT(*) FROM memory_nodes", [], |row| row.get(0))
    }

    pub fn nodes(&self, kind: Option<MemoryNodeKind>) -> Result<Vec<MemoryNode>, StorageError> {
        let ids = if let Some(kind) = kind {
            let mut statement = self.connection.prepare(
                "
                SELECT id
                FROM memory_nodes
                WHERE kind = ?
                ORDER BY id
                ",
            )?;
            statement
                .query_map([kind.as_str()], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            let mut statement = self.connection.prepare(
                "
                SELECT id
                FROM memory_nodes
                ORDER BY id
                ",
            )?;
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };

        let mut nodes = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(node) = self.load_node(&MemoryNodeId(id))? {
                nodes.push(node);
            }
        }

        Ok(nodes)
    }

    pub fn recent_nodes(&self, limit: usize) -> Result<Vec<MemoryNode>, StorageError> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let mut statement = self.connection.prepare(
            "
            SELECT id
            FROM memory_nodes
            ORDER BY last_seen_at DESC, id ASC
            LIMIT ?
            ",
        )?;
        let ids = statement
            .query_map([i64::try_from(limit).unwrap_or(i64::MAX)], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut nodes = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(node) = self.load_node(&MemoryNodeId(id))? {
                nodes.push(node);
            }
        }

        Ok(nodes)
    }

    pub fn initialise(&self) -> rusqlite::Result<()> {
        self.connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS memory_nodes (
                id              TEXT PRIMARY KEY,
                kind            TEXT NOT NULL,
                label           TEXT NOT NULL,
                created_at      INTEGER NOT NULL,
                last_seen_at    INTEGER NOT NULL,
                expires_at      INTEGER,
                state           TEXT NOT NULL,
                priority        TEXT NOT NULL,
                retention       TEXT NOT NULL,
                decay_policy    TEXT NOT NULL,
                decay_rate      INTEGER
            );

            CREATE TABLE IF NOT EXISTS memory_relationships (
                id                          TEXT PRIMARY KEY,
                kind                        TEXT NOT NULL,
                source                      TEXT NOT NULL,
                target                      TEXT NOT NULL,
                created_at                  INTEGER NOT NULL,
                last_seen_at                INTEGER NOT NULL,
                observation_count           INTEGER NOT NULL,
                expires_at                  INTEGER,
                state                       TEXT NOT NULL,
                priority                    TEXT NOT NULL,
                retention                   TEXT NOT NULL,
                decay_policy                TEXT NOT NULL,
                decay_rate                  INTEGER,
                strength                    INTEGER NOT NULL,
                confidence                  INTEGER NOT NULL,
                reinforcement_reason        TEXT,
                reinforcement_incident_id   TEXT,
                reinforcement_evidence_ids  TEXT
            );
            ",
        )?;

        Ok(())
    }

    pub fn save_node(&self, node: &MemoryNode) -> rusqlite::Result<()> {
        let decay_rate = node.decay_policy.rate().map(|rate| rate.value());

        self.connection.execute(
            "
            INSERT INTO memory_nodes (
                id,
                kind,
                label,
                created_at,
                last_seen_at,
                expires_at,
                state,
                priority,
                retention,
                decay_policy,
                decay_rate
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                kind = excluded.kind,
                label = excluded.label,
                last_seen_at = excluded.last_seen_at,
                expires_at = excluded.expires_at,
                state = excluded.state,
                priority = excluded.priority,
                retention = excluded.retention,
                decay_policy = excluded.decay_policy,
                decay_rate = excluded.decay_rate
            ",
            params![
                &node.id.0,
                node.kind.as_str(),
                &node.label,
                node.created_at,
                node.last_seen_at,
                node.expires_at,
                node.state.as_str(),
                node.priority.as_str(),
                node.retention.as_str(),
                node.decay_policy.as_str(),
                decay_rate,
            ],
        )?;

        Ok(())
    }

    pub fn load_node(&self, id: &MemoryNodeId) -> Result<Option<MemoryNode>, StorageError> {
        let stored = self
            .connection
            .query_row(
                "
                SELECT
                    id,
                    kind,
                    label,
                    created_at,
                    last_seen_at,
                    expires_at,
                    state,
                    priority,
                    retention,
                    decay_policy,
                    decay_rate
                FROM memory_nodes
                WHERE id = ?
                ",
                [&id.0],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, u64>(3)?,
                        row.get::<_, u64>(4)?,
                        row.get::<_, Option<u64>>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, Option<u8>>(10)?,
                    ))
                },
            )
            .optional()?;

        let Some((
            id,
            kind,
            label,
            created_at,
            last_seen_at,
            expires_at,
            state,
            priority,
            retention,
            decay_policy,
            decay_rate,
        )) = stored
        else {
            return Ok(None);
        };

        Ok(Some(MemoryNode {
            id: MemoryNodeId(id),
            kind: decode_node_kind(kind)?,
            label,
            created_at,
            last_seen_at,
            expires_at,
            state: decode_memory_state(state)?,
            priority: decode_priority(priority)?,
            retention: decode_retention_class(retention)?,
            decay_policy: decode_decay_policy(decay_policy, decay_rate)?,
        }))
    }

    pub fn save_relationship(&self, relationship: &MemoryRelationship) -> rusqlite::Result<()> {
        let decay_rate = relationship.decay_policy.rate().map(|rate| rate.value());

        let reinforcement_reason = relationship
            .reinforcement
            .as_ref()
            .map(|reinforcement| reinforcement.reason.as_str());

        let reinforcement_incident_id = relationship
            .reinforcement
            .as_ref()
            .and_then(|reinforcement| reinforcement.incident_id.as_ref())
            .map(|id| id.0.as_str());

        let reinforcement_evidence_ids = relationship
            .reinforcement
            .as_ref()
            .map(|reinforcement| {
                reinforcement
                    .evidence_ids
                    .iter()
                    .map(|id| id.0.as_str())
                    .collect::<Vec<_>>()
            })
            .map(|ids| serde_json::to_string(&ids))
            .transpose()
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;

        self.connection.execute(
            "
            INSERT INTO memory_relationships (
                id,
                kind,
                source,
                target,
                created_at,
                last_seen_at,
                observation_count,
                expires_at,
                state,
                priority,
                retention,
                decay_policy,
                decay_rate,
                strength,
                confidence,
                reinforcement_reason,
                reinforcement_incident_id,
                reinforcement_evidence_ids
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                kind = excluded.kind,
                source = excluded.source,
                target = excluded.target,
                last_seen_at = excluded.last_seen_at,
                observation_count = excluded.observation_count,
                expires_at = excluded.expires_at,
                state = excluded.state,
                priority = excluded.priority,
                retention = excluded.retention,
                decay_policy = excluded.decay_policy,
                decay_rate = excluded.decay_rate,
                strength = excluded.strength,
                confidence = excluded.confidence,
                reinforcement_reason = excluded.reinforcement_reason,
                reinforcement_incident_id = excluded.reinforcement_incident_id,
                reinforcement_evidence_ids = excluded.reinforcement_evidence_ids
            ",
            params![
                &relationship.id.0,
                relationship.kind.as_str(),
                &relationship.source.0,
                &relationship.target.0,
                relationship.created_at,
                relationship.last_seen_at,
                relationship.observation_count,
                relationship.expires_at,
                relationship.state.as_str(),
                relationship.priority.as_str(),
                relationship.retention.as_str(),
                relationship.decay_policy.as_str(),
                decay_rate,
                relationship.strength.value(),
                relationship.confidence.value(),
                reinforcement_reason,
                reinforcement_incident_id,
                reinforcement_evidence_ids,
            ],
        )?;

        Ok(())
    }

    pub fn load_relationship(
        &self,
        id: &MemoryRelationshipId,
    ) -> Result<Option<MemoryRelationship>, StorageError> {
        let stored = self
            .connection
            .query_row(
                "
                SELECT
                    id,
                    kind,
                    source,
                    target,
                    created_at,
                    last_seen_at,
                    observation_count,
                    expires_at,
                    state,
                    priority,
                    retention,
                    decay_policy,
                    decay_rate,
                    strength,
                    confidence,
                    reinforcement_reason,
                    reinforcement_incident_id,
                    reinforcement_evidence_ids
                FROM memory_relationships
                WHERE id = ?
                ",
                [&id.0],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, u64>(4)?,
                        row.get::<_, u64>(5)?,
                        row.get::<_, u64>(6)?,
                        row.get::<_, Option<u64>>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, String>(10)?,
                        row.get::<_, String>(11)?,
                        row.get::<_, Option<u8>>(12)?,
                        row.get::<_, u8>(13)?,
                        row.get::<_, u8>(14)?,
                        row.get::<_, Option<String>>(15)?,
                        row.get::<_, Option<String>>(16)?,
                        row.get::<_, Option<String>>(17)?,
                    ))
                },
            )
            .optional()?;

        let Some((
            id,
            kind,
            source,
            target,
            created_at,
            last_seen_at,
            observation_count,
            expires_at,
            state,
            priority,
            retention,
            decay_policy,
            decay_rate,
            strength,
            confidence,
            reinforcement_reason,
            reinforcement_incident_id,
            reinforcement_evidence_ids,
        )) = stored
        else {
            return Ok(None);
        };

        Ok(Some(MemoryRelationship {
            id: MemoryRelationshipId(id),
            kind: decode_relationship_kind(kind)?,
            source: MemoryNodeId(source),
            target: MemoryNodeId(target),
            created_at,
            last_seen_at,
            observation_count,
            expires_at,
            state: decode_memory_state(state)?,
            priority: decode_priority(priority)?,
            retention: decode_retention_class(retention)?,
            decay_policy: decode_decay_policy(decay_policy, decay_rate)?,
            strength: decode_strength(strength)?,
            confidence: decode_confidence(confidence)?,
            reinforcement: decode_reinforcement(
                reinforcement_reason,
                reinforcement_incident_id,
                reinforcement_evidence_ids,
            )?,
        }))
    }

    pub fn relationships_from(
        &self,
        node_id: &MemoryNodeId,
    ) -> Result<Vec<MemoryRelationship>, StorageError> {
        let mut statement = self.connection.prepare(
            "
            SELECT id
            FROM memory_relationships
            WHERE source = ?
            ORDER BY id
            ",
        )?;

        let ids = statement
            .query_map([&node_id.0], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        self.load_relationships(ids)
    }

    pub fn relationships_to(
        &self,
        node_id: &MemoryNodeId,
    ) -> Result<Vec<MemoryRelationship>, StorageError> {
        let mut statement = self.connection.prepare(
            "
            SELECT id
            FROM memory_relationships
            WHERE target = ?
            ORDER BY id
            ",
        )?;

        let ids = statement
            .query_map([&node_id.0], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        self.load_relationships(ids)
    }

    pub fn relationships_for(
        &self,
        node_id: &MemoryNodeId,
    ) -> Result<Vec<MemoryRelationship>, StorageError> {
        let mut statement = self.connection.prepare(
            "
            SELECT id
            FROM memory_relationships
            WHERE source = ? OR target = ?
            ORDER BY id
            ",
        )?;

        let ids = statement
            .query_map(params![&node_id.0, &node_id.0], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        self.load_relationships(ids)
    }

    pub fn neighbours(&self, node_id: &MemoryNodeId) -> Result<Vec<MemoryNodeId>, StorageError> {
        let relationships = self.relationships_for(node_id)?;
        let mut neighbours = relationships
            .into_iter()
            .filter_map(|relationship| {
                if relationship.source == *node_id && relationship.target != *node_id {
                    Some(relationship.target)
                } else if relationship.target == *node_id && relationship.source != *node_id {
                    Some(relationship.source)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        neighbours.sort_by(|left, right| left.0.cmp(&right.0));
        neighbours.dedup();

        Ok(neighbours)
    }

    pub fn traverse(
        &self,
        start: &MemoryNodeId,
        max_depth: usize,
    ) -> Result<Vec<TraversalVisit>, StorageError> {
        if max_depth == 0 {
            return Ok(Vec::new());
        }

        let mut visited = HashSet::new();
        visited.insert(start.0.clone());

        let mut queue = VecDeque::new();
        queue.push_back((start.clone(), 0_usize));

        let mut visits = Vec::new();

        while let Some((node_id, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }

            for neighbour in self.neighbours(&node_id)? {
                if !visited.insert(neighbour.0.clone()) {
                    continue;
                }

                let neighbour_depth = depth + 1;
                visits.push(TraversalVisit {
                    node_id: neighbour.clone(),
                    depth: neighbour_depth,
                });
                queue.push_back((neighbour, neighbour_depth));
            }
        }

        Ok(visits)
    }

    pub fn expired_nodes(&self, now: u64) -> Result<Vec<MemoryNode>, StorageError> {
        let mut statement = self.connection.prepare(
            "
            SELECT id
            FROM memory_nodes
            WHERE expires_at IS NOT NULL
              AND expires_at <= ?
              AND state IN ('observed', 'correlated', 'supported', 'established')
            ORDER BY id
            ",
        )?;

        let ids = statement
            .query_map([now], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut nodes = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(node) = self.load_node(&MemoryNodeId(id))? {
                nodes.push(node);
            }
        }
        Ok(nodes)
    }

    pub fn expired_relationships(&self, now: u64) -> Result<Vec<MemoryRelationship>, StorageError> {
        let mut statement = self.connection.prepare(
            "
            SELECT id
            FROM memory_relationships
            WHERE expires_at IS NOT NULL
              AND expires_at <= ?
              AND state IN ('observed', 'correlated', 'supported', 'established')
            ORDER BY id
            ",
        )?;

        let ids = statement
            .query_map([now], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        self.load_relationships(ids)
    }

    pub fn mark_expired(&self, now: u64) -> Result<LifecycleUpdate, StorageError> {
        let relationships_expired = self.connection.execute(
            "
            UPDATE memory_relationships
            SET state = 'expired'
            WHERE expires_at IS NOT NULL
              AND expires_at <= ?
              AND state IN ('observed', 'correlated', 'supported', 'established')
            ",
            [now],
        )?;

        let nodes_expired = self.connection.execute(
            "
            UPDATE memory_nodes
            SET state = 'expired'
            WHERE expires_at IS NOT NULL
              AND expires_at <= ?
              AND state IN ('observed', 'correlated', 'supported', 'established')
            ",
            [now],
        )?;

        Ok(LifecycleUpdate {
            relationships_expired,
            nodes_expired,
        })
    }

    pub fn purge_eligible_nodes(
        &self,
        now: u64,
        grace_period: u64,
    ) -> Result<Vec<MemoryNode>, StorageError> {
        let mut statement = self.connection.prepare(
            "
            SELECT id
            FROM memory_nodes
            WHERE state = 'expired'
              AND retention != 'persistent'
            ORDER BY id
            ",
        )?;

        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut nodes = Vec::new();
        for id in ids {
            if let Some(node) = self.load_node(&MemoryNodeId(id))?
                && node.is_purge_eligible(now, grace_period)
            {
                nodes.push(node);
            }
        }
        Ok(nodes)
    }

    pub fn purge_eligible_relationships(
        &self,
        now: u64,
        grace_period: u64,
    ) -> Result<Vec<MemoryRelationship>, StorageError> {
        let mut statement = self.connection.prepare(
            "
            SELECT id
            FROM memory_relationships
            WHERE state = 'expired'
              AND retention != 'persistent'
            ORDER BY id
            ",
        )?;

        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(self
            .load_relationships(ids)?
            .into_iter()
            .filter(|relationship| relationship.is_purge_eligible(now, grace_period))
            .collect())
    }

    pub fn evaluate_decay(
        &self,
        now: u64,
    ) -> Result<Vec<RelationshipDecayEvaluation>, StorageError> {
        let mut statement = self.connection.prepare(
            "
            SELECT id
            FROM memory_relationships
            WHERE state IN ('observed', 'correlated', 'supported', 'established')
            ORDER BY id
            ",
        )?;

        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(self
            .load_relationships(ids)?
            .into_iter()
            .map(|relationship| RelationshipDecayEvaluation {
                relationship_id: relationship.id.clone(),
                stored_strength: relationship.strength,
                effective_strength: relationship.effective_strength(now),
            })
            .collect())
    }

    pub fn reinforce_relationship(
        &self,
        id: &MemoryRelationshipId,
        reinforcement: ReinforcementProvenance,
    ) -> Result<bool, StorageError> {
        let Some(mut relationship) = self.load_relationship(id)? else {
            return Ok(false);
        };

        relationship.reinforcement = Some(reinforcement);
        self.save_relationship(&relationship)?;
        Ok(true)
    }

    pub fn revoke_relationship_reinforcement(
        &self,
        id: &MemoryRelationshipId,
    ) -> Result<bool, StorageError> {
        let Some(mut relationship) = self.load_relationship(id)? else {
            return Ok(false);
        };

        relationship.reinforcement = None;
        self.save_relationship(&relationship)?;
        Ok(true)
    }

    pub fn observe_relationship(
        &self,
        observation: &MemoryRelationship,
    ) -> Result<MemoryRelationshipId, StorageError> {
        let mut statement = self.connection.prepare(
            "
            SELECT id
            FROM memory_relationships
            WHERE kind = ?
              AND source = ?
              AND target = ?
              AND state != 'revoked'
            ORDER BY created_at, id
            LIMIT 1
            ",
        )?;

        let existing_id = statement
            .query_row(
                params![
                    observation.kind.as_str(),
                    &observation.source.0,
                    &observation.target.0,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;

        if let Some(existing_id) = existing_id {
            let id = MemoryRelationshipId(existing_id);
            let Some(mut existing) = self.load_relationship(&id)? else {
                return Ok(id);
            };

            existing.record_observation(observation.last_seen_at);
            existing.expires_at = match (existing.expires_at, observation.expires_at) {
                (Some(left), Some(right)) => Some(left.max(right)),
                (None, other) | (other, None) => other,
            };
            existing.priority = existing.priority.max(observation.priority);
            existing.strength = existing.strength.max(observation.strength);
            existing.confidence = existing.confidence.max(observation.confidence);
            if existing.state == MemoryState::Expired {
                existing.state = MemoryState::Observed;
            }

            self.save_relationship(&existing)?;
            return Ok(id);
        }

        self.save_relationship(observation)?;
        Ok(observation.id.clone())
    }

    pub fn active_relationships_for(
        &self,
        node_id: &MemoryNodeId,
    ) -> Result<Vec<MemoryRelationship>, StorageError> {
        Ok(self
            .relationships_for(node_id)?
            .into_iter()
            .filter(|relationship| relationship.state.is_active_for_reasoning())
            .collect())
    }

    pub fn find_path(
        &self,
        start: &MemoryNodeId,
        target: &MemoryNodeId,
        query: &PathQuery,
    ) -> Result<Option<MemoryPath>, StorageError> {
        if start == target {
            return Ok(Some(MemoryPath {
                nodes: vec![start.clone()],
                relationships: Vec::new(),
                weakest_strength: MemoryStrength::new(100).expect("100 must be valid"),
                weakest_confidence: MemoryConfidence::new(100).expect("100 must be valid"),
            }));
        }

        if query.max_depth == 0 {
            return Ok(None);
        }

        #[derive(Clone)]
        struct Candidate {
            node: MemoryNodeId,
            nodes: Vec<MemoryNodeId>,
            relationships: Vec<MemoryRelationshipId>,
            weakest_strength: MemoryStrength,
            weakest_confidence: MemoryConfidence,
        }

        let full_strength = MemoryStrength::new(100).expect("100 must be valid");
        let full_confidence = MemoryConfidence::new(100).expect("100 must be valid");
        let mut visited = HashSet::from([start.0.clone()]);
        let mut queue = VecDeque::from([Candidate {
            node: start.clone(),
            nodes: vec![start.clone()],
            relationships: Vec::new(),
            weakest_strength: full_strength,
            weakest_confidence: full_confidence,
        }]);

        while let Some(candidate) = queue.pop_front() {
            if candidate.relationships.len() >= query.max_depth {
                continue;
            }

            for relationship in self.reasoning_relationships(&candidate.node, query)? {
                let next = match query.direction {
                    TraversalDirection::Any if relationship.source == candidate.node => {
                        relationship.target.clone()
                    }
                    TraversalDirection::Any => relationship.source.clone(),
                    TraversalDirection::Outgoing => relationship.target.clone(),
                    TraversalDirection::Incoming => relationship.source.clone(),
                };

                if !visited.insert(next.0.clone()) {
                    continue;
                }

                let mut nodes = candidate.nodes.clone();
                nodes.push(next.clone());
                let mut relationships = candidate.relationships.clone();
                relationships.push(relationship.id.clone());
                let edge_strength = query.evaluation_time.map_or(relationship.strength, |now| {
                    relationship.effective_strength(now)
                });
                let weakest_strength = candidate.weakest_strength.min(edge_strength);
                let weakest_confidence = candidate.weakest_confidence.min(relationship.confidence);

                if next == *target {
                    return Ok(Some(MemoryPath {
                        nodes,
                        relationships,
                        weakest_strength,
                        weakest_confidence,
                    }));
                }

                queue.push_back(Candidate {
                    node: next,
                    nodes,
                    relationships,
                    weakest_strength,
                    weakest_confidence,
                });
            }
        }

        Ok(None)
    }

    pub fn threat_paths_from(
        &self,
        start: &MemoryNodeId,
        query: &PathQuery,
    ) -> Result<Vec<ThreatPath>, StorageError> {
        let mut statement = self.connection.prepare(
            "
            SELECT id
            FROM memory_nodes
            WHERE kind = 'threat'
              AND state IN ('observed', 'correlated', 'supported', 'established')
            ORDER BY id
            ",
        )?;

        let threat_ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut paths = Vec::new();
        for threat_id in threat_ids {
            let threat = MemoryNodeId(threat_id);
            if let Some(path) = self.find_path(start, &threat, query)? {
                paths.push(ThreatPath { threat, path });
            }
        }

        paths.sort_by(|left, right| {
            right
                .path
                .score()
                .cmp(&left.path.score())
                .then_with(|| {
                    left.path
                        .relationships
                        .len()
                        .cmp(&right.path.relationships.len())
                })
                .then_with(|| left.threat.0.cmp(&right.threat.0))
        });

        Ok(paths)
    }

    fn reasoning_relationships(
        &self,
        node_id: &MemoryNodeId,
        query: &PathQuery,
    ) -> Result<Vec<MemoryRelationship>, StorageError> {
        let relationships = match query.direction {
            TraversalDirection::Any => self.relationships_for(node_id)?,
            TraversalDirection::Outgoing => self.relationships_from(node_id)?,
            TraversalDirection::Incoming => self.relationships_to(node_id)?,
        };

        Ok(relationships
            .into_iter()
            .filter(|relationship| relationship.state.is_active_for_reasoning())
            .filter(|relationship| {
                query.relationship_kinds.is_empty()
                    || query.relationship_kinds.contains(&relationship.kind)
            })
            .filter(|relationship| {
                let strength = query.evaluation_time.map_or(relationship.strength, |now| {
                    relationship.effective_strength(now)
                });
                query
                    .minimum_strength
                    .is_none_or(|minimum| strength >= minimum)
            })
            .filter(|relationship| {
                query
                    .minimum_confidence
                    .is_none_or(|minimum| relationship.confidence >= minimum)
            })
            .collect())
    }

    fn load_relationships(
        &self,
        ids: Vec<String>,
    ) -> Result<Vec<MemoryRelationship>, StorageError> {
        let mut relationships = Vec::with_capacity(ids.len());

        for id in ids {
            if let Some(relationship) = self.load_relationship(&MemoryRelationshipId(id))? {
                relationships.push(relationship);
            }
        }

        Ok(relationships)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DecayRate;

    fn test_relationship(id: &str, source: &str, target: &str) -> MemoryRelationship {
        MemoryRelationship {
            id: MemoryRelationshipId(id.into()),
            kind: MemoryRelationshipKind::AssociatedWith,
            source: MemoryNodeId(source.into()),
            target: MemoryNodeId(target.into()),
            created_at: 100,
            last_seen_at: 100,
            observation_count: 1,
            expires_at: None,
            state: MemoryState::Observed,
            priority: MemoryPriority::Normal,
            retention: RetentionClass::ShortTerm,
            decay_policy: DecayPolicy::None,
            strength: MemoryStrength::new(50).unwrap(),
            confidence: MemoryConfidence::new(50).unwrap(),
            reinforcement: None,
        }
    }

    fn save_test_relationships(store: &MemoryStore, relationships: &[MemoryRelationship]) {
        for relationship in relationships {
            store.save_relationship(relationship).unwrap();
        }
    }

    #[test]
    fn initialise_creates_memory_nodes_table() {
        let store = MemoryStore::open(":memory:").unwrap();

        store.initialise().unwrap();

        let count: i64 = store
            .connection
            .query_row(
                "
                SELECT COUNT(*)
                FROM sqlite_master
                WHERE type = 'table'
                  AND name = 'memory_nodes'
                ",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(count, 1);
    }

    #[test]
    fn initialise_creates_memory_relationships_table() {
        let store = MemoryStore::open(":memory:").unwrap();

        store.initialise().unwrap();

        let count: i64 = store
            .connection
            .query_row(
                "
                SELECT COUNT(*)
                FROM sqlite_master
                WHERE type = 'table'
                AND name = 'memory_relationships'
                ",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(count, 1);
    }

    #[test]
    fn save_node_persists_memory_node() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

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

        store.save_node(&node).unwrap();

        let (id, kind, label): (String, String, String) = store
            .connection
            .query_row(
                "
                SELECT id, kind, label
                FROM memory_nodes
                WHERE id = ?
                ",
                [&node.id.0],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();

        assert_eq!(id, "node-1");
        assert_eq!(kind, "process");
        assert_eq!(label, "nginx");
    }

    #[test]
    fn load_node_returns_persisted_memory_node() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        let node = MemoryNode {
            id: MemoryNodeId("node-1".into()),
            kind: MemoryNodeKind::Process,
            label: "nginx".into(),
            created_at: 100,
            last_seen_at: 200,
            expires_at: Some(300),
            state: MemoryState::Supported,
            priority: MemoryPriority::Elevated,
            retention: RetentionClass::LongTerm,
            decay_policy: DecayPolicy::Linear {
                rate: DecayRate::new(25).unwrap(),
            },
        };

        store.save_node(&node).unwrap();

        let loaded = store
            .load_node(&node.id)
            .unwrap()
            .expect("saved node should exist");

        assert_eq!(loaded, node);
    }

    #[test]
    fn load_node_returns_none_when_node_does_not_exist() {
        use crate::model::MemoryNodeId;

        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        let loaded = store
            .load_node(&MemoryNodeId("missing-node".into()))
            .unwrap();

        assert_eq!(loaded, None);
    }

    #[test]
    fn save_node_updates_existing_node_without_changing_created_at() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        let original = MemoryNode {
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

        store.save_node(&original).unwrap();

        let updated = MemoryNode {
            id: MemoryNodeId("node-1".into()),
            kind: MemoryNodeKind::Process,
            label: "nginx-worker".into(),
            created_at: 999,
            last_seen_at: 250,
            expires_at: Some(400),
            state: MemoryState::Supported,
            priority: MemoryPriority::Elevated,
            retention: RetentionClass::LongTerm,
            decay_policy: DecayPolicy::None,
        };

        store.save_node(&updated).unwrap();

        let (created_at, last_seen_at, label): (u64, u64, String) = store
            .connection
            .query_row(
                "
                SELECT created_at, last_seen_at, label
                FROM memory_nodes
                WHERE id = ?
                ",
                [&updated.id.0],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();

        assert_eq!(created_at, 100);
        assert_eq!(last_seen_at, 250);
        assert_eq!(label, "nginx-worker");
    }

    #[test]
    fn save_relationship_persists_memory_relationship() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        let relationship = MemoryRelationship {
            id: MemoryRelationshipId("rel-1".into()),
            kind: MemoryRelationshipKind::ConnectedTo,
            source: MemoryNodeId("node-1".into()),
            target: MemoryNodeId("node-2".into()),
            created_at: 100,
            last_seen_at: 200,
            observation_count: 3,
            expires_at: Some(300),
            state: MemoryState::Observed,
            priority: MemoryPriority::Normal,
            retention: RetentionClass::ShortTerm,
            decay_policy: DecayPolicy::None,
            strength: MemoryStrength::new(70).unwrap(),
            confidence: MemoryConfidence::new(80).unwrap(),
            reinforcement: None,
        };

        store.save_relationship(&relationship).unwrap();

        let (id, kind, source, target): (String, String, String, String) = store
            .connection
            .query_row(
                "
                SELECT id, kind, source, target
                FROM memory_relationships
                WHERE id = ?
                ",
                [&relationship.id.0],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();

        assert_eq!(id, "rel-1");
        assert_eq!(kind, "connected_to");
        assert_eq!(source, "node-1");
        assert_eq!(target, "node-2");
    }

    #[test]
    fn load_relationship_returns_persisted_memory_relationship() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        let relationship = MemoryRelationship {
            id: MemoryRelationshipId("rel-1".into()),
            kind: MemoryRelationshipKind::AssociatedWith,
            source: MemoryNodeId("node-1".into()),
            target: MemoryNodeId("node-2".into()),
            created_at: 100,
            last_seen_at: 200,
            observation_count: 4,
            expires_at: Some(500),
            state: MemoryState::Established,
            priority: MemoryPriority::High,
            retention: RetentionClass::LongTerm,
            decay_policy: DecayPolicy::Linear {
                rate: DecayRate::new(20).unwrap(),
            },
            strength: MemoryStrength::new(90).unwrap(),
            confidence: MemoryConfidence::new(95).unwrap(),
            reinforcement: Some(ReinforcementProvenance {
                reason: ReinforcementReason::ConfirmedHighRisk,
                incident_id: Some(IncidentId("incident-1".into())),
                evidence_ids: vec![
                    EvidenceId("evidence-1".into()),
                    EvidenceId("evidence-2".into()),
                ],
            }),
        };

        store.save_relationship(&relationship).unwrap();

        let loaded = store
            .load_relationship(&relationship.id)
            .unwrap()
            .expect("saved relationship should exist");

        assert_eq!(loaded, relationship);
    }

    #[test]
    fn load_relationship_returns_none_when_relationship_does_not_exist() {
        use crate::model::MemoryRelationshipId;

        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        let loaded = store
            .load_relationship(&MemoryRelationshipId("missing-relationship".into()))
            .unwrap();

        assert_eq!(loaded, None);
    }

    #[test]
    fn load_relationship_round_trips_without_reinforcement() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        let relationship = MemoryRelationship {
            id: MemoryRelationshipId("rel-no-reinforcement".into()),
            kind: MemoryRelationshipKind::Executed,
            source: MemoryNodeId("process-1".into()),
            target: MemoryNodeId("file-1".into()),
            created_at: 100,
            last_seen_at: 150,
            observation_count: 2,
            expires_at: Some(500),
            state: MemoryState::Correlated,
            priority: MemoryPriority::Elevated,
            retention: RetentionClass::ShortTerm,
            decay_policy: DecayPolicy::Linear {
                rate: DecayRate::new(15).unwrap(),
            },
            strength: MemoryStrength::new(65).unwrap(),
            confidence: MemoryConfidence::new(75).unwrap(),
            reinforcement: None,
        };

        store.save_relationship(&relationship).unwrap();

        let loaded = store
            .load_relationship(&relationship.id)
            .unwrap()
            .expect("saved relationship should exist");

        assert_eq!(loaded, relationship);
    }

    #[test]
    fn save_relationship_persists_reinforcement_evidence_ids() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        let relationship = MemoryRelationship {
            id: MemoryRelationshipId("rel-1".into()),
            kind: MemoryRelationshipKind::AssociatedWith,
            source: MemoryNodeId("node-1".into()),
            target: MemoryNodeId("node-2".into()),
            created_at: 100,
            last_seen_at: 200,
            observation_count: 1,
            expires_at: None,
            state: MemoryState::Established,
            priority: MemoryPriority::High,
            retention: RetentionClass::LongTerm,
            decay_policy: DecayPolicy::None,
            strength: MemoryStrength::new(90).unwrap(),
            confidence: MemoryConfidence::new(95).unwrap(),
            reinforcement: Some(ReinforcementProvenance {
                reason: ReinforcementReason::ConfirmedHighRisk,
                incident_id: None,
                evidence_ids: vec![
                    EvidenceId("evidence-1".into()),
                    EvidenceId("evidence-2".into()),
                ],
            }),
        };

        store.save_relationship(&relationship).unwrap();

        let stored: String = store
            .connection
            .query_row(
                "
                SELECT reinforcement_evidence_ids
                FROM memory_relationships
                WHERE id = ?
                ",
                [&relationship.id.0],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(stored, r#"["evidence-1","evidence-2"]"#);
    }

    #[test]
    fn save_relationship_updates_existing_relationship_without_changing_created_at() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        let original = MemoryRelationship {
            id: MemoryRelationshipId("rel-1".into()),
            kind: MemoryRelationshipKind::ConnectedTo,
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
            strength: MemoryStrength::new(60).unwrap(),
            confidence: MemoryConfidence::new(70).unwrap(),
            reinforcement: None,
        };

        store.save_relationship(&original).unwrap();

        let updated = MemoryRelationship {
            id: MemoryRelationshipId("rel-1".into()),
            kind: MemoryRelationshipKind::AssociatedWith,
            source: MemoryNodeId("node-1".into()),
            target: MemoryNodeId("node-3".into()),
            created_at: 999,
            last_seen_at: 250,
            observation_count: 4,
            expires_at: Some(500),
            state: MemoryState::Supported,
            priority: MemoryPriority::High,
            retention: RetentionClass::LongTerm,
            decay_policy: DecayPolicy::None,
            strength: MemoryStrength::new(85).unwrap(),
            confidence: MemoryConfidence::new(90).unwrap(),
            reinforcement: None,
        };

        store.save_relationship(&updated).unwrap();

        let loaded = store
            .load_relationship(&updated.id)
            .unwrap()
            .expect("updated relationship should exist");

        assert_eq!(loaded.created_at, 100);
        assert_eq!(loaded.last_seen_at, 250);
        assert_eq!(loaded.observation_count, 4);
        assert_eq!(loaded.kind, MemoryRelationshipKind::AssociatedWith);
        assert_eq!(loaded.target, MemoryNodeId("node-3".into()));
        assert_eq!(loaded.strength, MemoryStrength::new(85).unwrap());
        assert_eq!(loaded.confidence, MemoryConfidence::new(90).unwrap());
    }

    #[test]
    fn load_node_rejects_invalid_stored_kind() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        store
            .connection
            .execute(
                "
                INSERT INTO memory_nodes (
                    id,
                    kind,
                    label,
                    created_at,
                    last_seen_at,
                    expires_at,
                    state,
                    priority,
                    retention,
                    decay_policy,
                    decay_rate
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ",
                params![
                    "node-invalid-kind",
                    "definitely_not_a_kind",
                    "invalid node",
                    100_u64,
                    200_u64,
                    Option::<u64>::None,
                    "observed",
                    "normal",
                    "short_term",
                    "none",
                    Option::<u8>::None,
                ],
            )
            .unwrap();

        let result = store.load_node(&MemoryNodeId("node-invalid-kind".into()));

        assert!(matches!(
            result,
            Err(StorageError::InvalidNodeKind(ref value))
                if value == "definitely_not_a_kind"
        ));
    }

    #[test]
    fn load_node_rejects_invalid_stored_decay_rate() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        store
            .connection
            .execute(
                "
                INSERT INTO memory_nodes (
                    id,
                    kind,
                    label,
                    created_at,
                    last_seen_at,
                    expires_at,
                    state,
                    priority,
                    retention,
                    decay_policy,
                    decay_rate
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ",
                params![
                    "node-invalid-decay",
                    "process",
                    "invalid decay node",
                    100_u64,
                    200_u64,
                    Option::<u64>::None,
                    "observed",
                    "normal",
                    "short_term",
                    "linear",
                    101_u8,
                ],
            )
            .unwrap();

        let result = store.load_node(&MemoryNodeId("node-invalid-decay".into()));

        assert!(matches!(
            result,
            Err(StorageError::InvalidDecayPolicy {
                ref kind,
                rate: Some(101),
            }) if kind == "linear"
        ));
    }

    #[test]
    fn load_relationship_rejects_malformed_reinforcement_evidence_json() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        store
            .connection
            .execute(
                "
                INSERT INTO memory_relationships (
                    id,
                    kind,
                    source,
                    target,
                    created_at,
                    last_seen_at,
                    observation_count,
                    expires_at,
                    state,
                    priority,
                    retention,
                    decay_policy,
                    decay_rate,
                    strength,
                    confidence,
                    reinforcement_reason,
                    reinforcement_incident_id,
                    reinforcement_evidence_ids
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ",
                params![
                    "rel-invalid-json",
                    "associated_with",
                    "node-1",
                    "node-2",
                    100_u64,
                    200_u64,
                    1_u64,
                    Option::<u64>::None,
                    "established",
                    "high",
                    "long_term",
                    "none",
                    Option::<u8>::None,
                    90_u8,
                    95_u8,
                    "confirmed_high_risk",
                    Option::<String>::None,
                    "{this is not valid json",
                ],
            )
            .unwrap();

        let result = store.load_relationship(&MemoryRelationshipId("rel-invalid-json".into()));

        assert!(matches!(
            result,
            Err(StorageError::InvalidReinforcementEvidenceJson(_))
        ));
    }

    #[test]
    fn load_relationship_rejects_invalid_stored_confidence() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        store
            .connection
            .execute(
                "
                INSERT INTO memory_relationships (
                    id,
                    kind,
                    source,
                    target,
                    created_at,
                    last_seen_at,
                    observation_count,
                    expires_at,
                    state,
                    priority,
                    retention,
                    decay_policy,
                    decay_rate,
                    strength,
                    confidence,
                    reinforcement_reason,
                    reinforcement_incident_id,
                    reinforcement_evidence_ids
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ",
                params![
                    "rel-invalid-confidence",
                    "connected_to",
                    "node-1",
                    "node-2",
                    100_u64,
                    200_u64,
                    1_u64,
                    Option::<u64>::None,
                    "observed",
                    "normal",
                    "short_term",
                    "none",
                    Option::<u8>::None,
                    70_u8,
                    101_u8,
                    Option::<String>::None,
                    Option::<String>::None,
                    Option::<String>::None,
                ],
            )
            .unwrap();

        let result =
            store.load_relationship(&MemoryRelationshipId("rel-invalid-confidence".into()));

        assert!(matches!(result, Err(StorageError::InvalidConfidence(101))));
    }

    #[test]
    fn relationships_from_returns_outgoing_relationships_in_id_order() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        save_test_relationships(
            &store,
            &[
                test_relationship("rel-2", "node-a", "node-c"),
                test_relationship("rel-1", "node-a", "node-b"),
                test_relationship("rel-3", "node-d", "node-a"),
            ],
        );

        let relationships = store
            .relationships_from(&MemoryNodeId("node-a".into()))
            .unwrap();

        let ids = relationships
            .into_iter()
            .map(|relationship| relationship.id.0)
            .collect::<Vec<_>>();

        assert_eq!(ids, vec!["rel-1", "rel-2"]);
    }

    #[test]
    fn relationships_to_returns_incoming_relationships_in_id_order() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        save_test_relationships(
            &store,
            &[
                test_relationship("rel-2", "node-c", "node-a"),
                test_relationship("rel-1", "node-b", "node-a"),
                test_relationship("rel-3", "node-a", "node-d"),
            ],
        );

        let relationships = store
            .relationships_to(&MemoryNodeId("node-a".into()))
            .unwrap();

        let ids = relationships
            .into_iter()
            .map(|relationship| relationship.id.0)
            .collect::<Vec<_>>();

        assert_eq!(ids, vec!["rel-1", "rel-2"]);
    }

    #[test]
    fn relationships_for_returns_both_directions_without_duplicates() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        save_test_relationships(
            &store,
            &[
                test_relationship("rel-1", "node-a", "node-b"),
                test_relationship("rel-2", "node-c", "node-a"),
                test_relationship("rel-3", "node-a", "node-a"),
                test_relationship("rel-4", "node-x", "node-y"),
            ],
        );

        let relationships = store
            .relationships_for(&MemoryNodeId("node-a".into()))
            .unwrap();

        let ids = relationships
            .into_iter()
            .map(|relationship| relationship.id.0)
            .collect::<Vec<_>>();

        assert_eq!(ids, vec!["rel-1", "rel-2", "rel-3"]);
    }

    #[test]
    fn neighbours_returns_unique_sorted_adjacent_node_ids() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        save_test_relationships(
            &store,
            &[
                test_relationship("rel-1", "node-a", "node-c"),
                test_relationship("rel-2", "node-b", "node-a"),
                test_relationship("rel-3", "node-a", "node-b"),
                test_relationship("rel-4", "node-a", "node-a"),
            ],
        );

        let neighbours = store.neighbours(&MemoryNodeId("node-a".into())).unwrap();

        assert_eq!(
            neighbours,
            vec![MemoryNodeId("node-b".into()), MemoryNodeId("node-c".into()),]
        );
    }

    #[test]
    fn neighbours_returns_empty_when_node_is_disconnected() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        save_test_relationships(&store, &[test_relationship("rel-1", "node-x", "node-y")]);

        let neighbours = store.neighbours(&MemoryNodeId("node-a".into())).unwrap();

        assert!(neighbours.is_empty());
    }

    #[test]
    fn traverse_uses_breadth_first_order_and_respects_max_depth() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        save_test_relationships(
            &store,
            &[
                test_relationship("rel-1", "node-a", "node-c"),
                test_relationship("rel-2", "node-a", "node-b"),
                test_relationship("rel-3", "node-b", "node-d"),
                test_relationship("rel-4", "node-c", "node-e"),
                test_relationship("rel-5", "node-d", "node-f"),
            ],
        );

        let zero_depth = store.traverse(&MemoryNodeId("node-a".into()), 0).unwrap();
        assert!(zero_depth.is_empty());

        let visits = store.traverse(&MemoryNodeId("node-a".into()), 2).unwrap();

        assert_eq!(
            visits,
            vec![
                TraversalVisit {
                    node_id: MemoryNodeId("node-b".into()),
                    depth: 1,
                },
                TraversalVisit {
                    node_id: MemoryNodeId("node-c".into()),
                    depth: 1,
                },
                TraversalVisit {
                    node_id: MemoryNodeId("node-d".into()),
                    depth: 2,
                },
                TraversalVisit {
                    node_id: MemoryNodeId("node-e".into()),
                    depth: 2,
                },
            ]
        );
    }

    #[test]
    fn traverse_handles_cycles_without_revisiting_nodes() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        save_test_relationships(
            &store,
            &[
                test_relationship("rel-1", "node-a", "node-b"),
                test_relationship("rel-2", "node-b", "node-c"),
                test_relationship("rel-3", "node-c", "node-a"),
            ],
        );

        let visits = store.traverse(&MemoryNodeId("node-a".into()), 10).unwrap();

        assert_eq!(
            visits,
            vec![
                TraversalVisit {
                    node_id: MemoryNodeId("node-b".into()),
                    depth: 1,
                },
                TraversalVisit {
                    node_id: MemoryNodeId("node-c".into()),
                    depth: 1,
                },
            ]
        );
    }

    fn test_node(id: &str, kind: MemoryNodeKind, state: MemoryState) -> MemoryNode {
        MemoryNode {
            id: MemoryNodeId(id.into()),
            kind,
            label: id.into(),
            created_at: 100,
            last_seen_at: 100,
            expires_at: None,
            state,
            priority: MemoryPriority::Normal,
            retention: RetentionClass::ShortTerm,
            decay_policy: DecayPolicy::None,
        }
    }

    #[test]
    fn expired_queries_return_only_active_records_past_expiry() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        let mut expired_node =
            test_node("node-expired", MemoryNodeKind::File, MemoryState::Observed);
        expired_node.expires_at = Some(100);
        let mut future_node = test_node("node-future", MemoryNodeKind::File, MemoryState::Observed);
        future_node.expires_at = Some(300);
        store.save_node(&expired_node).unwrap();
        store.save_node(&future_node).unwrap();

        let mut expired_relationship = test_relationship("rel-expired", "node-a", "node-b");
        expired_relationship.expires_at = Some(100);
        let mut future_relationship = test_relationship("rel-future", "node-a", "node-c");
        future_relationship.expires_at = Some(300);
        store.save_relationship(&expired_relationship).unwrap();
        store.save_relationship(&future_relationship).unwrap();

        assert_eq!(store.expired_nodes(200).unwrap(), vec![expired_node]);
        assert_eq!(
            store.expired_relationships(200).unwrap(),
            vec![expired_relationship]
        );
    }

    #[test]
    fn mark_expired_marks_relationships_and_nodes_without_overwriting_revoked_state() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        let mut node = test_node("node-a", MemoryNodeKind::Process, MemoryState::Observed);
        node.expires_at = Some(100);
        store.save_node(&node).unwrap();

        let mut relationship = test_relationship("rel-a", "node-a", "node-b");
        relationship.expires_at = Some(100);
        store.save_relationship(&relationship).unwrap();

        let mut revoked = test_relationship("rel-revoked", "node-a", "node-c");
        revoked.expires_at = Some(100);
        revoked.state = MemoryState::Revoked;
        store.save_relationship(&revoked).unwrap();

        let update = store.mark_expired(100).unwrap();
        assert_eq!(update.relationships_expired, 1);
        assert_eq!(update.nodes_expired, 1);
        assert_eq!(
            store.load_node(&node.id).unwrap().unwrap().state,
            MemoryState::Expired
        );
        assert_eq!(
            store
                .load_relationship(&relationship.id)
                .unwrap()
                .unwrap()
                .state,
            MemoryState::Expired
        );
        assert_eq!(
            store.load_relationship(&revoked.id).unwrap().unwrap().state,
            MemoryState::Revoked
        );
    }

    #[test]
    fn purge_eligible_queries_respect_grace_period_and_persistent_retention() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        let mut node = test_node("node-old", MemoryNodeKind::File, MemoryState::Expired);
        node.expires_at = Some(100);
        store.save_node(&node).unwrap();

        let mut persistent = test_node(
            "node-persistent",
            MemoryNodeKind::Host,
            MemoryState::Expired,
        );
        persistent.expires_at = Some(100);
        persistent.retention = RetentionClass::Persistent;
        store.save_node(&persistent).unwrap();

        let mut relationship = test_relationship("rel-old", "node-a", "node-b");
        relationship.state = MemoryState::Expired;
        relationship.expires_at = Some(100);
        store.save_relationship(&relationship).unwrap();

        assert!(store.purge_eligible_nodes(149, 50).unwrap().is_empty());
        assert_eq!(store.purge_eligible_nodes(150, 50).unwrap(), vec![node]);
        assert_eq!(
            store.purge_eligible_relationships(150, 50).unwrap(),
            vec![relationship]
        );
    }

    #[test]
    fn reinforcement_can_be_applied_and_revoked() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();
        let relationship = test_relationship("rel-reinforce", "node-a", "node-b");
        store.save_relationship(&relationship).unwrap();

        let provenance = ReinforcementProvenance {
            reason: ReinforcementReason::ConfirmedHighRisk,
            incident_id: Some(IncidentId("incident-1".into())),
            evidence_ids: vec![EvidenceId("evidence-1".into())],
        };
        assert!(
            store
                .reinforce_relationship(&relationship.id, provenance.clone())
                .unwrap()
        );
        assert_eq!(
            store
                .load_relationship(&relationship.id)
                .unwrap()
                .unwrap()
                .reinforcement,
            Some(provenance)
        );

        assert!(
            store
                .revoke_relationship_reinforcement(&relationship.id)
                .unwrap()
        );
        assert_eq!(
            store
                .load_relationship(&relationship.id)
                .unwrap()
                .unwrap()
                .reinforcement,
            None
        );
    }

    #[test]
    fn observe_relationship_consolidates_matching_edges() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        let original = test_relationship("rel-original", "node-a", "node-b");
        store.save_relationship(&original).unwrap();

        let mut observation = test_relationship("rel-new-id", "node-a", "node-b");
        observation.last_seen_at = 250;
        observation.strength = MemoryStrength::new(80).unwrap();
        observation.confidence = MemoryConfidence::new(75).unwrap();
        observation.priority = MemoryPriority::High;

        let canonical_id = store.observe_relationship(&observation).unwrap();
        assert_eq!(canonical_id, original.id);

        let loaded = store.load_relationship(&canonical_id).unwrap().unwrap();
        assert_eq!(loaded.observation_count, 2);
        assert_eq!(loaded.last_seen_at, 250);
        assert_eq!(loaded.strength, MemoryStrength::new(80).unwrap());
        assert_eq!(loaded.confidence, MemoryConfidence::new(75).unwrap());
        assert_eq!(loaded.priority, MemoryPriority::High);
        assert!(store.load_relationship(&observation.id).unwrap().is_none());
    }

    #[test]
    fn active_relationships_for_excludes_terminal_relationship_states() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        let active = test_relationship("rel-active", "node-a", "node-b");
        let mut expired = test_relationship("rel-expired", "node-a", "node-c");
        expired.state = MemoryState::Expired;
        save_test_relationships(&store, &[active.clone(), expired]);

        assert_eq!(
            store
                .active_relationships_for(&MemoryNodeId("node-a".into()))
                .unwrap(),
            vec![active]
        );
    }

    #[test]
    fn find_path_respects_direction_and_active_state() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();
        save_test_relationships(
            &store,
            &[
                test_relationship("rel-ab", "node-a", "node-b"),
                test_relationship("rel-bc", "node-b", "node-c"),
            ],
        );

        let outgoing = PathQuery {
            max_depth: 3,
            direction: TraversalDirection::Outgoing,
            ..PathQuery::default()
        };
        assert!(
            store
                .find_path(
                    &MemoryNodeId("node-a".into()),
                    &MemoryNodeId("node-c".into()),
                    &outgoing
                )
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .find_path(
                    &MemoryNodeId("node-c".into()),
                    &MemoryNodeId("node-a".into()),
                    &outgoing
                )
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn find_path_filters_relationship_kind_strength_and_confidence() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        let mut relationship = test_relationship("rel-ab", "node-a", "node-b");
        relationship.kind = MemoryRelationshipKind::Executed;
        relationship.strength = MemoryStrength::new(80).unwrap();
        relationship.confidence = MemoryConfidence::new(70).unwrap();
        store.save_relationship(&relationship).unwrap();

        let allowed = PathQuery {
            max_depth: 1,
            relationship_kinds: vec![MemoryRelationshipKind::Executed],
            minimum_strength: Some(MemoryStrength::new(80).unwrap()),
            minimum_confidence: Some(MemoryConfidence::new(70).unwrap()),
            ..PathQuery::default()
        };
        assert!(
            store
                .find_path(
                    &MemoryNodeId("node-a".into()),
                    &MemoryNodeId("node-b".into()),
                    &allowed
                )
                .unwrap()
                .is_some()
        );

        let blocked = PathQuery {
            minimum_confidence: Some(MemoryConfidence::new(71).unwrap()),
            ..allowed
        };
        assert!(
            store
                .find_path(
                    &MemoryNodeId("node-a".into()),
                    &MemoryNodeId("node-b".into()),
                    &blocked
                )
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn find_path_reports_weakest_link_score() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        let mut first = test_relationship("rel-ab", "node-a", "node-b");
        first.strength = MemoryStrength::new(90).unwrap();
        first.confidence = MemoryConfidence::new(85).unwrap();
        let mut second = test_relationship("rel-bc", "node-b", "node-c");
        second.strength = MemoryStrength::new(60).unwrap();
        second.confidence = MemoryConfidence::new(95).unwrap();
        save_test_relationships(&store, &[first, second]);

        let path = store
            .find_path(
                &MemoryNodeId("node-a".into()),
                &MemoryNodeId("node-c".into()),
                &PathQuery::default(),
            )
            .unwrap()
            .unwrap();

        assert_eq!(path.weakest_strength, MemoryStrength::new(60).unwrap());
        assert_eq!(path.weakest_confidence, MemoryConfidence::new(85).unwrap());
        assert_eq!(path.score(), 60);
    }

    #[test]
    fn threat_paths_are_ranked_by_weakest_link_score() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        for node in [
            test_node(
                "threat-high",
                MemoryNodeKind::Threat,
                MemoryState::Established,
            ),
            test_node(
                "threat-low",
                MemoryNodeKind::Threat,
                MemoryState::Established,
            ),
        ] {
            store.save_node(&node).unwrap();
        }

        let mut high = test_relationship("rel-high", "start", "threat-high");
        high.strength = MemoryStrength::new(90).unwrap();
        high.confidence = MemoryConfidence::new(95).unwrap();
        let mut low = test_relationship("rel-low", "start", "threat-low");
        low.strength = MemoryStrength::new(50).unwrap();
        low.confidence = MemoryConfidence::new(80).unwrap();
        save_test_relationships(&store, &[low, high]);

        let paths = store
            .threat_paths_from(&MemoryNodeId("start".into()), &PathQuery::default())
            .unwrap();

        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].threat, MemoryNodeId("threat-high".into()));
        assert_eq!(paths[0].path.score(), 90);
        assert_eq!(paths[1].threat, MemoryNodeId("threat-low".into()));
        assert_eq!(paths[1].path.score(), 50);
    }

    #[test]
    fn evaluate_decay_is_non_destructive_and_respects_reinforcement() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        let mut decaying = test_relationship("rel-decay", "node-a", "node-b");
        decaying.created_at = 100;
        decaying.expires_at = Some(200);
        decaying.decay_policy = DecayPolicy::Linear {
            rate: DecayRate::new(50).unwrap(),
        };
        decaying.strength = MemoryStrength::new(100).unwrap();

        let mut reinforced = test_relationship("rel-reinforced", "node-a", "node-c");
        reinforced.created_at = 100;
        reinforced.expires_at = Some(200);
        reinforced.decay_policy = DecayPolicy::Linear {
            rate: DecayRate::new(50).unwrap(),
        };
        reinforced.strength = MemoryStrength::new(100).unwrap();
        reinforced.reinforcement = Some(ReinforcementProvenance {
            reason: ReinforcementReason::ConfirmedHighRisk,
            incident_id: None,
            evidence_ids: Vec::new(),
        });

        save_test_relationships(&store, &[decaying.clone(), reinforced.clone()]);
        let evaluations = store.evaluate_decay(200).unwrap();

        assert_eq!(evaluations.len(), 2);
        assert_eq!(evaluations[0].relationship_id, decaying.id);
        assert_eq!(evaluations[0].stored_strength.value(), 100);
        assert_eq!(evaluations[0].effective_strength.value(), 50);
        assert_eq!(evaluations[1].effective_strength.value(), 100);

        assert_eq!(
            store
                .load_relationship(&MemoryRelationshipId("rel-decay".into()))
                .unwrap()
                .unwrap()
                .strength
                .value(),
            100
        );
    }

    #[test]
    fn find_path_can_filter_using_effective_decayed_strength() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        let mut relationship = test_relationship("rel-decayed", "node-a", "node-b");
        relationship.created_at = 100;
        relationship.expires_at = Some(200);
        relationship.strength = MemoryStrength::new(100).unwrap();
        relationship.decay_policy = DecayPolicy::Linear {
            rate: DecayRate::new(50).unwrap(),
        };
        store.save_relationship(&relationship).unwrap();

        let query = PathQuery {
            max_depth: 1,
            minimum_strength: Some(MemoryStrength::new(60).unwrap()),
            evaluation_time: Some(200),
            ..PathQuery::default()
        };

        assert!(
            store
                .find_path(
                    &MemoryNodeId("node-a".into()),
                    &MemoryNodeId("node-b".into()),
                    &query,
                )
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn nodes_can_be_filtered_by_kind() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        store
            .save_node(&test_node(
                "file-a",
                MemoryNodeKind::File,
                MemoryState::Observed,
            ))
            .unwrap();
        store
            .save_node(&test_node(
                "process-a",
                MemoryNodeKind::Process,
                MemoryState::Observed,
            ))
            .unwrap();
        store
            .save_node(&test_node(
                "process-b",
                MemoryNodeKind::Process,
                MemoryState::Observed,
            ))
            .unwrap();

        let processes = store.nodes(Some(MemoryNodeKind::Process)).unwrap();
        assert_eq!(
            processes
                .into_iter()
                .map(|node| node.id.0)
                .collect::<Vec<_>>(),
            vec!["process-a", "process-b"]
        );
    }

    #[test]
    fn recent_nodes_are_ordered_by_last_seen_and_limited() {
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        let mut old = test_node("old", MemoryNodeKind::File, MemoryState::Observed);
        old.last_seen_at = 10;
        let mut newest = test_node("newest", MemoryNodeKind::File, MemoryState::Observed);
        newest.last_seen_at = 30;
        let mut middle = test_node("middle", MemoryNodeKind::File, MemoryState::Observed);
        middle.last_seen_at = 20;

        for node in [old, newest, middle] {
            store.save_node(&node).unwrap();
        }

        let recent = store.recent_nodes(2).unwrap();
        assert_eq!(
            recent.into_iter().map(|node| node.id.0).collect::<Vec<_>>(),
            vec!["newest", "middle"]
        );
    }
}
