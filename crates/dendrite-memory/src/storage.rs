use crate::model::{
    DecayPolicy, MAX_PROVENANCE_LINEAGE, MemoryConfidence, MemoryNode, MemoryNodeId,
    MemoryNodeKind, MemoryPriority, MemoryProvenance, MemoryRelationship, MemoryRelationshipId,
    MemoryRelationshipKind, MemoryState, MemoryStrength, ReinforcementProvenance,
    ReinforcementReason, RetentionClass,
};
use dendrite_protocol::{EvidenceId, IncidentId};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::{HashSet, VecDeque};
use std::str::FromStr;
use std::sync::{
    Arc,
    mpsc::{self, SyncSender},
};
use std::thread;
use std::time::Duration;

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
    InvalidProvenanceLineageJson(serde_json::Error),
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
    /// Caps how many relationships the search expands through at any single
    /// node, at any hop - not just at the search's own starting node. A
    /// hub node (e.g. an "unresolvable process" bucket like `host:local`,
    /// or a heavily-shared file) can have thousands of edges; without this,
    /// `find_path`/`threat_paths_from` fan out through all of them at every
    /// hop, and `max_depth` alone doesn't bound that - it limits how *far*
    /// the search goes, not how *wide* it is at each step. `None` means
    /// uncapped (the original behavior). When set, the kept edges are the
    /// *strongest* ones (by effective strength at `evaluation_time`, or raw
    /// strength if unset) rather than an arbitrary subset - threat-path
    /// scoring is weakest-link-based, so keeping the strongest candidates
    /// and dropping the long tail of repetitive/weak noise edges is the
    /// truncation that best preserves what the search is actually for.
    pub max_relationships_per_node: Option<usize>,
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
            max_relationships_per_node: None,
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

fn decode_provenance(
    origin_instance_id: Option<String>,
    imported_from_instance_id: Option<String>,
    derived_by_instance_id: Option<String>,
    lineage_json: String,
) -> Result<MemoryProvenance, StorageError> {
    let lineage = serde_json::from_str::<Vec<String>>(&lineage_json)
        .map_err(StorageError::InvalidProvenanceLineageJson)?;
    Ok(MemoryProvenance::new(
        origin_instance_id,
        imported_from_instance_id,
        derived_by_instance_id,
        lineage,
    ))
}

fn encode_lineage(provenance: &MemoryProvenance) -> rusqlite::Result<String> {
    let start = provenance
        .lineage
        .len()
        .saturating_sub(MAX_PROVENANCE_LINEAGE);
    serde_json::to_string(&provenance.lineage[start..])
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
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

const MEMORY_WRITER_QUEUE_CAPACITY: usize = 8_192;

struct TieredWriters {
    stm_tx: SyncSender<WriterCommand>,
    ltm_tx: SyncSender<WriterCommand>,
    stm_path: String,
    ltm_path: String,
}

enum WriterCommand {
    SaveNode {
        node: MemoryNode,
        created_at: u64,
        reply: mpsc::Sender<rusqlite::Result<()>>,
    },
    DeleteNode {
        id: String,
        reply: mpsc::Sender<rusqlite::Result<()>>,
    },
    SaveRelationship {
        relationship: MemoryRelationship,
        created_at: u64,
        reply: mpsc::Sender<rusqlite::Result<()>>,
    },
    DeleteRelationship {
        id: String,
        reply: mpsc::Sender<rusqlite::Result<()>>,
    },
    MarkExpired {
        now: u64,
        reply: mpsc::Sender<rusqlite::Result<LifecycleUpdate>>,
    },
    /// Runs an arbitrary closure directly against this writer's own
    /// connection, on the writer thread, start to finish. Used for batched
    /// routine ingestion (see `MemoryStore::run_stm_batch`): a whole batch's
    /// reads and writes share this one connection, so a later read in the
    /// batch sees an earlier write in the *same* batch without needing a
    /// snapshot or staging layer - it's the same connection, not a copy.
    ///
    /// This variant carries no reply of its own because an enum variant
    /// can't be generic independently of the whole enum; the closure is
    /// responsible for reporting its own result back over whatever channel
    /// it captured (see `run_stm_batch`, which builds exactly that closure).
    RunBatch(Box<dyn FnOnce(&Connection) + Send>),
}

pub struct MemoryStore {
    // Reader connection only in normal tiered operation. STM is `main` and LTM
    // is attached so existing graph-wide SQL can continue to use the unified
    // temporary views. Physical writes are owned by the per-tier writer actors.
    connection: Connection,
    writers: Option<Arc<TieredWriters>>,
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

fn writer_channel_error() -> rusqlite::Error {
    // A disconnected writer actor means the storage backend is no longer usable.
    // `InvalidQuery` is used as the closest rusqlite-owned error without adding a
    // new public StorageError variant solely for an internal channel failure.
    rusqlite::Error::InvalidQuery
}

pub fn execute_node_upsert(
    connection: &Connection,
    node: &MemoryNode,
    created_at: u64,
) -> rusqlite::Result<()> {
    let decay_rate = node.decay_policy.rate().map(|rate| rate.value());
    let lineage = encode_lineage(&node.provenance)?;
    connection.execute(
        "
        INSERT INTO memory_nodes (
            id, kind, label, created_at, last_seen_at, expires_at, state,
            priority, retention, decay_policy, decay_rate,
            origin_instance_id, imported_from_instance_id, derived_by_instance_id, lineage
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            kind = excluded.kind,
            label = excluded.label,
            last_seen_at = excluded.last_seen_at,
            expires_at = excluded.expires_at,
            state = excluded.state,
            priority = excluded.priority,
            retention = excluded.retention,
            decay_policy = excluded.decay_policy,
            decay_rate = excluded.decay_rate,
            origin_instance_id = excluded.origin_instance_id,
            imported_from_instance_id = excluded.imported_from_instance_id,
            derived_by_instance_id = excluded.derived_by_instance_id,
            lineage = excluded.lineage
        ",
        params![
            &node.id.0,
            node.kind.as_str(),
            &node.label,
            created_at,
            node.last_seen_at,
            node.expires_at,
            node.state.as_str(),
            node.priority.as_str(),
            node.retention.as_str(),
            node.decay_policy.as_str(),
            decay_rate,
            node.provenance.origin_instance_id.as_deref(),
            node.provenance.imported_from_instance_id.as_deref(),
            node.provenance.derived_by_instance_id.as_deref(),
            lineage,
        ],
    )?;
    Ok(())
}

pub fn execute_relationship_upsert(
    connection: &Connection,
    relationship: &MemoryRelationship,
    created_at: u64,
) -> rusqlite::Result<()> {
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
    let lineage = encode_lineage(&relationship.provenance)?;

    connection.execute(
        "
        INSERT INTO memory_relationships (
            id, kind, source, target, created_at, last_seen_at, observation_count,
            expires_at, state, priority, retention, decay_policy, decay_rate,
            strength, confidence, reinforcement_reason, reinforcement_incident_id,
            reinforcement_evidence_ids, origin_instance_id, imported_from_instance_id,
            derived_by_instance_id, lineage
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            reinforcement_evidence_ids = excluded.reinforcement_evidence_ids,
            origin_instance_id = excluded.origin_instance_id,
            imported_from_instance_id = excluded.imported_from_instance_id,
            derived_by_instance_id = excluded.derived_by_instance_id,
            lineage = excluded.lineage
        ",
        params![
            &relationship.id.0,
            relationship.kind.as_str(),
            &relationship.source.0,
            &relationship.target.0,
            created_at,
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
            relationship.provenance.origin_instance_id.as_deref(),
            relationship.provenance.imported_from_instance_id.as_deref(),
            relationship.provenance.derived_by_instance_id.as_deref(),
            lineage,
        ],
    )?;
    Ok(())
}

fn execute_mark_expired(connection: &Connection, now: u64) -> rusqlite::Result<LifecycleUpdate> {
    let relationships_expired = connection.execute(
        "UPDATE memory_relationships
         SET state = 'expired'
         WHERE expires_at IS NOT NULL
           AND expires_at <= ?
           AND state IN ('observed', 'correlated', 'supported', 'established')",
        [now],
    )?;
    let nodes_expired = connection.execute(
        "UPDATE memory_nodes
         SET state = 'expired'
         WHERE expires_at IS NOT NULL
           AND expires_at <= ?
           AND state IN ('observed', 'correlated', 'supported', 'established')",
        [now],
    )?;
    Ok(LifecycleUpdate {
        relationships_expired,
        nodes_expired,
    })
}

fn spawn_writer(
    path: String,
    name: &str,
    read_only_attach: Option<String>,
) -> rusqlite::Result<SyncSender<WriterCommand>> {
    // Open once here so startup fails synchronously if the path/configuration is
    // invalid instead of leaving a daemon with a dead writer thread.
    let connection = Connection::open(&path)?;
    configure_connection(&connection, &path)?;
    if let Some(other_path) = &read_only_attach {
        // Attached `mode=ro` so this is enforced by SQLite itself, not just
        // convention: a `RunBatch` closure that tried to write through this
        // attachment would hit "attempt to write a readonly database"
        // instead of silently taking the other tier's writer lock. Only the
        // STM writer attaches its companion this way (see `open_tiered`) -
        // batched routine ingestion writes to STM directly and defers any
        // LTM-destined save to the ordinary post-batch `save_node`/
        // `save_relationship` path, which already owns cross-tier promotion.
        connection.execute(
            "ATTACH DATABASE ?1 AS ltm",
            [format!("file:{other_path}?mode=ro")],
        )?;
        create_unified_views(&connection)?;
    }
    let (tx, rx) = mpsc::sync_channel(MEMORY_WRITER_QUEUE_CAPACITY);
    let thread_name = name.to_owned();
    thread::Builder::new()
        .name(thread_name)
        .spawn(move || {
            while let Ok(command) = rx.recv() {
                match command {
                    WriterCommand::SaveNode {
                        node,
                        created_at,
                        reply,
                    } => {
                        let _ = reply.send(execute_node_upsert(&connection, &node, created_at));
                    }
                    WriterCommand::DeleteNode { id, reply } => {
                        let result = connection
                            .execute("DELETE FROM memory_nodes WHERE id = ?1", [&id])
                            .map(|_| ());
                        let _ = reply.send(result);
                    }
                    WriterCommand::SaveRelationship {
                        relationship,
                        created_at,
                        reply,
                    } => {
                        let _ = reply.send(execute_relationship_upsert(
                            &connection,
                            &relationship,
                            created_at,
                        ));
                    }
                    WriterCommand::DeleteRelationship { id, reply } => {
                        let result = connection
                            .execute("DELETE FROM memory_relationships WHERE id = ?1", [&id])
                            .map(|_| ());
                        let _ = reply.send(result);
                    }
                    WriterCommand::MarkExpired { now, reply } => {
                        let _ = reply.send(execute_mark_expired(&connection, now));
                    }
                    WriterCommand::RunBatch(work) => {
                        work(&connection);
                    }
                }
            }
        })
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(tx)
}

fn send_writer_command(
    sender: &SyncSender<WriterCommand>,
    build: impl FnOnce(mpsc::Sender<rusqlite::Result<()>>) -> WriterCommand,
) -> rusqlite::Result<()> {
    let (reply_tx, reply_rx) = mpsc::channel();
    sender
        .send(build(reply_tx))
        .map_err(|_| writer_channel_error())?;
    reply_rx.recv().map_err(|_| writer_channel_error())?
}

fn create_unified_views(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "
        DROP VIEW IF EXISTS temp.all_memory_nodes;
        CREATE TEMP VIEW all_memory_nodes AS
            SELECT * FROM main.memory_nodes
            UNION ALL
            SELECT * FROM ltm.memory_nodes;

        DROP VIEW IF EXISTS temp.all_memory_relationships;
        CREATE TEMP VIEW all_memory_relationships AS
            SELECT * FROM main.memory_relationships
            UNION ALL
            SELECT * FROM ltm.memory_relationships;
        ",
    )
}

/// A read-only view over one graph connection. All of `MemoryStore`'s graph
/// *read* queries live here, parametrised over the connection they run
/// against, instead of being pinned to `MemoryStore`'s own reader
/// connection. `MemoryStore` itself only ever constructs one of these
/// against its own connection (via `reader()`), so nothing about its public
/// API changes.
///
/// The reason this type exists at all: a routine ingestion batch that reads
/// and writes through the STM writer's own connection (see
/// `MemoryStore::run_stm_batch`) needs the exact same graph-read logic used
/// everywhere else, but running against that writer's connection instead of
/// a separate reader connection - otherwise a batch's later reads can't see
/// its own earlier writes, which was the correctness gap that ruled out a
/// read-once-upfront batching plan. Duplicating this logic instead of
/// sharing it would have been a second, divergent copy of exactly the code
/// most in need of staying correct.
/// Applies `PathQuery::max_relationships_per_node` (see its doc comment for
/// why this exists): if `relationships` is within the cap, or no cap is
/// set, it's returned unchanged - this is the common case and stays O(n).
/// Otherwise it's sorted by effective strength descending and truncated,
/// keeping the strongest edges rather than an arbitrary prefix.
fn cap_relationships_by_strength(
    mut relationships: Vec<MemoryRelationship>,
    query: &PathQuery,
) -> Vec<MemoryRelationship> {
    let Some(cap) = query.max_relationships_per_node else {
        return relationships;
    };
    if relationships.len() <= cap {
        return relationships;
    }
    relationships.sort_by(|left, right| {
        let left_strength = query
            .evaluation_time
            .map_or(left.strength, |now| left.effective_strength(now));
        let right_strength = query
            .evaluation_time
            .map_or(right.strength, |now| right.effective_strength(now));
        right_strength.cmp(&left_strength)
    });
    relationships.truncate(cap);
    relationships
}

pub struct GraphReader<'a> {
    connection: &'a Connection,
}

impl<'a> GraphReader<'a> {
    pub fn new(connection: &'a Connection) -> Self {
        Self { connection }
    }

    /// The same existing-edge lookup `observe_relationship` opens with -
    /// exposed on its own so batched routine ingestion can do the same
    /// consolidate-or-create decision without going through the per-item
    /// writer-actor dispatch that `MemoryStore::observe_relationship` uses.
    pub fn find_relationship_id(
        &self,
        kind: MemoryRelationshipKind,
        source: &MemoryNodeId,
        target: &MemoryNodeId,
    ) -> Result<Option<MemoryRelationshipId>, StorageError> {
        let mut statement = self.connection.prepare(
            "
            SELECT id
            FROM all_memory_relationships
            WHERE kind = ?
              AND source = ?
              AND target = ?
              AND state != 'revoked'
            ORDER BY created_at, id
            LIMIT 1
            ",
        )?;
        let existing_id = statement
            .query_row(params![kind.as_str(), &source.0, &target.0], |row| {
                row.get::<_, String>(0)
            })
            .optional()?;
        Ok(existing_id.map(MemoryRelationshipId))
    }

    pub fn load_node(&self, id: &MemoryNodeId) -> Result<Option<MemoryNode>, StorageError> {
        let stored = self
            .connection
            .query_row(
                "
                SELECT
                    id, kind, label, created_at, last_seen_at, expires_at,
                    state, priority, retention, decay_policy, decay_rate,
                    origin_instance_id, imported_from_instance_id, derived_by_instance_id, lineage
                FROM all_memory_nodes
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
                        row.get::<_, Option<String>>(11)?,
                        row.get::<_, Option<String>>(12)?,
                        row.get::<_, Option<String>>(13)?,
                        row.get::<_, String>(14)?,
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
            origin_instance_id,
            imported_from_instance_id,
            derived_by_instance_id,
            lineage,
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
            provenance: decode_provenance(
                origin_instance_id,
                imported_from_instance_id,
                derived_by_instance_id,
                lineage,
            )?,
        }))
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
                    id, kind, source, target, created_at, last_seen_at, observation_count,
                    expires_at, state, priority, retention, decay_policy, decay_rate,
                    strength, confidence, reinforcement_reason, reinforcement_incident_id,
                    reinforcement_evidence_ids, origin_instance_id, imported_from_instance_id,
                    derived_by_instance_id, lineage
                FROM all_memory_relationships
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
                        row.get::<_, Option<String>>(18)?,
                        row.get::<_, Option<String>>(19)?,
                        row.get::<_, Option<String>>(20)?,
                        row.get::<_, String>(21)?,
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
            origin_instance_id,
            imported_from_instance_id,
            derived_by_instance_id,
            lineage,
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
            provenance: decode_provenance(
                origin_instance_id,
                imported_from_instance_id,
                derived_by_instance_id,
                lineage,
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
            FROM all_memory_relationships
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
            FROM all_memory_relationships
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
            FROM all_memory_relationships
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
            FROM all_memory_nodes
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

        let relationships = relationships
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
            .collect::<Vec<_>>();

        Ok(cap_relationships_by_strength(relationships, query))
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

impl MemoryStore {
    /// A read-only view bound to this store's own connection. Every
    /// graph-read method on `MemoryStore` is a thin wrapper over this -
    /// see `GraphReader` for why the split exists.
    fn reader(&self) -> GraphReader<'_> {
        GraphReader::new(&self.connection)
    }

    fn load_relationships(
        &self,
        ids: Vec<String>,
    ) -> Result<Vec<MemoryRelationship>, StorageError> {
        self.reader().load_relationships(ids)
    }

    pub fn open(path: &str) -> rusqlite::Result<Self> {
        // Keep the in-memory/single-path constructor intentionally simple for
        // unit tests and compatibility callers. Normal daemon operation uses
        // `open_tiered`, which enables independent physical writers.
        let connection = Connection::open(path)?;
        configure_connection(&connection, path)?;
        connection.execute("ATTACH DATABASE ':memory:' AS ltm", [])?;
        Ok(Self {
            connection,
            writers: None,
        })
    }

    pub fn open_tiered(stm_path: &str, ltm_path: &str) -> rusqlite::Result<Self> {
        let connection = Connection::open(stm_path)?;
        configure_connection(&connection, stm_path)?;
        connection.execute("ATTACH DATABASE ?1 AS ltm", [ltm_path])?;
        if ltm_path != ":memory:" {
            connection
                .execute_batch("PRAGMA ltm.journal_mode = WAL; PRAGMA ltm.synchronous = NORMAL;")?;
        }

        // Separate writer actors are only meaningful for two file-backed DBs.
        // In-memory compatibility paths keep the old single-connection behavior.
        let writers = if stm_path != ":memory:" && ltm_path != ":memory:" {
            let stm_path = stm_path.to_owned();
            let ltm_path = ltm_path.to_owned();
            let stm_tx = spawn_writer(
                stm_path.clone(),
                "dendrite-memory-stm-writer",
                Some(ltm_path.clone()),
            )?;
            let ltm_tx = spawn_writer(ltm_path.clone(), "dendrite-memory-ltm-writer", None)?;
            Some(Arc::new(TieredWriters {
                stm_tx,
                ltm_tx,
                stm_path,
                ltm_path,
            }))
        } else {
            None
        };

        Ok(Self {
            connection,
            writers,
        })
    }

    /// Opens another graph reader while sharing the same two physical writer
    /// actors. This is how the runtime's priority/routine workers retain
    /// independent read connections without creating competing SQLite writers.
    pub fn fork_reader(&self) -> rusqlite::Result<Self> {
        let Some(writers) = &self.writers else {
            return Err(rusqlite::Error::InvalidQuery);
        };
        let connection = Connection::open(&writers.stm_path)?;
        configure_connection(&connection, &writers.stm_path)?;
        connection.execute("ATTACH DATABASE ?1 AS ltm", [&writers.ltm_path])?;
        connection
            .execute_batch("PRAGMA ltm.journal_mode = WAL; PRAGMA ltm.synchronous = NORMAL;")?;
        create_unified_views(&connection)?;
        Ok(Self {
            connection,
            writers: Some(Arc::clone(writers)),
        })
    }

    pub fn ping(&self) -> rusqlite::Result<()> {
        self.connection.execute_batch("SELECT 1;")?;
        Ok(())
    }

    /// Legacy single-connection stores can batch exactly as before. Tiered
    /// stores intentionally autocommit through the dedicated writer actors: a
    /// separate reader connection must be able to observe each save immediately
    /// because `ingest_observation` performs graph reads between writes.
    pub fn begin_batch(&self) -> rusqlite::Result<()> {
        if self.writers.is_some() {
            Ok(())
        } else {
            self.connection.execute_batch("BEGIN")
        }
    }

    pub fn commit_batch(&self) -> rusqlite::Result<()> {
        if self.writers.is_some() {
            Ok(())
        } else {
            self.connection.execute_batch("COMMIT")
        }
    }

    pub fn rollback_batch(&self) -> rusqlite::Result<()> {
        if self.writers.is_some() {
            Ok(())
        } else {
            self.connection.execute_batch("ROLLBACK")
        }
    }

    /// Runs `work` once, on the STM writer's own thread, against its own
    /// connection - wrapped in one transaction, so a whole routine
    /// ingestion batch commits (or fails) atomically instead of once per
    /// item. `work` receives a `GraphReader` over that same connection, so
    /// its reads see this batch's own earlier writes directly (no snapshot,
    /// because there isn't one - it's one connection, used sequentially).
    ///
    /// `work` is given the raw STM `&Connection` too, not just the reader,
    /// because it also needs to *write*: `GraphReader` is read-only by
    /// design (see its own doc comment), and this is the one place that
    /// intentionally bypasses `save_node`/`save_relationship`'s normal
    /// per-item writer-actor dispatch to avoid paying a channel round trip
    /// per write. Only STM-destined saves belong here - anything that
    /// should end up in LTM must still go through the ordinary `save_node`/
    /// `save_relationship` path after this batch returns, exactly as
    /// promotion already works outside of batching; this connection's `ltm`
    /// attachment is `mode=ro` specifically so a mistaken write there fails
    /// loudly instead of silently taking the other tier's writer lock.
    ///
    /// Falls back to running `work` directly against this store's own
    /// connection when there is no separate STM writer (the `open()`
    /// compatibility path used by unit tests and non-tiered callers) -
    /// there is no other thread to hand it to, and no promotion/attachment
    /// concerns apply there either.
    pub fn run_stm_batch<T, F>(&self, work: F) -> rusqlite::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection, GraphReader<'_>) -> T + Send + 'static,
    {
        let Some(writers) = &self.writers else {
            return Ok(work(&self.connection, GraphReader::new(&self.connection)));
        };
        let (reply_tx, reply_rx) = mpsc::channel::<T>();
        let command = WriterCommand::RunBatch(Box::new(move |connection: &Connection| {
            let outcome = connection
                .execute_batch("BEGIN IMMEDIATE")
                .map(|()| work(connection, GraphReader::new(connection)));
            match outcome {
                Ok(result) => {
                    // A commit failure here is a real problem, but there is
                    // no reply channel for it beyond what `work` itself
                    // already reported - the alternative (swallowing it
                    // silently) is worse, so it is left to surface as a
                    // reply-channel disconnect on the *next* batch instead
                    // of panicking this thread. `work` already ran and
                    // computed its result on data that will now be rolled
                    // back if commit fails; callers should treat a
                    // subsequent `Err` from this method as "nothing in that
                    // batch is guaranteed durable".
                    let _ = connection.execute_batch("COMMIT");
                    let _ = reply_tx.send(result);
                }
                Err(_) => {
                    let _ = connection.execute_batch("ROLLBACK");
                    // Dropping `reply_tx` without sending turns the caller's
                    // `reply_rx.recv()` into a disconnect error below.
                }
            }
        }));
        writers
            .stm_tx
            .send(command)
            .map_err(|_| writer_channel_error())?;
        reply_rx.recv().map_err(|_| writer_channel_error())
    }

    pub fn node_count(&self) -> rusqlite::Result<u64> {
        self.connection
            .query_row("SELECT COUNT(*) FROM all_memory_nodes", [], |row| {
                row.get(0)
            })
    }

    pub fn relationship_count(&self) -> rusqlite::Result<u64> {
        self.connection
            .query_row("SELECT COUNT(*) FROM all_memory_relationships", [], |row| {
                row.get(0)
            })
    }

    pub fn nodes(&self, kind: Option<MemoryNodeKind>) -> Result<Vec<MemoryNode>, StorageError> {
        let ids = if let Some(kind) = kind {
            let mut statement = self.connection.prepare(
                "
                SELECT id
                FROM all_memory_nodes
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
                FROM all_memory_nodes
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
            SELECT
                id, kind, label, created_at, last_seen_at, expires_at,
                state, priority, retention, decay_policy, decay_rate,
                origin_instance_id, imported_from_instance_id, derived_by_instance_id, lineage
            FROM all_memory_nodes
            ORDER BY last_seen_at DESC, id ASC
            LIMIT ?
            ",
        )?;
        let rows = statement
            .query_map([i64::try_from(limit).unwrap_or(i64::MAX)], |row| {
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
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<String>>(13)?,
                    row.get::<_, String>(14)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        rows.into_iter()
            .map(
                |(
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
                    origin_instance_id,
                    imported_from_instance_id,
                    derived_by_instance_id,
                    lineage,
                )| {
                    Ok(MemoryNode {
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
                        provenance: decode_provenance(
                            origin_instance_id,
                            imported_from_instance_id,
                            derived_by_instance_id,
                            lineage,
                        )?,
                    })
                },
            )
            .collect()
    }

    pub fn relationships(&self) -> Result<Vec<MemoryRelationship>, StorageError> {
        let mut statement = self.connection.prepare(
            "
            SELECT
                id, kind, source, target, created_at, last_seen_at,
                observation_count, expires_at, state, priority, retention,
                decay_policy, decay_rate, strength, confidence,
                reinforcement_reason, reinforcement_incident_id,
                reinforcement_evidence_ids, origin_instance_id,
                imported_from_instance_id, derived_by_instance_id, lineage
            FROM all_memory_relationships
            ORDER BY id
            ",
        )?;

        let rows = statement
            .query_map([], |row| {
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
                    row.get::<_, Option<String>>(18)?,
                    row.get::<_, Option<String>>(19)?,
                    row.get::<_, Option<String>>(20)?,
                    row.get::<_, String>(21)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        rows.into_iter()
            .map(
                |(
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
                    origin_instance_id,
                    imported_from_instance_id,
                    derived_by_instance_id,
                    lineage,
                )| {
                    Ok(MemoryRelationship {
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
                        provenance: decode_provenance(
                            origin_instance_id,
                            imported_from_instance_id,
                            derived_by_instance_id,
                            lineage,
                        )?,
                    })
                },
            )
            .collect()
    }

    pub fn relationships_between_recent_nodes(
        &self,
        limit: usize,
    ) -> Result<Vec<MemoryRelationship>, StorageError> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let mut statement = self.connection.prepare(
            "
            WITH recent AS (
                SELECT id
                FROM all_memory_nodes
                ORDER BY last_seen_at DESC, id ASC
                LIMIT ?1
            )
            SELECT
                r.id, r.kind, r.source, r.target, r.created_at, r.last_seen_at,
                r.observation_count, r.expires_at, r.state, r.priority, r.retention,
                r.decay_policy, r.decay_rate, r.strength, r.confidence,
                r.reinforcement_reason, r.reinforcement_incident_id,
                r.reinforcement_evidence_ids, r.origin_instance_id,
                r.imported_from_instance_id, r.derived_by_instance_id, r.lineage
            FROM all_memory_relationships r
            INNER JOIN recent source_node ON source_node.id = r.source
            INNER JOIN recent target_node ON target_node.id = r.target
            ORDER BY r.id
            ",
        )?;

        let rows = statement
            .query_map([i64::try_from(limit).unwrap_or(i64::MAX)], |row| {
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
                    row.get::<_, Option<String>>(18)?,
                    row.get::<_, Option<String>>(19)?,
                    row.get::<_, Option<String>>(20)?,
                    row.get::<_, String>(21)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        rows.into_iter()
            .map(
                |(
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
                    origin_instance_id,
                    imported_from_instance_id,
                    derived_by_instance_id,
                    lineage,
                )| {
                    Ok(MemoryRelationship {
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
                        provenance: decode_provenance(
                            origin_instance_id,
                            imported_from_instance_id,
                            derived_by_instance_id,
                            lineage,
                        )?,
                    })
                },
            )
            .collect()
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
                decay_rate      INTEGER,
                origin_instance_id          TEXT,
                imported_from_instance_id   TEXT,
                derived_by_instance_id      TEXT,
                lineage                     TEXT NOT NULL DEFAULT '[]'
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
                reinforcement_evidence_ids  TEXT,
                origin_instance_id          TEXT,
                imported_from_instance_id   TEXT,
                derived_by_instance_id      TEXT,
                lineage                     TEXT NOT NULL DEFAULT '[]'
            );
            ",
        )?;

        self.connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS ltm.memory_nodes (
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
                decay_rate      INTEGER,
                origin_instance_id          TEXT,
                imported_from_instance_id   TEXT,
                derived_by_instance_id      TEXT,
                lineage                     TEXT NOT NULL DEFAULT '[]'
            );

            CREATE TABLE IF NOT EXISTS ltm.memory_relationships (
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
                reinforcement_evidence_ids  TEXT,
                origin_instance_id          TEXT,
                imported_from_instance_id   TEXT,
                derived_by_instance_id      TEXT,
                lineage                     TEXT NOT NULL DEFAULT '[]'
            );

            DROP VIEW IF EXISTS temp.all_memory_nodes;
            CREATE TEMP VIEW all_memory_nodes AS
                SELECT * FROM main.memory_nodes
                UNION ALL
                SELECT * FROM ltm.memory_nodes;

            DROP VIEW IF EXISTS temp.all_memory_relationships;
            CREATE TEMP VIEW all_memory_relationships AS
                SELECT * FROM main.memory_relationships
                UNION ALL
                SELECT * FROM ltm.memory_relationships;
            ",
        )?;

        Ok(())
    }

    pub fn save_node(&self, node: &MemoryNode) -> rusqlite::Result<()> {
        let created_at = self
            .connection
            .query_row(
                "SELECT created_at FROM all_memory_nodes WHERE id = ?1 LIMIT 1",
                [&node.id.0],
                |row| row.get::<_, u64>(0),
            )
            .optional()?
            .unwrap_or(node.created_at);

        if let Some(writers) = &self.writers {
            let (destination, other) = match node.retention {
                RetentionClass::ShortTerm => (&writers.stm_tx, &writers.ltm_tx),
                RetentionClass::LongTerm | RetentionClass::Persistent => {
                    (&writers.ltm_tx, &writers.stm_tx)
                }
            };
            send_writer_command(destination, |reply| WriterCommand::SaveNode {
                node: node.clone(),
                created_at,
                reply,
            })?;
            // Promotion is deliberately destination-first. If Dendrite stops
            // between these operations the durable copy already exists; the
            // next save is idempotent and removes the stale opposite-tier row.
            send_writer_command(other, |reply| WriterCommand::DeleteNode {
                id: node.id.0.clone(),
                reply,
            })?;
            return Ok(());
        }

        let decay_rate = node.decay_policy.rate().map(|rate| rate.value());
        let lineage = encode_lineage(&node.provenance)?;
        let (table, other_table) = match node.retention {
            RetentionClass::ShortTerm => ("main.memory_nodes", "ltm.memory_nodes"),
            RetentionClass::LongTerm | RetentionClass::Persistent => {
                ("ltm.memory_nodes", "main.memory_nodes")
            }
        };
        let sql = format!(
            "
            INSERT INTO {table} (
                id, kind, label, created_at, last_seen_at, expires_at, state,
                priority, retention, decay_policy, decay_rate,
                origin_instance_id, imported_from_instance_id, derived_by_instance_id, lineage
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                kind = excluded.kind,
                label = excluded.label,
                last_seen_at = excluded.last_seen_at,
                expires_at = excluded.expires_at,
                state = excluded.state,
                priority = excluded.priority,
                retention = excluded.retention,
                decay_policy = excluded.decay_policy,
                decay_rate = excluded.decay_rate,
                origin_instance_id = excluded.origin_instance_id,
                imported_from_instance_id = excluded.imported_from_instance_id,
                derived_by_instance_id = excluded.derived_by_instance_id,
                lineage = excluded.lineage
            "
        );
        self.connection.execute(
            &sql,
            params![
                &node.id.0,
                node.kind.as_str(),
                &node.label,
                created_at,
                node.last_seen_at,
                node.expires_at,
                node.state.as_str(),
                node.priority.as_str(),
                node.retention.as_str(),
                node.decay_policy.as_str(),
                decay_rate,
                node.provenance.origin_instance_id.as_deref(),
                node.provenance.imported_from_instance_id.as_deref(),
                node.provenance.derived_by_instance_id.as_deref(),
                lineage,
            ],
        )?;
        self.connection.execute(
            &format!("DELETE FROM {other_table} WHERE id = ?1"),
            [&node.id.0],
        )?;
        Ok(())
    }

    pub fn load_node(&self, id: &MemoryNodeId) -> Result<Option<MemoryNode>, StorageError> {
        self.reader().load_node(id)
    }

    pub fn save_relationship(&self, relationship: &MemoryRelationship) -> rusqlite::Result<()> {
        let created_at = self
            .connection
            .query_row(
                "SELECT created_at FROM all_memory_relationships WHERE id = ?1 LIMIT 1",
                [&relationship.id.0],
                |row| row.get::<_, u64>(0),
            )
            .optional()?
            .unwrap_or(relationship.created_at);

        if let Some(writers) = &self.writers {
            let (destination, other) = match relationship.retention {
                RetentionClass::ShortTerm => (&writers.stm_tx, &writers.ltm_tx),
                RetentionClass::LongTerm | RetentionClass::Persistent => {
                    (&writers.ltm_tx, &writers.stm_tx)
                }
            };
            send_writer_command(destination, |reply| WriterCommand::SaveRelationship {
                relationship: relationship.clone(),
                created_at,
                reply,
            })?;
            send_writer_command(other, |reply| WriterCommand::DeleteRelationship {
                id: relationship.id.0.clone(),
                reply,
            })?;
            return Ok(());
        }

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
        let lineage = encode_lineage(&relationship.provenance)?;
        let (table, other_table) = match relationship.retention {
            RetentionClass::ShortTerm => ("main.memory_relationships", "ltm.memory_relationships"),
            RetentionClass::LongTerm | RetentionClass::Persistent => {
                ("ltm.memory_relationships", "main.memory_relationships")
            }
        };
        let sql = format!(
            "
            INSERT INTO {table} (
                id, kind, source, target, created_at, last_seen_at, observation_count,
                expires_at, state, priority, retention, decay_policy, decay_rate,
                strength, confidence, reinforcement_reason, reinforcement_incident_id,
                reinforcement_evidence_ids, origin_instance_id, imported_from_instance_id,
                derived_by_instance_id, lineage
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                reinforcement_evidence_ids = excluded.reinforcement_evidence_ids,
                origin_instance_id = excluded.origin_instance_id,
                imported_from_instance_id = excluded.imported_from_instance_id,
                derived_by_instance_id = excluded.derived_by_instance_id,
                lineage = excluded.lineage
            "
        );
        self.connection.execute(
            &sql,
            params![
                &relationship.id.0,
                relationship.kind.as_str(),
                &relationship.source.0,
                &relationship.target.0,
                created_at,
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
                relationship.provenance.origin_instance_id.as_deref(),
                relationship.provenance.imported_from_instance_id.as_deref(),
                relationship.provenance.derived_by_instance_id.as_deref(),
                lineage,
            ],
        )?;
        self.connection.execute(
            &format!("DELETE FROM {other_table} WHERE id = ?1"),
            [&relationship.id.0],
        )?;
        Ok(())
    }

    pub fn load_relationship(
        &self,
        id: &MemoryRelationshipId,
    ) -> Result<Option<MemoryRelationship>, StorageError> {
        self.reader().load_relationship(id)
    }

    /// Exposed alongside `relationships_for`/`load_relationship` so callers
    /// outside this module (the daemon's expiry pass, batched ingestion) can
    /// make the same consolidate-onto-an-existing-edge decision
    /// `observe_relationship` and `persist_relationship_batched` already
    /// make, without reaching into a private `GraphReader`.
    pub fn find_relationship_id(
        &self,
        kind: MemoryRelationshipKind,
        source: &MemoryNodeId,
        target: &MemoryNodeId,
    ) -> Result<Option<MemoryRelationshipId>, StorageError> {
        self.reader().find_relationship_id(kind, source, target)
    }

    pub fn relationships_from(
        &self,
        node_id: &MemoryNodeId,
    ) -> Result<Vec<MemoryRelationship>, StorageError> {
        self.reader().relationships_from(node_id)
    }

    pub fn relationships_to(
        &self,
        node_id: &MemoryNodeId,
    ) -> Result<Vec<MemoryRelationship>, StorageError> {
        self.reader().relationships_to(node_id)
    }

    pub fn relationships_for(
        &self,
        node_id: &MemoryNodeId,
    ) -> Result<Vec<MemoryRelationship>, StorageError> {
        self.reader().relationships_for(node_id)
    }

    pub fn neighbours(&self, node_id: &MemoryNodeId) -> Result<Vec<MemoryNodeId>, StorageError> {
        self.reader().neighbours(node_id)
    }

    pub fn traverse(
        &self,
        start: &MemoryNodeId,
        max_depth: usize,
    ) -> Result<Vec<TraversalVisit>, StorageError> {
        self.reader().traverse(start, max_depth)
    }

    pub fn expired_nodes(&self, now: u64) -> Result<Vec<MemoryNode>, StorageError> {
        let mut statement = self.connection.prepare(
            "
            SELECT id
            FROM all_memory_nodes
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
            FROM all_memory_relationships
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
        if let Some(writers) = &self.writers {
            let (stm_reply_tx, stm_reply_rx) = mpsc::channel();
            let (ltm_reply_tx, ltm_reply_rx) = mpsc::channel();
            writers
                .stm_tx
                .send(WriterCommand::MarkExpired {
                    now,
                    reply: stm_reply_tx,
                })
                .map_err(|_| StorageError::Database(writer_channel_error()))?;
            writers
                .ltm_tx
                .send(WriterCommand::MarkExpired {
                    now,
                    reply: ltm_reply_tx,
                })
                .map_err(|_| StorageError::Database(writer_channel_error()))?;
            let stm = stm_reply_rx
                .recv()
                .map_err(|_| StorageError::Database(writer_channel_error()))??;
            let ltm = ltm_reply_rx
                .recv()
                .map_err(|_| StorageError::Database(writer_channel_error()))??;
            return Ok(LifecycleUpdate {
                relationships_expired: stm.relationships_expired + ltm.relationships_expired,
                nodes_expired: stm.nodes_expired + ltm.nodes_expired,
            });
        }

        let mut relationships_expired = 0;
        let mut nodes_expired = 0;
        for schema in ["main", "ltm"] {
            relationships_expired += self.connection.execute(
                &format!(
                    "UPDATE {schema}.memory_relationships
                     SET state = 'expired'
                     WHERE expires_at IS NOT NULL
                       AND expires_at <= ?
                       AND state IN ('observed', 'correlated', 'supported', 'established')"
                ),
                [now],
            )?;
            nodes_expired += self.connection.execute(
                &format!(
                    "UPDATE {schema}.memory_nodes
                     SET state = 'expired'
                     WHERE expires_at IS NOT NULL
                       AND expires_at <= ?
                       AND state IN ('observed', 'correlated', 'supported', 'established')"
                ),
                [now],
            )?;
        }

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
            FROM all_memory_nodes
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
            FROM all_memory_relationships
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
            FROM all_memory_relationships
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
            FROM all_memory_relationships
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
        self.reader().find_path(start, target, query)
    }

    pub fn threat_paths_from(
        &self,
        start: &MemoryNodeId,
        query: &PathQuery,
    ) -> Result<Vec<ThreatPath>, StorageError> {
        self.reader().threat_paths_from(start, query)
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
            provenance: MemoryProvenance::local("test-instance"),
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
            provenance: MemoryProvenance::local("test-instance"),
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

        let (origin, imported_from, derived_by, lineage): (
            Option<String>,
            Option<String>,
            Option<String>,
            String,
        ) = store
            .connection
            .query_row(
                "
                SELECT origin_instance_id, imported_from_instance_id,
                       derived_by_instance_id, lineage
                FROM memory_nodes
                WHERE id = ?
                ",
                [&node.id.0],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();

        assert_eq!(origin.as_deref(), Some("test-instance"));
        assert_eq!(imported_from, None);
        assert_eq!(derived_by, None);
        assert_eq!(lineage, "[\"test-instance\"]");
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
            provenance: MemoryProvenance::local("test-instance"),
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
            provenance: MemoryProvenance::local("test-instance"),
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
            provenance: MemoryProvenance::local("test-instance"),
        };

        store.save_node(&updated).unwrap();

        let (created_at, last_seen_at, label): (u64, u64, String) = store
            .connection
            .query_row(
                "
                SELECT created_at, last_seen_at, label
                FROM ltm.memory_nodes
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
            provenance: MemoryProvenance::local("test-instance"),
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
            provenance: MemoryProvenance::local("test-instance"),
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
            provenance: MemoryProvenance::local("test-instance"),
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
            provenance: MemoryProvenance::local("test-instance"),
        };

        store.save_relationship(&relationship).unwrap();

        let stored: String = store
            .connection
            .query_row(
                "
                SELECT reinforcement_evidence_ids
                FROM ltm.memory_relationships
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
            provenance: MemoryProvenance::local("test-instance"),
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
            provenance: MemoryProvenance::local("test-instance"),
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
            provenance: MemoryProvenance::local("test-instance"),
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
    fn max_relationships_per_node_keeps_the_strongest_edges_at_a_hub_node() {
        // "start" is a hub: hundreds of weak edges to unrelated nodes, plus
        // one strong direct edge to a threat. Without a cap, the search
        // still finds the threat (it's not incorrect, just potentially
        // very expensive at a real hub's actual scale - hundreds of
        // thousands of edges, not hundreds). With a small cap, this proves
        // the truncation keeps the strong signal rather than discarding it
        // arbitrarily by insertion order.
        let store = MemoryStore::open(":memory:").unwrap();
        store.initialise().unwrap();

        store
            .save_node(&test_node(
                "threat-1",
                MemoryNodeKind::Threat,
                MemoryState::Established,
            ))
            .unwrap();

        let mut noise = Vec::new();
        for index in 0..500 {
            let node_id = format!("noise-{index}");
            store
                .save_node(&test_node(
                    &node_id,
                    MemoryNodeKind::Process,
                    MemoryState::Observed,
                ))
                .unwrap();
            let mut relationship =
                test_relationship(&format!("rel-noise-{index}"), "start", &node_id);
            relationship.strength = MemoryStrength::new(1).unwrap();
            noise.push(relationship);
        }
        save_test_relationships(&store, &noise);

        let mut strong = test_relationship("rel-strong", "start", "threat-1");
        strong.strength = MemoryStrength::new(99).unwrap();
        save_test_relationships(&store, &[strong]);

        let capped_query = PathQuery {
            max_relationships_per_node: Some(5),
            ..PathQuery::default()
        };
        let paths = store
            .threat_paths_from(&MemoryNodeId("start".into()), &capped_query)
            .unwrap();
        assert_eq!(
            paths.len(),
            1,
            "the strong direct edge to the threat must survive truncation to 5 edges out of 501"
        );
        assert_eq!(paths[0].threat, MemoryNodeId("threat-1".into()));

        // Uncapped still finds it too - the cap changes performance
        // characteristics, not correctness of what a search that does
        // complete finds.
        let paths = store
            .threat_paths_from(&MemoryNodeId("start".into()), &PathQuery::default())
            .unwrap();
        assert_eq!(paths.len(), 1);
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
    #[test]
    fn tiered_file_store_shares_writers_and_routes_physical_tiers() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "dendrite-memory-tiered-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let stm_path = directory.join("stm.sqlite3");
        let ltm_path = directory.join("ltm.sqlite3");
        let stm_text = stm_path.to_string_lossy().into_owned();
        let ltm_text = ltm_path.to_string_lossy().into_owned();

        let store = MemoryStore::open_tiered(&stm_text, &ltm_text).unwrap();
        store.initialise().unwrap();
        let worker_reader = store.fork_reader().unwrap();

        let short = test_node("short", MemoryNodeKind::Process, MemoryState::Observed);
        worker_reader.save_node(&short).unwrap();

        let mut durable = test_node("durable", MemoryNodeKind::Threat, MemoryState::Observed);
        durable.retention = RetentionClass::LongTerm;
        store.save_node(&durable).unwrap();

        assert!(store.load_node(&short.id).unwrap().is_some());
        assert!(worker_reader.load_node(&durable.id).unwrap().is_some());

        let stm = Connection::open(&stm_path).unwrap();
        let ltm = Connection::open(&ltm_path).unwrap();
        let stm_short: u64 = stm
            .query_row(
                "SELECT COUNT(*) FROM memory_nodes WHERE id = 'short'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let stm_durable: u64 = stm
            .query_row(
                "SELECT COUNT(*) FROM memory_nodes WHERE id = 'durable'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let ltm_short: u64 = ltm
            .query_row(
                "SELECT COUNT(*) FROM memory_nodes WHERE id = 'short'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let ltm_durable: u64 = ltm
            .query_row(
                "SELECT COUNT(*) FROM memory_nodes WHERE id = 'durable'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!((stm_short, stm_durable), (1, 0));
        assert_eq!((ltm_short, ltm_durable), (0, 1));

        drop(worker_reader);
        drop(store);
        let _ = std::fs::remove_dir_all(directory);
    }
}
