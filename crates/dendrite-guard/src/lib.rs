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
    IntegrityManifestEntryDto, IntegrityManifestStatusDto, IntegrityMismatchDto, IntegritySeverity,
    IntegrityVerificationDto, ObjectId, RecoveryBeginDto, RecoveryCompleteDto, TrustState,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Used for every timestamp this crate records (guard-state transitions,
/// findings, and the integrity manifest below) — not gated behind
/// `#[cfg(debug_assertions)]` like `dendrited`'s equivalent helpers,
/// because establishing/verifying the integrity manifest is real,
/// release-build functionality, not a development-only surface.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

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
    /// Key generation/parsing failures (OS RNG, malformed key material) —
    /// mirrors `dendrited`'s own `SelfStoreError::Crypto`.
    Crypto(String),
    /// The signing key or manifest is missing, malformed, or otherwise in
    /// a state that can't be trusted (wrong file mode, unknown key
    /// reference, no baseline established yet).
    InvalidKeyState(String),
    /// A recovery step (`begin_recovery`/`complete_recovery`) was called
    /// out of order, or the submitted token didn't match the one issued —
    /// see `README.md`'s "Recovery" section.
    Recovery(String),
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for GuardStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "database error: {error}"),
            Self::InvalidTrustState(state) => write!(formatter, "invalid trust state: {state}"),
            Self::InvalidSeverity(severity) => write!(formatter, "invalid severity: {severity}"),
            Self::Crypto(message) => write!(formatter, "crypto error: {message}"),
            Self::InvalidKeyState(message) => write!(formatter, "invalid key state: {message}"),
            Self::Recovery(message) => write!(formatter, "recovery error: {message}"),
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Json(error) => write!(formatter, "JSON error: {error}"),
        }
    }
}

impl From<rusqlite::Error> for GuardStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

impl From<std::io::Error> for GuardStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for GuardStoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
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
    /// Where Guard's own ed25519 private key material lives — a `keys/`
    /// subdirectory next to `guard.sqlite3`, inside Guard's own now
    /// privilege-separated `StateDirectory=` (mode `0700`, owned solely by
    /// the `dendrite-guard` user — see `README.md`'s "Privilege
    /// separation" section). Never derived from anything `dendrited` can
    /// influence.
    key_dir: PathBuf,
    /// Where `begin_recovery` writes the one-time recovery token — next to
    /// `guard.sqlite3`, inside the same privilege-separated
    /// `StateDirectory=` as `key_dir`. `dendrited`'s own user has no access
    /// to this directory at all (see `README.md`'s "Privilege separation"
    /// section), which is exactly what makes reading this file proof of
    /// real host access rather than just IPC reachability — see
    /// `README.md`'s "Recovery" section.
    recovery_token_path: PathBuf,
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
            CREATE TABLE IF NOT EXISTS guard_signing_keys (
                key_id TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                private_key_reference TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                is_active INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS integrity_manifest (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                key_id TEXT NOT NULL,
                manifest_json TEXT NOT NULL,
                signature TEXT NOT NULL,
                entry_count INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS guard_open_mismatches (
                path TEXT PRIMARY KEY,
                current_digest TEXT NOT NULL,
                severity TEXT NOT NULL,
                first_detected_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS guard_recovery (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                token_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
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

        let db_parent = Path::new(path)
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty());
        let key_dir = db_parent
            .map(|parent| parent.join("keys"))
            .unwrap_or_else(|| PathBuf::from("keys"));
        let recovery_token_path = db_parent
            .map(|parent| parent.join("recovery_token"))
            .unwrap_or_else(|| PathBuf::from("recovery_token"));

        Ok(Self {
            connection,
            guard: Guard::new(trust_state),
            key_dir,
            recovery_token_path,
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
    /// gating this method itself — see `README.md`. Unconditional — unlike
    /// `escalate_trust_state`, this can move to a *better* state too, which
    /// is exactly why it's development-only: real trust-state changes only
    /// ever come from `escalate_trust_state` (monotonic, never auto-improves).
    pub fn debug_set_state(&mut self, state: &str, now: u64) -> Result<(), GuardStoreError> {
        let state = TrustState::from_str(state)
            .map_err(|_| GuardStoreError::InvalidTrustState(state.into()))?;
        self.set_trust_state(state, now)
    }

    fn set_trust_state(&mut self, state: TrustState, now: u64) -> Result<(), GuardStoreError> {
        self.guard.set_trust_state(state);
        self.connection.execute(
            "UPDATE guard_state SET trust_state = ?1, updated_at = ?2 WHERE singleton = 1",
            params![state.as_str(), now],
        )?;
        Ok(())
    }

    /// Moves trust state to `candidate` only if that's *worse* than the
    /// current state (see `trust_rank`) — real verification findings only
    /// ever degrade trust automatically, never restore it. Recovering back
    /// to `Trusted` after a legitimate fix is deliberately not handled here;
    /// see `complete_recovery`. Returns whether the state actually changed.
    fn escalate_trust_state(
        &mut self,
        candidate: TrustState,
        now: u64,
    ) -> Result<bool, GuardStoreError> {
        if trust_rank(candidate) > trust_rank(self.guard.trust_state()) {
            self.set_trust_state(candidate, now)?;
            Ok(true)
        } else {
            Ok(false)
        }
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
        self.insert_finding(target, severity, description, now)
    }

    fn insert_finding(
        &mut self,
        target: &str,
        severity: IntegritySeverity,
        description: &str,
        now: u64,
    ) -> Result<(), GuardStoreError> {
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

    /// Records a real (non-debug) integrity finding for a specific watched
    /// path or manifest-level event, but only when it's genuinely new
    /// (`current_marker` — the current digest, or a fixed sentinel for a
    /// non-per-path event like a bad manifest signature — differs from what
    /// was last recorded for this key) so a mismatch that persists across
    /// many verification passes produces one finding, not one per pass.
    /// `guard_open_mismatches` is cleared by `establish_baseline`, which is
    /// the only thing that resets it — a re-baseline is an acknowledged
    /// fresh start, not automatic recovery (see `complete_recovery`).
    fn record_open_mismatch(
        &mut self,
        key: &str,
        severity: IntegritySeverity,
        description: &str,
        current_marker: &str,
        now: u64,
    ) -> Result<(), GuardStoreError> {
        let existing: Option<String> = self
            .connection
            .query_row(
                "SELECT current_digest FROM guard_open_mismatches WHERE path = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        if existing.as_deref() != Some(current_marker) {
            self.insert_finding(key, severity, description, now)?;
        }
        self.connection.execute(
            "INSERT INTO guard_open_mismatches(path, current_digest, severity, first_detected_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(path) DO UPDATE SET
                current_digest = excluded.current_digest,
                severity = excluded.severity",
            params![key, current_marker, severity.as_str(), now],
        )?;
        Ok(())
    }

    pub fn has_baseline(&self) -> Result<bool, GuardStoreError> {
        let count: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM integrity_manifest WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Returns Guard's own current signing key, generating and persisting
    /// one on first use. See `README.md`'s "Integrity manifest" section on
    /// why this is a separate keypair from `dendrited`'s own instance key
    /// (`crates/dendrited/src/self_store.rs`'s `InstanceKeyRecord`): Guard
    /// verifies `dendrited`, so `dendrited` must never hold a key that
    /// could re-sign a tampered manifest as trusted, and after the
    /// privilege-separation work `dendrited`'s user can no longer read
    /// Guard's key material at all.
    pub fn ensure_signing_key(&mut self) -> Result<GuardKeyRecord, GuardStoreError> {
        if let Some(key) = self.load_active_key()? {
            return Ok(key);
        }
        let key = self.generate_key()?;
        if let Err(error) = self.insert_key(&key) {
            let _ = fs::remove_file(private_key_path(&key.private_key_reference));
            return Err(error);
        }
        Ok(key)
    }

    fn load_active_key(&self) -> Result<Option<GuardKeyRecord>, GuardStoreError> {
        Ok(self
            .connection
            .query_row(
                "SELECT key_id, public_key, private_key_reference, fingerprint, created_at, is_active
             FROM guard_signing_keys WHERE is_active = 1 ORDER BY created_at DESC LIMIT 1",
                [],
                read_key_row,
            )
            .optional()?)
    }

    fn load_key(&self, key_id: &str) -> Result<Option<GuardKeyRecord>, GuardStoreError> {
        Ok(self
            .connection
            .query_row(
                "SELECT key_id, public_key, private_key_reference, fingerprint, created_at, is_active
             FROM guard_signing_keys WHERE key_id = ?1",
                params![key_id],
                read_key_row,
            )
            .optional()?)
    }

    fn insert_key(&self, key: &GuardKeyRecord) -> Result<(), GuardStoreError> {
        self.connection.execute(
            "INSERT INTO guard_signing_keys(
                key_id, public_key, private_key_reference, fingerprint, created_at, is_active
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                key.key_id,
                key.public_key,
                key.private_key_reference,
                key.fingerprint,
                key.created_at,
                i64::from(key.is_active),
            ],
        )?;
        Ok(())
    }

    fn next_key_id(&self) -> Result<String, GuardStoreError> {
        let mut statement = self
            .connection
            .prepare("SELECT key_id FROM guard_signing_keys")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut max_id = 0u64;
        for key_id in rows {
            let key_id = key_id?;
            if let Some(number) = key_id
                .strip_prefix("guardkey_")
                .and_then(|value| value.parse().ok())
            {
                max_id = max_id.max(number);
            }
        }
        Ok(format!("guardkey_{:08}", max_id + 1))
    }

    fn generate_key(&self) -> Result<GuardKeyRecord, GuardStoreError> {
        let key_id = self.next_key_id()?;
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret)
            .map_err(|error| GuardStoreError::Crypto(format!("OS RNG failed: {error}")))?;
        let signing_key = SigningKey::from_bytes(&secret);
        let public_bytes = signing_key.verifying_key().to_bytes();
        let public_key = format!("ed25519:{}", hex::encode(public_bytes));
        let fingerprint = format!("sha256:{}", hex::encode(Sha256::digest(public_bytes)));

        fs::create_dir_all(&self.key_dir)?;
        fs::set_permissions(&self.key_dir, fs::Permissions::from_mode(0o700))?;
        let key_path = self.key_dir.join(format!("{key_id}.ed25519"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)?;
        file.write_all(&secret)?;
        file.sync_all()?;
        drop(file);

        Ok(GuardKeyRecord {
            key_id,
            public_key,
            private_key_reference: format!("file:{}", key_path.display()),
            fingerprint,
            created_at: unix_now(),
            is_active: true,
        })
    }

    /// Hashes `watch_paths` (already resolved by the caller — `main.rs`'s
    /// own `DENDRITE_GUARD_WATCH_PATHS`, never anything supplied over the
    /// `GuardRequest` wire, see `guard_ipc.rs`) and stores the signed
    /// result as the new baseline, replacing any previous one. Signing
    /// Guard's own manifest (rather than just hashing) means a later
    /// `verify_integrity` call can detect the baseline itself having been
    /// hand-edited or corrupted, not just the watched files drifting from
    /// it.
    pub fn establish_baseline(
        &mut self,
        watch_paths: &[PathBuf],
        now: u64,
    ) -> Result<IntegrityManifestStatusDto, GuardStoreError> {
        let key = self.ensure_signing_key()?;

        let mut paths: Vec<&PathBuf> = watch_paths.iter().collect();
        paths.sort();
        paths.dedup();
        let entries: Vec<IntegrityManifestEntryDto> = paths
            .into_iter()
            .map(|path| IntegrityManifestEntryDto {
                path: path.display().to_string(),
                digest: hash_path(path),
            })
            .collect();

        let manifest_json = serde_json::to_string(&entries)?;
        let secret = read_private_seed(&key.private_key_reference, &key.key_id)?;
        let signing_key = SigningKey::from_bytes(&secret);
        let preimage = manifest_preimage(&key.key_id, manifest_json.as_bytes());
        let signature: Signature = signing_key.sign(&preimage);
        let signature = format!("ed25519:{}", hex::encode(signature.to_bytes()));

        self.connection.execute(
            "INSERT INTO integrity_manifest(singleton, key_id, manifest_json, signature, entry_count, created_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(singleton) DO UPDATE SET
                key_id = excluded.key_id,
                manifest_json = excluded.manifest_json,
                signature = excluded.signature,
                entry_count = excluded.entry_count,
                created_at = excluded.created_at",
            params![key.key_id, manifest_json, signature, entries.len() as i64, now],
        )?;
        // A fresh baseline is an acknowledged, explicit reset point — clear
        // any previously-tracked open mismatches so the next
        // `verify_integrity` starts clean against the new baseline rather
        // than immediately re-flagging findings from before. This is
        // deliberately the only thing that resets `guard_open_mismatches`;
        // it does not touch trust state — see `complete_recovery` for the
        // one explicit, separately-gated path back to `Trusted`.
        self.connection
            .execute("DELETE FROM guard_open_mismatches", [])?;

        Ok(IntegrityManifestStatusDto {
            established: true,
            entry_count: entries.len(),
            key_id: key.key_id,
            fingerprint: key.fingerprint,
            created_at: now,
        })
    }

    /// Current baseline summary, or `established: false` if none has been
    /// recorded yet.
    pub fn manifest_status(&self) -> Result<IntegrityManifestStatusDto, GuardStoreError> {
        let stored: Option<(String, i64, i64)> = self
            .connection
            .query_row(
                "SELECT key_id, entry_count, created_at FROM integrity_manifest WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((key_id, entry_count, created_at)) = stored else {
            return Ok(IntegrityManifestStatusDto {
                established: false,
                entry_count: 0,
                key_id: String::new(),
                fingerprint: String::new(),
                created_at: 0,
            });
        };
        let key = self.load_key(&key_id)?.ok_or_else(|| {
            GuardStoreError::InvalidKeyState(format!("manifest references unknown key {key_id}"))
        })?;
        Ok(IntegrityManifestStatusDto {
            established: true,
            entry_count: entry_count as usize,
            key_id,
            fingerprint: key.fingerprint,
            created_at: created_at as u64,
        })
    }

    /// Recomputes hashes for `watch_paths` and compares them against the
    /// stored signed baseline — this is the one real verification pass,
    /// called identically whether it's `dendrite-guard`'s own periodic
    /// background check (`main.rs`'s `run_periodic_verification`, on
    /// startup and every `DENDRITE_GUARD_VERIFY_INTERVAL_SECONDS`) or an
    /// operator's on-demand `dendrite guard verify` — there is no separate
    /// read-only mode; both trigger the same side effects. A mismatch that
    /// wasn't already open (see `record_open_mismatch`) becomes a real
    /// `IntegrityFinding`, and the worst severity found this pass can
    /// escalate trust state (see `escalate_trust_state` — this only ever
    /// makes trust state worse, never better; see `complete_recovery` for
    /// the explicit, separately-gated path back to `Trusted`).
    ///
    /// If the stored baseline's own signature no longer verifies — the
    /// trust anchor itself may be corrupted or tampered — this is treated
    /// as an unconditional `Compromised`-level finding and per-path
    /// comparison is skipped entirely: `manifest_json` can't be trusted
    /// enough to diff against.
    pub fn verify_integrity(
        &mut self,
        watch_paths: &[PathBuf],
        now: u64,
    ) -> Result<IntegrityVerificationDto, GuardStoreError> {
        let stored: Option<(String, String, String)> = self
            .connection
            .query_row(
                "SELECT key_id, manifest_json, signature FROM integrity_manifest WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((key_id, manifest_json, signature)) = stored else {
            return Err(GuardStoreError::InvalidKeyState(
                "no integrity baseline has been established yet".into(),
            ));
        };
        let key = self.load_key(&key_id)?.ok_or_else(|| {
            GuardStoreError::InvalidKeyState(format!("manifest references unknown key {key_id}"))
        })?;

        let public_bytes = parse_public_key(&key.public_key)?;
        let verifying_key = VerifyingKey::from_bytes(&public_bytes).map_err(|error| {
            GuardStoreError::Crypto(format!("invalid Ed25519 public key: {error}"))
        })?;
        let signature_bytes = parse_signature(&signature)?;
        let preimage = manifest_preimage(&key_id, manifest_json.as_bytes());
        let signature_valid = verifying_key.verify(&preimage, &signature_bytes).is_ok();

        if !signature_valid {
            self.record_open_mismatch(
                "guard:manifest-signature",
                IntegritySeverity::Critical,
                "The stored integrity baseline's own signature no longer verifies against Guard's signing key — the baseline itself may be corrupted or tampered, not just a watched file",
                "invalid",
                now,
            )?;
            self.escalate_trust_state(TrustState::Compromised, now)?;
            return Ok(IntegrityVerificationDto {
                signature_valid: false,
                matches: false,
                mismatches: Vec::new(),
            });
        }

        let baseline_entries: Vec<IntegrityManifestEntryDto> =
            serde_json::from_str(&manifest_json)?;
        let mut mismatches = Vec::new();
        let mut worst_severity: Option<IntegritySeverity> = None;
        for entry in &baseline_entries {
            let current = hash_path(Path::new(&entry.path));
            if current != entry.digest {
                let severity = default_severity_for_path(&entry.path);
                self.record_open_mismatch(
                    &entry.path,
                    severity,
                    &format!(
                        "File no longer matches the signed baseline (expected {}, found {})",
                        entry.digest, current
                    ),
                    &current,
                    now,
                )?;
                worst_severity = Some(match worst_severity {
                    Some(existing) => existing.max(severity),
                    None => severity,
                });
                mismatches.push(IntegrityMismatchDto {
                    path: entry.path.clone(),
                    baseline_digest: entry.digest.clone(),
                    current_digest: current,
                });
            }
        }
        // A watch path configured now but absent from the stored baseline
        // (e.g. `DENDRITE_GUARD_WATCH_PATHS` grew since the baseline was
        // established) is surfaced for visibility, but deliberately isn't a
        // finding or a trust-state input: it's operator config drift (an
        // unbaselined path), not evidence of tampering.
        let baseline_paths: std::collections::HashSet<&str> = baseline_entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect();
        for path in watch_paths {
            let path_str = path.display().to_string();
            if !baseline_paths.contains(path_str.as_str()) {
                mismatches.push(IntegrityMismatchDto {
                    path: path_str,
                    baseline_digest: "not-in-baseline".into(),
                    current_digest: hash_path(path),
                });
            }
        }

        if let Some(severity) = worst_severity {
            self.escalate_trust_state(state_for_severity(severity), now)?;
        }

        Ok(IntegrityVerificationDto {
            signature_valid: true,
            matches: mismatches.is_empty(),
            mismatches,
        })
    }

    /// Recovery step 1 of 2 (see `README.md`'s "Recovery" section for the
    /// full design). `escalate_trust_state`
    /// only ever makes trust worse, by design — restoring it needs its own
    /// explicit, deliberately harder-to-reach path, gated on proving real
    /// host access rather than just IPC reachability.
    ///
    /// Refuses to start from `Trusted` (nothing to recover from). From any
    /// other state, generates a random one-time token, writes it in
    /// plaintext to `recovery_token_path` (inside Guard's own
    /// privilege-separated `StateDirectory=`, unreadable by `dendrited`'s
    /// user), stores only its hash, and moves trust state to `Recovering`.
    /// The token itself is **never** returned here — it travels back
    /// through `dendrited`'s own IPC relay, which a compromised `dendrited`
    /// could read; the whole point is that a compromised `dendrited` can
    /// relay this request (and would learn `token_path`, which isn't
    /// secret) but still can't read the file itself.
    pub fn begin_recovery(&mut self, now: u64) -> Result<RecoveryBeginDto, GuardStoreError> {
        if self.guard.trust_state() == TrustState::Trusted {
            return Err(GuardStoreError::Recovery(
                "trust state is already Trusted; nothing to recover from".into(),
            ));
        }

        let mut token_bytes = [0u8; 32];
        getrandom::fill(&mut token_bytes)
            .map_err(|error| GuardStoreError::Crypto(format!("OS RNG failed: {error}")))?;
        let token = hex::encode(token_bytes);
        let token_hash = hex::encode(Sha256::digest(token.as_bytes()));

        write_recovery_token(&self.recovery_token_path, &token)?;
        self.connection.execute(
            "INSERT INTO guard_recovery(singleton, token_hash, created_at)
             VALUES (1, ?1, ?2)
             ON CONFLICT(singleton) DO UPDATE SET
                token_hash = excluded.token_hash,
                created_at = excluded.created_at",
            params![token_hash, now],
        )?;
        // `Recovering` is the highest-ranked state (see `trust_rank`), so
        // this always succeeds as an "escalation" from any non-Trusted
        // state — including re-issuing a fresh token while already
        // Recovering, which is a deliberate no-op on trust state itself.
        self.escalate_trust_state(TrustState::Recovering, now)?;

        Ok(RecoveryBeginDto {
            trust_state: self.guard.trust_state().as_str().into(),
            token_path: self.recovery_token_path.display().to_string(),
        })
    }

    /// Recovery step 2 of 2. Requires trust state to already be
    /// `Recovering` (i.e. `begin_recovery` was called first) and the
    /// submitted `token` to match the one written to `recovery_token_path`.
    /// A mismatch changes nothing and returns an error — the stored token
    /// remains valid so the correct one can still be submitted. On a match,
    /// establishes a fresh baseline against `watch_paths` (the same as
    /// `establish_baseline` — a legitimate recovery accepts current content
    /// as the new known-good state) and restores trust to `Trusted`. This
    /// is the one deliberate bypass of `escalate_trust_state`'s
    /// monotonic rule in the entire crate, and it only runs after the
    /// caller has proven they could read a file `dendrited`'s own user
    /// cannot.
    pub fn complete_recovery(
        &mut self,
        token: &str,
        watch_paths: &[PathBuf],
        now: u64,
    ) -> Result<RecoveryCompleteDto, GuardStoreError> {
        if self.guard.trust_state() != TrustState::Recovering {
            return Err(GuardStoreError::Recovery(
                "recovery was not started; call begin_recovery first".into(),
            ));
        }
        let stored_hash: Option<String> = self
            .connection
            .query_row(
                "SELECT token_hash FROM guard_recovery WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let Some(stored_hash) = stored_hash else {
            return Err(GuardStoreError::Recovery(
                "no recovery token has been issued".into(),
            ));
        };
        let candidate_hash = hex::encode(Sha256::digest(token.as_bytes()));
        if !constant_time_eq(&candidate_hash, &stored_hash) {
            return Err(GuardStoreError::Recovery(
                "recovery token does not match".into(),
            ));
        }

        let manifest_status = self.establish_baseline(watch_paths, now)?;
        self.connection
            .execute("DELETE FROM guard_recovery WHERE singleton = 1", [])?;
        let _ = fs::remove_file(&self.recovery_token_path);
        self.set_trust_state(TrustState::Trusted, now)?;

        Ok(RecoveryCompleteDto {
            trust_state: self.guard.trust_state().as_str().into(),
            manifest_status,
        })
    }
}

/// Automatic, built-in severity for a watched path's own mismatch (hash
/// changed or the file went missing) — deliberately simple rather than
/// operator-configurable per path (a possible later refinement): the
/// binaries whose trust is actually load-bearing here (`dendrited` itself,
/// and `dendrite-guard`'s own binary — if that's tampered, nothing this
/// crate reports can be trusted either) jump straight to `Critical`
/// (→ `Compromised`, see `state_for_severity`); a systemd unit file is
/// `High` (→ `Suspected` — it governs what runs with what privileges, but
/// isn't the running code itself); anything else configured (MAGI's
/// binary, the eBPF object, ...) is `Warning` (→ `Degraded`).
fn default_severity_for_path(path: &str) -> IntegritySeverity {
    let name = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path);
    match name {
        "dendrited" | "dendrite-guard" => IntegritySeverity::Critical,
        _ if name.ends_with(".service") => IntegritySeverity::High,
        _ => IntegritySeverity::Warning,
    }
}

/// Maps a finding's severity to the trust state an automatic verification
/// pass escalates *toward* (subject to `escalate_trust_state`'s
/// never-improve rule). `Informational` never escalates — it isn't
/// currently produced by `verify_integrity` itself, but is a valid
/// `IntegritySeverity` for `debug_record_finding`/future callers, so it
/// maps to `Trusted` (the identity — `escalate_trust_state` only moves
/// forward, so this is a no-op against any current state).
fn state_for_severity(severity: IntegritySeverity) -> TrustState {
    match severity {
        IntegritySeverity::Informational => TrustState::Trusted,
        IntegritySeverity::Warning => TrustState::Degraded,
        IntegritySeverity::High => TrustState::Suspected,
        IntegritySeverity::Critical => TrustState::Compromised,
    }
}

/// Where each `TrustState` sits on the escalation ladder
/// (`escalate_trust_state` only ever moves up this ranking, never down —
/// restoring `Trusted` is instead `complete_recovery`'s job, gated on a
/// token proving real host access rather than reachable automatically; see
/// `README.md`'s "Recovery" section). Follows the pipeline order in
/// `README.md`'s diagram: `TRUSTED -> DEGRADED ->
/// SUSPECTED -> QUARANTINED -> COMPROMISED -> RECOVERING`.
fn trust_rank(state: TrustState) -> u8 {
    match state {
        TrustState::Trusted => 0,
        TrustState::Degraded => 1,
        TrustState::Suspected => 2,
        TrustState::Quarantined => 3,
        TrustState::Compromised => 4,
        TrustState::Recovering => 5,
    }
}

/// Guard's own ed25519 signing key — never shared with or derived from
/// `dendrited`'s own instance key. See `ensure_signing_key`.
#[derive(Debug, Clone)]
pub struct GuardKeyRecord {
    pub key_id: String,
    pub public_key: String,
    pub private_key_reference: String,
    pub fingerprint: String,
    pub created_at: u64,
    pub is_active: bool,
}

fn read_key_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<GuardKeyRecord> {
    Ok(GuardKeyRecord {
        key_id: row.get(0)?,
        public_key: row.get(1)?,
        private_key_reference: row.get(2)?,
        fingerprint: row.get(3)?,
        created_at: row.get(4)?,
        is_active: row.get::<_, i64>(5)? != 0,
    })
}

fn private_key_path(reference: &str) -> &str {
    reference.strip_prefix("file:").unwrap_or(reference)
}

fn read_private_seed(reference: &str, key_id: &str) -> Result<[u8; 32], GuardStoreError> {
    let path = reference.strip_prefix("file:").ok_or_else(|| {
        GuardStoreError::InvalidKeyState(format!("unsupported private key reference for {key_id}"))
    })?;
    let metadata = fs::metadata(path)?;
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(GuardStoreError::InvalidKeyState(format!(
            "private key {key_id} must have mode 0600"
        )));
    }
    fs::read(path)?.try_into().map_err(|_| {
        GuardStoreError::InvalidKeyState(format!(
            "private key {key_id} is not a 32-byte Ed25519 seed"
        ))
    })
}

fn parse_public_key(value: &str) -> Result<[u8; 32], GuardStoreError> {
    let encoded = value
        .strip_prefix("ed25519:")
        .ok_or_else(|| GuardStoreError::Crypto("unsupported public key algorithm".into()))?;
    let bytes = hex::decode(encoded)
        .map_err(|error| GuardStoreError::Crypto(format!("invalid public key hex: {error}")))?;
    bytes
        .try_into()
        .map_err(|_| GuardStoreError::Crypto("Ed25519 public key must contain 32 bytes".into()))
}

fn parse_signature(value: &str) -> Result<Signature, GuardStoreError> {
    let encoded = value
        .strip_prefix("ed25519:")
        .ok_or_else(|| GuardStoreError::Crypto("unsupported signature algorithm".into()))?;
    let bytes = hex::decode(encoded)
        .map_err(|error| GuardStoreError::Crypto(format!("invalid signature hex: {error}")))?;
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| GuardStoreError::Crypto("Ed25519 signature must contain 64 bytes".into()))?;
    Ok(Signature::from_bytes(&bytes))
}

/// Domain-separated preimage for signing/verifying a manifest — mirrors
/// `dendrited`'s own `instance_bound_preimage` in `self_store.rs`, with its
/// own distinct version tag so a signature produced for one purpose can
/// never be replayed as valid for the other.
fn manifest_preimage(key_id: &str, payload: &[u8]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(32 + key_id.len() + payload.len());
    preimage.extend_from_slice(b"DENDRITE-GUARD-MANIFEST-V1\0");
    preimage.extend_from_slice(key_id.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(payload);
    preimage
}

/// `sha256:<hex>` for a readable file, `absent` for a path that doesn't
/// exist (a watched binary disappearing is itself worth being able to
/// report, not just a hashing failure to swallow), or `unreadable` for any
/// other I/O error (permission denied, etc.) — kept distinct from `absent`
/// since those mean different things to an operator.
fn hash_path(path: &Path) -> String {
    match fs::read(path) {
        Ok(bytes) => format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "absent".into(),
        Err(_) => "unreadable".into(),
    }
}

/// Writes the plaintext recovery token to `path`, mode `0600`, inside
/// Guard's own privilege-separated `StateDirectory=` — see
/// `GuardStore::recovery_token_path`. Overwrites any previous token
/// unconditionally (`begin_recovery` re-issuing invalidates the old one).
fn write_recovery_token(path: &Path, token: &str) -> Result<(), GuardStoreError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(token.as_bytes())?;
    file.sync_all()?;
    drop(file);
    // `.mode(0o600)` only applies the permission at creation time (per
    // `open(2)`'s `O_CREAT` semantics) — explicitly reassert it so a
    // pre-existing file from an earlier run can't leave looser permissions
    // in place.
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Constant-time comparison for the recovery token's hash, so a timing
/// side-channel can't help an attacker narrow it down byte by byte. Both
/// inputs are fixed-length SHA-256 hex digests in practice, so the length
/// check isn't itself a meaningful leak.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
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

    /// A fresh temp directory to hold both a `GuardStore`'s `guard.sqlite3`
    /// (and its `keys/` subdirectory, created alongside it) and any dummy
    /// watched files a test wants to hash — cleaned up on drop so key
    /// material and manifest fixtures never leak between test runs.
    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "dendrite-guard-manifest-test-{label}-{}-{}",
                std::process::id(),
                line!()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn db_path(&self) -> String {
            self.0.join("guard.sqlite3").to_str().unwrap().to_owned()
        }

        fn write_watched(&self, name: &str, contents: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, contents).unwrap();
            path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn signing_key_is_generated_once_and_persists_across_reopen() {
        let dir = TestDir::new("key-persist");

        let first = {
            let mut store = GuardStore::open(&dir.db_path()).unwrap();
            store.ensure_signing_key().unwrap()
        };
        let second = {
            let mut store = GuardStore::open(&dir.db_path()).unwrap();
            store.ensure_signing_key().unwrap()
        };

        assert_eq!(first.key_id, second.key_id);
        assert_eq!(first.public_key, second.public_key);
        assert_eq!(first.fingerprint, second.fingerprint);
    }

    #[test]
    fn baseline_round_trips_and_reports_no_mismatches_when_unchanged() {
        let dir = TestDir::new("round-trip");
        let watched = vec![dir.write_watched("binary-a", b"hello world")];

        let mut store = GuardStore::open(&dir.db_path()).unwrap();
        let status = store.establish_baseline(&watched, 1000).unwrap();
        assert!(status.established);
        assert_eq!(status.entry_count, 1);

        let result = store.verify_integrity(&watched, 2000).unwrap();
        assert!(result.signature_valid);
        assert!(result.matches);
        assert!(result.mismatches.is_empty());
    }

    #[test]
    fn verify_integrity_flags_a_modified_watched_file() {
        let dir = TestDir::new("modified-file");
        let watched = vec![dir.write_watched("binary-a", b"original contents")];

        let mut store = GuardStore::open(&dir.db_path()).unwrap();
        store.establish_baseline(&watched, 1000).unwrap();

        fs::write(&watched[0], b"tampered contents").unwrap();

        let result = store.verify_integrity(&watched, 2000).unwrap();
        assert!(result.signature_valid);
        assert!(!result.matches);
        assert_eq!(result.mismatches.len(), 1);
        assert_eq!(result.mismatches[0].path, watched[0].display().to_string());

        // A real (non-debug) finding should have been recorded for this,
        // and — since "binary-a" doesn't match the built-in
        // dendrited/dendrite-guard critical-path heuristic — trust state
        // should have degraded exactly one step, not jumped to compromised.
        let findings = store.findings().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "warning");
        assert_eq!(store.trust_state(), TrustState::Degraded);
    }

    #[test]
    fn verify_integrity_flags_a_deleted_watched_file() {
        let dir = TestDir::new("deleted-file");
        let watched = vec![dir.write_watched("binary-a", b"present")];

        let mut store = GuardStore::open(&dir.db_path()).unwrap();
        store.establish_baseline(&watched, 1000).unwrap();

        fs::remove_file(&watched[0]).unwrap();

        let result = store.verify_integrity(&watched, 2000).unwrap();
        assert!(!result.matches);
        assert_eq!(result.mismatches[0].current_digest, "absent");
    }

    #[test]
    fn verify_integrity_flags_a_watch_path_added_after_the_baseline() {
        let dir = TestDir::new("added-path");
        let first = dir.write_watched("binary-a", b"present");

        let mut store = GuardStore::open(&dir.db_path()).unwrap();
        store
            .establish_baseline(std::slice::from_ref(&first), 1000)
            .unwrap();

        let second = dir.write_watched("binary-b", b"new file");
        let result = store.verify_integrity(&[first, second], 2000).unwrap();
        assert!(!result.matches);
        assert_eq!(result.mismatches[0].baseline_digest, "not-in-baseline");

        // A path missing from the baseline is config drift, not a security
        // event — it must not produce a finding or move trust state.
        assert!(store.findings().unwrap().is_empty());
        assert_eq!(store.trust_state(), TrustState::Trusted);
    }

    #[test]
    fn verify_integrity_detects_a_hand_edited_baseline_signature() {
        let dir = TestDir::new("tampered-signature");
        let watched = vec![dir.write_watched("binary-a", b"present")];

        let mut store = GuardStore::open(&dir.db_path()).unwrap();
        store.establish_baseline(&watched, 1000).unwrap();
        let bogus_signature = format!("ed25519:{}", "00".repeat(64));
        store
            .connection
            .execute(
                "UPDATE integrity_manifest SET signature = ?1 WHERE singleton = 1",
                params![bogus_signature],
            )
            .unwrap();

        let result = store.verify_integrity(&watched, 2000).unwrap();
        assert!(!result.signature_valid);
        assert!(!result.matches);

        // A bad baseline signature is a Critical, unconditional finding —
        // straight to Compromised, regardless of which paths are watched.
        let findings = store.findings().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "critical");
        assert_eq!(store.trust_state(), TrustState::Compromised);
    }

    #[test]
    fn verify_integrity_without_a_baseline_is_an_error() {
        let dir = TestDir::new("no-baseline");
        let mut store = GuardStore::open(&dir.db_path()).unwrap();
        assert!(store.verify_integrity(&[], 2000).is_err());
    }

    #[test]
    fn a_critical_watched_binary_mismatch_jumps_straight_to_compromised() {
        let dir = TestDir::new("critical-binary");
        // "dendrited" is one of the two hard-coded critical basenames (see
        // `default_severity_for_path`) regardless of its directory.
        let watched = vec![dir.write_watched("dendrited", b"original bytes")];

        let mut store = GuardStore::open(&dir.db_path()).unwrap();
        store.establish_baseline(&watched, 1000).unwrap();
        fs::write(&watched[0], b"tampered bytes").unwrap();

        let result = store.verify_integrity(&watched, 2000).unwrap();
        assert!(!result.matches);
        assert_eq!(store.trust_state(), TrustState::Compromised);
    }

    #[test]
    fn repeated_verification_of_the_same_mismatch_records_only_one_finding() {
        let dir = TestDir::new("dedup-mismatch");
        let watched = vec![dir.write_watched("binary-a", b"original contents")];

        let mut store = GuardStore::open(&dir.db_path()).unwrap();
        store.establish_baseline(&watched, 1000).unwrap();
        fs::write(&watched[0], b"tampered once").unwrap();

        store.verify_integrity(&watched, 2000).unwrap();
        store.verify_integrity(&watched, 3000).unwrap();
        store.verify_integrity(&watched, 4000).unwrap();
        assert_eq!(store.findings().unwrap().len(), 1);

        // A further change to the same path is a new event and gets its
        // own finding.
        fs::write(&watched[0], b"tampered again, differently").unwrap();
        store.verify_integrity(&watched, 5000).unwrap();
        assert_eq!(store.findings().unwrap().len(), 2);
    }

    #[test]
    fn re_establishing_a_baseline_clears_open_mismatches_but_not_trust_state() {
        let dir = TestDir::new("rebaseline-clears");
        let watched = vec![dir.write_watched("binary-a", b"v1")];

        let mut store = GuardStore::open(&dir.db_path()).unwrap();
        store.establish_baseline(&watched, 1000).unwrap();
        fs::write(&watched[0], b"v2 (unexpected change)").unwrap();
        store.verify_integrity(&watched, 2000).unwrap();
        assert_eq!(store.trust_state(), TrustState::Degraded);
        assert_eq!(store.findings().unwrap().len(), 1);

        // Re-baselining acknowledges the new content as the trusted
        // baseline going forward...
        store.establish_baseline(&watched, 3000).unwrap();
        let result = store.verify_integrity(&watched, 4000).unwrap();
        assert!(result.matches);
        // ...but does not itself restore trust — that's `complete_recovery`'s
        // job, gated on a token an operator must read off the host (see the
        // `recovery_` tests below).
        assert_eq!(store.trust_state(), TrustState::Degraded);
        assert_eq!(store.findings().unwrap().len(), 1);
    }

    #[test]
    fn trust_state_never_auto_improves_after_a_worse_finding() {
        let dir = TestDir::new("no-auto-improve");
        let watched = vec![dir.write_watched("dendrited", b"original")];

        let mut store = GuardStore::open(&dir.db_path()).unwrap();
        store.establish_baseline(&watched, 1000).unwrap();
        fs::write(&watched[0], b"tampered").unwrap();
        store.verify_integrity(&watched, 2000).unwrap();
        assert_eq!(store.trust_state(), TrustState::Compromised);

        // Put the file back exactly as the baseline expects — a clean
        // verification pass must not un-compromise Guard by itself.
        fs::write(&watched[0], b"original").unwrap();
        let result = store.verify_integrity(&watched, 3000).unwrap();
        assert!(result.matches);
        assert_eq!(store.trust_state(), TrustState::Compromised);
    }

    /// Reads back whatever `begin_recovery` wrote to disk — standing in for
    /// an operator with real host access (`sudo cat`), which is the whole
    /// point: `dendrited`'s own user cannot do this (see `README.md`'s
    /// "Recovery" section).
    fn read_recovery_token(result: &RecoveryBeginDto) -> String {
        fs::read_to_string(&result.token_path).unwrap()
    }

    #[test]
    fn begin_recovery_refuses_when_already_trusted() {
        let dir = TestDir::new("recovery-already-trusted");
        let mut store = GuardStore::open(&dir.db_path()).unwrap();
        assert_eq!(store.trust_state(), TrustState::Trusted);
        assert!(store.begin_recovery(1000).is_err());
    }

    #[test]
    fn recovery_round_trip_restores_trust_and_rebaselines() {
        let dir = TestDir::new("recovery-round-trip");
        let watched = vec![dir.write_watched("dendrited", b"original")];

        let mut store = GuardStore::open(&dir.db_path()).unwrap();
        store.establish_baseline(&watched, 1000).unwrap();
        fs::write(&watched[0], b"tampered").unwrap();
        store.verify_integrity(&watched, 2000).unwrap();
        assert_eq!(store.trust_state(), TrustState::Compromised);

        let begun = store.begin_recovery(3000).unwrap();
        assert_eq!(begun.trust_state, "recovering");
        assert_eq!(store.trust_state(), TrustState::Recovering);

        // Operator applies/accepts the fix, then reads the token directly
        // off the host (not over the IPC wire) and submits it.
        let token = read_recovery_token(&begun);
        let recovered = store.complete_recovery(&token, &watched, 4000).unwrap();
        assert_eq!(recovered.trust_state, "trusted");
        assert_eq!(store.trust_state(), TrustState::Trusted);
        assert!(recovered.manifest_status.established);

        // The fresh baseline was established against current (tampered)
        // content, so a verification pass right after recovery is clean.
        let result = store.verify_integrity(&watched, 5000).unwrap();
        assert!(result.matches);
        assert_eq!(store.trust_state(), TrustState::Trusted);
    }

    #[test]
    fn complete_recovery_rejects_a_wrong_token_and_changes_nothing() {
        let dir = TestDir::new("recovery-wrong-token");
        let watched = vec![dir.write_watched("dendrited", b"original")];

        let mut store = GuardStore::open(&dir.db_path()).unwrap();
        store.establish_baseline(&watched, 1000).unwrap();
        fs::write(&watched[0], b"tampered").unwrap();
        store.verify_integrity(&watched, 2000).unwrap();
        store.begin_recovery(3000).unwrap();

        assert!(
            store
                .complete_recovery("not-the-real-token", &watched, 4000)
                .is_err()
        );
        assert_eq!(store.trust_state(), TrustState::Recovering);
    }

    #[test]
    fn complete_recovery_refuses_without_a_prior_begin_recovery() {
        let dir = TestDir::new("recovery-no-begin");
        let watched = vec![dir.write_watched("dendrited", b"original")];

        let mut store = GuardStore::open(&dir.db_path()).unwrap();
        store.establish_baseline(&watched, 1000).unwrap();
        // Never compromised, never began recovery — trust state is still
        // Trusted, so there is no issued token to match against.
        assert!(store.complete_recovery("anything", &watched, 2000).is_err());
        assert_eq!(store.trust_state(), TrustState::Trusted);
    }

    #[test]
    fn re_issuing_recovery_invalidates_the_previous_token() {
        let dir = TestDir::new("recovery-reissue");
        let watched = vec![dir.write_watched("dendrited", b"original")];

        let mut store = GuardStore::open(&dir.db_path()).unwrap();
        store.establish_baseline(&watched, 1000).unwrap();
        fs::write(&watched[0], b"tampered").unwrap();
        store.verify_integrity(&watched, 2000).unwrap();

        let first = store.begin_recovery(3000).unwrap();
        let old_token = read_recovery_token(&first);
        let second = store.begin_recovery(3500).unwrap();
        assert_eq!(store.trust_state(), TrustState::Recovering);

        // The old token (from the first begin_recovery call) must no
        // longer work now that a new one has been issued.
        assert!(store.complete_recovery(&old_token, &watched, 4000).is_err());
        assert_eq!(store.trust_state(), TrustState::Recovering);

        let new_token = read_recovery_token(&second);
        assert!(store.complete_recovery(&new_token, &watched, 4500).is_ok());
        assert_eq!(store.trust_state(), TrustState::Trusted);
    }
}
