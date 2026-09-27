use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PRIVATE_KEY_PREFIX: &str = "file:";

#[derive(Debug)]
pub enum SelfStoreError {
    Database(rusqlite::Error),
    Io(std::io::Error),
    Crypto(String),
    InvalidKeyState(String),
}

impl From<rusqlite::Error> for SelfStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

impl From<std::io::Error> for SelfStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceKeyRecord {
    pub key_id: String,
    pub instance_id: String,
    pub public_key: String,
    pub private_key_reference: String,
    pub fingerprint: String,
    pub created_at: u64,
    pub retired_at: Option<u64>,
    pub revoked_at: Option<u64>,
    pub is_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AnalysisReviewRecord {
    pub review_id: String,
    pub antiserum_id: String,
    pub label: Option<String>,
    pub created_at: u64,
    pub last_opened_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AntiserumKnowledgeAcceptanceRecord {
    pub antiserum_id: String,
    pub issuer_instance_id: String,
    pub accepted_at: u64,
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

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

pub struct SelfStore {
    connection: Connection,
    key_dir: PathBuf,
}

impl SelfStore {
    pub fn open(path: &str) -> Result<Self, SelfStoreError> {
        let connection = Connection::open(path)?;
        configure_connection(&connection, path)?;
        let key_dir = default_key_dir(path)?;
        let store = Self {
            connection,
            key_dir,
        };
        store.initialise()?;
        Ok(store)
    }

    #[cfg(test)]
    fn open_with_key_dir(path: &str, key_dir: PathBuf) -> Result<Self, SelfStoreError> {
        let connection = Connection::open(path)?;
        configure_connection(&connection, path)?;
        let store = Self {
            connection,
            key_dir,
        };
        store.initialise()?;
        Ok(store)
    }

    /// Cheap liveness probe for the self-store database (instance identity
    /// and signing keys).
    pub fn ping(&self) -> Result<(), SelfStoreError> {
        self.connection.execute_batch("SELECT 1;")?;
        Ok(())
    }

    fn initialise(&self) -> Result<(), SelfStoreError> {
        self.connection.execute_batch(
            "
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS instance_identity (
                singleton   INTEGER PRIMARY KEY CHECK (singleton = 1),
                instance_id TEXT NOT NULL UNIQUE,
                created_at  INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS instance_keys (
                key_id                TEXT PRIMARY KEY,
                instance_id           TEXT NOT NULL,
                public_key            TEXT NOT NULL,
                private_key_reference TEXT NOT NULL,
                fingerprint           TEXT NOT NULL UNIQUE,
                created_at            INTEGER NOT NULL,
                retired_at            INTEGER,
                revoked_at            INTEGER,
                is_active             INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
                FOREIGN KEY(instance_id) REFERENCES instance_identity(instance_id)
            );
            CREATE INDEX IF NOT EXISTS idx_instance_keys_instance
                ON instance_keys(instance_id, is_active);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_instance_keys_one_active
                ON instance_keys(instance_id) WHERE is_active = 1;

            CREATE TABLE IF NOT EXISTS antiserum_export_sequences (
                stream   TEXT PRIMARY KEY,
                sequence INTEGER NOT NULL CHECK(sequence >= 0)
            );

            CREATE TABLE IF NOT EXISTS antiserum_import_sequences (
                issuer_instance_id TEXT NOT NULL,
                key_fingerprint    TEXT NOT NULL,
                stream             TEXT NOT NULL,
                sequence           INTEGER NOT NULL CHECK(sequence >= 0),
                PRIMARY KEY(issuer_instance_id, key_fingerprint, stream)
            );

            CREATE TABLE IF NOT EXISTS analysis_reviews (
                review_id      TEXT PRIMARY KEY,
                antiserum_id   TEXT NOT NULL,
                label          TEXT,
                created_at     INTEGER NOT NULL,
                last_opened_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_analysis_reviews_last_opened
                ON analysis_reviews(last_opened_at DESC, created_at DESC);


            CREATE TABLE IF NOT EXISTS antiserum_knowledge_acceptance (
                antiserum_id       TEXT PRIMARY KEY,
                issuer_instance_id TEXT NOT NULL,
                accepted_at        INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS http_api_token (
                singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
                token      TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            ",
        )?;

        let existing = self
            .connection
            .query_row(
                "SELECT instance_id FROM instance_identity WHERE singleton = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;

        if existing.is_none() {
            let instance_id = uuid::Uuid::new_v4().to_string();
            self.connection.execute(
                "INSERT INTO instance_identity (singleton, instance_id, created_at)
                 VALUES (1, ?1, ?2)",
                params![instance_id, unix_now()],
            )?;
        }

        self.ensure_key_directories()?;
        Ok(())
    }

    pub fn instance_id(&self) -> Result<String, SelfStoreError> {
        Ok(self.connection.query_row(
            "SELECT instance_id FROM instance_identity WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?)
    }

    /// Bearer token that gates `dendrited`'s HTTP API and `/ws` WebSocket
    /// upgrade (see `crates/dendrited/src/http.rs`). Generated once and
    /// stable across restarts — like the signing key, but deliberately not
    /// rotated automatically, since there's no revocation/re-issue UI flow
    /// yet and rotating it out from under an already-authenticated browser
    /// tab (localStorage) or long-lived automation would be a worse default
    /// than a stable value an operator can explicitly rotate later. Unlike
    /// the signing key's private material, this is stored directly in
    /// `self.sqlite3` (not a separate `0600` file) — it's a shared secret
    /// with no asymmetric structure to protect, and this file already lives
    /// under `/var/lib/dendrite`, which is not readable outside the
    /// `dendrite` account.
    pub fn ensure_http_api_token(&mut self) -> Result<String, SelfStoreError> {
        if let Some(token) = self
            .connection
            .query_row(
                "SELECT token FROM http_api_token WHERE singleton = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            return Ok(token);
        }
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret)
            .map_err(|error| SelfStoreError::Crypto(format!("OS RNG failed: {error}")))?;
        let token = hex::encode(secret);
        self.connection.execute(
            "INSERT INTO http_api_token (singleton, token, created_at) VALUES (1, ?1, ?2)",
            params![token, unix_now()],
        )?;
        Ok(token)
    }

    pub fn active_key(&self) -> Result<Option<InstanceKeyRecord>, SelfStoreError> {
        let instance_id = self.instance_id()?;
        let mut statement = self.connection.prepare(
            "SELECT key_id, instance_id, public_key, private_key_reference, fingerprint,
                    created_at, retired_at, revoked_at, is_active
             FROM instance_keys
             WHERE instance_id = ?1 AND is_active = 1",
        )?;
        let mut rows = statement.query(params![instance_id])?;
        let first = rows.next()?.map(read_key_row).transpose()?;
        if rows.next()?.is_some() {
            return Err(SelfStoreError::InvalidKeyState(
                "more than one active signing key exists for this instance".into(),
            ));
        }
        Ok(first)
    }

    pub fn ensure_active_signing_key(&mut self) -> Result<InstanceKeyRecord, SelfStoreError> {
        if let Some(active) = self.active_key()? {
            self.validate_key_material(&active)?;
            return Ok(active);
        }
        self.create_initial_key()
    }

    pub fn rotate_active_signing_key(&mut self) -> Result<InstanceKeyRecord, SelfStoreError> {
        let current = self.active_key()?.ok_or_else(|| {
            SelfStoreError::InvalidKeyState("cannot rotate without an active signing key".into())
        })?;
        let replacement = self.prepare_key_material()?;
        let now = unix_now();
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "UPDATE instance_keys
             SET is_active = 0, retired_at = ?2
             WHERE key_id = ?1 AND is_active = 1",
            params![current.key_id, now],
        )?;
        if let Err(error) = insert_key(&transaction, &replacement) {
            let _ = fs::remove_file(private_key_path(&replacement.private_key_reference));
            return Err(error.into());
        }
        transaction.commit()?;
        Ok(replacement)
    }

    pub fn revoke_key(
        &mut self,
        key_id: &str,
    ) -> Result<Option<InstanceKeyRecord>, SelfStoreError> {
        let existing = self.load_key(key_id)?.ok_or_else(|| {
            SelfStoreError::InvalidKeyState(format!("unknown signing key {key_id}"))
        })?;
        if existing.revoked_at.is_some() {
            return self.active_key();
        }

        let replacement = if existing.is_active {
            Some(self.prepare_key_material()?)
        } else {
            None
        };
        let now = unix_now();
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "UPDATE instance_keys
             SET is_active = 0, revoked_at = ?2
             WHERE key_id = ?1",
            params![key_id, now],
        )?;
        if let Some(ref key) = replacement
            && let Err(error) = insert_key(&transaction, key)
        {
            let _ = fs::remove_file(private_key_path(&key.private_key_reference));
            return Err(error.into());
        }
        transaction.commit()?;
        Ok(replacement.or(self.active_key()?))
    }

    pub fn list_keys(&self) -> Result<Vec<InstanceKeyRecord>, SelfStoreError> {
        let instance_id = self.instance_id()?;
        let mut statement = self.connection.prepare(
            "SELECT key_id, instance_id, public_key, private_key_reference, fingerprint,
                    created_at, retired_at, revoked_at, is_active
             FROM instance_keys
             WHERE instance_id = ?1
             ORDER BY created_at, key_id",
        )?;
        let rows = statement.query_map(params![instance_id], read_key_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn sign_instance_bound(
        &self,
        key_id: &str,
        context: &str,
        payload: &[u8],
    ) -> Result<String, SelfStoreError> {
        let key = self.load_key(key_id)?.ok_or_else(|| {
            SelfStoreError::InvalidKeyState(format!("unknown signing key {key_id}"))
        })?;
        if !key.is_active || key.revoked_at.is_some() {
            return Err(SelfStoreError::InvalidKeyState(format!(
                "signing key {key_id} is not active"
            )));
        }
        self.validate_key_material(&key)?;
        let secret = read_private_seed(&key.private_key_reference, &key.key_id)?;
        let signing_key = SigningKey::from_bytes(&secret);
        let preimage = instance_bound_preimage(&key.instance_id, &key.key_id, context, payload);
        let signature: Signature = signing_key.sign(&preimage);
        Ok(format!("ed25519:{}", hex::encode(signature.to_bytes())))
    }

    pub fn verify_instance_bound(
        instance_id: &str,
        key_id: &str,
        public_key: &str,
        fingerprint: &str,
        context: &str,
        payload: &[u8],
        signature: &str,
    ) -> Result<(), SelfStoreError> {
        let public_bytes = parse_public_key(public_key)?;
        let expected_fingerprint = format!("sha256:{}", hex::encode(Sha256::digest(public_bytes)));
        if expected_fingerprint != fingerprint {
            return Err(SelfStoreError::InvalidKeyState(
                "public key fingerprint does not match supplied fingerprint".into(),
            ));
        }
        let verifying_key = VerifyingKey::from_bytes(&public_bytes).map_err(|error| {
            SelfStoreError::Crypto(format!("invalid Ed25519 public key: {error}"))
        })?;
        let signature = parse_signature(signature)?;
        let preimage = instance_bound_preimage(instance_id, key_id, context, payload);
        verifying_key
            .verify(&preimage, &signature)
            .map_err(|error| {
                SelfStoreError::Crypto(format!("signature verification failed: {error}"))
            })
    }

    pub fn next_antiserum_sequence(&mut self, stream: &str) -> Result<u64, SelfStoreError> {
        if stream.is_empty() {
            return Err(SelfStoreError::InvalidKeyState(
                "Antiserum sequence stream must not be empty".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let current: Option<u64> = transaction
            .query_row(
                "SELECT sequence FROM antiserum_export_sequences WHERE stream = ?1",
                params![stream],
                |row| row.get(0),
            )
            .optional()?;
        let next = current.unwrap_or(0).checked_add(1).ok_or_else(|| {
            SelfStoreError::InvalidKeyState("Antiserum sequence exhausted".into())
        })?;
        transaction.execute(
            "INSERT INTO antiserum_export_sequences(stream, sequence) VALUES (?1, ?2)
             ON CONFLICT(stream) DO UPDATE SET sequence = excluded.sequence",
            params![stream, next],
        )?;
        transaction.commit()?;
        Ok(next)
    }

    pub fn accept_antiserum_sequence(
        &mut self,
        issuer_instance_id: &str,
        key_fingerprint: &str,
        stream: &str,
        sequence: u64,
    ) -> Result<(), SelfStoreError> {
        if sequence == 0 || stream.is_empty() {
            return Err(SelfStoreError::InvalidKeyState(
                "Antiserum sequence and stream are invalid".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let highest: Option<u64> = transaction
            .query_row(
                "SELECT sequence FROM antiserum_import_sequences
                 WHERE issuer_instance_id = ?1 AND key_fingerprint = ?2 AND stream = ?3",
                params![issuer_instance_id, key_fingerprint, stream],
                |row| row.get(0),
            )
            .optional()?;
        if highest.is_some_and(|highest| sequence <= highest) {
            return Err(SelfStoreError::InvalidKeyState(format!(
                "Antiserum sequence {sequence} is not newer than accepted sequence {}",
                highest.unwrap_or_default()
            )));
        }
        transaction.execute(
            "INSERT INTO antiserum_import_sequences(
                issuer_instance_id, key_fingerprint, stream, sequence
             ) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(issuer_instance_id, key_fingerprint, stream)
             DO UPDATE SET sequence = excluded.sequence",
            params![issuer_instance_id, key_fingerprint, stream, sequence],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn create_analysis_review(
        &self,
        antiserum_id: &str,
        label: Option<&str>,
        now: u64,
    ) -> Result<AnalysisReviewRecord, SelfStoreError> {
        if antiserum_id.trim().is_empty() {
            return Err(SelfStoreError::InvalidKeyState(
                "analysis review requires an Antiserum ID".into(),
            ));
        }
        let review = AnalysisReviewRecord {
            review_id: uuid::Uuid::new_v4().to_string(),
            antiserum_id: antiserum_id.to_owned(),
            label: label
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
            created_at: now,
            last_opened_at: now,
        };
        self.connection.execute(
            "INSERT INTO analysis_reviews(review_id, antiserum_id, label, created_at, last_opened_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                review.review_id,
                review.antiserum_id,
                review.label,
                review.created_at,
                review.last_opened_at
            ],
        )?;
        Ok(review)
    }

    pub fn analysis_reviews(&self) -> Result<Vec<AnalysisReviewRecord>, SelfStoreError> {
        let mut statement = self.connection.prepare(
            "SELECT review_id, antiserum_id, label, created_at, last_opened_at
             FROM analysis_reviews
             ORDER BY last_opened_at DESC, created_at DESC, review_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(AnalysisReviewRecord {
                review_id: row.get(0)?,
                antiserum_id: row.get(1)?,
                label: row.get(2)?,
                created_at: row.get(3)?,
                last_opened_at: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn touch_analysis_review(
        &self,
        review_id: &str,
        now: u64,
    ) -> Result<Option<AnalysisReviewRecord>, SelfStoreError> {
        let changed = self.connection.execute(
            "UPDATE analysis_reviews SET last_opened_at = ?2 WHERE review_id = ?1",
            params![review_id, now],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        self.analysis_review(review_id)
    }

    pub fn analysis_review(
        &self,
        review_id: &str,
    ) -> Result<Option<AnalysisReviewRecord>, SelfStoreError> {
        self.connection
            .query_row(
                "SELECT review_id, antiserum_id, label, created_at, last_opened_at
                 FROM analysis_reviews WHERE review_id = ?1",
                params![review_id],
                |row| {
                    Ok(AnalysisReviewRecord {
                        review_id: row.get(0)?,
                        antiserum_id: row.get(1)?,
                        label: row.get(2)?,
                        created_at: row.get(3)?,
                        last_opened_at: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(SelfStoreError::from)
    }

    pub fn delete_analysis_review(&self, review_id: &str) -> Result<bool, SelfStoreError> {
        Ok(self.connection.execute(
            "DELETE FROM analysis_reviews WHERE review_id = ?1",
            params![review_id],
        )? > 0)
    }

    pub fn antiserum_knowledge_acceptance(
        &self,
        antiserum_id: &str,
    ) -> Result<Option<AntiserumKnowledgeAcceptanceRecord>, SelfStoreError> {
        self.connection
            .query_row(
                "SELECT antiserum_id, issuer_instance_id, accepted_at
                 FROM antiserum_knowledge_acceptance WHERE antiserum_id = ?1",
                params![antiserum_id],
                |row| {
                    Ok(AntiserumKnowledgeAcceptanceRecord {
                        antiserum_id: row.get(0)?,
                        issuer_instance_id: row.get(1)?,
                        accepted_at: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(SelfStoreError::from)
    }

    pub fn mark_antiserum_knowledge_accepted(
        &self,
        antiserum_id: &str,
        issuer_instance_id: &str,
        accepted_at: u64,
    ) -> Result<AntiserumKnowledgeAcceptanceRecord, SelfStoreError> {
        if antiserum_id.trim().is_empty() || issuer_instance_id.trim().is_empty() {
            return Err(SelfStoreError::InvalidKeyState(
                "Antiserum knowledge acceptance requires package and issuer IDs".into(),
            ));
        }
        self.connection.execute(
            "INSERT INTO antiserum_knowledge_acceptance(antiserum_id, issuer_instance_id, accepted_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(antiserum_id) DO NOTHING",
            params![antiserum_id, issuer_instance_id, accepted_at],
        )?;
        self.antiserum_knowledge_acceptance(antiserum_id)?
            .ok_or_else(|| {
                SelfStoreError::InvalidKeyState(
                    "failed to persist Antiserum knowledge acceptance".into(),
                )
            })
    }

    fn create_initial_key(&mut self) -> Result<InstanceKeyRecord, SelfStoreError> {
        let key = self.prepare_key_material()?;
        if let Err(error) = insert_key(&self.connection, &key) {
            let _ = fs::remove_file(private_key_path(&key.private_key_reference));
            return Err(error.into());
        }
        Ok(key)
    }

    fn load_key(&self, key_id: &str) -> Result<Option<InstanceKeyRecord>, SelfStoreError> {
        Ok(self
            .connection
            .query_row(
                "SELECT key_id, instance_id, public_key, private_key_reference, fingerprint,
                    created_at, retired_at, revoked_at, is_active
             FROM instance_keys WHERE key_id = ?1",
                params![key_id],
                read_key_row,
            )
            .optional()?)
    }

    fn prepare_key_material(&self) -> Result<InstanceKeyRecord, SelfStoreError> {
        let instance_id = self.instance_id()?;
        let key_id = self.next_key_id()?;
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret)
            .map_err(|error| SelfStoreError::Crypto(format!("OS RNG failed: {error}")))?;
        let signing_key = SigningKey::from_bytes(&secret);
        let public_bytes = signing_key.verifying_key().to_bytes();
        let public_key = format!("ed25519:{}", hex::encode(public_bytes));
        let fingerprint = format!("sha256:{}", hex::encode(Sha256::digest(public_bytes)));

        self.ensure_key_directories()?;
        let key_path = self.key_dir.join(format!("{key_id}.ed25519"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)?;
        file.write_all(&secret)?;
        file.sync_all()?;
        drop(file);

        Ok(InstanceKeyRecord {
            key_id,
            instance_id,
            public_key,
            private_key_reference: format!("{PRIVATE_KEY_PREFIX}{}", key_path.display()),
            fingerprint,
            created_at: unix_now(),
            retired_at: None,
            revoked_at: None,
            is_active: true,
        })
    }

    fn validate_key_material(&self, key: &InstanceKeyRecord) -> Result<(), SelfStoreError> {
        self.ensure_key_directories()?;
        let secret = read_private_seed(&key.private_key_reference, &key.key_id)?;
        let signing_key = SigningKey::from_bytes(&secret);
        let public_bytes = signing_key.verifying_key().to_bytes();
        let expected_public = format!("ed25519:{}", hex::encode(public_bytes));
        let expected_fingerprint = format!("sha256:{}", hex::encode(Sha256::digest(public_bytes)));
        if key.public_key != expected_public || key.fingerprint != expected_fingerprint {
            return Err(SelfStoreError::InvalidKeyState(format!(
                "private key material does not match stored public identity for {}",
                key.key_id
            )));
        }
        Ok(())
    }

    fn ensure_key_directories(&self) -> Result<(), SelfStoreError> {
        let identity_dir = self.key_dir.parent().ok_or_else(|| {
            SelfStoreError::InvalidKeyState("identity key directory has no parent".into())
        })?;
        fs::create_dir_all(identity_dir)?;
        fs::set_permissions(identity_dir, fs::Permissions::from_mode(0o700))?;
        fs::create_dir_all(&self.key_dir)?;
        fs::set_permissions(&self.key_dir, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn next_key_id(&self) -> Result<String, SelfStoreError> {
        let instance_id = self.instance_id()?;
        let mut statement = self
            .connection
            .prepare("SELECT key_id FROM instance_keys WHERE instance_id = ?1")?;
        let rows = statement.query_map(params![instance_id], |row| row.get::<_, String>(0))?;
        let mut max_id = 0u64;
        for key_id in rows {
            let key_id = key_id?;
            if let Some(number) = key_id
                .strip_prefix("key_")
                .and_then(|value| value.parse().ok())
            {
                max_id = max_id.max(number);
            }
        }
        Ok(format!("key_{:08}", max_id + 1))
    }
}

fn read_private_seed(reference: &str, key_id: &str) -> Result<[u8; 32], SelfStoreError> {
    let path = reference.strip_prefix(PRIVATE_KEY_PREFIX).ok_or_else(|| {
        SelfStoreError::InvalidKeyState(format!("unsupported private key reference for {key_id}"))
    })?;
    let metadata = fs::metadata(path)?;
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(SelfStoreError::InvalidKeyState(format!(
            "private key {key_id} must have mode 0600"
        )));
    }
    fs::read(path)?.try_into().map_err(|_| {
        SelfStoreError::InvalidKeyState(format!(
            "private key {key_id} is not a 32-byte Ed25519 seed"
        ))
    })
}

fn parse_public_key(value: &str) -> Result<[u8; 32], SelfStoreError> {
    let encoded = value
        .strip_prefix("ed25519:")
        .ok_or_else(|| SelfStoreError::Crypto("unsupported public key algorithm".into()))?;
    let bytes = hex::decode(encoded)
        .map_err(|error| SelfStoreError::Crypto(format!("invalid public key hex: {error}")))?;
    bytes
        .try_into()
        .map_err(|_| SelfStoreError::Crypto("Ed25519 public key must contain 32 bytes".into()))
}

fn parse_signature(value: &str) -> Result<Signature, SelfStoreError> {
    let encoded = value
        .strip_prefix("ed25519:")
        .ok_or_else(|| SelfStoreError::Crypto("unsupported signature algorithm".into()))?;
    let bytes = hex::decode(encoded)
        .map_err(|error| SelfStoreError::Crypto(format!("invalid signature hex: {error}")))?;
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| SelfStoreError::Crypto("Ed25519 signature must contain 64 bytes".into()))?;
    Ok(Signature::from_bytes(&bytes))
}

fn instance_bound_preimage(
    instance_id: &str,
    key_id: &str,
    context: &str,
    payload: &[u8],
) -> Vec<u8> {
    let mut preimage =
        Vec::with_capacity(32 + instance_id.len() + key_id.len() + context.len() + payload.len());
    preimage.extend_from_slice(b"DENDRITE-SIGNATURE-V1\0");
    preimage.extend_from_slice(instance_id.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(key_id.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(context.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(payload);
    preimage
}

fn insert_key(connection: &Connection, key: &InstanceKeyRecord) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO instance_keys (
            key_id, instance_id, public_key, private_key_reference, fingerprint,
            created_at, retired_at, revoked_at, is_active
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            key.key_id,
            key.instance_id,
            key.public_key,
            key.private_key_reference,
            key.fingerprint,
            key.created_at,
            key.retired_at,
            key.revoked_at,
            i64::from(key.is_active),
        ],
    )?;
    Ok(())
}

fn read_key_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<InstanceKeyRecord> {
    Ok(InstanceKeyRecord {
        key_id: row.get(0)?,
        instance_id: row.get(1)?,
        public_key: row.get(2)?,
        private_key_reference: row.get(3)?,
        fingerprint: row.get(4)?,
        created_at: row.get(5)?,
        retired_at: row.get(6)?,
        revoked_at: row.get(7)?,
        is_active: row.get::<_, i64>(8)? != 0,
    })
}

fn default_key_dir(self_path: &str) -> Result<PathBuf, SelfStoreError> {
    if self_path == ":memory:" {
        return Ok(std::env::temp_dir()
            .join("dendrite-memory-identity")
            .join(uuid::Uuid::new_v4().to_string()));
    }
    let path = Path::new(self_path);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let parent = absolute.parent().unwrap_or_else(|| Path::new("."));
    Ok(parent.join("identity").join("keys"))
}

fn private_key_path(reference: &str) -> &Path {
    Path::new(
        reference
            .strip_prefix(PRIVATE_KEY_PREFIX)
            .unwrap_or(reference),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_paths(name: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "dendrite-self-test-{name}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        (root.join("self.sqlite3"), root.join("identity/keys"))
    }

    #[test]
    fn initialise_generates_one_stable_instance_id() {
        let (path, key_dir) = test_paths("identity");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let path_text = path.to_string_lossy().into_owned();

        let first = {
            let store = SelfStore::open_with_key_dir(&path_text, key_dir.clone()).unwrap();
            store.instance_id().unwrap()
        };
        let second = {
            let store = SelfStore::open_with_key_dir(&path_text, key_dir).unwrap();
            store.instance_id().unwrap()
        };

        let _ = fs::remove_dir_all(path.parent().unwrap());
        assert_eq!(first, second);
        assert!(uuid::Uuid::parse_str(&first).is_ok());
    }

    #[test]
    fn signing_key_is_generated_once_and_private_material_stays_out_of_sqlite() {
        let (path, key_dir) = test_paths("key");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let path_text = path.to_string_lossy().into_owned();
        let mut store = SelfStore::open_with_key_dir(&path_text, key_dir).unwrap();

        let first = store.ensure_active_signing_key().unwrap();
        let second = store.ensure_active_signing_key().unwrap();
        assert_eq!(first, second);
        assert_eq!(first.key_id, "key_00000001");
        assert!(first.public_key.starts_with("ed25519:"));
        assert!(first.fingerprint.starts_with("sha256:"));
        assert_eq!(first.fingerprint.len(), 71);

        let key_path = private_key_path(&first.private_key_reference);
        assert_eq!(fs::read(key_path).unwrap().len(), 32);
        assert_eq!(
            fs::metadata(key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let private_blob: Option<String> = store
            .connection
            .query_row(
                "SELECT public_key FROM instance_keys WHERE key_id = ?1",
                params![first.key_id],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        assert!(private_blob.unwrap().starts_with("ed25519:"));

        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn http_api_token_is_generated_once_and_stable_across_reopen() {
        let (path, key_dir) = test_paths("http-token");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let path_text = path.to_string_lossy().into_owned();

        let first = {
            let mut store = SelfStore::open_with_key_dir(&path_text, key_dir.clone()).unwrap();
            let first = store.ensure_http_api_token().unwrap();
            let second = store.ensure_http_api_token().unwrap();
            assert_eq!(first, second);
            first
        };
        let reopened = {
            let mut store = SelfStore::open_with_key_dir(&path_text, key_dir).unwrap();
            store.ensure_http_api_token().unwrap()
        };

        let _ = fs::remove_dir_all(path.parent().unwrap());
        assert_eq!(first, reopened);
        // 32 random bytes, hex-encoded.
        assert_eq!(first.len(), 64);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn rotation_retires_old_key_and_keeps_exactly_one_active_key() {
        let (path, key_dir) = test_paths("rotate");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let path_text = path.to_string_lossy().into_owned();
        let mut store = SelfStore::open_with_key_dir(&path_text, key_dir).unwrap();
        let first = store.ensure_active_signing_key().unwrap();
        let second = store.rotate_active_signing_key().unwrap();

        assert_ne!(first.key_id, second.key_id);
        assert_eq!(second.key_id, "key_00000002");
        let keys = store.list_keys().unwrap();
        assert_eq!(keys.iter().filter(|key| key.is_active).count(), 1);
        assert!(
            keys.iter()
                .find(|key| key.key_id == first.key_id)
                .unwrap()
                .retired_at
                .is_some()
        );
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn identity_directories_are_hardened_to_0700() {
        let (path, key_dir) = test_paths("permissions");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::create_dir_all(key_dir.parent().unwrap()).unwrap();
        fs::set_permissions(key_dir.parent().unwrap(), fs::Permissions::from_mode(0o775)).unwrap();
        let path_text = path.to_string_lossy().into_owned();
        let mut store = SelfStore::open_with_key_dir(&path_text, key_dir.clone()).unwrap();
        store.ensure_active_signing_key().unwrap();

        assert_eq!(
            fs::metadata(key_dir.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&key_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn antiserum_sequences_are_monotonic_and_replays_are_rejected() {
        let (path, key_dir) = test_paths("sequences");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let path_text = path.to_string_lossy().into_owned();
        let mut store = SelfStore::open_with_key_dir(&path_text, key_dir).unwrap();

        assert_eq!(store.next_antiserum_sequence("default").unwrap(), 1);
        assert_eq!(store.next_antiserum_sequence("default").unwrap(), 2);
        store
            .accept_antiserum_sequence("instance-a", "sha256:key-a", "default", 7)
            .unwrap();
        assert!(
            store
                .accept_antiserum_sequence("instance-a", "sha256:key-a", "default", 7)
                .is_err()
        );
        assert!(
            store
                .accept_antiserum_sequence("instance-a", "sha256:key-a", "default", 6)
                .is_err()
        );
        store
            .accept_antiserum_sequence("instance-a", "sha256:key-a", "default", 8)
            .unwrap();
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn revoking_active_key_provisions_a_replacement() {
        let (path, key_dir) = test_paths("revoke");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let path_text = path.to_string_lossy().into_owned();
        let mut store = SelfStore::open_with_key_dir(&path_text, key_dir).unwrap();
        let first = store.ensure_active_signing_key().unwrap();
        let replacement = store.revoke_key(&first.key_id).unwrap().unwrap();

        assert_ne!(first.key_id, replacement.key_id);
        let keys = store.list_keys().unwrap();
        let revoked = keys.iter().find(|key| key.key_id == first.key_id).unwrap();
        assert!(revoked.revoked_at.is_some());
        assert!(!revoked.is_active);
        assert_eq!(keys.iter().filter(|key| key.is_active).count(), 1);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}
