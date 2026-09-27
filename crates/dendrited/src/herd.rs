//! Herd: automated, full-mesh Antiserum exchange between operator-named
//! peer hosts.
//!
//! There is no leader and no election anywhere in this module, deliberately
//! — nothing in the codebase does host-to-host consensus, and building a
//! real one (Raft/corosync-style) is a separate, much larger undertaking
//! than a first skeleton warrants. Instead this reuses the existing,
//! already-validated Antiserum export/import/verify pipeline
//! (`crate::antiserum`, `crate::analysis`) exactly as it works for a
//! manual, one-off `.danti` exchange today, and just automates it on a
//! timer between a statically configured, full-mesh peer list — the same
//! way a Proxmox cluster's config is fully replicated to every node rather
//! than funnelled through one.
//!
//! Two things this deliberately does *not* do, both worth being explicit
//! about rather than silently deciding:
//!
//! - **No auto-accept.** Pushing a package to a peer's
//!   `/api/v1/analysis/import` only verifies, deduplicates, and stores it —
//!   it does not merge into that peer's live memory graph or vulnerability
//!   data. That merge (`DaemonCore::accept_antiserum_knowledge`) stays an
//!   explicit operator action, matching the trust model the rest of
//!   Antiserum already uses ("each acceptance an explicit operator
//!   action" — see `docs/ROADMAP.md`). A per-peer `auto_accept` flag exists
//!   in config for an operator to opt into for hosts they fully trust, but
//!   nothing in this module calls `accept_antiserum_knowledge` yet — that
//!   wiring is a deliberate follow-up, not an oversight.
//! - **Push only, not pull.** A peer that's down or unreachable simply
//!   fails that tick and is retried next interval; there is no read-side
//!   reconciliation. Fine for a skeleton, worth outgrowing later.

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub enum HerdError {
    Io(std::io::Error),
    Database(rusqlite::Error),
    Json(serde_json::Error),
    Transport(String),
}

impl From<std::io::Error> for HerdError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for HerdError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

impl From<serde_json::Error> for HerdError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

/// One operator-configured peer. Loaded from a small JSON file (see
/// `load_peers`) rather than an env var, since a peer list is naturally
/// more than one line and grows over time — matches
/// `packaging/herd.json.example`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HerdPeerConfig {
    /// A short operator-chosen name for this peer, used as its primary key
    /// in `HerdStore` and shown by `dendrite-cli herd status`. Must be
    /// unique across the configured peer list.
    pub label: String,
    /// The peer's own `dendrited` HTTP API base URL, e.g.
    /// `http://10.20.0.5:8766` — no trailing slash.
    pub base_url: String,
    /// Bearer token for the peer's HTTP API (its own
    /// `DENDRITE_HTTP_TOKEN_FILE` contents — see `http.rs`). Required: the
    /// receiving `/api/v1/analysis/import` route is gated the same as every
    /// other route on that API.
    pub token: String,
    /// Reserved for a future, explicitly-opted-in step that would call
    /// `DaemonCore::accept_antiserum_knowledge` on the *receiving* side
    /// automatically. Not acted on anywhere yet — see the module doc
    /// comment — but recorded now so a config file written today doesn't
    /// need reshaping later.
    #[serde(default)]
    pub auto_accept: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HerdPeerStatus {
    pub label: String,
    pub base_url: String,
    pub last_attempt_at: Option<u64>,
    pub last_success_at: Option<u64>,
    pub last_error: Option<String>,
    pub packages_pushed: u64,
}

/// Reads a peer list from a JSON file (an array of `HerdPeerConfig`). A
/// missing file is not an error — it means Herd is simply not configured
/// on this host, which is the correct default for a normal single-node
/// install — and returns an empty list.
pub fn load_peers(path: &Path) -> Result<Vec<HerdPeerConfig>, HerdError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(path)?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

/// Persists per-peer push status across restarts (`dendrite-cli herd
/// status` reads this). Deliberately does not store the peer's own
/// knowledge — only "did our last push to them succeed, and when" — the
/// actual exchanged data lives in the ordinary `AntiserumPackageStore` on
/// whichever side received it, exactly as a manual `.danti` import does
/// today.
pub struct HerdStore {
    connection: Connection,
}

impl HerdStore {
    pub fn open(path: &str) -> Result<Self, HerdError> {
        let connection = Connection::open(path)?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS herd_peer_status (
                label TEXT PRIMARY KEY,
                base_url TEXT NOT NULL,
                last_attempt_at INTEGER,
                last_success_at INTEGER,
                last_error TEXT,
                packages_pushed INTEGER NOT NULL DEFAULT 0
            );",
        )?;
        Ok(Self { connection })
    }

    pub fn record_attempt(&self, label: &str, base_url: &str, now: u64) -> Result<(), HerdError> {
        self.connection.execute(
            "INSERT INTO herd_peer_status (label, base_url, last_attempt_at, packages_pushed)
             VALUES (?1, ?2, ?3, 0)
             ON CONFLICT(label) DO UPDATE SET
                base_url = excluded.base_url,
                last_attempt_at = excluded.last_attempt_at",
            params![label, base_url, now],
        )?;
        Ok(())
    }

    pub fn record_success(&self, label: &str, now: u64) -> Result<(), HerdError> {
        self.connection.execute(
            "UPDATE herd_peer_status
             SET last_success_at = ?2, last_error = NULL, packages_pushed = packages_pushed + 1
             WHERE label = ?1",
            params![label, now],
        )?;
        Ok(())
    }

    pub fn record_error(&self, label: &str, error: &str) -> Result<(), HerdError> {
        self.connection.execute(
            "UPDATE herd_peer_status SET last_error = ?2 WHERE label = ?1",
            params![label, error],
        )?;
        Ok(())
    }

    pub fn status(&self, label: &str) -> Result<Option<HerdPeerStatus>, HerdError> {
        Ok(self
            .connection
            .query_row(
                "SELECT label, base_url, last_attempt_at, last_success_at, last_error, packages_pushed
                 FROM herd_peer_status WHERE label = ?1",
                params![label],
                row_to_status,
            )
            .optional()?)
    }

    pub fn list_status(&self) -> Result<Vec<HerdPeerStatus>, HerdError> {
        let mut statement = self.connection.prepare(
            "SELECT label, base_url, last_attempt_at, last_success_at, last_error, packages_pushed
             FROM herd_peer_status ORDER BY label ASC",
        )?;
        let rows = statement
            .query_map([], row_to_status)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

fn row_to_status(row: &rusqlite::Row<'_>) -> rusqlite::Result<HerdPeerStatus> {
    Ok(HerdPeerStatus {
        label: row.get(0)?,
        base_url: row.get(1)?,
        last_attempt_at: row.get(2)?,
        last_success_at: row.get(3)?,
        last_error: row.get(4)?,
        packages_pushed: row.get(5)?,
    })
}

/// POSTs a `.danti` package's raw bytes to a peer's existing
/// `/api/v1/analysis/import` route — the same route a manual, one-off
/// import already uses (see `http.rs`), just called automatically instead
/// of by an operator uploading a file. Authentication is the peer's own
/// ordinary HTTP API bearer token; message authenticity/integrity comes
/// from the Antiserum envelope's own Ed25519 signature, verified on the
/// receiving end exactly as a manual import is — the transport itself
/// carries no additional trust. An operator who wants transport encryption
/// between hosts (e.g. across untrusted network segments) is expected to
/// put a TLS-terminating reverse proxy in front of each peer's API, the
/// same way they would for the UI.
pub fn push_to_peer(bytes: &[u8], peer: &HerdPeerConfig) -> Result<(), HerdError> {
    let url = format!(
        "{}/api/v1/analysis/import",
        peer.base_url.trim_end_matches('/')
    );
    ureq::post(&url)
        .set("Authorization", &format!("Bearer {}", peer.token))
        .set("Content-Type", "application/octet-stream")
        .send_bytes(bytes)
        .map_err(|error| HerdError::Transport(error.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_peer_file_means_herd_is_disabled_not_an_error() {
        let path = Path::new("/nonexistent/herd-config-that-does-not-exist.json");
        let peers = load_peers(path).unwrap();
        assert!(peers.is_empty());
    }

    #[test]
    fn peer_file_parses_into_configs() {
        let dir = std::env::temp_dir().join(format!("dendrite-herd-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("herd.json");
        fs::write(
            &path,
            r#"[{"label":"host-b","base_url":"http://10.20.0.5:8766","token":"secret"}]"#,
        )
        .unwrap();

        let peers = load_peers(&path).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].label, "host-b");
        assert_eq!(peers[0].base_url, "http://10.20.0.5:8766");
        assert!(!peers[0].auto_accept);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn store_tracks_attempts_success_and_error_per_peer() {
        let path = std::env::temp_dir().join(format!(
            "dendrite-herd-store-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        let store = HerdStore::open(path.to_str().unwrap()).unwrap();

        store
            .record_attempt("host-b", "http://10.20.0.5:8766", 100)
            .unwrap();
        let status = store.status("host-b").unwrap().unwrap();
        assert_eq!(status.last_attempt_at, Some(100));
        assert_eq!(status.packages_pushed, 0);

        store.record_success("host-b", 105).unwrap();
        let status = store.status("host-b").unwrap().unwrap();
        assert_eq!(status.last_success_at, Some(105));
        assert_eq!(status.packages_pushed, 1);
        assert_eq!(status.last_error, None);

        store
            .record_attempt("host-b", "http://10.20.0.5:8766", 200)
            .unwrap();
        store.record_error("host-b", "connection refused").unwrap();
        let status = store.status("host-b").unwrap().unwrap();
        assert_eq!(status.last_attempt_at, Some(200));
        assert_eq!(status.last_success_at, Some(105));
        assert_eq!(status.last_error.as_deref(), Some("connection refused"));

        let all = store.list_status().unwrap();
        assert_eq!(all.len(), 1);

        let _ = fs::remove_file(path);
    }
}
