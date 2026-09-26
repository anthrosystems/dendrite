use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum AdaptiveAnalysisError {
    Io(std::io::Error),
    Database(rusqlite::Error),
    Json(serde_json::Error),
    Invalid(String),
}

impl From<std::io::Error> for AdaptiveAnalysisError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for AdaptiveAnalysisError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

impl From<serde_json::Error> for AdaptiveAnalysisError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveAnalysisSources {
    pub self_db: PathBuf,
    pub stm_db: PathBuf,
    pub ltm_db: PathBuf,
    pub incidents_db: PathBuf,
    pub guard_db: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveAnalysisCampaign {
    pub campaign_id: String,
    pub label: Option<String>,
    pub state: String,
    pub created_at: u64,
    pub workspace: PathBuf,
    pub baseline: AdaptiveAnalysisSources,
    pub run_count: u64,
    pub notes: Vec<String>,
}

/// Low-level foundation for the future Adaptive Malware Analysis system.
///
/// The important invariant is intentional: a campaign receives SQLite snapshots of the
/// live Dendrite stores and experimentation is expected to open only the copies under
/// `workspace`. This manager never returns a mutable handle to the production databases.
pub struct AdaptiveAnalysisManager {
    root: PathBuf,
}

impl AdaptiveAnalysisManager {
    pub fn open(root: PathBuf) -> Result<Self, AdaptiveAnalysisError> {
        secure_dir(&root)?;
        Ok(Self { root })
    }

    pub fn create_campaign(
        &self,
        sources: &AdaptiveAnalysisSources,
        label: Option<&str>,
        now: u64,
    ) -> Result<AdaptiveAnalysisCampaign, AdaptiveAnalysisError> {
        for (name, path) in [
            ("self", &sources.self_db),
            ("stm", &sources.stm_db),
            ("ltm", &sources.ltm_db),
            ("incidents", &sources.incidents_db),
            ("guard", &sources.guard_db),
        ] {
            if !path.exists() {
                return Err(AdaptiveAnalysisError::Invalid(format!(
                    "cannot create Adaptive Malware Analysis campaign: {name} database {} does not exist",
                    path.display()
                )));
            }
        }

        let campaign_id = format!("ama-{}", uuid::Uuid::new_v4());
        let workspace = self.root.join(&campaign_id);
        secure_dir(&workspace)?;
        secure_dir(&workspace.join("artifacts"))?;

        let baseline = AdaptiveAnalysisSources {
            self_db: workspace.join("self.sqlite3"),
            stm_db: workspace.join("stm.sqlite3"),
            ltm_db: workspace.join("ltm.sqlite3"),
            incidents_db: workspace.join("incidents.sqlite3"),
            guard_db: workspace.join("guard.sqlite3"),
        };

        for (source, destination) in [
            (&sources.self_db, &baseline.self_db),
            (&sources.stm_db, &baseline.stm_db),
            (&sources.ltm_db, &baseline.ltm_db),
            (&sources.incidents_db, &baseline.incidents_db),
            (&sources.guard_db, &baseline.guard_db),
        ] {
            sqlite_snapshot(source, destination)?;
        }

        let campaign = AdaptiveAnalysisCampaign {
            campaign_id,
            label: label.map(str::to_owned),
            state: "prepared".into(),
            created_at: now,
            workspace: workspace.clone(),
            baseline,
            run_count: 0,
            notes: vec![
                "Campaign databases are isolated snapshots. No experimental mutation is permitted against the active Dendrite databases.".into(),
                "Counter execution is intentionally not implemented here; future counters must use the normal MAGI -> policy -> Guard -> transaction pipeline inside the contained campaign environment.".into(),
            ],
        };

        write_manifest(&workspace.join("campaign.json"), &campaign)?;
        Ok(campaign)
    }

    pub fn list_campaigns(&self) -> Result<Vec<AdaptiveAnalysisCampaign>, AdaptiveAnalysisError> {
        let mut campaigns = Vec::new();

        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;

            if !entry.file_type()?.is_dir() {
                continue;
            }

            let path = entry.path().join("campaign.json");

            if !path.exists() {
                continue;
            }

            let campaign: AdaptiveAnalysisCampaign = serde_json::from_slice(&fs::read(path)?)?;

            campaigns.push(campaign);
        }

        campaigns.sort_by_key(|campaign| std::cmp::Reverse(campaign.created_at));

        Ok(campaigns)
    }

    pub fn discard_campaign(&self, campaign_id: &str) -> Result<bool, AdaptiveAnalysisError> {
        validate_campaign_id(campaign_id)?;

        let path = self.root.join(campaign_id);

        if !path.exists() {
            return Ok(false);
        }

        fs::remove_dir_all(path)?;
        Ok(true)
    }
}

fn sqlite_snapshot(source: &Path, destination: &Path) -> Result<(), AdaptiveAnalysisError> {
    if destination.exists() {
        return Err(AdaptiveAnalysisError::Invalid(format!(
            "campaign snapshot destination {} already exists",
            destination.display()
        )));
    }

    let source = Connection::open(source)?;
    source.busy_timeout(std::time::Duration::from_secs(5))?;

    source.execute(
        "VACUUM INTO ?1",
        params![destination.to_string_lossy().as_ref()],
    )?;

    fs::set_permissions(destination, fs::Permissions::from_mode(0o600))?;

    Ok(())
}

fn write_manifest(
    path: &Path,
    value: &AdaptiveAnalysisCampaign,
) -> Result<(), AdaptiveAnalysisError> {
    let bytes = serde_json::to_vec_pretty(value)?;

    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true).mode(0o600);

    let mut file = options.open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;

    Ok(())
}

fn secure_dir(path: &Path) -> Result<(), AdaptiveAnalysisError> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn validate_campaign_id(value: &str) -> Result<(), AdaptiveAnalysisError> {
    if !value.starts_with("ama-")
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(AdaptiveAnalysisError::Invalid(
            "invalid Adaptive Malware Analysis campaign id".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_db(path: &Path, value: &str) {
        let connection = Connection::open(path).unwrap();

        connection
            .execute_batch("CREATE TABLE state(value TEXT NOT NULL);")
            .unwrap();

        connection
            .execute("INSERT INTO state(value) VALUES (?1)", [value])
            .unwrap();
    }

    #[test]
    fn campaign_snapshots_are_independent_of_live_databases() {
        let root = std::env::temp_dir().join(format!("dendrite-ama-test-{}", uuid::Uuid::new_v4()));

        fs::create_dir_all(&root).unwrap();

        let active = root.join("active");
        fs::create_dir_all(&active).unwrap();

        let sources = AdaptiveAnalysisSources {
            self_db: active.join("self.sqlite3"),
            stm_db: active.join("stm.sqlite3"),
            ltm_db: active.join("ltm.sqlite3"),
            incidents_db: active.join("incidents.sqlite3"),
            guard_db: active.join("guard.sqlite3"),
        };

        for path in [
            &sources.self_db,
            &sources.stm_db,
            &sources.ltm_db,
            &sources.incidents_db,
            &sources.guard_db,
        ] {
            create_db(path, "live");
        }

        let manager = AdaptiveAnalysisManager::open(root.join("campaigns")).unwrap();

        let campaign = manager
            .create_campaign(&sources, Some("sample"), 10)
            .unwrap();

        let campaign_memory = Connection::open(&campaign.baseline.stm_db).unwrap();

        campaign_memory
            .execute("UPDATE state SET value = 'campaign'", [])
            .unwrap();

        let active_memory = Connection::open(&sources.stm_db).unwrap();

        let active_value: String = active_memory
            .query_row("SELECT value FROM state", [], |row| row.get(0))
            .unwrap();

        let campaign_value: String = campaign_memory
            .query_row("SELECT value FROM state", [], |row| row.get(0))
            .unwrap();

        assert_eq!(active_value, "live");
        assert_eq!(campaign_value, "campaign");

        fs::remove_dir_all(root).unwrap();
    }
}
