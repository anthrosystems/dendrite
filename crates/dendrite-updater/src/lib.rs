//! Package remediation and Dendrite self-update primitives.
//!
//! The updater never grants itself authority. Callers must complete Dendrite's
//! MAGI -> policy -> Guard authorisation path before invoking mutating package
//! operations. Self-updates additionally require an independently verifiable
//! signed manifest and a rollback package before commit.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateCandidate {
    pub package: String,
    pub architecture: String,
    pub installed_version: String,
    pub candidate_version: String,
    pub fixed_version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    Verified,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePlan {
    pub candidate: UpdateCandidate,
    pub verification: VerificationStatus,
}

#[derive(Debug)]
pub enum UpdateError {
    RejectedPlan,
    MissingFixedVersion,
    NoCandidate(String),
    CandidateNotNewer {
        installed: String,
        candidate: String,
    },
    CandidateDoesNotFix {
        candidate: String,
        fixed: String,
    },
    PackageChanged {
        expected: String,
        actual: String,
    },
    PrivilegeRequired,
    PackageManager(String),
    Io(io::Error),
    Json(serde_json::Error),
    InvalidManifest(String),
    SignatureRejected(String),
    HashMismatch {
        expected: String,
        actual: String,
    },
    DowngradeRejected {
        current: String,
        requested: String,
    },
    RevokedVersion(String),
    RollbackUnavailable(String),
    HealthCheckFailed(String),
}

impl From<io::Error> for UpdateError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for UpdateError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

pub trait PackageManager {
    fn apply(&mut self, candidate: &UpdateCandidate) -> Result<(), UpdateError>;
    fn rollback(&mut self, candidate: &UpdateCandidate) -> Result<(), UpdateError>;
}

pub struct Updater<P> {
    package_manager: P,
}

impl<P> Updater<P>
where
    P: PackageManager,
{
    pub fn new(package_manager: P) -> Self {
        Self { package_manager }
    }

    pub fn apply_verified(&mut self, plan: &UpdatePlan) -> Result<(), UpdateError> {
        if plan.verification != VerificationStatus::Verified {
            return Err(UpdateError::RejectedPlan);
        }
        self.package_manager.apply(&plan.candidate)
    }

    pub fn rollback(&mut self, candidate: &UpdateCandidate) -> Result<(), UpdateError> {
        self.package_manager.rollback(candidate)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AptPackageManager;

impl AptPackageManager {
    pub fn prepare(
        &self,
        package: &str,
        architecture: &str,
        expected_installed: &str,
        fixed_version: Option<&str>,
    ) -> Result<UpdatePlan, UpdateError> {
        let fixed = fixed_version.ok_or(UpdateError::MissingFixedVersion)?;
        let actual = installed_version(package, architecture)?;
        if actual != expected_installed {
            return Err(UpdateError::PackageChanged {
                expected: expected_installed.into(),
                actual,
            });
        }
        let candidate =
            apt_candidate(package)?.ok_or_else(|| UpdateError::NoCandidate(package.into()))?;
        if !dpkg_version_test(&candidate, "gt", expected_installed)? {
            return Err(UpdateError::CandidateNotNewer {
                installed: expected_installed.into(),
                candidate,
            });
        }
        if !dpkg_version_test(&candidate, "ge", fixed)? {
            return Err(UpdateError::CandidateDoesNotFix {
                candidate,
                fixed: fixed.into(),
            });
        }
        Ok(UpdatePlan {
            candidate: UpdateCandidate {
                package: package.into(),
                architecture: architecture.into(),
                installed_version: expected_installed.into(),
                candidate_version: candidate,
                fixed_version: Some(fixed.into()),
            },
            verification: VerificationStatus::Verified,
        })
    }

    pub fn revalidate(&self, plan: &UpdatePlan) -> Result<(), UpdateError> {
        let actual = installed_version(&plan.candidate.package, &plan.candidate.architecture)?;
        if actual != plan.candidate.installed_version {
            return Err(UpdateError::PackageChanged {
                expected: plan.candidate.installed_version.clone(),
                actual,
            });
        }
        let candidate = apt_candidate(&plan.candidate.package)?
            .ok_or_else(|| UpdateError::NoCandidate(plan.candidate.package.clone()))?;
        if candidate != plan.candidate.candidate_version {
            return Err(UpdateError::PackageChanged {
                expected: plan.candidate.candidate_version.clone(),
                actual: candidate,
            });
        }
        Ok(())
    }

    pub fn verify_fixed(&self, plan: &UpdatePlan) -> Result<(), UpdateError> {
        let actual = installed_version(&plan.candidate.package, &plan.candidate.architecture)?;
        let Some(fixed) = plan.candidate.fixed_version.as_deref() else {
            return Err(UpdateError::MissingFixedVersion);
        };
        if dpkg_version_test(&actual, "ge", fixed)? {
            Ok(())
        } else {
            Err(UpdateError::CandidateDoesNotFix {
                candidate: actual,
                fixed: fixed.into(),
            })
        }
    }
}

impl PackageManager for AptPackageManager {
    fn apply(&mut self, candidate: &UpdateCandidate) -> Result<(), UpdateError> {
        require_root()?;
        let spec = format!("{}={}", candidate.package, candidate.candidate_version);
        run_checked(
            Command::new("apt-get").args([
                "install",
                "--only-upgrade",
                "--assume-yes",
                "--",
                &spec,
            ]),
            "apt-get package update",
        )?;
        Ok(())
    }

    fn rollback(&mut self, candidate: &UpdateCandidate) -> Result<(), UpdateError> {
        require_root()?;
        let spec = format!("{}={}", candidate.package, candidate.installed_version);
        run_checked(
            Command::new("apt-get").args([
                "install",
                "--assume-yes",
                "--allow-downgrades",
                "--",
                &spec,
            ]),
            "apt-get package rollback",
        )?;
        Ok(())
    }
}

fn installed_version(package: &str, architecture: &str) -> Result<String, UpdateError> {
    let package_spec = if architecture.is_empty() {
        package.to_owned()
    } else {
        format!("{package}:{architecture}")
    };
    let output = Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", &package_spec])
        .output()
        .map_err(UpdateError::Io)?;
    checked_stdout(output, "dpkg-query installed version")
}

fn apt_candidate(package: &str) -> Result<Option<String>, UpdateError> {
    let output = Command::new("apt-cache")
        .args(["policy", package])
        .output()
        .map_err(UpdateError::Io)?;
    let text = checked_stdout(output, "apt-cache policy")?;
    Ok(parse_apt_candidate(&text))
}

fn parse_apt_candidate(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix("Candidate:")
            .map(str::trim)
            .filter(|value| !value.is_empty() && *value != "(none)")
            .map(str::to_owned)
    })
}

fn dpkg_version_test(left: &str, operator: &str, right: &str) -> Result<bool, UpdateError> {
    let status = Command::new("dpkg")
        .args(["--compare-versions", left, operator, right])
        .status()
        .map_err(UpdateError::Io)?;
    Ok(status.success())
}

fn require_root() -> Result<(), UpdateError> {
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    if unsafe { libc::geteuid() } == 0 {
        Ok(())
    } else {
        Err(UpdateError::PrivilegeRequired)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelfUpdateManifest {
    pub schema_version: u32,
    pub product: String,
    pub version: String,
    pub package_format: String,
    pub artifact_filename: String,
    pub artifact_sha256: String,
    pub issued_at: u64,
    #[serde(default)]
    pub revoked_versions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedSelfUpdate {
    pub manifest: SelfUpdateManifest,
    pub manifest_path: PathBuf,
    pub signature_path: PathBuf,
    pub artifact_path: PathBuf,
    pub stage_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct SelfUpdater {
    installed_version: String,
}

impl Default for SelfUpdater {
    fn default() -> Self {
        Self {
            installed_version: env!("CARGO_PKG_VERSION").into(),
        }
    }
}

impl SelfUpdater {
    pub fn new(installed_version: impl Into<String>) -> Self {
        Self {
            installed_version: installed_version.into(),
        }
    }

    pub fn verify_and_stage(
        &self,
        manifest_path: &Path,
        signature_path: &Path,
        artifact_path: &Path,
        public_key_path: &Path,
        stage_root: &Path,
    ) -> Result<StagedSelfUpdate, UpdateError> {
        let manifest_bytes = fs::read(manifest_path)?;
        let manifest: SelfUpdateManifest = serde_json::from_slice(&manifest_bytes)?;
        validate_manifest(&manifest)?;
        self.enforce_version_policy(&manifest)?;
        verify_ed25519_signature(manifest_path, signature_path, public_key_path)?;
        let actual_hash = sha256_file(artifact_path)?;
        if !actual_hash.eq_ignore_ascii_case(&manifest.artifact_sha256) {
            return Err(UpdateError::HashMismatch {
                expected: manifest.artifact_sha256.clone(),
                actual: actual_hash,
            });
        }
        let actual_name = artifact_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if actual_name != manifest.artifact_filename {
            return Err(UpdateError::InvalidManifest(format!(
                "artifact filename mismatch: manifest={} supplied={actual_name}",
                manifest.artifact_filename
            )));
        }

        let stage_dir = stage_root.join(&manifest.version);
        fs::create_dir_all(&stage_dir)?;
        let staged_manifest = stage_dir.join("manifest.json");
        let staged_signature = stage_dir.join("manifest.sig");
        let staged_artifact = stage_dir.join(&manifest.artifact_filename);
        fs::copy(manifest_path, &staged_manifest)?;
        fs::copy(signature_path, &staged_signature)?;
        fs::copy(artifact_path, &staged_artifact)?;

        Ok(StagedSelfUpdate {
            manifest,
            manifest_path: staged_manifest,
            signature_path: staged_signature,
            artifact_path: staged_artifact,
            stage_dir,
        })
    }

    pub fn install_staged(&self, staged: &StagedSelfUpdate) -> Result<(), UpdateError> {
        require_root()?;
        if staged.manifest.package_format != "deb" {
            return Err(UpdateError::InvalidManifest(
                "only native Debian packages are supported for self-update".into(),
            ));
        }

        let rollback_package = self.prepare_rollback_package(&staged.stage_dir)?;
        let install_result = self.install_deb(&staged.artifact_path).and_then(|_| {
            restart_dendrited()?;
            self.verify_installed_version(&staged.manifest.version)?;
            verify_dendrited_health()
        });

        if let Err(error) = install_result {
            let rollback_result = self
                .install_deb(&rollback_package)
                .and_then(|_| restart_dendrited());
            if let Err(rollback_error) = rollback_result {
                return Err(UpdateError::PackageManager(format!(
                    "self-update failed ({error:?}) and rollback also failed ({rollback_error:?})"
                )));
            }
            return Err(error);
        }
        Ok(())
    }

    fn enforce_version_policy(&self, manifest: &SelfUpdateManifest) -> Result<(), UpdateError> {
        if manifest
            .revoked_versions
            .iter()
            .any(|v| v == &manifest.version)
        {
            return Err(UpdateError::RevokedVersion(manifest.version.clone()));
        }
        if compare_release_versions(&manifest.version, &self.installed_version)?
            != Ordering::Greater
        {
            return Err(UpdateError::DowngradeRejected {
                current: self.installed_version.clone(),
                requested: manifest.version.clone(),
            });
        }
        Ok(())
    }

    fn prepare_rollback_package(&self, stage_dir: &Path) -> Result<PathBuf, UpdateError> {
        let rollback_dir = stage_dir.join("rollback");
        fs::create_dir_all(&rollback_dir)?;
        let spec = format!("dendrite={}", self.installed_version);
        let output = Command::new("apt-get")
            .current_dir(&rollback_dir)
            .args(["download", &spec])
            .output()
            .map_err(UpdateError::Io)?;
        if !output.status.success() {
            return Err(UpdateError::RollbackUnavailable(
                String::from_utf8_lossy(&output.stderr).trim().into(),
            ));
        }
        let mut debs = fs::read_dir(&rollback_dir)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("deb"))
            .collect::<Vec<_>>();
        debs.sort();
        debs.into_iter().next().ok_or_else(|| {
            UpdateError::RollbackUnavailable("apt-get download produced no rollback .deb".into())
        })
    }

    fn install_deb(&self, path: &Path) -> Result<(), UpdateError> {
        run_checked(
            Command::new("dpkg").arg("--install").arg(path),
            "dpkg install",
        )?;
        Ok(())
    }

    fn verify_installed_version(&self, expected: &str) -> Result<(), UpdateError> {
        let output = Command::new("dpkg-query")
            .args(["-W", "-f=${Version}", "dendrite"])
            .output()
            .map_err(UpdateError::Io)?;
        let actual = checked_stdout(output, "dpkg-query dendrite version")?;
        if actual == expected {
            Ok(())
        } else {
            Err(UpdateError::PackageChanged {
                expected: expected.into(),
                actual,
            })
        }
    }
}

fn validate_manifest(manifest: &SelfUpdateManifest) -> Result<(), UpdateError> {
    if manifest.schema_version != 1 {
        return Err(UpdateError::InvalidManifest(format!(
            "unsupported update manifest schema {}",
            manifest.schema_version
        )));
    }
    if manifest.product != "dendrite" {
        return Err(UpdateError::InvalidManifest(
            "manifest product must be dendrite".into(),
        ));
    }
    if manifest.package_format != "deb" {
        return Err(UpdateError::InvalidManifest(
            "package_format must be deb".into(),
        ));
    }
    if manifest.artifact_filename.is_empty() || manifest.artifact_sha256.len() != 64 {
        return Err(UpdateError::InvalidManifest(
            "artifact filename/hash is invalid".into(),
        ));
    }
    Ok(())
}

fn verify_ed25519_signature(
    manifest: &Path,
    signature: &Path,
    public_key: &Path,
) -> Result<(), UpdateError> {
    let output = Command::new("openssl")
        .args(["pkeyutl", "-verify", "-pubin", "-inkey"])
        .arg(public_key)
        .args(["-rawin", "-in"])
        .arg(manifest)
        .args(["-sigfile"])
        .arg(signature)
        .output()
        .map_err(UpdateError::Io)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(UpdateError::SignatureRejected(
            String::from_utf8_lossy(&output.stderr).trim().into(),
        ))
    }
}

fn sha256_file(path: &Path) -> Result<String, UpdateError> {
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .map_err(UpdateError::Io)?;
    let text = checked_stdout(output, "sha256sum")?;
    text.split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| UpdateError::PackageManager("sha256sum returned no digest".into()))
}

fn compare_release_versions(left: &str, right: &str) -> Result<Ordering, UpdateError> {
    fn parts(value: &str) -> Result<Vec<u64>, UpdateError> {
        let core = value.split_once('-').map_or(value, |(core, _)| core);
        core.split('.')
            .map(|part| {
                part.parse::<u64>().map_err(|_| {
                    UpdateError::InvalidManifest(format!("unsupported release version {value}"))
                })
            })
            .collect()
    }
    let mut left_parts = parts(left)?;
    let mut right_parts = parts(right)?;
    let len = left_parts.len().max(right_parts.len());
    left_parts.resize(len, 0);
    right_parts.resize(len, 0);
    Ok(left_parts.cmp(&right_parts))
}

fn restart_dendrited() -> Result<(), UpdateError> {
    run_checked(
        Command::new("systemctl").args(["restart", "dendrited.service"]),
        "restart dendrited",
    )?;
    Ok(())
}

fn verify_dendrited_health() -> Result<(), UpdateError> {
    let output = Command::new("systemctl")
        .args(["is-active", "--quiet", "dendrited.service"])
        .output()
        .map_err(UpdateError::Io)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(UpdateError::HealthCheckFailed(
            "dendrited.service is not active".into(),
        ))
    }
}

fn run_checked(command: &mut Command, label: &str) -> Result<Output, UpdateError> {
    let output = command.output().map_err(UpdateError::Io)?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(UpdateError::PackageManager(format!(
            "{label} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn checked_stdout(output: Output, label: &str) -> Result<String, UpdateError> {
    if !output.status.success() {
        return Err(UpdateError::PackageManager(format!(
            "{label} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingPackageManager {
        applied: usize,
    }

    impl PackageManager for RecordingPackageManager {
        fn apply(&mut self, _: &UpdateCandidate) -> Result<(), UpdateError> {
            self.applied += 1;
            Ok(())
        }
        fn rollback(&mut self, _: &UpdateCandidate) -> Result<(), UpdateError> {
            Ok(())
        }
    }

    fn candidate() -> UpdateCandidate {
        UpdateCandidate {
            package: "example".into(),
            architecture: "amd64".into(),
            installed_version: "1.0".into(),
            candidate_version: "1.1".into(),
            fixed_version: Some("1.1".into()),
        }
    }

    #[test]
    fn rejected_plan_never_reaches_package_manager() {
        let manager = RecordingPackageManager::default();
        let mut updater = Updater::new(manager);
        let result = updater.apply_verified(&UpdatePlan {
            candidate: candidate(),
            verification: VerificationStatus::Rejected,
        });
        assert!(matches!(result, Err(UpdateError::RejectedPlan)));
        assert_eq!(updater.package_manager.applied, 0);
    }

    #[test]
    fn apt_candidate_parser_ignores_none() {
        assert_eq!(
            parse_apt_candidate("Installed: 1\nCandidate: 2\n"),
            Some("2".into())
        );
        assert_eq!(parse_apt_candidate("Candidate: (none)\n"), None);
    }

    #[test]
    fn release_version_comparison_blocks_downgrade() {
        assert_eq!(
            compare_release_versions("1.2.0", "1.1.9").unwrap(),
            Ordering::Greater
        );
        assert_eq!(
            compare_release_versions("1.0", "1.0.0").unwrap(),
            Ordering::Equal
        );
        assert_eq!(
            compare_release_versions("0.9.9", "1.0.0").unwrap(),
            Ordering::Less
        );
    }
}
