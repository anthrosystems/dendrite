//! Software update and remediation interfaces.
//!
//! No concrete package-manager mutation is implemented in this foundation layer.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateCandidate {
    pub package: String,
    pub installed_version: String,
    pub candidate_version: String,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateError {
    RejectedPlan,
    PackageManager(String),
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
            installed_version: "1.0".into(),
            candidate_version: "1.1".into(),
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

        assert_eq!(result, Err(UpdateError::RejectedPlan));
        assert_eq!(updater.package_manager.applied, 0);
    }
}
