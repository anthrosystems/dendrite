use dendrite_updater::SelfUpdater;
use std::env;
use std::path::Path;

const DEFAULT_STAGE_ROOT: &str = "/var/lib/dendrite/updates/staged";

fn main() {
    if let Err(error) = run() {
        eprintln!("dendrite-updater: {error:?}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), dendrite_updater::UpdateError> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [command, manifest, signature, artifact, public_key] if command == "verify" => {
            let temp =
                env::temp_dir().join(format!("dendrite-update-verify-{}", std::process::id()));
            let staged = SelfUpdater::default().verify_and_stage(
                Path::new(manifest),
                Path::new(signature),
                Path::new(artifact),
                Path::new(public_key),
                &temp,
            )?;
            println!(
                "verified Dendrite {} ({})",
                staged.manifest.version, staged.manifest.artifact_filename
            );
            let _ = std::fs::remove_dir_all(temp);
        }
        [command, manifest, signature, artifact, public_key] if command == "stage" => {
            stage(
                manifest,
                signature,
                artifact,
                public_key,
                Path::new(DEFAULT_STAGE_ROOT),
            )?;
        }
        [
            command,
            manifest,
            signature,
            artifact,
            public_key,
            stage_root,
        ] if command == "stage" => {
            stage(
                manifest,
                signature,
                artifact,
                public_key,
                Path::new(stage_root),
            )?;
        }
        [command, manifest, signature, artifact, public_key] if command == "install" => {
            install(
                manifest,
                signature,
                artifact,
                public_key,
                Path::new(DEFAULT_STAGE_ROOT),
            )?;
        }
        [
            command,
            manifest,
            signature,
            artifact,
            public_key,
            stage_root,
        ] if command == "install" => {
            install(
                manifest,
                signature,
                artifact,
                public_key,
                Path::new(stage_root),
            )?;
        }
        _ => {
            println!(
                "Dendrite updater {}\n\nUsage:\n  dendrite-updater verify <manifest.json> <manifest.sig> <artifact.deb> <public-key.pem>\n  dendrite-updater stage  <manifest.json> <manifest.sig> <artifact.deb> <public-key.pem> [stage-root]\n  dendrite-updater install <manifest.json> <manifest.sig> <artifact.deb> <public-key.pem> [stage-root]\n\nThe manifest signature and artifact hash are verified before staging. Install also requires root, refuses downgrade/revoked target versions, requires a rollback package before commit, restarts dendrited, verifies the installed package version and checks dendrited.service health.",
                env!("CARGO_PKG_VERSION")
            );
        }
    }
    Ok(())
}

fn stage(
    manifest: &str,
    signature: &str,
    artifact: &str,
    public_key: &str,
    root: &Path,
) -> Result<(), dendrite_updater::UpdateError> {
    let staged = SelfUpdater::default().verify_and_stage(
        Path::new(manifest),
        Path::new(signature),
        Path::new(artifact),
        Path::new(public_key),
        root,
    )?;
    println!(
        "staged Dendrite {} at {}",
        staged.manifest.version,
        staged.stage_dir.display()
    );
    Ok(())
}

fn install(
    manifest: &str,
    signature: &str,
    artifact: &str,
    public_key: &str,
    root: &Path,
) -> Result<(), dendrite_updater::UpdateError> {
    let updater = SelfUpdater::default();
    let staged = updater.verify_and_stage(
        Path::new(manifest),
        Path::new(signature),
        Path::new(artifact),
        Path::new(public_key),
        root,
    )?;
    updater.install_staged(&staged)?;
    println!(
        "installed Dendrite {} and passed health verification",
        staged.manifest.version
    );
    Ok(())
}
