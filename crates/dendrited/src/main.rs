use dendrited::{DaemonRuntime, RuntimeConfig};
use std::env;
use std::path::PathBuf;
use std::time::Duration;

fn main() {
    let mut config = RuntimeConfig::development_defaults();
    if let Ok(value) = env::var("DENDRITE_MEMORY_DB") {
        config.memory_path = PathBuf::from(value);
    }
    if let Ok(value) = env::var("DENDRITE_INCIDENT_DB") {
        config.incident_path = PathBuf::from(value);
    }
    if let Ok(value) = env::var("DENDRITE_GUARD_DB") {
        config.guard_path = PathBuf::from(value);
    }
    if let Ok(value) = env::var("DENDRITE_SOCKET") {
        config.socket_path = PathBuf::from(value);
    }
    if let Ok(value) = env::var("DENDRITE_HTTP_ADDR")
        && let Ok(address) = value.parse()
    {
        config.http_addr = address;
    }
    if let Ok(value) = env::var("DENDRITE_FANOTIFY") {
        config.fanotify_enabled = matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        );
    }

    if let Ok(value) = env::var("DENDRITE_WATCH_PATHS") {
        config.watch_paths = value
            .split(':')
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .collect();
    }
    if let Ok(value) = env::var("DENDRITE_TELEMETRY_INTERVAL_SECONDS")
        && let Ok(seconds) = value.parse::<u64>()
    {
        config.telemetry_interval = Duration::from_secs(seconds.max(1));
    }

    eprintln!(
        "dendrited starting on {} (HTTP {})",
        config.socket_path.display(),
        config.http_addr
    );
    if let Err(error) = DaemonRuntime::open(config).and_then(DaemonRuntime::run) {
        eprintln!("dendrited failed: {error:?}");
        std::process::exit(1);
    }
}
