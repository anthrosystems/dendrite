use dendrited::{DaemonRuntime, RuntimeConfig};
use std::env;
use std::path::PathBuf;
use std::time::Duration;

fn main() {
    let mut config = RuntimeConfig::development_defaults();
    if let Ok(value) = env::var("DENDRITE_SELF_DB") {
        config.self_path = PathBuf::from(value);
    }
    if let Ok(value) = env::var("DENDRITE_STM_DB") {
        config.stm_path = PathBuf::from(value);
    }
    if let Ok(value) = env::var("DENDRITE_LTM_DB") {
        config.ltm_path = PathBuf::from(value);
    }
    if let Ok(value) = env::var("DENDRITE_INCIDENT_DB") {
        config.incident_path = PathBuf::from(value);
    }
    if let Ok(value) = env::var("DENDRITE_CVE_SNAPSHOT") {
        config.cve_snapshot_path = PathBuf::from(value);
    }
    if let Ok(value) = env::var("DENDRITE_SOCKET") {
        config.socket_path = PathBuf::from(value);
    }
    if let Ok(value) = env::var("DENDRITE_MAGI_SOCKET") {
        config.magi_socket_path = PathBuf::from(value);
    }
    if let Ok(value) = env::var("DENDRITE_GUARD_SOCKET") {
        config.guard_socket_path = PathBuf::from(value);
    }
    if let Ok(value) = env::var("DENDRITE_HTTP_ADDR")
        && let Ok(address) = value.parse()
    {
        config.http_addr = address;
    }
    if let Ok(value) = env::var("DENDRITE_SOCKET_GROUP") {
        let value = value.trim();
        if !value.is_empty() {
            config.socket_group = Some(value.to_owned());
        }
    }

    if let Ok(value) = env::var("DENDRITE_SOCKET_MODE") {
        match u32::from_str_radix(value.trim().trim_start_matches("0o"), 8) {
            Ok(mode) => config.socket_mode = mode,
            Err(_) => {
                eprintln!("invalid DENDRITE_SOCKET_MODE `{value}`; expected octal like 0660");
                std::process::exit(2);
            }
        }
    }

    if let Ok(value) = env::var("DENDRITE_FANOTIFY") {
        // Opt-out, not opt-in: the default (this var unset) is enabled — see
        // RuntimeConfig::development_defaults(). Setting this to anything
        // other than a truthy value (e.g. "0", "false") explicitly disables it.
        config.fanotify_enabled = matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        );
    }
    if let Ok(value) = env::var("DENDRITE_EBPF") {
        // Opt-out, not opt-in: the default (this var unset) is enabled — see
        // RuntimeConfig::development_defaults(). Setting this to anything
        // other than a truthy value (e.g. "0", "false") explicitly disables it.
        config.ebpf_enabled = matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        );
    }
    if let Ok(value) = env::var("DENDRITE_EBPF_OBJECT") {
        let value = value.trim();
        if !value.is_empty() {
            config.ebpf_object = PathBuf::from(value);
        }
    }

    if let Ok(value) = env::var("DENDRITE_WATCH_MOUNTS") {
        config.watch_mounts = value
            .split(':')
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .collect();
    }
    if let Ok(value) = env::var("DENDRITE_WATCH_INCLUDE_PATHS") {
        config.watch_include_paths = value
            .split(':')
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .collect();
    }
    if let Ok(value) = env::var("DENDRITE_WATCH_EXCLUDE_PATHS") {
        config.watch_exclude_paths = value
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
        "dendrited starting on {} (HTTP + WebSocket {}, WebSocket path /ws)",
        config.socket_path.display(),
        config.http_addr,
    );
    if let Err(error) = DaemonRuntime::open(config).and_then(DaemonRuntime::run) {
        eprintln!("dendrited failed: {error:?}");
        std::process::exit(1);
    }
}
