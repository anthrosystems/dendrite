//! `dendrite-guard`: a small, standalone process that owns Dendrite's trust
//! state and integrity findings, and answers authority checks over a Unix
//! socket. See `crates/dendrite-guard/README.md` for why this is its own
//! process rather than in-process logic inside `dendrited`.

use dendrite_guard::GuardStore;
use dendrite_protocol::{GuardRequest, GuardResponse};
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Mutex;
#[cfg(debug_assertions)]
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_SOCKET_PATH: &str = "/tmp/dendrite-guard.sock";
const DEFAULT_DB_PATH: &str = "data/guard.sqlite3";

/// Only the `#[cfg(debug_assertions)]` debug handlers below need a
/// timestamp to record, so this would otherwise be dead code in a release
/// build.
#[cfg(debug_assertions)]
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn main() {
    let db_path = env::var("DENDRITE_GUARD_DB").unwrap_or_else(|_| DEFAULT_DB_PATH.into());
    let socket_path = env::var("DENDRITE_GUARD_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SOCKET_PATH));

    if let Some(parent) = std::path::Path::new(&db_path).parent()
        && !parent.as_os_str().is_empty()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        eprintln!(
            "dendrite-guard: failed to create data directory {}: {error}",
            parent.display()
        );
        std::process::exit(1);
    }

    let store = match GuardStore::open(&db_path) {
        Ok(store) => Mutex::new(store),
        Err(error) => {
            eprintln!("dendrite-guard: failed to open {db_path}: {error}");
            std::process::exit(1);
        }
    };

    if socket_path.exists() {
        if UnixStream::connect(&socket_path).is_ok() {
            eprintln!(
                "dendrite-guard: {} is already in use by a running instance",
                socket_path.display()
            );
            std::process::exit(1);
        }
        if let Err(error) = std::fs::remove_file(&socket_path) {
            eprintln!(
                "dendrite-guard: failed to remove stale socket {}: {error}",
                socket_path.display()
            );
            std::process::exit(1);
        }
    }

    let listener = match UnixListener::bind(&socket_path) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!(
                "dendrite-guard: failed to bind {}: {error}",
                socket_path.display()
            );
            std::process::exit(1);
        }
    };
    println!(
        "dendrite-guard: listening on {} ({db_path})",
        socket_path.display()
    );

    for incoming in listener.incoming() {
        let Ok(stream) = incoming else { continue };
        if let Err(error) = handle_connection(stream, &store) {
            eprintln!("dendrite-guard: request failed: {error}");
        }
    }
}

fn handle_connection(mut stream: UnixStream, store: &Mutex<GuardStore>) -> std::io::Result<()> {
    let mut line = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut line)?;

    let response = match serde_json::from_str::<GuardRequest>(line.trim()) {
        Ok(request) => handle_request(request, store),
        Err(error) => GuardResponse::Error {
            message: format!("invalid request: {error}"),
        },
    };

    let mut body = serde_json::to_string(&response)
        .unwrap_or_else(|error| format!("{{\"status\":\"error\",\"message\":\"{error}\"}}"));
    body.push('\n');
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

fn handle_request(request: GuardRequest, store: &Mutex<GuardStore>) -> GuardResponse {
    let mut store = match store.lock() {
        Ok(store) => store,
        Err(_) => {
            return GuardResponse::Error {
                message: "internal: guard store lock poisoned".into(),
            };
        }
    };

    match request {
        GuardRequest::EvaluateAuthority { proposal } => GuardResponse::Authority {
            decision: store.evaluate_authority(&proposal),
        },
        GuardRequest::TrustState => GuardResponse::TrustState {
            trust_state: store.trust_state(),
        },
        GuardRequest::Status => match store.status() {
            Ok(guard_status) => GuardResponse::Info { guard_status },
            Err(error) => GuardResponse::Error {
                message: format!("{error}"),
            },
        },
        GuardRequest::Findings => match store.findings() {
            Ok(findings) => GuardResponse::Findings { findings },
            Err(error) => GuardResponse::Error {
                message: format!("{error}"),
            },
        },
        GuardRequest::DebugSetState { state } => debug_set_state(&mut store, &state),
        GuardRequest::DebugRecordFinding {
            target,
            severity,
            description,
        } => debug_record_finding(&mut store, &target, &severity, &description),
    }
}

/// Development-only surface, mirroring `dendrited`'s own
/// `#[cfg(debug_assertions)]`-gated debug commands — refused outright in a
/// release build rather than silently applied, since a packaged
/// `dendrite-guard` should never let anything but its own real integrity
/// checks move trust state.
#[cfg(debug_assertions)]
fn debug_set_state(store: &mut GuardStore, state: &str) -> GuardResponse {
    match store.debug_set_state(state, unix_now()) {
        Ok(()) => GuardResponse::Ack,
        Err(error) => GuardResponse::Error {
            message: format!("{error}"),
        },
    }
}

#[cfg(not(debug_assertions))]
fn debug_set_state(_store: &mut GuardStore, _state: &str) -> GuardResponse {
    GuardResponse::Error {
        message: "debug guard-state is a development-only surface, disabled in release builds"
            .into(),
    }
}

#[cfg(debug_assertions)]
fn debug_record_finding(
    store: &mut GuardStore,
    target: &str,
    severity: &str,
    description: &str,
) -> GuardResponse {
    match store.debug_record_finding(target, severity, description, unix_now()) {
        Ok(()) => GuardResponse::Ack,
        Err(error) => GuardResponse::Error {
            message: format!("{error}"),
        },
    }
}

#[cfg(not(debug_assertions))]
fn debug_record_finding(
    _store: &mut GuardStore,
    _target: &str,
    _severity: &str,
    _description: &str,
) -> GuardResponse {
    GuardResponse::Error {
        message: "debug guard-finding is a development-only surface, disabled in release builds"
            .into(),
    }
}
