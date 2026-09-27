//! `dendrite-guard`: a small, standalone process that owns Dendrite's trust
//! state and integrity findings, and answers authority checks over a Unix
//! socket. See `crates/dendrite-guard/README.md` for why this is its own
//! process rather than in-process logic inside `dendrited`.

use dendrite_guard::{GuardStore, unix_now};
use dendrite_protocol::{GuardRequest, GuardResponse};
use std::env;
use std::ffi::CString;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const DEFAULT_SOCKET_PATH: &str = "/tmp/dendrite-guard.sock";
const DEFAULT_DB_PATH: &str = "data/guard.sqlite3";
/// Same default as `dendrited`'s own `RuntimeConfig::socket_mode` — see
/// `crates/dendrited/src/runtime.rs`. Dev mode leaves `DENDRITE_GUARD_SOCKET_GROUP`
/// unset (no chown attempted), which is fine when both processes run as the
/// same local user; a packaged install sets it explicitly (see
/// `packaging/dendrite-guard.service`) since `dendrite-guard` now runs as its
/// own dedicated user, distinct from `dendrited`'s (see `README.md`'s
/// "Privilege separation" section).
const DEFAULT_SOCKET_MODE: u32 = 0o660;
/// How often the background thread re-verifies against the stored
/// baseline (see `run_periodic_verification`) when
/// `DENDRITE_GUARD_VERIFY_INTERVAL_SECONDS` isn't set. `dendrite guard
/// verify` triggers the identical check on demand any time, independent of
/// this interval.
const DEFAULT_VERIFY_INTERVAL_SECONDS: u64 = 300;

fn main() {
    let db_path = env::var("DENDRITE_GUARD_DB").unwrap_or_else(|_| DEFAULT_DB_PATH.into());
    let socket_path = env::var("DENDRITE_GUARD_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SOCKET_PATH));

    let socket_mode = match env::var("DENDRITE_GUARD_SOCKET_MODE") {
        Ok(value) => match u32::from_str_radix(value.trim().trim_start_matches("0o"), 8) {
            Ok(mode) => mode,
            Err(_) => {
                eprintln!(
                    "dendrite-guard: invalid DENDRITE_GUARD_SOCKET_MODE `{value}`; expected octal like 0660"
                );
                std::process::exit(2);
            }
        },
        Err(_) => DEFAULT_SOCKET_MODE,
    };
    let socket_group = env::var("DENDRITE_GUARD_SOCKET_GROUP")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());

    // The set of paths the integrity manifest hashes — configured on
    // Guard's own side, deliberately never accepted as part of a
    // `GuardRequest` (see `guard_ipc.rs`'s `EstablishBaseline`/
    // `VerifyIntegrity` doc comments): a compromised `dendrited` asking
    // Guard to hash/verify attacker-chosen paths instead of the real
    // watched set would make the whole manifest meaningless.
    let watch_paths: Vec<PathBuf> = env::var("DENDRITE_GUARD_WATCH_PATHS")
        .unwrap_or_default()
        .split(':')
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .collect();

    let verify_interval_secs = match env::var("DENDRITE_GUARD_VERIFY_INTERVAL_SECONDS") {
        Ok(value) => match value.trim().parse::<u64>() {
            Ok(0) => {
                eprintln!(
                    "dendrite-guard: invalid DENDRITE_GUARD_VERIFY_INTERVAL_SECONDS `{value}`; must be a positive number of seconds"
                );
                std::process::exit(2);
            }
            Ok(seconds) => seconds,
            Err(_) => {
                eprintln!(
                    "dendrite-guard: invalid DENDRITE_GUARD_VERIFY_INTERVAL_SECONDS `{value}`; expected a positive number of seconds"
                );
                std::process::exit(2);
            }
        },
        Err(_) => DEFAULT_VERIFY_INTERVAL_SECONDS,
    };

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
        Ok(store) => Arc::new(Mutex::new(store)),
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
    if let Err(error) = fs::set_permissions(&socket_path, fs::Permissions::from_mode(socket_mode)) {
        eprintln!(
            "dendrite-guard: failed to set permissions on {}: {error}",
            socket_path.display()
        );
        std::process::exit(1);
    }
    if let Some(group) = socket_group.as_deref()
        && let Err(error) = set_socket_group(&socket_path, group)
    {
        eprintln!(
            "dendrite-guard: failed to chown {} to group `{group}`: {error}",
            socket_path.display()
        );
        std::process::exit(1);
    }
    println!(
        "dendrite-guard: listening on {} ({db_path})",
        socket_path.display()
    );

    // A real verification pass on startup and periodically, not just when
    // something asks for one. Runs in its own thread since it shares the
    // same `store` lock as request handling — see
    // `run_periodic_verification`'s doc comment. Started only when
    // something is actually configured to watch: with an empty
    // `DENDRITE_GUARD_WATCH_PATHS`, there's nothing to verify and no
    // baseline can meaningfully exist yet.
    if !watch_paths.is_empty() {
        let store = Arc::clone(&store);
        let watch_paths = watch_paths.clone();
        thread::spawn(move || {
            run_periodic_verification(&store, &watch_paths, verify_interval_secs)
        });
    }

    for incoming in listener.incoming() {
        let Ok(stream) = incoming else { continue };
        if let Err(error) = handle_connection(stream, &store, &watch_paths) {
            eprintln!("dendrite-guard: request failed: {error}");
        }
    }
}

/// Runs `GuardStore::verify_integrity` immediately (the "on startup" half
/// of item #3) and then every `interval_secs` (the "periodically" half),
/// for as long as the process runs. `dendrite guard verify` (see
/// `handle_request`'s `GuardRequest::VerifyIntegrity` arm) triggers the
/// identical check on demand — there's exactly one verification code path,
/// just two ways to trigger it.
///
/// Shares `store`'s `Mutex` with request handling: a verification pass
/// holds the lock for as long as hashing every configured watch path takes
/// (real I/O, potentially real file reads), so a request arriving mid-pass
/// waits for it to finish. Acceptable given how infrequently this runs by
/// default and how small a real watch set should be — see
/// `crates/dendrite-guard/README.md`'s "Integrity manifest" section.
fn run_periodic_verification(
    store: &Mutex<GuardStore>,
    watch_paths: &[PathBuf],
    interval_secs: u64,
) {
    loop {
        {
            let mut store = match store.lock() {
                Ok(store) => store,
                Err(poisoned) => poisoned.into_inner(),
            };
            match store.has_baseline() {
                Ok(true) => {
                    if let Err(error) = store.verify_integrity(watch_paths, unix_now()) {
                        eprintln!(
                            "dendrite-guard: periodic integrity verification failed: {error}"
                        );
                    }
                }
                Ok(false) => {
                    // No baseline established yet (nobody has run `dendrite
                    // guard baseline`) — nothing to verify against, and not
                    // worth logging every interval while that's true.
                }
                Err(error) => {
                    eprintln!("dendrite-guard: failed to check for an integrity baseline: {error}")
                }
            }
        }
        thread::sleep(Duration::from_secs(interval_secs));
    }
}

/// Chowns the socket file's group (not owner — `u32::MAX` to `chown(2)`
/// means "leave the owner unchanged") to the named group, so a caller that
/// isn't `dendrite-guard`'s own user but *is* a member of that group (e.g.
/// `dendrited`, running as its own dedicated user in a packaged install —
/// see `README.md`'s "Privilege separation" section) can still connect.
/// Mirrors `dendrited`'s own `set_socket_group` in `crates/dendrited/src/runtime.rs`
/// verbatim; duplicated rather than shared since it's a handful of lines of
/// direct libc use, not worth a shared crate for.
fn set_socket_group(path: &Path, group: &str) -> std::io::Result<()> {
    let group_name =
        CString::new(group).map_err(|_| std::io::Error::other("socket group contains NUL byte"))?;

    // SAFETY: getgrnam reads the provided NUL-terminated group name and
    // returns a pointer to libc-managed storage valid until the next group
    // lookup.
    let entry = unsafe { libc::getgrnam(group_name.as_ptr()) };
    if entry.is_null() {
        return Err(std::io::Error::other(format!(
            "socket group `{group}` does not exist"
        )));
    }

    // SAFETY: entry was checked for null above.
    let gid = unsafe { (*entry).gr_gid };
    let path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::other("socket path contains NUL byte"))?;

    // uid_t::MAX means "do not change owner" for chown.
    // SAFETY: path is NUL-terminated and points to the bound socket path.
    let result = unsafe { libc::chown(path.as_ptr(), u32::MAX as libc::uid_t, gid) };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

fn handle_connection(
    mut stream: UnixStream,
    store: &Mutex<GuardStore>,
    watch_paths: &[PathBuf],
) -> std::io::Result<()> {
    let mut line = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut line)?;

    let response = match serde_json::from_str::<GuardRequest>(line.trim()) {
        Ok(request) => handle_request(request, store, watch_paths),
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

fn handle_request(
    request: GuardRequest,
    store: &Mutex<GuardStore>,
    watch_paths: &[PathBuf],
) -> GuardResponse {
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
        GuardRequest::EstablishBaseline => {
            if watch_paths.is_empty() {
                return GuardResponse::Error {
                    message: "DENDRITE_GUARD_WATCH_PATHS is empty; nothing configured to baseline"
                        .into(),
                };
            }
            match store.establish_baseline(watch_paths, unix_now()) {
                Ok(manifest_status) => GuardResponse::Manifest { manifest_status },
                Err(error) => GuardResponse::Error {
                    message: format!("{error}"),
                },
            }
        }
        GuardRequest::VerifyIntegrity => match store.verify_integrity(watch_paths, unix_now()) {
            Ok(result) => GuardResponse::Verification { result },
            Err(error) => GuardResponse::Error {
                message: format!("{error}"),
            },
        },
        GuardRequest::BeginRecovery => match store.begin_recovery(unix_now()) {
            Ok(result) => GuardResponse::RecoveryBegun { result },
            Err(error) => GuardResponse::Error {
                message: format!("{error}"),
            },
        },
        GuardRequest::CompleteRecovery { token } => {
            if watch_paths.is_empty() {
                return GuardResponse::Error {
                    message: "DENDRITE_GUARD_WATCH_PATHS is empty; nothing configured to baseline"
                        .into(),
                };
            }
            match store.complete_recovery(&token, watch_paths, unix_now()) {
                Ok(result) => GuardResponse::Recovered { result },
                Err(error) => GuardResponse::Error {
                    message: format!("{error}"),
                },
            }
        }
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
