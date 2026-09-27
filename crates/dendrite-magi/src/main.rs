//! `dendrite-magi`: a small, standalone process that evaluates MAGI quorum
//! votes over a Unix socket. See `crates/dendrite-magi/README.md` for why
//! this is its own process rather than in-process logic inside `dendrited`.

use dendrite_magi::SeatSources;
use dendrite_protocol::{Evaluator, MagiEvaluation, MagiRequest, MagiResponse};
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

const DEFAULT_SOCKET_PATH: &str = "/tmp/dendrite-magi.sock";

fn main() {
    let seat_sources = match SeatSources::from_env() {
        Ok(seat_sources) => seat_sources,
        Err(error) => {
            eprintln!("dendrite-magi: {error}");
            std::process::exit(1);
        }
    };

    // A single multi-thread runtime, built once at startup: the socket loop
    // below stays the same simple synchronous accept-and-handle shape it
    // always was (MAGI requests are low-volume and inherently serialised by
    // the quorum-vote semantics), but each request's per-seat evaluation may
    // now need to await an MCP round-trip, so the (still synchronous)
    // request handler hands that one `evaluate_seat` future to the runtime
    // via `block_on` rather than the whole process becoming async.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("dendrite-magi: failed to start the async runtime: {error}");
            std::process::exit(1);
        }
    };

    let socket_path = env::var("DENDRITE_MAGI_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SOCKET_PATH));

    if socket_path.exists() {
        if UnixStream::connect(&socket_path).is_ok() {
            eprintln!(
                "dendrite-magi: {} is already in use by a running instance",
                socket_path.display()
            );
            std::process::exit(1);
        }
        if let Err(error) = std::fs::remove_file(&socket_path) {
            eprintln!(
                "dendrite-magi: failed to remove stale socket {}: {error}",
                socket_path.display()
            );
            std::process::exit(1);
        }
    }

    let listener = match UnixListener::bind(&socket_path) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!(
                "dendrite-magi: failed to bind {}: {error}",
                socket_path.display()
            );
            std::process::exit(1);
        }
    };
    println!("dendrite-magi: listening on {}", socket_path.display());

    for incoming in listener.incoming() {
        let Ok(stream) = incoming else { continue };
        if let Err(error) = handle_connection(stream, &seat_sources, &runtime) {
            eprintln!("dendrite-magi: request failed: {error}");
        }
    }
}

fn handle_connection(
    mut stream: UnixStream,
    seat_sources: &SeatSources,
    runtime: &tokio::runtime::Runtime,
) -> std::io::Result<()> {
    let mut line = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut line)?;

    let response = match serde_json::from_str::<MagiRequest>(line.trim()) {
        Ok(MagiRequest::Evaluate {
            action,
            user_authorised,
        }) => {
            let evaluations =
                runtime.block_on(evaluate_all_seats(seat_sources, action, user_authorised));
            MagiResponse::Evaluations { evaluations }
        }
        Err(error) => MagiResponse::Error {
            message: format!("invalid request: {error}"),
        },
    };

    let mut body = serde_json::to_string(&response)
        .unwrap_or_else(|error| format!("{{\"status\":\"error\",\"message\":\"{error}\"}}"));
    body.push('\n');
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

/// Runs all three seats' [`dendrite_magi::evaluate_seat`] calls concurrently
/// — each seat is independent (an MCP-backed seat's round-trip never blocks
/// the others) — and returns them in the fixed Host/User/Environment order
/// the rest of the quorum pipeline expects.
async fn evaluate_all_seats(
    seat_sources: &SeatSources,
    action: dendrite_protocol::ActionType,
    user_authorised: bool,
) -> Vec<MagiEvaluation> {
    let (host, user, environment) = tokio::join!(
        dendrite_magi::evaluate_seat(Evaluator::Host, &seat_sources.host, action, user_authorised),
        dendrite_magi::evaluate_seat(Evaluator::User, &seat_sources.user, action, user_authorised),
        dendrite_magi::evaluate_seat(
            Evaluator::Environment,
            &seat_sources.environment,
            action,
            user_authorised
        ),
    );

    [
        (Evaluator::Host, host),
        (Evaluator::User, user),
        (Evaluator::Environment, environment),
    ]
    .into_iter()
    .map(|(evaluator, (verdict, reason))| MagiEvaluation {
        evaluator,
        verdict,
        reason,
    })
    .collect()
}
