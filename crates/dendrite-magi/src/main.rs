//! `dendrite-magi`: a small, standalone process that evaluates MAGI quorum
//! votes over a Unix socket. See `crates/dendrite-magi/README.md` for why
//! this is its own process rather than in-process logic inside `dendrited`.

use dendrite_protocol::{MagiEvaluation, MagiRequest, MagiResponse};
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

const DEFAULT_SOCKET_PATH: &str = "/tmp/dendrite-magi.sock";

fn main() {
    if let Err(error) = dendrite_magi::read_seat_sources_from_env() {
        eprintln!("dendrite-magi: {error}");
        std::process::exit(1);
    }

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
        if let Err(error) = handle_connection(stream) {
            eprintln!("dendrite-magi: request failed: {error}");
        }
    }
}

fn handle_connection(mut stream: UnixStream) -> std::io::Result<()> {
    let mut line = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut line)?;

    let response = match serde_json::from_str::<MagiRequest>(line.trim()) {
        Ok(MagiRequest::Evaluate {
            action,
            user_authorised,
        }) => {
            let evaluations = dendrite_magi::evaluate(action, user_authorised)
                .into_iter()
                .map(|(evaluation, reason)| MagiEvaluation {
                    evaluator: evaluation.evaluator,
                    verdict: evaluation.verdict,
                    reason,
                })
                .collect();
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
