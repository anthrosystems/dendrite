use dendrite_cli::{Command, execute};
use std::env;
use std::path::PathBuf;

/// Where a packaged install's `dendrited.service` actually listens (see
/// `packaging/dendrited.service`'s `DENDRITE_SOCKET` — that's a
/// systemd-unit-scoped env var, invisible to an interactive shell, which is
/// exactly why this can't just be "read the same env var dendrited reads").
const PACKAGED_SOCKET_PATH: &str = "/run/dendrite/dendrited.sock";
/// Matches `dendrited`'s own local-dev default (`DEFAULT_SOCKET_PATH` in
/// `crates/dendrited/src/runtime.rs`) so an unpackaged `cargo run` daemon and
/// a bare `dendrite-cli` invocation agree without either side setting
/// `DENDRITE_SOCKET`.
const DEV_SOCKET_PATH: &str = "/tmp/dendrited.sock";

/// `DENDRITE_SOCKET` always wins when set. Otherwise, prefer the packaged
/// socket path if it's actually there (and reachable — an ordinary user not
/// in the `dendrite` group gets `false` here too, since the `0750`
/// `/run/dendrite` directory denies the stat entirely, and falls through to
/// the dev path below exactly as before), falling back to the local-dev
/// default. This only changes behavior for a packaged install: local dev
/// never had a file at `/run/dendrite/dendrited.sock` to begin with.
fn default_socket_path() -> PathBuf {
    let packaged = PathBuf::from(PACKAGED_SOCKET_PATH);
    if packaged.exists() {
        packaged
    } else {
        PathBuf::from(DEV_SOCKET_PATH)
    }
}

fn main() {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let command = Command::parse(&arguments);
    let socket = env::var("DENDRITE_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_socket_path());

    match execute(&command, &socket) {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("dendrite: {error:?}");
            std::process::exit(1);
        }
    }
}
