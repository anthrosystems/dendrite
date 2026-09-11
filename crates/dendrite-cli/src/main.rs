use dendrite_cli::{Command, execute};
use std::env;
use std::path::PathBuf;

fn main() {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let command = Command::parse(&arguments);
    let socket = env::var("DENDRITE_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/dendrited.sock"));

    match execute(&command, &socket) {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("dendrite: {error:?}");
            std::process::exit(1);
        }
    }
}
