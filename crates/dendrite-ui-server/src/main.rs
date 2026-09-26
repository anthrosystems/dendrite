//! Standalone static-file server for the built Dendrite UI (`ui/dist`).
//!
//! This is deliberately its own process/systemd unit (`dendrite-ui.service`)
//! rather than something `dendrited` serves itself: the UI is just static
//! HTML/JS/CSS with no privileged state of its own, so there's no reason for
//! it to share `dendrited`'s process, capabilities, or restart lifecycle.
//! Splitting it out means an operator can stop/disable the UI independently
//! of the daemon (`systemctl disable --now dendrite-ui`) without touching
//! telemetry collection, Memory Graph ingestion, or action authorisation at
//! all.
//!
//! The served UI talks to `dendrited`'s own HTTP/WebSocket port directly,
//! cross-origin, via the `VITE_DENDRITE_API_BASE`/`VITE_DENDRITE_WS_URL`
//! build-time values baked into `ui/dist` (see `scripts/build-deb.sh` and
//! `docs/CONFIGURATION.md`) — `dendrited`'s existing `Origin` allowlist in
//! `http.rs` is what authorises that cross-origin access, the same
//! mechanism that already covers the `npm run dev` Vite server today.

use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;

const DEFAULT_ADDR: &str = "127.0.0.1:8767";
const MAX_HEADER_LINES: usize = 64;

fn main() {
    let ui_dir = match env::var("DENDRITE_UI_DIR") {
        Ok(value) if !value.trim().is_empty() => PathBuf::from(value.trim()),
        _ => {
            eprintln!("dendrite-ui-server: DENDRITE_UI_DIR must be set to the built UI directory");
            std::process::exit(1);
        }
    };
    if ui_dir.canonicalize().is_err() {
        eprintln!(
            "dendrite-ui-server: DENDRITE_UI_DIR ({}) does not exist",
            ui_dir.display()
        );
        std::process::exit(1);
    }

    let addr = env::var("DENDRITE_UI_ADDR").unwrap_or_else(|_| DEFAULT_ADDR.to_owned());
    let listener = match TcpListener::bind(&addr) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("dendrite-ui-server: failed to bind {addr}: {error}");
            std::process::exit(1);
        }
    };
    println!("dendrite-ui-server: serving {} on {addr}", ui_dir.display());

    for incoming in listener.incoming() {
        let Ok(stream) = incoming else { continue };
        let ui_dir = ui_dir.clone();
        thread::spawn(move || {
            let mut stream = stream;
            if let Err(error) = handle_connection(&mut stream, &ui_dir)
                && !is_peer_disconnect(&error)
            {
                eprintln!("dendrite-ui-server: request failed: {error}");
            }
        });
    }
}

fn is_peer_disconnect(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof
    )
}

/// Reads one request (request line + headers, ignoring any body — this
/// server only ever handles bodyless `GET`s), then serves a static file or a
/// plain-text error. Deliberately minimal compared to `dendrited::http`'s
/// full request parser: this process has no API routes, no JSON, no
/// WebSocket upgrade, and no request body to speak of.
fn handle_connection(stream: &mut TcpStream, ui_dir: &Path) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    let mut lines_read = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        lines_read += 1;
        if line == "\r\n" || line.is_empty() || lines_read > MAX_HEADER_LINES {
            break;
        }
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let path = target.split_once('?').map_or(target, |(path, _)| path);

    if method != "GET" && method != "HEAD" {
        return write_plain_text(stream, 405, "only GET/HEAD are supported");
    }

    serve_static_file(stream, ui_dir, path)
}

/// A path that resolves to a real file under `ui_dir` is served as-is. A
/// path that doesn't (a client-side route like `/incidents/123`, a
/// directory, or a path-traversal attempt — rejected by the containment
/// check below) falls back to `index.html`, letting the UI's own router
/// handle it, same as any single-page-app static host.
fn serve_static_file(stream: &mut TcpStream, ui_dir: &Path, request_path: &str) -> io::Result<()> {
    let resolved_ui_dir = match ui_dir.canonicalize() {
        Ok(path) => path,
        Err(_) => {
            return write_plain_text(stream, 500, "configured UI directory does not exist");
        }
    };

    let relative = request_path.trim_start_matches('/');
    let requested = (!relative.is_empty()).then(|| resolved_ui_dir.join(relative));

    let served = requested
        .as_deref()
        .and_then(|path| path.canonicalize().ok())
        .filter(|path| path.starts_with(&resolved_ui_dir) && path.is_file());

    let served = match served {
        Some(path) => path,
        None => {
            let index = resolved_ui_dir.join("index.html");
            if !index.is_file() {
                return write_plain_text(stream, 404, "UI is not installed on this host");
            }
            index
        }
    };

    let bytes = fs::read(&served)?;
    write_static_bytes(stream, &bytes, static_content_type(&served))
}

fn static_content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json" | "map") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("wasm") => "application/wasm",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn write_plain_text(stream: &mut TcpStream, status: u16, body: &str) -> io::Result<()> {
    let reason = match status {
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Internal Server Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )?;
    stream.flush()
}

fn write_static_bytes(stream: &mut TcpStream, body: &[u8], content_type: &str) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()
}
