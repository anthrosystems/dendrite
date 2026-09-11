use crate::{DaemonCore, DaemonError};
use dendrite_protocol::{CreateActionDto, DaemonStatusDto, HealthDto, MemoryPathDto};
use serde::Serialize;
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const ALLOWED_ORIGINS: [&str; 2] = ["http://127.0.0.1:5173", "http://localhost:5173"];
const MAX_BODY_BYTES: usize = 16 * 1024;

pub fn handle_http_stream(
    core: &mut DaemonCore,
    socket_path: &Path,
    mut stream: TcpStream,
) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    let mut origin = None;
    let mut content_length = 0usize;

    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" || line.is_empty() {
            break;
        }

        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("origin") {
                origin = Some(value.trim().to_owned());
            } else if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse::<usize>().unwrap_or(0);
            }
        }
    }

    if let Some(origin_value) = origin.as_deref()
        && !ALLOWED_ORIGINS.contains(&origin_value)
    {
        return write_json(
            &mut stream,
            403,
            &ErrorBody::new("origin is not allowed"),
            None,
        );
    }

    if content_length > MAX_BODY_BYTES {
        return write_json(
            &mut stream,
            413,
            &ErrorBody::new("request body is too large"),
            origin.as_deref(),
        );
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();

    match route(core, socket_path, method, target, &body) {
        Ok(HttpBody::Status(value)) => write_json(&mut stream, 200, &value, origin.as_deref()),
        Ok(HttpBody::Health(value)) => write_json(&mut stream, 200, &value, origin.as_deref()),
        Ok(HttpBody::Json(value)) => write_raw_json(&mut stream, 200, &value, origin.as_deref()),
        Ok(HttpBody::Created(value)) => write_raw_json(&mut stream, 201, &value, origin.as_deref()),
        Err(HttpRouteError::NotFound(message)) => write_json(
            &mut stream,
            404,
            &ErrorBody::new(message),
            origin.as_deref(),
        ),
        Err(HttpRouteError::BadRequest(message)) => write_json(
            &mut stream,
            400,
            &ErrorBody::new(message),
            origin.as_deref(),
        ),
        Err(HttpRouteError::MethodNotAllowed(message)) => write_json(
            &mut stream,
            405,
            &ErrorBody::new(message),
            origin.as_deref(),
        ),
        Err(HttpRouteError::Daemon(error)) => write_json(
            &mut stream,
            500,
            &ErrorBody::new(format!("{error:?}")),
            origin.as_deref(),
        ),
        Err(HttpRouteError::Json(error)) => write_json(
            &mut stream,
            500,
            &ErrorBody::new(format!("JSON encoding failed: {error}")),
            origin.as_deref(),
        ),
    }
}

enum HttpBody {
    Status(DaemonStatusDto),
    Health(HealthDto),
    Json(String),
    Created(String),
}

#[derive(Debug)]
enum HttpRouteError {
    NotFound(String),
    BadRequest(String),
    MethodNotAllowed(String),
    Daemon(DaemonError),
    Json(serde_json::Error),
}

impl From<DaemonError> for HttpRouteError {
    fn from(error: DaemonError) -> Self {
        Self::Daemon(error)
    }
}

impl From<serde_json::Error> for HttpRouteError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

fn route(
    core: &mut DaemonCore,
    socket_path: &Path,
    method: &str,
    target: &str,
    body: &[u8],
) -> Result<HttpBody, HttpRouteError> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let query = parse_query(query)?;

    match (method, path) {
        ("GET", "/api/v1/status") => Ok(HttpBody::Status(DaemonStatusDto {
            version: env!("CARGO_PKG_VERSION").into(),
            observations_ingested: core.observations_ingested(),
            incidents_open: core.incident_count()?,
            memory_nodes_known: core.memory().node_count().map_err(DaemonError::from)?,
            socket_path: socket_path.to_string_lossy().into_owned(),
        })),
        ("GET", "/api/v1/health") => Ok(HttpBody::Health(HealthDto {
            daemon: "ok".into(),
            memory: if core.memory().ping().is_ok() {
                "ok".into()
            } else {
                "error".into()
            },
            guard: core.guard_status()?.trust_state,
        })),
        ("GET", "/api/v1/incidents") => Ok(HttpBody::Json(serde_json::to_string(
            &core.list_incidents()?,
        )?)),
        ("GET", "/api/v1/memory/nodes") => {
            let nodes = core.memory_nodes(query.get("kind").map(String::as_str))?;
            Ok(HttpBody::Json(serde_json::to_string(&nodes)?))
        }
        ("GET", "/api/v1/memory/recent") => {
            let limit = query.get("limit").map_or(Ok(20usize), |value| {
                value.parse::<usize>().map_err(|_| {
                    HttpRouteError::BadRequest("limit must be a positive integer".into())
                })
            })?;
            Ok(HttpBody::Json(serde_json::to_string(
                &core.memory_recent(limit.min(500))?,
            )?))
        }
        ("GET", "/api/v1/memory/neighbours") => {
            let node_id = required_query(&query, "node_id")?;
            let payload = serde_json::json!({
                "node_id": node_id,
                "neighbours": core.memory_neighbours(node_id)?,
            });
            Ok(HttpBody::Json(payload.to_string()))
        }
        ("GET", "/api/v1/memory/path") => {
            let source = required_query(&query, "source")?;
            let target = required_query(&query, "target")?;
            let path = core.memory_path(source, target)?.map(|path| {
                let score = path.score();
                MemoryPathDto {
                    nodes: path.nodes.into_iter().map(|node| node.0).collect(),
                    relationships: path
                        .relationships
                        .into_iter()
                        .map(|relationship| relationship.0)
                        .collect(),
                    score,
                }
            });
            Ok(HttpBody::Json(serde_json::to_string(&path)?))
        }
        ("GET", "/api/v1/guard") => Ok(HttpBody::Json(serde_json::to_string(
            &core.guard_status()?,
        )?)),
        ("GET", "/api/v1/guard/findings") => Ok(HttpBody::Json(serde_json::to_string(
            &core.guard_findings()?,
        )?)),
        ("GET", "/api/v1/telemetry/status") => Ok(HttpBody::Json(serde_json::to_string(
            &core.telemetry_status(),
        )?)),
        ("GET", "/api/v1/telemetry/recent") => {
            let limit = query.get("limit").map_or(Ok(100usize), |value| {
                value.parse::<usize>().map_err(|_| {
                    HttpRouteError::BadRequest("limit must be a positive integer".into())
                })
            })?;
            Ok(HttpBody::Json(serde_json::to_string(
                &core.telemetry_recent(limit.min(512)),
            )?))
        }
        ("GET", "/api/v1/actions") => Ok(HttpBody::Json(serde_json::to_string(
            &core.list_actions()?,
        )?)),
        ("POST", "/api/v1/actions") => {
            let request: CreateActionDto = serde_json::from_slice(body).map_err(|error| {
                HttpRouteError::BadRequest(format!("invalid JSON body: {error}"))
            })?;
            let detail = core.create_action(
                &request.incident_id,
                &request.action,
                &request.target,
                unix_now(),
            )?;
            Ok(HttpBody::Created(serde_json::to_string(&detail)?))
        }
        ("GET", _) if path.starts_with("/api/v1/incidents/") => {
            let encoded = path.trim_start_matches("/api/v1/incidents/");
            let id = percent_decode(encoded)?;
            match core.incident_detail(&id)? {
                Some(detail) => Ok(HttpBody::Json(serde_json::to_string(&detail)?)),
                None => Err(HttpRouteError::NotFound(format!(
                    "incident {id} was not found"
                ))),
            }
        }
        ("GET", _) if path.starts_with("/api/v1/actions/") => {
            let encoded = path.trim_start_matches("/api/v1/actions/");
            let id = percent_decode(encoded)?;
            match core.action_detail(&id)? {
                Some(detail) => Ok(HttpBody::Json(serde_json::to_string(&detail)?)),
                None => Err(HttpRouteError::NotFound(format!(
                    "action proposal {id} was not found"
                ))),
            }
        }
        ("POST", _) if path.starts_with("/api/v1/actions/") && path.ends_with("/evaluate") => {
            let encoded = path
                .trim_start_matches("/api/v1/actions/")
                .trim_end_matches("/evaluate")
                .trim_end_matches('/');
            let id = percent_decode(encoded)?;
            let detail = core.evaluate_action(&id, unix_now())?;
            Ok(HttpBody::Json(serde_json::to_string(&detail)?))
        }
        ("GET" | "POST", _) => Err(HttpRouteError::NotFound("API route was not found".into())),
        _ => Err(HttpRouteError::MethodNotAllowed(
            "only GET and the documented safe POST action routes are supported".into(),
        )),
    }
}

fn parse_query(query: &str) -> Result<HashMap<String, String>, HttpRouteError> {
    let mut values = HashMap::new();
    if query.is_empty() {
        return Ok(values);
    }
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        values.insert(percent_decode(key)?, percent_decode(value)?);
    }
    Ok(values)
}

fn required_query<'a>(
    query: &'a HashMap<String, String>,
    key: &str,
) -> Result<&'a str, HttpRouteError> {
    query
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| HttpRouteError::BadRequest(format!("missing query parameter: {key}")))
}

fn percent_decode(value: &str) -> Result<String, HttpRouteError> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let high = hex(bytes[index + 1])
                    .ok_or_else(|| HttpRouteError::BadRequest("invalid percent encoding".into()))?;
                let low = hex(bytes[index + 2])
                    .ok_or_else(|| HttpRouteError::BadRequest("invalid percent encoding".into()))?;
                output.push((high << 4) | low);
                index += 3;
            }
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(output)
        .map_err(|_| HttpRouteError::BadRequest("query parameter is not UTF-8".into()))
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl ErrorBody {
    fn new(message: impl Into<String>) -> Self {
        Self {
            error: message.into(),
        }
    }
}

fn write_json<T: Serialize>(
    stream: &mut TcpStream,
    status: u16,
    body: &T,
    origin: Option<&str>,
) -> io::Result<()> {
    let body = serde_json::to_string(body).map_err(io::Error::other)?;
    write_raw_json(stream, status, &body, origin)
}

fn write_raw_json(
    stream: &mut TcpStream,
    status: u16,
    body: &str,
    origin: Option<&str>,
) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        _ => "Internal Server Error",
    };
    let cors = origin
        .filter(|value| ALLOWED_ORIGINS.contains(value))
        .map_or(String::new(), |value| {
            format!("Access-Control-Allow-Origin: {value}\r\nVary: Origin\r\n")
        });
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n{}\r\n{}",
        body.len(),
        cors,
        body
    )?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_handles_node_ids() {
        assert_eq!(
            percent_decode("file%3A%2Ftmp%2Fexample.txt").unwrap(),
            "file:/tmp/example.txt"
        );
    }

    #[test]
    fn query_parser_decodes_values() {
        let query = parse_query("source=process%3A1&target=threat%3Atest").unwrap();
        assert_eq!(query.get("source").unwrap(), "process:1");
        assert_eq!(query.get("target").unwrap(), "threat:test");
    }
}
