use crate::{
    CreateAntiserumRequest, DaemonCore, DaemonError, VulnerabilityCandidateRequest,
    VulnerabilityService, live::LiveBroadcaster,
};
use dendrite_protocol::{
    CreateActionDto, DaemonStatusDto, HealthDto, MemoryPathDto, VulnerabilityRemediationDto,
};
use serde::Serialize;
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tungstenite::handshake::derive_accept_key;
use tungstenite::protocol::{Role, WebSocket};

const ALLOWED_ORIGINS: [&str; 4] = [
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "http://127.0.0.1:8767",
    "http://localhost:8767",
];
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// The live-event WebSocket path. It shares this listener/port with the
/// rest of the HTTP API (see the module doc comment below) rather than
/// binding a separate `DENDRITE_WS_ADDR` port, so distribution packaging
/// only needs to expose one address for both.
const WEBSOCKET_PATH: &str = "/ws";

pub fn handle_http_stream(
    core: &mut DaemonCore,
    vulnerability: &mut VulnerabilityService,
    socket_path: &Path,
    live: &LiveBroadcaster,
    mut stream: TcpStream,
) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    let mut origin = None;
    let mut content_length = 0usize;
    let mut connection_header = None;
    let mut upgrade_header = None;
    let mut sec_websocket_key = None;
    let mut authorization = None;

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
            } else if name.eq_ignore_ascii_case("connection") {
                connection_header = Some(value.trim().to_owned());
            } else if name.eq_ignore_ascii_case("upgrade") {
                upgrade_header = Some(value.trim().to_owned());
            } else if name.eq_ignore_ascii_case("sec-websocket-key") {
                sec_websocket_key = Some(value.trim().to_owned());
            } else if name.eq_ignore_ascii_case("authorization") {
                authorization = Some(value.trim().to_owned());
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

    // Bearer-token auth. `ALLOWED_ORIGINS` above only restricts *browser*
    // requests (it's a no-op for any client that omits `Origin`, which is
    // every non-browser HTTP client), so this is the only check that
    // actually gates the API. Ordinary requests carry the token in the
    // `Authorization: Bearer <token>` header; the WebSocket handshake is
    // issued by the browser itself and can't set custom headers on it, so
    // it's also accepted via a `?token=` query parameter on the upgrade
    // target.
    let request_target = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    if !token_authorised(core, authorization.as_deref(), &request_target) {
        return write_json(
            &mut stream,
            401,
            &ErrorBody::new("missing or invalid bearer token"),
            origin.as_deref(),
        );
    }

    let mut upgrade_parts = request_line.split_whitespace();
    let upgrade_method = upgrade_parts.next().unwrap_or_default();
    let upgrade_target = upgrade_parts.next().unwrap_or_default();
    let upgrade_path = upgrade_target
        .split_once('?')
        .map_or(upgrade_target, |(path, _)| path);
    let is_websocket_upgrade = upgrade_method == "GET"
        && upgrade_path == WEBSOCKET_PATH
        && connection_header
            .as_deref()
            .is_some_and(|value| value.to_ascii_lowercase().contains("upgrade"))
        && upgrade_header
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));

    if is_websocket_upgrade {
        return match sec_websocket_key {
            Some(key) => {
                complete_websocket_upgrade(&mut stream, live, &key)?;
                Ok(())
            }
            None => write_json(
                &mut stream,
                400,
                &ErrorBody::new("WebSocket upgrade is missing Sec-WebSocket-Key"),
                origin.as_deref(),
            ),
        };
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

    let routed = route(core, vulnerability, socket_path, method, target, &body);
    match routed {
        Ok(HttpBody::Status(value)) => write_json(&mut stream, 200, &value, origin.as_deref()),
        Ok(HttpBody::Health(value)) => write_json(&mut stream, 200, &value, origin.as_deref()),
        Ok(HttpBody::Json(value)) => {
            publish_http_mutation(live, method, target, &value);
            write_raw_json(&mut stream, 200, &value, origin.as_deref())
        }
        Ok(HttpBody::Created(value)) => {
            publish_http_mutation(live, method, target, &value);
            write_raw_json(&mut stream, 201, &value, origin.as_deref())
        }
        Ok(HttpBody::Binary { bytes, filename }) => {
            write_binary(&mut stream, 200, &bytes, &filename, origin.as_deref())
        }
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

/// Completes an already-detected WebSocket upgrade request on this HTTP
/// listener's connection: writes the `101 Switching Protocols` handshake
/// response by hand (the handshake headers were already parsed by the
/// caller's ordinary HTTP header loop, so this deliberately does not call
/// `tungstenite`'s own handshake reader — that expects to read the request
/// itself from a fresh stream), then hands the connection to
/// `WebSocket::from_raw_socket` for framing and registers it with `live` as
/// a subscriber. `stream`'s write half is used directly; the read half was
/// already consumed up through the blank line terminating the request
/// headers by the caller's `BufReader`-wrapped clone of the same socket.
fn complete_websocket_upgrade(
    stream: &mut TcpStream,
    live: &LiveBroadcaster,
    sec_websocket_key: &str,
) -> io::Result<()> {
    let accept_key = derive_accept_key(sec_websocket_key.as_bytes());
    write!(
        stream,
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept_key}\r\n\r\n"
    )?;
    stream.flush()?;
    let websocket = WebSocket::from_raw_socket(stream.try_clone()?, Role::Server, None);
    live.accept_websocket(websocket);
    Ok(())
}

enum HttpBody {
    Status(DaemonStatusDto),
    Health(HealthDto),
    Json(String),
    Created(String),
    Binary { bytes: Vec<u8>, filename: String },
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

/// Checks the request's bearer token against `core`'s HTTP API token
/// (see [`DaemonCore::http_api_token`]). Accepts either an
/// `Authorization: Bearer <token>` header or, since the WebSocket
/// handshake can't carry custom headers from a browser, a `?token=`
/// query parameter on `target`.
fn token_authorised(core: &DaemonCore, authorization: Option<&str>, target: &str) -> bool {
    let expected = core.http_api_token();
    if let Some(header) = authorization
        && let Some(token) = header.strip_prefix("Bearer ")
        && token == expected
    {
        return true;
    }
    if let Some((_, query)) = target.split_once('?') {
        for pair in query.split('&') {
            if let Some(token) = pair.strip_prefix("token=")
                && token == expected
            {
                return true;
            }
        }
    }
    false
}

fn route(
    core: &mut DaemonCore,
    vulnerability: &mut VulnerabilityService,
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
            instance_id: core.instance_id().into(),
            signing_key: core.signing_key_status(),
            observations_ingested: core.observations_ingested(),
            incidents_open: core.incident_count()?,
            memory_nodes_known: core.memory().node_count().map_err(DaemonError::from)?,
            socket_path: socket_path.to_string_lossy().into_owned(),
        })),
        ("GET", "/api/v1/health") => Ok(HttpBody::Health(core.health_check()?)),
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
        ("GET", "/api/v1/memory/graph") => {
            let limit = query.get("limit").map_or(Ok(0usize), |value| {
                value.parse::<usize>().map_err(|_| {
                    HttpRouteError::BadRequest("limit must be a non-negative integer".into())
                })
            })?;
            Ok(HttpBody::Json(serde_json::to_string(
                &core.memory_graph(limit)?,
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
        ("GET", "/api/v1/analysis/packages") => Ok(HttpBody::Json(serde_json::to_string(
            &core.analysis_packages(unix_now())?,
        )?)),
        ("GET", "/api/v1/analysis/chains") => Ok(HttpBody::Json(serde_json::to_string(
            &core.analysis_attack_chains()?,
        )?)),
        ("GET", "/api/v1/analysis/cves") => Ok(HttpBody::Json(serde_json::to_string(
            &vulnerability
                .knowledge_records()
                .map_err(DaemonError::from)?,
        )?)),
        ("GET", "/api/v1/analysis/behaviours") => {
            Ok(HttpBody::Json(serde_json::to_string(&core.behaviours()?)?))
        }
        ("GET", "/api/v1/analysis/vulnerability-candidates") => Ok(HttpBody::Json(
            serde_json::to_string(&vulnerability.candidates().map_err(DaemonError::from)?)?,
        )),
        ("POST", "/api/v1/analysis/vulnerability-candidates") => {
            let request: VulnerabilityCandidateRequest =
                serde_json::from_slice(body).map_err(|error| {
                    HttpRouteError::BadRequest(format!(
                        "invalid vulnerability candidate request: {error}"
                    ))
                })?;
            let candidate = vulnerability
                .create_candidate(&request, unix_now())
                .map_err(DaemonError::from)?;
            Ok(HttpBody::Created(serde_json::to_string(&candidate)?))
        }
        ("POST", "/api/v1/analysis/import") => {
            if body.is_empty() {
                return Err(HttpRouteError::BadRequest(
                    "Antiserum package body is empty".into(),
                ));
            }
            let summary = core.import_antiserum_package(body, unix_now())?;
            Ok(HttpBody::Created(serde_json::to_string(&summary)?))
        }
        ("POST", "/api/v1/analysis/export") => {
            let request: CreateAntiserumRequest =
                serde_json::from_slice(body).map_err(|error| {
                    HttpRouteError::BadRequest(format!("invalid Antiserum export request: {error}"))
                })?;
            let summary = core.create_antiserum_export(vulnerability, &request, unix_now())?;
            Ok(HttpBody::Created(serde_json::to_string(&summary)?))
        }
        ("GET", "/api/v1/analysis/reviews") => Ok(HttpBody::Json(serde_json::to_string(
            &core.analysis_reviews()?,
        )?)),
        ("POST", "/api/v1/analysis/reviews") => {
            #[derive(serde::Deserialize)]
            struct ReviewRequest {
                antiserum_id: String,
                label: Option<String>,
            }
            let request: ReviewRequest = serde_json::from_slice(body).map_err(|error| {
                HttpRouteError::BadRequest(format!("invalid review request: {error}"))
            })?;
            let review = core.create_analysis_review(
                &request.antiserum_id,
                request.label.as_deref(),
                unix_now(),
            )?;
            Ok(HttpBody::Created(serde_json::to_string(&review)?))
        }
        ("POST", _)
            if path.starts_with("/api/v1/analysis/packages/") && path.ends_with("/accept") =>
        {
            let encoded = path
                .trim_start_matches("/api/v1/analysis/packages/")
                .trim_end_matches("/accept")
                .trim_end_matches('/');
            let id = percent_decode(encoded)?;
            let result = core.accept_antiserum_knowledge(vulnerability, &id, unix_now())?;
            Ok(HttpBody::Json(serde_json::to_string(&result)?))
        }
        ("GET", _)
            if path.starts_with("/api/v1/analysis/packages/") && path.ends_with("/download") =>
        {
            let encoded = path
                .trim_start_matches("/api/v1/analysis/packages/")
                .trim_end_matches("/download")
                .trim_end_matches('/');
            let id = percent_decode(encoded)?;
            let bytes = core.analysis_package_bytes(&id)?;
            Ok(HttpBody::Binary {
                bytes,
                filename: format!("{id}.danti"),
            })
        }
        ("GET", _)
            if path.starts_with("/api/v1/analysis/packages/") && path.ends_with("/graph") =>
        {
            let encoded = path
                .trim_start_matches("/api/v1/analysis/packages/")
                .trim_end_matches("/graph")
                .trim_end_matches('/');
            let id = percent_decode(encoded)?;
            Ok(HttpBody::Json(serde_json::to_string(
                &core.analysis_package_graph(&id, unix_now())?,
            )?))
        }
        ("GET", _) if path.starts_with("/api/v1/analysis/vulnerability-candidates/") => {
            let encoded = path.trim_start_matches("/api/v1/analysis/vulnerability-candidates/");
            let id = percent_decode(encoded)?;
            match vulnerability.candidate(&id).map_err(DaemonError::from)? {
                Some(candidate) => Ok(HttpBody::Json(serde_json::to_string(&candidate)?)),
                None => Err(HttpRouteError::NotFound(format!(
                    "vulnerability candidate {id} was not found"
                ))),
            }
        }
        ("GET", _) if path.starts_with("/api/v1/analysis/packages/") => {
            let encoded = path.trim_start_matches("/api/v1/analysis/packages/");
            let id = percent_decode(encoded)?;
            Ok(HttpBody::Json(serde_json::to_string(
                &core.analysis_package_detail(&id, unix_now())?,
            )?))
        }
        ("POST", _) if path.starts_with("/api/v1/analysis/reviews/") && path.ends_with("/open") => {
            let encoded = path
                .trim_start_matches("/api/v1/analysis/reviews/")
                .trim_end_matches("/open")
                .trim_end_matches('/');
            let id = percent_decode(encoded)?;
            match core.touch_analysis_review(&id, unix_now())? {
                Some(review) => Ok(HttpBody::Json(serde_json::to_string(&review)?)),
                None => Err(HttpRouteError::NotFound(format!(
                    "review {id} was not found"
                ))),
            }
        }
        ("DELETE", _) if path.starts_with("/api/v1/analysis/reviews/") => {
            let encoded = path.trim_start_matches("/api/v1/analysis/reviews/");
            let id = percent_decode(encoded)?;
            if core.unload_analysis_review(&id)? {
                Ok(HttpBody::Json(
                    serde_json::json!({"unloaded": true, "review_id": id}).to_string(),
                ))
            } else {
                Err(HttpRouteError::NotFound(format!(
                    "review {id} was not found"
                )))
            }
        }
        ("GET", "/api/v1/vulnerabilities/status") => Ok(HttpBody::Json(serde_json::to_string(
            &vulnerability
                .knowledge_status()
                .map_err(DaemonError::from)?,
        )?)),
        ("GET", "/api/v1/vulnerabilities/inventory") => Ok(HttpBody::Json(serde_json::to_string(
            &vulnerability.inventory().map_err(DaemonError::from)?,
        )?)),
        ("GET", "/api/v1/vulnerabilities") => {
            let include_resolved = query
                .get("include_resolved")
                .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes"));
            Ok(HttpBody::Json(serde_json::to_string(
                &vulnerability
                    .exposures(include_resolved)
                    .map_err(DaemonError::from)?,
            )?))
        }
        ("POST", "/api/v1/vulnerabilities/refresh") => {
            let now = unix_now();
            vulnerability
                .refresh_inventory(now)
                .map_err(DaemonError::from)?;
            let exposures = vulnerability.assess(now).map_err(DaemonError::from)?;
            for exposure in &exposures {
                core.record_vulnerability_exposure(exposure, now)?;
            }
            Ok(HttpBody::Json(serde_json::to_string(&exposures)?))
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
        ("POST", _)
            if path.starts_with("/api/v1/vulnerabilities/") && path.ends_with("/manual") =>
        {
            let encoded = path
                .trim_start_matches("/api/v1/vulnerabilities/")
                .trim_end_matches("/manual")
                .trim_end_matches('/');
            let id = percent_decode(encoded)?;
            match vulnerability
                .mark_manual(&id, unix_now())
                .map_err(DaemonError::from)?
            {
                Some(exposure) => Ok(HttpBody::Json(serde_json::to_string(&exposure)?)),
                None => Err(HttpRouteError::NotFound(format!(
                    "vulnerability exposure {id} was not found or already resolved"
                ))),
            }
        }
        ("POST", _)
            if path.starts_with("/api/v1/vulnerabilities/") && path.ends_with("/authorise") =>
        {
            let encoded = path
                .trim_start_matches("/api/v1/vulnerabilities/")
                .trim_end_matches("/authorise")
                .trim_end_matches('/');
            let id = percent_decode(encoded)?;
            match vulnerability
                .authorise(&id, unix_now())
                .map_err(DaemonError::from)?
            {
                Some(exposure) => Ok(HttpBody::Json(serde_json::to_string(&exposure)?)),
                None => Err(HttpRouteError::NotFound(format!(
                    "vulnerability exposure {id} was not found or already resolved"
                ))),
            }
        }
        ("POST", _)
            if path.starts_with("/api/v1/vulnerabilities/") && path.ends_with("/update") =>
        {
            let encoded = path
                .trim_start_matches("/api/v1/vulnerabilities/")
                .trim_end_matches("/update")
                .trim_end_matches('/');
            let id = percent_decode(encoded)?;
            let now = unix_now();
            let Some(exposure) = vulnerability
                .authorise(&id, now)
                .map_err(DaemonError::from)?
            else {
                return Err(HttpRouteError::NotFound(format!(
                    "vulnerability exposure {id} was not found or already resolved"
                )));
            };
            if exposure.fixed_version.is_none() {
                return Err(HttpRouteError::BadRequest(format!(
                    "vulnerability exposure {id} has no known fixed version; Dendrite will not mutate the package"
                )));
            }

            let action = core.execute_authorised_vulnerability_update(&exposure, now)?;
            if action.proposal.status == "completed" {
                let refreshed_at = unix_now();
                vulnerability
                    .refresh_inventory(refreshed_at)
                    .map_err(DaemonError::from)?;
                let active = vulnerability
                    .assess(refreshed_at)
                    .map_err(DaemonError::from)?;
                for current in &active {
                    core.record_vulnerability_exposure(current, refreshed_at)?;
                }
            } else {
                vulnerability
                    .clear_authorisation(&id, unix_now())
                    .map_err(DaemonError::from)?;
            }
            let current = vulnerability
                .exposure(&id)
                .map_err(DaemonError::from)?
                .unwrap_or(exposure);
            let result = VulnerabilityRemediationDto {
                exposure: current,
                action,
            };
            Ok(HttpBody::Json(serde_json::to_string(&result)?))
        }
        ("POST", _)
            if path.starts_with("/api/v1/vulnerabilities/") && path.ends_with("/ignore") =>
        {
            let encoded = path
                .trim_start_matches("/api/v1/vulnerabilities/")
                .trim_end_matches("/ignore")
                .trim_end_matches('/');
            let id = percent_decode(encoded)?;
            match vulnerability.ignore_exposure(&id, unix_now()) {
                Ok(exposure) => Ok(HttpBody::Json(serde_json::to_string(&exposure)?)),
                Err(error) => Err(HttpRouteError::BadRequest(error.to_string())),
            }
        }
        // POST, not the DELETE verb: this server has no CORS preflight/OPTIONS
        // handling, and DELETE is never a "simple" CORS method (unlike GET/POST),
        // so a real browser would block it before it ever reached this route.
        ("POST", _)
            if path.starts_with("/api/v1/vulnerabilities/") && path.ends_with("/delete") =>
        {
            let encoded = path
                .trim_start_matches("/api/v1/vulnerabilities/")
                .trim_end_matches("/delete")
                .trim_end_matches('/');
            let id = percent_decode(encoded)?;
            let deleted = vulnerability
                .delete_exposure(&id)
                .map_err(DaemonError::from)?;
            if deleted {
                Ok(HttpBody::Json(serde_json::to_string(
                    &serde_json::json!({"deleted": true}),
                )?))
            } else {
                Err(HttpRouteError::NotFound(format!(
                    "vulnerability exposure {id} was not found"
                )))
            }
        }
        ("GET", _) if path.starts_with("/api/v1/vulnerabilities/") => {
            let encoded = path.trim_start_matches("/api/v1/vulnerabilities/");
            let id = percent_decode(encoded)?;
            match vulnerability.exposure(&id).map_err(DaemonError::from)? {
                Some(exposure) => Ok(HttpBody::Json(serde_json::to_string(&exposure)?)),
                None => Err(HttpRouteError::NotFound(format!(
                    "vulnerability exposure {id} was not found"
                ))),
            }
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
        ("POST", _) if path.starts_with("/api/v1/actions/") && path.ends_with("/reevaluate") => {
            let encoded = path
                .trim_start_matches("/api/v1/actions/")
                .trim_end_matches("/reevaluate")
                .trim_end_matches('/');
            let id = percent_decode(encoded)?;
            let detail = core.reevaluate_action(&id, unix_now())?;
            Ok(HttpBody::Created(serde_json::to_string(&detail)?))
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
        ("GET" | "POST" | "DELETE", _) => {
            Err(HttpRouteError::NotFound("API route was not found".into()))
        }
        _ => Err(HttpRouteError::MethodNotAllowed(
            "only GET, POST, DELETE and the documented safe action routes are supported".into(),
        )),
    }
}

fn publish_http_mutation(live: &LiveBroadcaster, method: &str, target: &str, body: &str) {
    if method != "POST" && method != "DELETE" {
        return;
    }
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    let kind = if path.starts_with("/api/v1/actions")
        || path.starts_with("/api/v1/vulnerabilities")
        || path.starts_with("/api/v1/analysis")
    {
        Some("control")
    } else {
        None
    };
    if let Some(kind) = kind {
        if let Ok(payload) = serde_json::from_str::<serde_json::Value>(body) {
            live.publish(kind, &payload);
        } else {
            live.publish(kind, &serde_json::json!({ "path": path }));
        }
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

fn write_binary(
    stream: &mut TcpStream,
    status: u16,
    body: &[u8],
    filename: &str,
    origin: Option<&str>,
) -> io::Result<()> {
    let cors = origin
        .filter(|value| ALLOWED_ORIGINS.contains(value))
        .map_or(String::new(), |value| {
            format!("Access-Control-Allow-Origin: {value}\r\nVary: Origin\r\n")
        });
    write!(
        stream,
        "HTTP/1.1 {status} OK\r\nContent-Type: application/vnd.dendrite.antiserum\r\nContent-Disposition: attachment; filename=\"{filename}\"\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n{}\r\n",
        body.len(),
        cors
    )?;
    stream.write_all(body)?;
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

    #[test]
    fn token_authorised_accepts_header_or_query_and_rejects_everything_else() {
        let core = DaemonCore::open(":memory:").unwrap();
        let token = core.http_api_token().to_owned();

        // Correct bearer header.
        assert!(token_authorised(
            &core,
            Some(&format!("Bearer {token}")),
            "/api/v1/status"
        ));
        // Correct `?token=` query param (the WebSocket-handshake path).
        assert!(token_authorised(&core, None, &format!("/ws?token={token}")));
        // No credentials at all.
        assert!(!token_authorised(&core, None, "/api/v1/status"));
        // Wrong token in either form.
        assert!(!token_authorised(
            &core,
            Some("Bearer not-the-token"),
            "/api/v1/status"
        ));
        assert!(!token_authorised(&core, None, "/ws?token=not-the-token"));
        // Header without the `Bearer ` prefix doesn't match even if the
        // raw value is otherwise correct.
        assert!(!token_authorised(&core, Some(&token), "/api/v1/status"));
    }
}
