//! Dendrite command-line client.

use dendrite_protocol::{ActionDetailDto, IpcRequest, IpcResponse, MemoryNodeDto};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

const DEFAULT_RECENT_LIMIT: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Status,
    Incidents,
    Incident(String),
    MemoryNodes {
        kind: Option<String>,
        limit: usize,
    },
    MemoryRecent {
        limit: usize,
    },
    MemoryNeighbours(String),
    MemoryPath(String, String),
    Actions,
    Action(String),
    CreateAction {
        incident_id: String,
        action: String,
        target: String,
    },
    EvaluateAction(String),
    GuardStatus,
    GuardFindings,
    GuardBaseline,
    GuardVerify,
    TelemetryStatus,
    TelemetryRecent {
        limit: usize,
    },
    DebugSeedIncident {
        label: Option<String>,
    },
    DebugInjectPriority {
        label: Option<String>,
    },
    DebugGuardState(String),
    DebugGuardFinding {
        target: String,
        severity: String,
        description: String,
    },
    VulnerabilityStatus,
    VulnerabilityInventory,
    Vulnerabilities {
        include_resolved: bool,
    },
    Vulnerability(String),
    VulnerabilityRefresh,
    VulnerabilityImport(String),
    VulnerabilityManual(String),
    VulnerabilityAuthorise(String),
    VulnerabilityUpdate(String),
    VulnerabilityIgnore(String),
    VulnerabilityDelete(String),
    Health,
    HttpToken,
    Version,
    Help(HelpTopic),
}

/// Which family of commands a `--help`/`-h` request applies to.
///
/// Only command families with more than one usage form (a subcommand, an
/// optional positional argument, or an optional flag) get their own topic.
/// Argument-less, single-form commands (`status`, `health`, `version`) do
/// not: a stray `--help`/`-h` passed to them is ignored rather than
/// explained, per design.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelpTopic {
    General,
    Incidents,
    Memory,
    Actions,
    Guard,
    Vulnerabilities,
    Vulnerability,
    Telemetry,
    Debug,
}

impl HelpTopic {
    fn for_family(family: &str) -> Option<Self> {
        match family {
            "incidents" | "incident" => Some(Self::Incidents),
            "memory" => Some(Self::Memory),
            "actions" | "action" => Some(Self::Actions),
            "guard" => Some(Self::Guard),
            "vulnerabilities" => Some(Self::Vulnerabilities),
            "vulnerability" => Some(Self::Vulnerability),
            "telemetry" => Some(Self::Telemetry),
            "debug" => Some(Self::Debug),
            _ => None,
        }
    }
}

impl Command {
    pub fn parse(arguments: &[String]) -> Self {
        if arguments.is_empty() {
            return Self::Help(HelpTopic::General);
        }
        if arguments.len() == 1 && matches!(arguments[0].as_str(), "--help" | "-h") {
            return Self::Help(HelpTopic::General);
        }

        let family = arguments[0].as_str();
        let has_help_flag = arguments
            .iter()
            .any(|value| value == "--help" || value == "-h");

        if has_help_flag {
            if let Some(topic) = HelpTopic::for_family(family) {
                return Self::Help(topic);
            }
            if matches!(
                family,
                "status" | "health" | "http-token" | "version" | "--version" | "-V"
            ) {
                // These commands take no arguments beyond the command word
                // itself and have no dedicated help surface; a stray
                // --help/-h is ignored and the command runs as if it were
                // never passed, rather than being rejected or explained.
                let filtered: Vec<String> = arguments
                    .iter()
                    .filter(|value| *value != "--help" && *value != "-h")
                    .cloned()
                    .collect();
                return Self::parse(&filtered);
            }
            return Self::Help(HelpTopic::General);
        }

        match arguments {
            [command] if command == "status" => Self::Status,
            [command] if command == "incidents" => Self::Incidents,
            [command, id] if command == "incident" || command == "incidents" => {
                Self::Incident(id.clone())
            }
            [command, subcommand] if command == "memory" && subcommand == "nodes" => {
                Self::MemoryNodes {
                    kind: None,
                    limit: DEFAULT_RECENT_LIMIT,
                }
            }
            [command, subcommand, limit] if command == "memory" && subcommand == "nodes" => {
                match limit.parse::<usize>() {
                    Ok(limit) => Self::MemoryNodes { kind: None, limit },
                    Err(_) => Self::Help(HelpTopic::Memory),
                }
            }
            [command, subcommand, flag, kind]
                if command == "memory" && subcommand == "nodes" && flag == "--kind" =>
            {
                Self::MemoryNodes {
                    kind: Some(kind.clone()),
                    limit: DEFAULT_RECENT_LIMIT,
                }
            }
            [command, subcommand, flag, kind, limit]
                if command == "memory" && subcommand == "nodes" && flag == "--kind" =>
            {
                match limit.parse::<usize>() {
                    Ok(limit) => Self::MemoryNodes {
                        kind: Some(kind.clone()),
                        limit,
                    },
                    Err(_) => Self::Help(HelpTopic::Memory),
                }
            }
            [command, subcommand] if command == "memory" && subcommand == "recent" => {
                Self::MemoryRecent {
                    limit: DEFAULT_RECENT_LIMIT,
                }
            }
            [command, subcommand, limit] if command == "memory" && subcommand == "recent" => {
                match limit.parse::<usize>() {
                    Ok(limit) => Self::MemoryRecent { limit },
                    Err(_) => Self::Help(HelpTopic::Memory),
                }
            }
            [command, subcommand, node] if command == "memory" && subcommand == "neighbours" => {
                Self::MemoryNeighbours(node.clone())
            }
            [command, subcommand, source, target]
                if command == "memory" && subcommand == "path" =>
            {
                Self::MemoryPath(source.clone(), target.clone())
            }
            [command] if command == "actions" => Self::Actions,
            [command, id]
                if (command == "action" || command == "actions")
                    && id != "propose"
                    && id != "evaluate" =>
            {
                Self::Action(id.clone())
            }
            [command, subcommand, incident_id, action, target]
                if command == "actions" && subcommand == "propose" =>
            {
                Self::CreateAction {
                    incident_id: incident_id.clone(),
                    action: action.clone(),
                    target: target.clone(),
                }
            }
            [command] if command == "guard" => Self::GuardStatus,
            [command, subcommand] if command == "guard" && subcommand == "findings" => {
                Self::GuardFindings
            }
            [command, subcommand] if command == "guard" && subcommand == "baseline" => {
                Self::GuardBaseline
            }
            [command, subcommand] if command == "guard" && subcommand == "verify" => {
                Self::GuardVerify
            }
            [command] if command == "telemetry" => Self::TelemetryStatus,
            [command, subcommand] if command == "telemetry" && subcommand == "recent" => {
                Self::TelemetryRecent { limit: 50 }
            }
            [command, subcommand, limit] if command == "telemetry" && subcommand == "recent" => {
                match limit.parse::<usize>() {
                    Ok(limit) => Self::TelemetryRecent { limit },
                    Err(_) => Self::Help(HelpTopic::Telemetry),
                }
            }
            [command] if command == "vulnerabilities" => Self::Vulnerabilities {
                include_resolved: false,
            },
            [command, flag] if command == "vulnerabilities" && flag == "--all" => {
                Self::Vulnerabilities {
                    include_resolved: true,
                }
            }
            [command, subcommand] if command == "vulnerability" && subcommand == "status" => {
                Self::VulnerabilityStatus
            }
            [command, subcommand] if command == "vulnerability" && subcommand == "inventory" => {
                Self::VulnerabilityInventory
            }
            [command, subcommand] if command == "vulnerability" && subcommand == "refresh" => {
                Self::VulnerabilityRefresh
            }
            [command, subcommand, path] if command == "vulnerability" && subcommand == "import" => {
                Self::VulnerabilityImport(path.clone())
            }
            [command, subcommand, id] if command == "vulnerability" && subcommand == "manual" => {
                Self::VulnerabilityManual(id.clone())
            }
            [command, subcommand, id]
                if command == "vulnerability" && subcommand == "authorise" =>
            {
                Self::VulnerabilityAuthorise(id.clone())
            }
            [command, subcommand, id] if command == "vulnerability" && subcommand == "update" => {
                Self::VulnerabilityUpdate(id.clone())
            }
            [command, subcommand, id] if command == "vulnerability" && subcommand == "ignore" => {
                Self::VulnerabilityIgnore(id.clone())
            }
            [command, subcommand, id] if command == "vulnerability" && subcommand == "delete" => {
                Self::VulnerabilityDelete(id.clone())
            }
            [command, id]
                if command == "vulnerability"
                    && !["manual", "authorise", "update", "ignore", "delete"]
                        .contains(&id.as_str()) =>
            {
                Self::Vulnerability(id.clone())
            }
            [command, subcommand] if command == "debug" && subcommand == "seed-incident" => {
                Self::DebugSeedIncident { label: None }
            }
            [command, subcommand, label] if command == "debug" && subcommand == "seed-incident" => {
                Self::DebugSeedIncident {
                    label: Some(label.clone()),
                }
            }
            [command, subcommand] if command == "debug" && subcommand == "inject-priority" => {
                Self::DebugInjectPriority { label: None }
            }
            [command, subcommand, label]
                if command == "debug" && subcommand == "inject-priority" =>
            {
                Self::DebugInjectPriority {
                    label: Some(label.clone()),
                }
            }
            [command, subcommand, state] if command == "debug" && subcommand == "guard-state" => {
                Self::DebugGuardState(state.clone())
            }
            [command, subcommand, target, severity, description]
                if command == "debug" && subcommand == "guard-finding" =>
            {
                Self::DebugGuardFinding {
                    target: target.clone(),
                    severity: severity.clone(),
                    description: description.clone(),
                }
            }
            [command, subcommand, id] if command == "actions" && subcommand == "evaluate" => {
                Self::EvaluateAction(id.clone())
            }
            [command] if command == "health" => Self::Health,
            [command] if command == "http-token" => Self::HttpToken,
            [command] if command == "version" || command == "--version" || command == "-V" => {
                Self::Version
            }
            _ => match HelpTopic::for_family(family) {
                Some(topic) => Self::Help(topic),
                None => Self::Help(HelpTopic::General),
            },
        }
    }

    fn request(&self) -> Option<IpcRequest> {
        match self {
            Self::Status => Some(IpcRequest::Status),
            Self::Incidents => Some(IpcRequest::Incidents),
            Self::Incident(id) => Some(IpcRequest::Incident { id: id.clone() }),
            Self::MemoryNodes { kind, .. } => Some(IpcRequest::MemoryNodes { kind: kind.clone() }),
            Self::MemoryRecent { limit } => Some(IpcRequest::MemoryRecent { limit: *limit }),
            Self::MemoryNeighbours(node_id) => Some(IpcRequest::MemoryNeighbours {
                node_id: node_id.clone(),
            }),
            Self::MemoryPath(source, target) => Some(IpcRequest::MemoryPath {
                source: source.clone(),
                target: target.clone(),
            }),
            Self::Actions => Some(IpcRequest::Actions),
            Self::Action(id) => Some(IpcRequest::Action { id: id.clone() }),
            Self::CreateAction {
                incident_id,
                action,
                target,
            } => Some(IpcRequest::CreateAction {
                incident_id: incident_id.clone(),
                action: action.clone(),
                target: target.clone(),
            }),
            Self::EvaluateAction(id) => Some(IpcRequest::EvaluateAction { id: id.clone() }),
            Self::GuardStatus => Some(IpcRequest::GuardStatus),
            Self::GuardFindings => Some(IpcRequest::GuardFindings),
            Self::GuardBaseline => Some(IpcRequest::GuardBaseline),
            Self::GuardVerify => Some(IpcRequest::GuardVerify),
            Self::TelemetryStatus => Some(IpcRequest::TelemetryStatus),
            Self::TelemetryRecent { limit } => Some(IpcRequest::TelemetryRecent { limit: *limit }),
            Self::DebugSeedIncident { label } => Some(IpcRequest::DebugSeedIncident {
                label: label.clone(),
            }),
            Self::DebugInjectPriority { label } => Some(IpcRequest::DebugInjectPriority {
                label: label.clone(),
            }),
            Self::DebugGuardState(state) => Some(IpcRequest::DebugGuardState {
                state: state.clone(),
            }),
            Self::DebugGuardFinding {
                target,
                severity,
                description,
            } => Some(IpcRequest::DebugGuardFinding {
                target: target.clone(),
                severity: severity.clone(),
                description: description.clone(),
            }),
            Self::VulnerabilityStatus => Some(IpcRequest::VulnerabilityStatus),
            Self::VulnerabilityInventory => Some(IpcRequest::VulnerabilityInventory),
            Self::Vulnerabilities { include_resolved } => Some(IpcRequest::Vulnerabilities {
                include_resolved: *include_resolved,
            }),
            Self::Vulnerability(id) => Some(IpcRequest::Vulnerability { id: id.clone() }),
            Self::VulnerabilityRefresh => Some(IpcRequest::VulnerabilityRefresh),
            Self::VulnerabilityImport(path) => {
                Some(IpcRequest::VulnerabilityImport { path: path.clone() })
            }
            Self::VulnerabilityManual(id) => {
                Some(IpcRequest::VulnerabilityManual { id: id.clone() })
            }
            Self::VulnerabilityAuthorise(id) => {
                Some(IpcRequest::VulnerabilityAuthorise { id: id.clone() })
            }
            Self::VulnerabilityUpdate(id) => {
                Some(IpcRequest::VulnerabilityUpdate { id: id.clone() })
            }
            Self::VulnerabilityIgnore(id) => {
                Some(IpcRequest::VulnerabilityIgnore { id: id.clone() })
            }
            Self::VulnerabilityDelete(id) => {
                Some(IpcRequest::VulnerabilityDelete { id: id.clone() })
            }
            Self::Health => Some(IpcRequest::Health),
            Self::HttpToken => Some(IpcRequest::HttpToken),
            Self::Version | Self::Help(_) => None,
        }
    }
}

#[derive(Debug)]
pub enum ClientError {
    Io(io::Error),
    Json(serde_json::Error),
}

impl From<io::Error> for ClientError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for ClientError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

pub fn execute(command: &Command, socket_path: &Path) -> Result<String, ClientError> {
    match command {
        Command::Version => Ok(format!("dendrite {}", env!("CARGO_PKG_VERSION"))),
        Command::Help(topic) => Ok(help(*topic)),
        Command::MemoryNodes { limit, .. } => {
            let response = send(
                socket_path,
                command.request().expect("IPC command has request"),
            )?;
            match response {
                IpcResponse::MemoryNodes { nodes } => Ok(render_memory_nodes(&nodes, *limit)),
                other => Ok(render_response(&other)),
            }
        }
        _ => {
            let response = send(
                socket_path,
                command.request().expect("IPC command has request"),
            )?;
            Ok(render_response(&response))
        }
    }
}

fn send(socket_path: &Path, request: IpcRequest) -> Result<IpcResponse, ClientError> {
    let mut stream = UnixStream::connect(socket_path)?;
    serde_json::to_writer(&mut stream, &request)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    Ok(serde_json::from_str(line.trim())?)
}

fn render_response(response: &IpcResponse) -> String {
    match response {
        IpcResponse::Status(status) => format!(
            "dendrited {}\ninstance id: {}\nsigning key: {} ({})\nkey fingerprint: {}\nobservations: {}\nopen incidents: {}\nmemory nodes: {}\nsocket: {}",
            status.version,
            status.instance_id,
            status.signing_key.key_id,
            status.signing_key.algorithm,
            status.signing_key.fingerprint,
            status.observations_ingested,
            status.incidents_open,
            status.memory_nodes_known,
            status.socket_path
        ),
        IpcResponse::Incidents { incidents } => {
            if incidents.is_empty() {
                return "No incidents.".into();
            }
            incidents
                .iter()
                .map(|incident| {
                    format!(
                        "{}  {:<8} {:<6} evidence={}  {}",
                        incident.id,
                        incident.severity,
                        incident.status,
                        incident.evidence_count,
                        incident.summary
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
        IpcResponse::Incident { incident } => {
            let evidence = incident
                .evidence
                .iter()
                .map(|item| {
                    format!(
                        "  {} [{} {}%] {}",
                        item.id, item.source, item.confidence, item.description
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            format!(
                "{} [{}] {}\nfirst seen: {}\nlast seen: {}\nobjects: {}\nevidence:\n{}",
                incident.incident.id,
                incident.incident.severity,
                incident.incident.summary,
                incident.incident.first_seen_at,
                incident.incident.last_seen_at,
                incident.related_objects.join(", "),
                evidence
            )
        }
        IpcResponse::MemoryNodes { nodes } | IpcResponse::MemoryRecent { nodes } => {
            render_nodes(nodes)
        }
        IpcResponse::MemoryNeighbours {
            node_id,
            neighbours,
        } => {
            if neighbours.is_empty() {
                format!("{node_id}: no neighbours")
            } else {
                format!("{node_id}:\n  {}", neighbours.join("\n  "))
            }
        }
        IpcResponse::MemoryPath { path } => match path {
            Some(path) => format!("score={}\n{}", path.score, path.nodes.join(" -> ")),
            None => "No path found.".into(),
        },
        IpcResponse::Actions { actions } => {
            if actions.is_empty() {
                return "No action proposals.".into();
            }
            actions
                .iter()
                .map(|action| {
                    format!(
                        "{}  {:<18} {:<15} {} -> {}",
                        action.id, action.action, action.status, action.incident_id, action.target
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
        IpcResponse::Action { action } => render_action(action),
        IpcResponse::GuardStatus(status) => format!(
            "trust: {}\nauthority: {}\nintegrity findings: {}",
            status.trust_state, status.authority, status.findings_count
        ),
        IpcResponse::GuardFindings { findings } => {
            if findings.is_empty() {
                "No integrity findings.".into()
            } else {
                findings
                    .iter()
                    .map(|finding| {
                        format!(
                            "{}  {:<13} {}  {}",
                            finding.id, finding.severity, finding.target, finding.description
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        }
        IpcResponse::GuardManifest(status) => {
            if status.established {
                format!(
                    "baseline established: {} entries, key {}, fingerprint {}, recorded at {}",
                    status.entry_count, status.key_id, status.fingerprint, status.created_at
                )
            } else {
                "No integrity baseline established yet.".into()
            }
        }
        IpcResponse::GuardVerification(result) => {
            let mut lines = vec![format!(
                "signature valid: {}\nmatches baseline: {}",
                result.signature_valid, result.matches
            )];
            if result.mismatches.is_empty() {
                lines.push("no mismatches.".into());
            } else {
                lines.push("mismatches:".into());
                for mismatch in &result.mismatches {
                    lines.push(format!(
                        "  {}  baseline={} current={}",
                        mismatch.path, mismatch.baseline_digest, mismatch.current_digest
                    ));
                }
            }
            lines.join("\n")
        }
        IpcResponse::TelemetryStatus(status) => status
            .sources
            .iter()
            .map(|source| {
                format!(
                    "{:<20} {:<10} {}",
                    source.source, source.status, source.detail
                )
            })
            .chain([
                format!("recent events: {}", status.recent_events),
                format!(
                    "queue: {}/{} (peak {})",
                    status.pipeline.queue_depth,
                    status.pipeline.queue_capacity,
                    status.pipeline.peak_queue_depth
                ),
                format!(
                    "processed: {}  dropped: {}  security observations: {}",
                    status.pipeline.events_processed,
                    status.pipeline.events_dropped,
                    status.pipeline.security_observations_ingested
                ),
                format!(
                    "queue wait: last={}ms max={}ms  processing: last={}ms max={}ms",
                    status.pipeline.last_queue_wait_ms,
                    status.pipeline.max_queue_wait_ms,
                    status.pipeline.last_processing_ms,
                    status.pipeline.max_processing_ms
                ),
                format!(
                    "  priority: {}/{} (peak {})  processed: {}  dropped: {}  wait: last={}ms max={}ms  processing: last={}ms max={}ms",
                    status.pipeline.priority.queue_depth,
                    status.pipeline.priority.queue_capacity,
                    status.pipeline.priority.peak_queue_depth,
                    status.pipeline.priority.events_processed,
                    status.pipeline.priority.events_dropped,
                    status.pipeline.priority.last_queue_wait_ms,
                    status.pipeline.priority.max_queue_wait_ms,
                    status.pipeline.priority.last_processing_ms,
                    status.pipeline.priority.max_processing_ms
                ),
                format!(
                    "  routine:  {}/{} (peak {})  processed: {}  dropped: {}  wait: last={}ms max={}ms  processing: last={}ms max={}ms",
                    status.pipeline.routine.queue_depth,
                    status.pipeline.routine.queue_capacity,
                    status.pipeline.routine.peak_queue_depth,
                    status.pipeline.routine.events_processed,
                    status.pipeline.routine.events_dropped,
                    status.pipeline.routine.last_queue_wait_ms,
                    status.pipeline.routine.max_queue_wait_ms,
                    status.pipeline.routine.last_processing_ms,
                    status.pipeline.routine.max_processing_ms
                ),
            ])
            .collect::<Vec<_>>()
            .join("\n"),
        IpcResponse::TelemetryRecent { events } => {
            if events.is_empty() {
                "No recent telemetry events.".into()
            } else {
                events
                    .iter()
                    .map(|event| {
                        format!(
                            "{}  {:<18} {:<18} pid={}  {} -> {}{}",
                            event.observed_at,
                            event.source,
                            event.event,
                            event
                                .process_id
                                .map_or_else(|| "-".into(), |pid| pid.to_string()),
                            event.source_object,
                            event.target_object.as_deref().unwrap_or("-"),
                            if event.incident_ids.is_empty() {
                                String::new()
                            } else {
                                format!("  incidents={}", event.incident_ids.join(","))
                            }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        }
        IpcResponse::VulnerabilityStatus(status) => format!(
            "CVE knowledge: {} records across {} packages\ninstalled packages: {}\nopen exposures: {}\nsource: {}\nknowledge generated: {}\nlast import: {}\ninventory refreshed: {}\nassessment: {}",
            status.records,
            status.packages,
            status.inventory_packages,
            status.open_exposures,
            status.source.as_deref().unwrap_or("-"),
            status
                .generated_at
                .map_or_else(|| "-".into(), |v| v.to_string()),
            status
                .last_imported_at
                .map_or_else(|| "-".into(), |v| v.to_string()),
            status
                .inventory_last_refreshed_at
                .map_or_else(|| "-".into(), |v| v.to_string()),
            status
                .assessment_last_run_at
                .map_or_else(|| "-".into(), |v| v.to_string()),
        ),
        IpcResponse::VulnerabilityInventory { packages } => {
            if packages.is_empty() {
                "No installed packages discovered.".into()
            } else {
                packages
                    .iter()
                    .map(|p| format!("{:<36} {:<10} {}", p.name, p.architecture, p.version))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        }
        IpcResponse::Vulnerabilities { exposures } => {
            if exposures.is_empty() {
                "No matching vulnerability exposures.".into()
            } else {
                exposures
                    .iter()
                    .map(|v| {
                        format!(
                            "{}  {:<8} {:<18} {} -> fixed {} [{}]",
                            v.cve_id,
                            v.severity,
                            v.package,
                            v.installed_version,
                            v.fixed_version.as_deref().unwrap_or("unknown"),
                            v.status
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        }
        IpcResponse::Vulnerability { exposure } => format!(
            "{} [{}]\npackage: {}:{} {}\nfixed version: {}\nstatus: {}\nfirst seen: {}\nlast seen: {}\nmanual revalidation: {}\nauthorised at: {}\nresolution source: {}",
            exposure.cve_id,
            exposure.severity,
            exposure.package,
            exposure.architecture,
            exposure.installed_version,
            exposure.fixed_version.as_deref().unwrap_or("unknown"),
            exposure.status,
            exposure.first_seen_at,
            exposure.last_seen_at,
            exposure.awaiting_manual,
            exposure
                .authorised_at
                .map_or_else(|| "-".into(), |v| v.to_string()),
            exposure.resolution_source.as_deref().unwrap_or("-")
        ),
        IpcResponse::VulnerabilityImport { imported, status } => format!(
            "imported {} CVE knowledge record(s); database now contains {} record(s), {} open exposure(s)",
            imported, status.records, status.open_exposures
        ),
        IpcResponse::VulnerabilityRemediation(remediation) => format!(
            "{} [{}] package {} {}\nremediation action: {} [{}]\nquorum: {}\npolicy: {}\nguard: {}\nexposure status: {}\nresolution source: {}",
            remediation.exposure.cve_id,
            remediation.exposure.severity,
            remediation.exposure.package,
            remediation.exposure.installed_version,
            remediation.action.proposal.id,
            remediation.action.proposal.status,
            remediation
                .action
                .proposal
                .quorum
                .as_deref()
                .unwrap_or("pending"),
            remediation
                .action
                .proposal
                .policy
                .as_deref()
                .unwrap_or("pending"),
            remediation
                .action
                .proposal
                .guard
                .as_deref()
                .unwrap_or("pending"),
            remediation.exposure.status,
            remediation
                .exposure
                .resolution_source
                .as_deref()
                .unwrap_or("-")
        ),
        IpcResponse::Health(health) => format!(
            "daemon: {}\nmemory: {}\nguard: {}",
            health.daemon, health.memory, health.guard
        ),
        IpcResponse::HttpToken { token } => token.clone(),
        IpcResponse::VulnerabilityDeleted { deleted } => {
            if *deleted {
                "vulnerability exposure deleted".to_string()
            } else {
                "no such vulnerability exposure".to_string()
            }
        }
        IpcResponse::DebugInjectPriority { queued } => {
            if *queued {
                "synthetic observation queued on the priority channel — check `telemetry` for its effect on the priority lane's queue depth/processing".to_string()
            } else {
                "priority channel was already full — synthetic observation dropped, same as real priority traffic would be under saturation".to_string()
            }
        }
        IpcResponse::Error { message } => format!("Error: {message}"),
    }
}

fn render_action(action: &ActionDetailDto) -> String {
    let evaluations = if action.evaluations.is_empty() {
        "  none".into()
    } else {
        action
            .evaluations
            .iter()
            .map(|evaluation| {
                format!(
                    "  {:<11} {:<8} {}",
                    evaluation.evaluator, evaluation.verdict, evaluation.reason
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let transactions = action
        .transactions
        .iter()
        .map(|event| {
            format!(
                "  {:<12} {:<15} {}",
                event.state,
                event.status,
                event.message.as_deref().unwrap_or("")
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "{} [{}] {}\nincident: {}\ntarget: {}\nquorum: {}\npolicy: {}\nguard: {}\nMAGI:\n{}\ntransaction:\n{}",
        action.proposal.id,
        action.proposal.status,
        action.proposal.action,
        action.proposal.incident_id,
        action.proposal.target,
        action.proposal.quorum.as_deref().unwrap_or("pending"),
        action.proposal.policy.as_deref().unwrap_or("pending"),
        action.proposal.guard.as_deref().unwrap_or("pending"),
        evaluations,
        transactions
    )
}

fn render_nodes(nodes: &[MemoryNodeDto]) -> String {
    if nodes.is_empty() {
        return "No memory nodes.".into();
    }
    nodes
        .iter()
        .map(|node| {
            format!(
                "{}  {:<16} {:<12} last_seen={}  {}",
                node.id, node.kind, node.state, node.last_seen_at, node.label
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Unlike `memory recent`/`memory graph`, the daemon's `MemoryNodes` IPC
/// response is unbounded by design (it feeds the HTTP API's own node
/// listing too, which the UI paginates/searches itself) — so `memory
/// nodes` must cap what actually gets printed to the terminal itself,
/// rather than dumping every node in the graph. `limit == 0` means
/// unlimited, matching the `limit == 0` convention `memory_graph` already
/// uses elsewhere in the daemon.
fn render_memory_nodes(nodes: &[MemoryNodeDto], limit: usize) -> String {
    if nodes.is_empty() {
        return "No memory nodes.".into();
    }
    if limit == 0 || nodes.len() <= limit {
        return render_nodes(nodes);
    }
    let shown = render_nodes(&nodes[..limit]);
    format!(
        "{shown}\n... and {} more (raise the limit, e.g. `memory nodes {}`, add `--kind` to narrow, or pass `0` for no limit)",
        nodes.len() - limit,
        nodes.len(),
    )
}

fn help(topic: HelpTopic) -> String {
    match topic {
        HelpTopic::General => help_general(),
        HelpTopic::Incidents => help_incidents(),
        HelpTopic::Memory => help_memory(),
        HelpTopic::Actions => help_actions(),
        HelpTopic::Guard => help_guard(),
        HelpTopic::Vulnerabilities => help_vulnerabilities(),
        HelpTopic::Vulnerability => help_vulnerability(),
        HelpTopic::Telemetry => help_telemetry(),
        HelpTopic::Debug => help_debug(),
    }
}

fn help_general() -> String {
    format!(
        "Dendrite {}\n\nUsage:\n  dendrite <COMMAND>\n\nCommands:\n  status                                      Show daemon status\n  incidents                                   List incidents / show details (see: incidents --help)\n  memory <SUBCOMMAND>                         Memory Graph queries (see: memory --help)\n  actions                                     List/inspect/propose/evaluate actions (see: actions --help)\n  guard                                       Guard trust state, findings, and integrity manifest (see: guard --help)\n  telemetry                                   Collector status and recent events (see: telemetry --help)\n  vulnerabilities [--all]                     List vulnerability exposures (see: vulnerabilities --help)\n  vulnerability <SUBCOMMAND>                  CVE/exposure management (see: vulnerability --help)\n  health                                      Show subsystem health\n  http-token                                   Print the HTTP API bearer token\n  version                                     Show CLI version\n  debug <SUBCOMMAND>                          Development-only surfaces (see: debug --help)\n\nRun `dendrite <COMMAND> --help` on any multi-form command above for its full usage.\n\nOptions:\n  -h, --help                                  Show this help\n  -V, --version                               Show CLI version",
        env!("CARGO_PKG_VERSION")
    )
}

fn help_incidents() -> String {
    "Usage:\n  dendrite incidents\n  dendrite incidents <ID>\n\n  incidents            List incidents\n  incidents <ID>       Show incident details (severity, status, evidence, related objects)".into()
}

fn help_memory() -> String {
    format!(
        "Usage:\n  dendrite memory nodes [--kind <KIND>] [LIMIT]\n  dendrite memory recent [LIMIT]\n  dendrite memory neighbours <NODE>\n  dendrite memory path <SOURCE> <TARGET>\n\n  memory nodes                       List known Memory Graph nodes (default: first {0}, 0 for no limit)\n  memory nodes --kind <KIND> [LIMIT]  Filter nodes by kind, and/or set the limit\n  memory recent [LIMIT]              Show recently seen nodes (default: {0})\n  memory neighbours <NODE>           List neighbouring node IDs\n  memory path <SOURCE> <TARGET>      Find a graph path\n\nNode kinds:\n  process, file, user, host, network_endpoint, service, container, incident, threat",
        DEFAULT_RECENT_LIMIT
    )
}

fn help_actions() -> String {
    "Usage:\n  dendrite actions\n  dendrite actions <ID>\n  dendrite actions propose <INCIDENT> <ACTION> <TARGET>\n  dendrite actions evaluate <ID>\n\n  actions                                       List action proposals\n  actions <ID>                                  Show proposal, MAGI and transaction details\n  actions propose <INCIDENT> <ACTION> <TARGET>  Create an action proposal\n  actions evaluate <ID>                         Evaluate and run a safe proposal\n\nExecutable actions:\n  observe, warn\n  update_package (only through authorised vulnerability remediation)\n\nPrivileged actions are represented but remain policy/Guard-denied until privileged executors are enabled.".into()
}

fn help_guard() -> String {
    "Usage:\n  dendrite guard\n  dendrite guard findings\n  dendrite guard baseline\n  dendrite guard verify\n\n  guard            Show Guard trust state and authority\n  guard findings   List Guard integrity findings\n  guard baseline   (Re)establish the signed integrity manifest baseline\n  guard verify     Compare current file hashes against the stored baseline\n\n`guard baseline`/`guard verify` hash the paths `dendrite-guard` is itself configured\nto watch (its own DENDRITE_GUARD_WATCH_PATHS, not anything supplied here) — see\ncrates/dendrite-guard/README.md's \"Integrity manifest\" section. `guard verify` triggers\nthe same verification pass dendrite-guard also runs automatically in the background\n(every DENDRITE_GUARD_VERIFY_INTERVAL_SECONDS, default 300s): a detected mismatch is\nrecorded as a finding (deduplicated across repeated checks) and escalates trust state,\nvia a monotonic rule that never auto-improves trust back toward trusted.\n\nTrust states:\n  trusted, degraded, suspected, quarantined, compromised, recovering".into()
}

fn help_vulnerabilities() -> String {
    "Usage:\n  dendrite vulnerabilities [--all]\n\n  vulnerabilities        List open vulnerability exposures\n  vulnerabilities --all  Include resolved exposures\n\nSee `vulnerability --help` for per-exposure and remediation commands.".into()
}

fn help_vulnerability() -> String {
    "Usage:\n  dendrite vulnerability <ID>\n  dendrite vulnerability status\n  dendrite vulnerability inventory\n  dendrite vulnerability refresh\n  dendrite vulnerability import <FILE>\n  dendrite vulnerability manual <ID>\n  dendrite vulnerability authorise <ID>\n  dendrite vulnerability update <ID>\n  dendrite vulnerability ignore <ID>\n  dendrite vulnerability delete <ID>\n\n  vulnerability <ID>            Show one exposure\n  vulnerability status          Show CVE/inventory status\n  vulnerability inventory       List installed dpkg packages\n  vulnerability refresh         Refresh inventory and revalidate exposures\n  vulnerability import <FILE>   Import a CVE knowledge bundle\n  vulnerability manual <ID>     Mark as being remediated manually\n  vulnerability authorise <ID>  Record explicit user update authority\n  vulnerability update <ID>     Authorise and execute native package remediation\n  vulnerability ignore <ID>     Dismiss an open/awaiting-revalidation exposure\n  vulnerability delete <ID>     Permanently remove an exposure record\n\n`vulnerability manual` creates the remediation proposal path; it does not directly mutate the package manager.\n`vulnerability authorise` records explicit user authority; stale authority must not be reusable for a changed target/state.\n`vulnerability update` remains transactional and policy/Guard-gated.\n`vulnerability ignore` is reversible: a later CVE bundle import that matches it via attack-chain/behaviour reclassification, or the package itself changing version, automatically re-raises it.\n`vulnerability delete` is not reversible and has no re-raise mechanism; normally the wrong tool outside debugging — prefer `ignore` for \"I've seen this, stop showing it to me.\"".into()
}

fn help_telemetry() -> String {
    "Usage:\n  dendrite telemetry\n  dendrite telemetry recent [LIMIT]\n\n  telemetry                 Show collector status (fanotify/eBPF/fallbacks) and queue health\n  telemetry recent [LIMIT]  Show recent telemetry events (default: 50)".into()
}

fn help_debug() -> String {
    "Development-only surfaces. Not a production operator API; disabled in release builds.\n\nUsage:\n  dendrite debug seed-incident [LABEL]\n  dendrite debug inject-priority [LABEL]\n  dendrite debug guard-state <STATE>\n  dendrite debug guard-finding <TARGET> <SEVERITY> <DESCRIPTION>\n\n  debug seed-incident [LABEL]                            Seed a synthetic incident/graph for local testing\n  debug inject-priority [LABEL]                          Push a synthetic Critical-severity observation through the real priority ingestion channel, for testing priority-lane behaviour under load — seed-incident does NOT exercise this, it bypasses the ingestion queue entirely\n  debug guard-state <STATE>                              Force Guard trust state\n  debug guard-finding <TARGET> <SEVERITY> <DESCRIPTION>   Record a synthetic integrity finding\n\nTrust states (for guard-state):\n  trusted, degraded, suspected, quarantined, compromised, recovering\n\nSeverities (for guard-finding):\n  informational, warning, high, critical".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).into()).collect()
    }

    #[test]
    fn parses_memory_path() {
        assert_eq!(
            Command::parse(&args(&["memory", "path", "a", "b"])),
            Command::MemoryPath("a".into(), "b".into())
        );
    }

    #[test]
    fn parses_incident_detail() {
        assert_eq!(
            Command::parse(&args(&["incidents", "inc_00000001"])),
            Command::Incident("inc_00000001".into())
        );
    }

    #[test]
    fn parses_memory_nodes_kind_filter() {
        assert_eq!(
            Command::parse(&args(&["memory", "nodes", "--kind", "process"])),
            Command::MemoryNodes {
                kind: Some("process".into()),
                limit: DEFAULT_RECENT_LIMIT,
            }
        );
    }

    #[test]
    fn parses_memory_nodes_with_no_arguments_using_the_default_limit() {
        assert_eq!(
            Command::parse(&args(&["memory", "nodes"])),
            Command::MemoryNodes {
                kind: None,
                limit: DEFAULT_RECENT_LIMIT,
            }
        );
    }

    #[test]
    fn parses_memory_nodes_bare_limit() {
        assert_eq!(
            Command::parse(&args(&["memory", "nodes", "100"])),
            Command::MemoryNodes {
                kind: None,
                limit: 100,
            }
        );
        assert_eq!(
            Command::parse(&args(&["memory", "nodes", "0"])),
            Command::MemoryNodes {
                kind: None,
                limit: 0,
            }
        );
    }

    #[test]
    fn parses_memory_nodes_kind_filter_with_limit() {
        assert_eq!(
            Command::parse(&args(&["memory", "nodes", "--kind", "process", "5"])),
            Command::MemoryNodes {
                kind: Some("process".into()),
                limit: 5,
            }
        );
    }

    #[test]
    fn parses_action_proposal_creation() {
        assert_eq!(
            Command::parse(&args(&[
                "actions",
                "propose",
                "inc_00000001",
                "warn",
                "process:1"
            ])),
            Command::CreateAction {
                incident_id: "inc_00000001".into(),
                action: "warn".into(),
                target: "process:1".into()
            }
        );
    }

    #[test]
    fn parses_action_evaluation() {
        assert_eq!(
            Command::parse(&args(&["actions", "evaluate", "act_00000001"])),
            Command::EvaluateAction("act_00000001".into())
        );
    }

    #[test]
    fn parses_telemetry_status() {
        assert_eq!(
            Command::parse(&args(&["telemetry"])),
            Command::TelemetryStatus
        );
    }

    #[test]
    fn parses_telemetry_recent_limit() {
        assert_eq!(
            Command::parse(&args(&["telemetry", "recent", "25"])),
            Command::TelemetryRecent { limit: 25 }
        );
    }

    #[test]
    fn parses_guard_baseline() {
        assert_eq!(
            Command::parse(&args(&["guard", "baseline"])),
            Command::GuardBaseline
        );
    }

    #[test]
    fn parses_guard_verify() {
        assert_eq!(
            Command::parse(&args(&["guard", "verify"])),
            Command::GuardVerify
        );
    }

    #[test]
    fn parses_debug_seed_incident() {
        assert_eq!(
            Command::parse(&args(&["debug", "seed-incident", "ui-test"])),
            Command::DebugSeedIncident {
                label: Some("ui-test".into())
            }
        );
    }

    #[test]
    fn parses_debug_inject_priority() {
        assert_eq!(
            Command::parse(&args(&["debug", "inject-priority"])),
            Command::DebugInjectPriority { label: None }
        );
        assert_eq!(
            Command::parse(&args(&["debug", "inject-priority", "load-test"])),
            Command::DebugInjectPriority {
                label: Some("load-test".into())
            }
        );
    }

    #[test]
    fn multi_level_command_help_flag_shows_family_topic() {
        assert_eq!(
            Command::parse(&args(&["incidents", "--help"])),
            Command::Help(HelpTopic::Incidents)
        );
        assert_eq!(
            Command::parse(&args(&["memory", "-h"])),
            Command::Help(HelpTopic::Memory)
        );
        assert_eq!(
            Command::parse(&args(&["memory", "nodes", "--kind", "process", "--help"])),
            Command::Help(HelpTopic::Memory)
        );
        assert_eq!(
            Command::parse(&args(&["debug", "guard-state", "trusted", "--help"])),
            Command::Help(HelpTopic::Debug)
        );
    }

    #[test]
    fn simple_argless_command_ignores_stray_help_flag() {
        assert_eq!(
            Command::parse(&args(&["status", "--help"])),
            Command::Status
        );
        assert_eq!(Command::parse(&args(&["health", "-h"])), Command::Health);
        assert_eq!(
            Command::parse(&args(&["version", "--help"])),
            Command::Version
        );
    }

    #[test]
    fn unrecognised_word_under_a_family_shows_that_familys_help() {
        // "help" is not special-cased at the subcommand level — it is
        // simply one more unrecognised word under a known family, and
        // (per the fallback fix) routes to that family's own help the
        // same as any other malformed subcommand would.
        assert_eq!(
            Command::parse(&args(&["memory", "help"])),
            Command::Help(HelpTopic::Memory)
        );
        assert_eq!(
            Command::parse(&args(&["memory", "blah"])),
            Command::Help(HelpTopic::Memory)
        );
        // Bare top-level "help" is not a recognised command word at all —
        // it is unrecognised input, exactly like any other typo, that
        // happens to fall back to general help via the same catch-all
        // every unknown command hits.
        assert_eq!(
            Command::parse(&args(&["help"])),
            Command::Help(HelpTopic::General)
        );
        assert_eq!(
            Command::parse(&args(&["frobnicate"])),
            Command::Help(HelpTopic::General)
        );
    }

    #[test]
    fn malformed_limit_falls_back_to_family_help() {
        assert_eq!(
            Command::parse(&args(&["memory", "recent", "not-a-number"])),
            Command::Help(HelpTopic::Memory)
        );
        assert_eq!(
            Command::parse(&args(&["telemetry", "recent", "not-a-number"])),
            Command::Help(HelpTopic::Telemetry)
        );
        assert_eq!(
            Command::parse(&args(&["memory", "nodes", "not-a-number"])),
            Command::Help(HelpTopic::Memory)
        );
        assert_eq!(
            Command::parse(&args(&[
                "memory",
                "nodes",
                "--kind",
                "process",
                "not-a-number"
            ])),
            Command::Help(HelpTopic::Memory)
        );
    }

    #[test]
    fn unrecognised_form_of_a_known_family_falls_back_to_that_familys_help() {
        // Previously these all fell through to the generic top-level help,
        // even though the first word names a known family.
        assert_eq!(
            Command::parse(&args(&["memory", "nodes", "--kind"])),
            Command::Help(HelpTopic::Memory)
        );
        assert_eq!(
            Command::parse(&args(&["vulnerability"])),
            Command::Help(HelpTopic::Vulnerability)
        );
        assert_eq!(
            Command::parse(&args(&["guard", "extra-garbage"])),
            Command::Help(HelpTopic::Guard)
        );
    }

    #[test]
    fn incomplete_actions_propose_or_evaluate_does_not_misparse_as_an_id_lookup() {
        // "propose"/"evaluate" typed without their required arguments used
        // to silently match the generic `actions <ID>` pattern instead of
        // signalling a missing-arguments error.
        assert_eq!(
            Command::parse(&args(&["actions", "propose"])),
            Command::Help(HelpTopic::Actions)
        );
        assert_eq!(
            Command::parse(&args(&["actions", "evaluate"])),
            Command::Help(HelpTopic::Actions)
        );
        // A real proposal ID is unaffected.
        assert_eq!(
            Command::parse(&args(&["actions", "act_00000001"])),
            Command::Action("act_00000001".into())
        );
    }

    #[test]
    fn incomplete_vulnerability_subcommands_do_not_misparse_as_an_id_lookup() {
        // Same class of bug as the actions propose/evaluate one above, for the
        // same reason: "manual"/"authorise"/"update"/"ignore"/"delete" typed
        // without their required ID argument used to silently match the
        // generic `vulnerability <ID>` pattern instead of showing help.
        for subcommand in ["manual", "authorise", "update", "ignore", "delete"] {
            assert_eq!(
                Command::parse(&args(&["vulnerability", subcommand])),
                Command::Help(HelpTopic::Vulnerability),
                "vulnerability {subcommand} (missing ID) should show help, not look up an exposure literally named {subcommand:?}"
            );
        }
        // A real exposure ID is unaffected.
        assert_eq!(
            Command::parse(&args(&["vulnerability", "vuln:cve-2099-00001:curl:amd64"])),
            Command::Vulnerability("vuln:cve-2099-00001:curl:amd64".into())
        );
    }
}
