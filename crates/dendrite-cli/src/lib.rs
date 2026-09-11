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
    TelemetryStatus,
    TelemetryRecent {
        limit: usize,
    },
    DebugSeedIncident {
        label: Option<String>,
    },
    DebugGuardState(String),
    DebugGuardFinding {
        target: String,
        severity: String,
        description: String,
    },
    Health,
    Version,
    Help,
}

impl Command {
    pub fn parse(arguments: &[String]) -> Self {
        match arguments {
            [] => Self::Help,
            [command] if command == "help" || command == "--help" || command == "-h" => Self::Help,
            [command] if command == "status" => Self::Status,
            [command] if command == "incidents" => Self::Incidents,
            [command, id] if command == "incident" || command == "incidents" => {
                Self::Incident(id.clone())
            }
            [command, subcommand] if command == "memory" && subcommand == "nodes" => {
                Self::MemoryNodes { kind: None }
            }
            [command, subcommand, flag, kind]
                if command == "memory" && subcommand == "nodes" && flag == "--kind" =>
            {
                Self::MemoryNodes {
                    kind: Some(kind.clone()),
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
                    Err(_) => Self::Help,
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
            [command, id] if command == "action" || command == "actions" => {
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
            [command] if command == "telemetry" => Self::TelemetryStatus,
            [command, subcommand] if command == "telemetry" && subcommand == "recent" => {
                Self::TelemetryRecent { limit: 50 }
            }
            [command, subcommand, limit] if command == "telemetry" && subcommand == "recent" => {
                match limit.parse::<usize>() {
                    Ok(limit) => Self::TelemetryRecent { limit },
                    Err(_) => Self::Help,
                }
            }
            [command, subcommand] if command == "debug" && subcommand == "seed-incident" => {
                Self::DebugSeedIncident { label: None }
            }
            [command, subcommand, label] if command == "debug" && subcommand == "seed-incident" => {
                Self::DebugSeedIncident {
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
            [command] if command == "version" || command == "--version" || command == "-V" => {
                Self::Version
            }
            _ => Self::Help,
        }
    }

    fn request(&self) -> Option<IpcRequest> {
        match self {
            Self::Status => Some(IpcRequest::Status),
            Self::Incidents => Some(IpcRequest::Incidents),
            Self::Incident(id) => Some(IpcRequest::Incident { id: id.clone() }),
            Self::MemoryNodes { kind } => Some(IpcRequest::MemoryNodes { kind: kind.clone() }),
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
            Self::TelemetryStatus => Some(IpcRequest::TelemetryStatus),
            Self::TelemetryRecent { limit } => Some(IpcRequest::TelemetryRecent { limit: *limit }),
            Self::DebugSeedIncident { label } => Some(IpcRequest::DebugSeedIncident {
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
            Self::Health => Some(IpcRequest::Health),
            Self::Version | Self::Help => None,
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
        Command::Help => Ok(help()),
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
            "dendrited {}\nobservations: {}\nopen incidents: {}\nmemory nodes: {}\nsocket: {}",
            status.version,
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
        IpcResponse::TelemetryStatus(status) => status
            .sources
            .iter()
            .map(|source| {
                format!(
                    "{:<20} {:<10} {}",
                    source.source, source.status, source.detail
                )
            })
            .chain(std::iter::once(format!(
                "recent events: {}",
                status.recent_events
            )))
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
        IpcResponse::Health(health) => format!(
            "daemon: {}\nmemory: {}\nguard: {}",
            health.daemon, health.memory, health.guard
        ),
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
        action.guard_requirement,
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

fn help() -> String {
    format!(
        "Dendrite {}\n\nUsage:\n  dendrite <COMMAND>\n\nCommands:\n  status                                      Show daemon status\n  incidents                                   List incidents\n  incidents <ID>                              Show incident details\n  memory nodes                                List known Memory Graph nodes\n  memory nodes --kind <KIND>                  Filter nodes by kind\n  memory recent [LIMIT]                       Show recently seen nodes (default: {})\n  memory neighbours <NODE>                    List neighbouring node IDs\n  memory path <SOURCE> <TARGET>               Find a graph path\n  actions                                     List action proposals\n  actions <ID>                                Show proposal, MAGI and transaction details\n  actions propose <INCIDENT> <ACTION> <TARGET> Create an action proposal\n  actions evaluate <ID>                       Evaluate and run a safe proposal\n  health                                      Show subsystem health\n  version                                     Show CLI version\n  help                                        Show this help\n\nBatch 3 executable actions:\n  observe, warn\n\nPrivileged actions are represented but policy-denied until Guard integration.\n\nNode kinds:\n  process, file, user, host, network_endpoint, service, container, incident, threat\n\nOptions:\n  -h, --help                                  Show this help\n  -V, --version                               Show CLI version",
        env!("CARGO_PKG_VERSION"),
        DEFAULT_RECENT_LIMIT
    )
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
                kind: Some("process".into())
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
    fn parses_debug_seed_incident() {
        assert_eq!(
            Command::parse(&args(&["debug", "seed-incident", "ui-test"])),
            Command::DebugSeedIncident {
                label: Some("ui-test".into())
            }
        );
    }
}
