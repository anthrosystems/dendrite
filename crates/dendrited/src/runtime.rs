use crate::{DaemonCore, DaemonError, TelemetryManager, http::handle_http_stream};
use dendrite_protocol::{
    DaemonStatusDto, HealthDto, IpcRequest, IpcResponse, MemoryPathDto, ObservationKind,
    TelemetryEventDto,
};
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

pub struct RuntimeConfig {
    pub memory_path: PathBuf,
    pub incident_path: PathBuf,
    pub guard_path: PathBuf,
    pub socket_path: PathBuf,
    pub http_addr: SocketAddr,
    pub watch_paths: Vec<PathBuf>,
    pub fanotify_enabled: bool,
    pub telemetry_interval: Duration,
}

impl RuntimeConfig {
    pub fn development_defaults() -> Self {
        Self {
            memory_path: PathBuf::from("data/memory.sqlite3"),
            incident_path: PathBuf::from("data/incidents.sqlite3"),
            guard_path: PathBuf::from("data/guard.sqlite3"),
            socket_path: PathBuf::from("/tmp/dendrited.sock"),
            http_addr: "127.0.0.1:8766"
                .parse()
                .expect("default HTTP address must be valid"),
            watch_paths: Vec::new(),
            fanotify_enabled: false,
            telemetry_interval: Duration::from_secs(2),
        }
    }
}

pub struct DaemonRuntime {
    core: DaemonCore,
    listener: UnixListener,
    http_listener: TcpListener,
    telemetry: TelemetryManager,
    socket_path: PathBuf,
    telemetry_interval: Duration,
}

impl DaemonRuntime {
    pub fn open(config: RuntimeConfig) -> Result<Self, RuntimeError> {
        ensure_parent(&config.memory_path)?;
        ensure_parent(&config.incident_path)?;
        ensure_parent(&config.guard_path)?;
        ensure_parent(&config.socket_path)?;
        if config.socket_path.exists() {
            if UnixStream::connect(&config.socket_path).is_ok() {
                return Err(RuntimeError::AlreadyRunning(config.socket_path));
            }
            fs::remove_file(&config.socket_path)?;
        }
        let listener = UnixListener::bind(&config.socket_path)?;
        fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let http_listener = TcpListener::bind(config.http_addr)?;
        http_listener.set_nonblocking(true)?;
        let memory = config.memory_path.to_string_lossy();
        let incidents = config.incident_path.to_string_lossy();
        let guard = config.guard_path.to_string_lossy();
        let mut core = DaemonCore::open_with_stores(&memory, &incidents, &guard)?;
        let telemetry = TelemetryManager::new(config.watch_paths, config.fanotify_enabled);
        core.set_telemetry_sources(telemetry.status());
        Ok(Self {
            core,
            listener,
            http_listener,
            telemetry,
            socket_path: config.socket_path,
            telemetry_interval: config.telemetry_interval,
        })
    }

    pub fn run(mut self) -> Result<(), RuntimeError> {
        let mut next_telemetry = Instant::now();
        loop {
            let mut handled_work = false;
            if Instant::now() >= next_telemetry {
                for collected in self.telemetry.collect() {
                    match self.core.ingest_observation(&collected.observation) {
                        Ok(outcome) => {
                            self.core.record_telemetry_event(TelemetryEventDto {
                                id: collected.observation.id.0.clone(),
                                source: collected.source.as_str().into(),
                                event: collected.event,
                                observation_kind: observation_kind_name(collected.observation.kind)
                                    .into(),
                                process_id: collected.process_id,
                                source_object: collected.observation.source.id.0.clone(),
                                target_object: collected
                                    .observation
                                    .target
                                    .as_ref()
                                    .map(|target| target.id.0.clone()),
                                target_label: collected
                                    .observation
                                    .target
                                    .as_ref()
                                    .map(|target| target.label.clone()),
                                observed_at: collected.observation.observed_at,
                                incident_ids: outcome
                                    .incidents
                                    .into_iter()
                                    .map(|incident| incident.0)
                                    .collect(),
                            });
                        }
                        Err(error) => {
                            eprintln!("telemetry ingestion failed: {error:?}");
                        }
                    }
                }
                next_telemetry = Instant::now() + self.telemetry_interval;
                handled_work = true;
            }

            match self.listener.accept() {
                Ok((stream, _)) => {
                    self.handle_stream(stream)?;
                    handled_work = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(RuntimeError::Io(error)),
            }

            match self.http_listener.accept() {
                Ok((stream, _)) => {
                    handle_http_stream(&mut self.core, &self.socket_path, stream)?;
                    handled_work = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(RuntimeError::Io(error)),
            }

            if !handled_work {
                thread::sleep(Duration::from_millis(50));
            }
        }
    }

    fn handle_stream(&mut self, mut stream: UnixStream) -> Result<(), RuntimeError> {
        let mut line = String::new();
        BufReader::new(stream.try_clone()?).read_line(&mut line)?;
        let request = match serde_json::from_str::<IpcRequest>(line.trim()) {
            Ok(request) => request,
            Err(error) => {
                write_response(
                    &mut stream,
                    &IpcResponse::Error {
                        message: format!("invalid request: {error}"),
                    },
                )?;
                return Ok(());
            }
        };
        let response = self.handle_request(request);
        write_response(&mut stream, &response)?;
        Ok(())
    }

    fn handle_request(&mut self, request: IpcRequest) -> IpcResponse {
        match self.try_handle_request(request) {
            Ok(response) => response,
            Err(error) => IpcResponse::Error {
                message: format!("{error:?}"),
            },
        }
    }

    fn try_handle_request(&mut self, request: IpcRequest) -> Result<IpcResponse, DaemonError> {
        match request {
            IpcRequest::Status => Ok(IpcResponse::Status(DaemonStatusDto {
                version: env!("CARGO_PKG_VERSION").into(),
                observations_ingested: self.core.observations_ingested(),
                incidents_open: self.core.incident_count()?,
                memory_nodes_known: self.core.memory().node_count()?,
                socket_path: self.socket_path.to_string_lossy().into_owned(),
            })),
            IpcRequest::Incidents => Ok(IpcResponse::Incidents {
                incidents: self.core.list_incidents()?,
            }),
            IpcRequest::Incident { id } => match self.core.incident_detail(&id)? {
                Some(incident) => Ok(IpcResponse::Incident { incident }),
                None => Ok(IpcResponse::Error {
                    message: format!("incident {id} was not found"),
                }),
            },
            IpcRequest::MemoryNodes { kind } => Ok(IpcResponse::MemoryNodes {
                nodes: self.core.memory_nodes(kind.as_deref())?,
            }),
            IpcRequest::MemoryRecent { limit } => Ok(IpcResponse::MemoryRecent {
                nodes: self.core.memory_recent(limit)?,
            }),
            IpcRequest::MemoryNeighbours { node_id } => Ok(IpcResponse::MemoryNeighbours {
                neighbours: self.core.memory_neighbours(&node_id)?,
                node_id,
            }),
            IpcRequest::MemoryPath { source, target } => {
                let path = self.core.memory_path(&source, &target)?.map(|path| {
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
                Ok(IpcResponse::MemoryPath { path })
            }

            IpcRequest::Actions => Ok(IpcResponse::Actions {
                actions: self.core.list_actions()?,
            }),
            IpcRequest::Action { id } => match self.core.action_detail(&id)? {
                Some(action) => Ok(IpcResponse::Action { action }),
                None => Ok(IpcResponse::Error {
                    message: format!("action proposal {id} was not found"),
                }),
            },
            IpcRequest::CreateAction {
                incident_id,
                action,
                target,
            } => {
                let detail = self
                    .core
                    .create_action(&incident_id, &action, &target, unix_now());
                match detail {
                    Ok(action) => Ok(IpcResponse::Action { action }),
                    Err(error) => Err(error),
                }
            }
            IpcRequest::EvaluateAction { id } => {
                let action = self.core.evaluate_action(&id, unix_now())?;
                Ok(IpcResponse::Action { action })
            }
            IpcRequest::GuardStatus => Ok(IpcResponse::GuardStatus(self.core.guard_status()?)),
            IpcRequest::GuardFindings => Ok(IpcResponse::GuardFindings {
                findings: self.core.guard_findings()?,
            }),
            IpcRequest::TelemetryRecent { limit } => Ok(IpcResponse::TelemetryRecent {
                events: self.core.telemetry_recent(limit),
            }),
            IpcRequest::TelemetryStatus => {
                Ok(IpcResponse::TelemetryStatus(self.core.telemetry_status()))
            }

            IpcRequest::DebugGuardState { state } => {
                #[cfg(debug_assertions)]
                {
                    Ok(IpcResponse::GuardStatus(
                        self.core.debug_set_guard_state(&state, unix_now())?,
                    ))
                }

                #[cfg(not(debug_assertions))]
                {
                    let _ = state;
                    Ok(IpcResponse::Error {
                        message: "debug commands are disabled in release builds".into(),
                    })
                }
            }
            IpcRequest::DebugGuardFinding {
                target,
                severity,
                description,
            } => {
                #[cfg(debug_assertions)]
                {
                    Ok(IpcResponse::GuardFindings {
                        findings: self.core.debug_record_guard_finding(
                            &target,
                            &severity,
                            &description,
                            unix_now(),
                        )?,
                    })
                }

                #[cfg(not(debug_assertions))]
                {
                    let _ = (target, severity, description);
                    Ok(IpcResponse::Error {
                        message: "debug commands are disabled in release builds".into(),
                    })
                }
            }
            IpcRequest::DebugSeedIncident { label } => {
                #[cfg(debug_assertions)]
                {
                    let incident = self
                        .core
                        .debug_seed_incident(label.as_deref(), unix_now())?;
                    Ok(IpcResponse::Incident { incident })
                }

                #[cfg(not(debug_assertions))]
                {
                    let _ = label;
                    Ok(IpcResponse::Error {
                        message: "debug commands are disabled in release builds".into(),
                    })
                }
            }
            IpcRequest::Health => Ok(IpcResponse::Health(HealthDto {
                daemon: "ok".into(),
                memory: if self.core.memory().ping().is_ok() {
                    "ok".into()
                } else {
                    "error".into()
                },
                guard: self.core.guard_status()?.trust_state,
            })),
        }
    }
}

impl Drop for DaemonRuntime {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket_path);
    }
}

#[derive(Debug)]
pub enum RuntimeError {
    Io(io::Error),
    AlreadyRunning(PathBuf),
    Json(serde_json::Error),
    Daemon(DaemonError),
}
impl From<io::Error> for RuntimeError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<serde_json::Error> for RuntimeError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}
impl From<DaemonError> for RuntimeError {
    fn from(error: DaemonError) -> Self {
        Self::Daemon(error)
    }
}

fn ensure_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn write_response(stream: &mut UnixStream, response: &IpcResponse) -> Result<(), RuntimeError> {
    serde_json::to_writer(&mut *stream, response)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn observation_kind_name(kind: ObservationKind) -> &'static str {
    match kind {
        ObservationKind::ProcessStarted => "process_started",
        ObservationKind::FileExecuted => "file_executed",
        ObservationKind::FileRead => "file_read",
        ObservationKind::FileWritten => "file_written",
        ObservationKind::NetworkConnection => "network_connection",
        ObservationKind::ServiceInteraction => "service_interaction",
        ObservationKind::Associated => "associated",
    }
}
