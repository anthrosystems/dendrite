use crate::{
    DaemonCore, DaemonError, TelemetryManager, VulnerabilityError, VulnerabilityService,
    http::handle_http_stream,
    live::LiveBroadcaster,
    telemetry::{CollectedObservation, TelemetryScope},
};
use dendrite_memory::storage::MemoryStore;
use dendrite_protocol::{
    Confidence, DaemonStatusDto, EntityKind, IntegritySeverity, IpcRequest, IpcResponse,
    MemoryPathDto, ObjectDescriptor, ObjectId, Observation, ObservationId, ObservationKind,
    Severity, TelemetryEventDto, TelemetryPipelineDto, TelemetryPipelineLaneDto, TrustState,
    VulnerabilityRemediationDto,
};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::flag;
use std::ffi::CString;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
};
use std::thread;
use std::time::{Duration, Instant};

const PRIORITY_QUEUE_CAPACITY: usize = 8_192;
const ROUTINE_QUEUE_CAPACITY: usize = 57_344;
const INGESTION_QUEUE_CAPACITY: usize = PRIORITY_QUEUE_CAPACITY + ROUTINE_QUEUE_CAPACITY;
const COMPLETED_QUEUE_CAPACITY: usize = 2_048;
const MAX_COMPLETIONS_PER_TICK: usize = 512;
const MAX_CONTROL_CLIENTS_PER_TICK: usize = 32;

pub struct RuntimeConfig {
    pub self_path: PathBuf,
    pub stm_path: PathBuf,
    pub ltm_path: PathBuf,
    pub incident_path: PathBuf,
    pub guard_path: PathBuf,
    pub cve_snapshot_path: PathBuf,
    pub socket_path: PathBuf,
    pub socket_mode: u32,
    pub socket_group: Option<String>,
    pub http_addr: SocketAddr,
    /// Unix socket for the separate `dendrite-magi` process (see
    /// `docs/CONFIGURATION.md`). Defaults to
    /// `crate::DEFAULT_MAGI_SOCKET_PATH` — this field exists mainly so
    /// `DENDRITE_MAGI_SOCKET` has somewhere to land before
    /// `DaemonRuntime::open` wires it into `DaemonCore`.
    pub magi_socket_path: PathBuf,
    pub watch_mounts: Vec<PathBuf>,
    pub watch_include_paths: Vec<PathBuf>,
    pub watch_exclude_paths: Vec<PathBuf>,
    pub fanotify_enabled: bool,
    pub ebpf_enabled: bool,
    pub ebpf_object: PathBuf,
    pub telemetry_interval: Duration,
}

impl RuntimeConfig {
    pub fn development_defaults() -> Self {
        Self {
            self_path: PathBuf::from("data/self.sqlite3"),
            stm_path: PathBuf::from("data/stm.sqlite3"),
            ltm_path: PathBuf::from("data/ltm.sqlite3"),
            incident_path: PathBuf::from("data/incidents.sqlite3"),
            guard_path: PathBuf::from("data/guard.sqlite3"),
            cve_snapshot_path: PathBuf::from("knowledge/cve-snapshot.json"),
            socket_path: PathBuf::from("/tmp/dendrited.sock"),
            socket_mode: 0o660,
            socket_group: None,
            http_addr: "127.0.0.1:8766"
                .parse()
                .expect("default HTTP address must be valid"),
            magi_socket_path: PathBuf::from(crate::DEFAULT_MAGI_SOCKET_PATH),
            watch_mounts: Vec::new(),
            watch_include_paths: Vec::new(),
            watch_exclude_paths: Vec::new(),
            // Opt-out, not opt-in — see the comment on DENDRITE_FANOTIFY parsing in main.rs.
            fanotify_enabled: true,
            ebpf_enabled: true,
            ebpf_object: PathBuf::from(
                "ebpf/dendrite-ebpf/target/bpfel-unknown-none/release/dendrite-ebpf",
            ),
            telemetry_interval: Duration::from_secs(5),
        }
    }
}

struct IngestionJob {
    collected: CollectedObservation,
    scope: TelemetryScope,
    queued_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IngestionLane {
    Priority,
    Routine,
}

fn ingestion_lane(job: &IngestionJob) -> IngestionLane {
    use dendrite_protocol::{EntityKind, Severity};

    let observation = &job.collected.observation;
    let high_severity = matches!(observation.severity, Severity::High | Severity::Critical);
    let threat_related = observation.source.kind == EntityKind::Threat
        || observation
            .target
            .as_ref()
            .is_some_and(|target| matches!(target.kind, EntityKind::Threat | EntityKind::Incident));

    if high_severity || threat_related {
        IngestionLane::Priority
    } else {
        IngestionLane::Routine
    }
}

#[derive(Default)]
struct PipelineLaneMetrics {
    queue_depth: AtomicUsize,
    peak_queue_depth: AtomicUsize,
    events_received: AtomicU64,
    events_processed: AtomicU64,
    events_dropped: AtomicU64,
    last_queue_wait_ms: AtomicU64,
    max_queue_wait_ms: AtomicU64,
    last_processing_ms: AtomicU64,
    max_processing_ms: AtomicU64,
}

impl PipelineLaneMetrics {
    fn snapshot(&self, queue_capacity: usize) -> TelemetryPipelineLaneDto {
        TelemetryPipelineLaneDto {
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
            queue_capacity,
            peak_queue_depth: self.peak_queue_depth.load(Ordering::Relaxed),
            events_received: self.events_received.load(Ordering::Relaxed),
            events_processed: self.events_processed.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
            last_queue_wait_ms: self.last_queue_wait_ms.load(Ordering::Relaxed),
            max_queue_wait_ms: self.max_queue_wait_ms.load(Ordering::Relaxed),
            last_processing_ms: self.last_processing_ms.load(Ordering::Relaxed),
            max_processing_ms: self.max_processing_ms.load(Ordering::Relaxed),
        }
    }

    fn queued(&self) {
        let depth = self.queue_depth.fetch_add(1, Ordering::Relaxed) + 1;
        update_max(&self.peak_queue_depth, depth);
    }

    fn dequeued(&self) {
        decrement_nonzero(&self.queue_depth);
    }
}

#[derive(Default)]
struct PipelineMetrics {
    queue_depth: AtomicUsize,
    peak_queue_depth: AtomicUsize,
    events_received: AtomicU64,
    events_processed: AtomicU64,
    events_dropped: AtomicU64,
    security_observations_ingested: AtomicU64,
    last_queue_wait_ms: AtomicU64,
    max_queue_wait_ms: AtomicU64,
    last_processing_ms: AtomicU64,
    max_processing_ms: AtomicU64,
    priority: PipelineLaneMetrics,
    routine: PipelineLaneMetrics,
}

impl PipelineMetrics {
    fn lane(&self, lane: IngestionLane) -> &PipelineLaneMetrics {
        match lane {
            IngestionLane::Priority => &self.priority,
            IngestionLane::Routine => &self.routine,
        }
    }

    fn snapshot(&self) -> TelemetryPipelineDto {
        TelemetryPipelineDto {
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
            queue_capacity: INGESTION_QUEUE_CAPACITY,
            peak_queue_depth: self.peak_queue_depth.load(Ordering::Relaxed),
            events_received: self.events_received.load(Ordering::Relaxed),
            events_processed: self.events_processed.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
            security_observations_ingested: self
                .security_observations_ingested
                .load(Ordering::Relaxed),
            last_queue_wait_ms: self.last_queue_wait_ms.load(Ordering::Relaxed),
            max_queue_wait_ms: self.max_queue_wait_ms.load(Ordering::Relaxed),
            last_processing_ms: self.last_processing_ms.load(Ordering::Relaxed),
            max_processing_ms: self.max_processing_ms.load(Ordering::Relaxed),
            priority: self.priority.snapshot(PRIORITY_QUEUE_CAPACITY),
            routine: self.routine.snapshot(ROUTINE_QUEUE_CAPACITY),
            scheduler_priority_weight: 4,
            scheduler_routine_weight: 1,
        }
    }

    fn received(&self, lane: IngestionLane) {
        self.events_received.fetch_add(1, Ordering::Relaxed);
        self.lane(lane)
            .events_received
            .fetch_add(1, Ordering::Relaxed);
    }

    fn queued(&self, lane: IngestionLane) {
        let depth = self.queue_depth.fetch_add(1, Ordering::Relaxed) + 1;
        update_max(&self.peak_queue_depth, depth);
        self.lane(lane).queued();
    }

    fn dequeued(&self, lane: IngestionLane) {
        decrement_nonzero(&self.queue_depth);
        self.lane(lane).dequeued();
    }

    fn dropped(&self, lane: IngestionLane) {
        self.events_dropped.fetch_add(1, Ordering::Relaxed);
        self.lane(lane)
            .events_dropped
            .fetch_add(1, Ordering::Relaxed);
    }

    fn queue_wait(&self, lane: IngestionLane, queue_wait_ms: u64) {
        self.last_queue_wait_ms
            .store(queue_wait_ms, Ordering::Relaxed);
        update_max_u64(&self.max_queue_wait_ms, queue_wait_ms);
        let metrics = self.lane(lane);
        metrics
            .last_queue_wait_ms
            .store(queue_wait_ms, Ordering::Relaxed);
        update_max_u64(&metrics.max_queue_wait_ms, queue_wait_ms);
    }

    fn processed(&self, lane: IngestionLane, processing_ms: u64) {
        self.events_processed.fetch_add(1, Ordering::Relaxed);
        self.last_processing_ms
            .store(processing_ms, Ordering::Relaxed);
        update_max_u64(&self.max_processing_ms, processing_ms);
        let metrics = self.lane(lane);
        metrics.events_processed.fetch_add(1, Ordering::Relaxed);
        metrics
            .last_processing_ms
            .store(processing_ms, Ordering::Relaxed);
        update_max_u64(&metrics.max_processing_ms, processing_ms);
    }
}

fn decrement_nonzero(target: &AtomicUsize) {
    let mut current = target.load(Ordering::Relaxed);
    while current > 0 {
        match target.compare_exchange_weak(
            current,
            current - 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
}

fn update_max(target: &AtomicUsize, value: usize) {
    let mut current = target.load(Ordering::Relaxed);
    while value > current {
        match target.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
}

fn update_max_u64(target: &AtomicU64, value: u64) {
    let mut current = target.load(Ordering::Relaxed);
    while value > current {
        match target.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
}

pub struct DaemonRuntime {
    core: DaemonCore,
    listener: UnixListener,
    http_listener: TcpListener,
    telemetry: TelemetryManager,
    vulnerability: VulnerabilityService,
    socket_path: PathBuf,
    telemetry_interval: Duration,
    priority_tx: SyncSender<IngestionJob>,
    routine_tx: SyncSender<IngestionJob>,
    completed_rx: Receiver<TelemetryEventDto>,
    pipeline: Arc<PipelineMetrics>,
    live: LiveBroadcaster,
    _socket_guard: SocketPathGuard,
}

impl DaemonRuntime {
    pub fn open(config: RuntimeConfig) -> Result<Self, RuntimeError> {
        ensure_parent(&config.self_path)?;
        ensure_parent(&config.stm_path)?;
        ensure_parent(&config.ltm_path)?;
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
        let socket_guard = SocketPathGuard::new(config.socket_path.clone());
        fs::set_permissions(
            &config.socket_path,
            fs::Permissions::from_mode(config.socket_mode),
        )?;
        if let Some(group) = config.socket_group.as_deref() {
            set_socket_group(&config.socket_path, group)?;
        }
        listener.set_nonblocking(true)?;

        let http_listener = TcpListener::bind(config.http_addr)?;
        http_listener.set_nonblocking(true)?;
        let live = LiveBroadcaster::new();

        let self_store = config.self_path.to_string_lossy().into_owned();
        let stm = config.stm_path.to_string_lossy().into_owned();
        let ltm = config.ltm_path.to_string_lossy().into_owned();
        let incidents = config.incident_path.to_string_lossy().into_owned();
        let guard = config.guard_path.to_string_lossy().into_owned();
        let mut core =
            DaemonCore::open_with_tiered_stores(&self_store, &stm, &ltm, &incidents, &guard)?;
        core.set_magi_socket_path(config.magi_socket_path.clone());
        let mut vulnerability = VulnerabilityService::open(&incidents)?;
        let now = unix_now();
        if config.cve_snapshot_path.exists()
            && let Err(error) = vulnerability.import_bundle_path(&config.cve_snapshot_path, now)
        {
            eprintln!("bundled CVE knowledge import failed: {error:?}");
        }
        if let Err(error) = vulnerability.refresh_inventory(now) {
            eprintln!("initial package inventory failed: {error:?}");
        }
        if let Ok(exposures) = vulnerability.assess(now) {
            for exposure in exposures {
                if let Err(error) = core.record_vulnerability_exposure(&exposure, now) {
                    eprintln!("failed to project vulnerability into Memory Graph: {error:?}");
                }
            }
        }
        let telemetry = TelemetryManager::new(
            config.watch_mounts,
            config.watch_include_paths,
            config.watch_exclude_paths,
            config.fanotify_enabled,
            config.ebpf_enabled,
            config.ebpf_object,
            config.http_addr,
        );
        core.set_telemetry_sources(telemetry.status());

        let pipeline = Arc::new(PipelineMetrics::default());
        let (priority_tx, priority_rx) = mpsc::sync_channel(PRIORITY_QUEUE_CAPACITY);
        let (routine_tx, routine_rx) = mpsc::sync_channel(ROUTINE_QUEUE_CAPACITY);
        let (completed_tx, completed_rx) = mpsc::sync_channel(COMPLETED_QUEUE_CAPACITY);
        let priority_memory = core.memory().fork_reader().map_err(DaemonError::Database)?;
        let routine_memory = core.memory().fork_reader().map_err(DaemonError::Database)?;
        let priority_stores = IngestionWorkerStores {
            self_path: self_store.clone(),
            memory: priority_memory,
            incident_path: incidents.clone(),
            guard_path: guard.clone(),
        };
        let routine_stores = IngestionWorkerStores {
            self_path: self_store,
            memory: routine_memory,
            incident_path: incidents,
            guard_path: guard,
        };
        spawn_priority_worker(
            priority_rx,
            completed_tx.clone(),
            Arc::clone(&pipeline),
            live.clone(),
            priority_stores,
        )?;
        spawn_routine_worker(
            routine_rx,
            completed_tx,
            Arc::clone(&pipeline),
            live.clone(),
            routine_stores,
        )?;

        Ok(Self {
            core,
            listener,
            http_listener,
            telemetry,
            vulnerability,
            socket_path: config.socket_path,
            telemetry_interval: config.telemetry_interval,
            priority_tx,
            routine_tx,
            completed_rx,
            pipeline,
            live,
            _socket_guard: socket_guard,
        })
    }

    pub fn run(mut self) -> Result<(), RuntimeError> {
        let shutdown_requested = Arc::new(AtomicBool::new(false));
        flag::register(SIGINT, Arc::clone(&shutdown_requested))?;
        flag::register(SIGTERM, Arc::clone(&shutdown_requested))?;

        let mut next_telemetry = Instant::now();
        let mut next_vulnerability_refresh = Instant::now() + Duration::from_secs(60);
        let mut next_pipeline_push = Instant::now();
        while !shutdown_requested.load(Ordering::Relaxed) {
            let mut handled_work = false;

            if Instant::now() >= next_telemetry {
                self.telemetry.rescan_mounts();
                let collected = self.telemetry.collect();
                for event in collected {
                    let job = IngestionJob {
                        scope: self.telemetry.scope_for(&event),
                        collected: event,
                        queued_at: Instant::now(),
                    };
                    let lane = ingestion_lane(&job);
                    self.pipeline.received(lane);
                    let sender = match lane {
                        IngestionLane::Priority => &self.priority_tx,
                        IngestionLane::Routine => &self.routine_tx,
                    };
                    match sender.try_send(job) {
                        Ok(()) => self.pipeline.queued(lane),
                        Err(TrySendError::Full(job)) => {
                            if lane == IngestionLane::Priority {
                                eprintln!(
                                    "priority telemetry queue saturated; preserving control-plane responsiveness while dropping event {}",
                                    job.collected.observation.id.0
                                );
                            }
                            self.pipeline.dropped(lane);
                        }
                        Err(TrySendError::Disconnected(_)) => {
                            return Err(RuntimeError::WorkerStopped);
                        }
                    }
                }
                next_telemetry = Instant::now() + self.telemetry_interval;
                handled_work = true;
            }

            if Instant::now() >= next_vulnerability_refresh {
                let now = unix_now();
                match self
                    .vulnerability
                    .refresh_inventory(now)
                    .and_then(|_| self.vulnerability.assess(now))
                {
                    Ok(exposures) => {
                        for exposure in exposures {
                            if let Err(error) =
                                self.core.record_vulnerability_exposure(&exposure, now)
                            {
                                eprintln!(
                                    "failed to project vulnerability into Memory Graph: {error:?}"
                                );
                            }
                        }
                    }
                    Err(error) => eprintln!("vulnerability refresh failed: {error:?}"),
                }
                next_vulnerability_refresh = Instant::now() + Duration::from_secs(60);
                handled_work = true;
            }

            for _ in 0..MAX_COMPLETIONS_PER_TICK {
                match self.completed_rx.try_recv() {
                    Ok(event) => {
                        self.core.record_telemetry_event(event);
                        handled_work = true;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => return Err(RuntimeError::WorkerStopped),
                }
            }

            self.refresh_pipeline_snapshot();

            for _ in 0..MAX_CONTROL_CLIENTS_PER_TICK {
                match self.listener.accept() {
                    Ok((stream, _)) => {
                        if let Err(error) = self.handle_stream(stream)
                            && !is_client_disconnect(&error)
                        {
                            eprintln!("IPC client request failed: {error:?}");
                        }
                        handled_work = true;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(RuntimeError::Io(error)),
                }
            }

            for _ in 0..MAX_CONTROL_CLIENTS_PER_TICK {
                match self.http_listener.accept() {
                    Ok((stream, _)) => {
                        if let Err(error) = handle_http_stream(
                            &mut self.core,
                            &mut self.vulnerability,
                            &self.socket_path,
                            &self.live,
                            stream,
                        ) && !is_peer_disconnect_kind(error.kind())
                        {
                            eprintln!("HTTP client request failed: {error}");
                        }
                        handled_work = true;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(RuntimeError::Io(error)),
                }
            }

            if Instant::now() >= next_pipeline_push {
                self.live.publish("pipeline", &self.pipeline.snapshot());
                next_pipeline_push = Instant::now() + Duration::from_secs(1);
            }

            if !handled_work {
                thread::sleep(Duration::from_millis(5));
            }
        }

        eprintln!("dendrited shutting down");
        Ok(())
    }

    fn refresh_pipeline_snapshot(&mut self) {
        let snapshot = self.pipeline.snapshot();
        self.core
            .set_observations_ingested(snapshot.security_observations_ingested);
        self.core.set_telemetry_pipeline(snapshot);
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
        let live_kind = live_kind_for_ipc_request(&request);
        let response = self.handle_request(request);
        write_response(&mut stream, &response)?;
        if let Some(kind) = live_kind {
            self.live
                .publish(kind, &serde_json::json!({ "source": "ipc" }));
        }
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
                instance_id: self.core.instance_id().into(),
                signing_key: self.core.signing_key_status(),
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

            IpcRequest::VulnerabilityStatus => Ok(IpcResponse::VulnerabilityStatus(
                self.vulnerability
                    .knowledge_status()
                    .map_err(DaemonError::from)?,
            )),
            IpcRequest::VulnerabilityInventory => Ok(IpcResponse::VulnerabilityInventory {
                packages: self.vulnerability.inventory().map_err(DaemonError::from)?,
            }),
            IpcRequest::Vulnerabilities { include_resolved } => Ok(IpcResponse::Vulnerabilities {
                exposures: self
                    .vulnerability
                    .exposures(include_resolved)
                    .map_err(DaemonError::from)?,
            }),
            IpcRequest::Vulnerability { id } => match self
                .vulnerability
                .exposure(&id)
                .map_err(DaemonError::from)?
            {
                Some(exposure) => Ok(IpcResponse::Vulnerability { exposure }),
                None => Ok(IpcResponse::Error {
                    message: format!("vulnerability exposure {id} was not found"),
                }),
            },
            IpcRequest::VulnerabilityRefresh => {
                let now = unix_now();
                self.vulnerability
                    .refresh_inventory(now)
                    .map_err(DaemonError::from)?;
                let exposures = self.vulnerability.assess(now).map_err(DaemonError::from)?;
                for exposure in &exposures {
                    self.core.record_vulnerability_exposure(exposure, now)?;
                }
                Ok(IpcResponse::Vulnerabilities { exposures })
            }
            IpcRequest::VulnerabilityImport { path } => {
                let now = unix_now();
                let imported = self
                    .vulnerability
                    .import_bundle_path(Path::new(&path), now)
                    .map_err(DaemonError::from)?;
                // Newly imported behaviour/CVE knowledge can match chains that
                // already existed before this import; classification is
                // otherwise only computed once, at chain-creation time, so it
                // needs to be re-run here for it to reach existing chains.
                let (_, matched_cve_ids) = self.core.reclassify_all_attack_chains(now)?;
                // A CVE the operator had previously ignored is re-raised if an
                // attack chain/behaviour now matches it — see the CVE
                // lifecycle design (ignore is reversible/re-raisable, unlike delete).
                self.vulnerability
                    .unignore_if_matched(&matched_cve_ids, now)
                    .map_err(DaemonError::from)?;
                let status = self
                    .vulnerability
                    .knowledge_status()
                    .map_err(DaemonError::from)?;
                Ok(IpcResponse::VulnerabilityImport { imported, status })
            }
            IpcRequest::VulnerabilityManual { id } => match self
                .vulnerability
                .mark_manual(&id, unix_now())
                .map_err(DaemonError::from)?
            {
                Some(exposure) => Ok(IpcResponse::Vulnerability { exposure }),
                None => Ok(IpcResponse::Error {
                    message: format!(
                        "vulnerability exposure {id} was not found or already resolved"
                    ),
                }),
            },
            IpcRequest::VulnerabilityAuthorise { id } => match self
                .vulnerability
                .authorise(&id, unix_now())
                .map_err(DaemonError::from)?
            {
                Some(exposure) => Ok(IpcResponse::Vulnerability { exposure }),
                None => Ok(IpcResponse::Error {
                    message: format!(
                        "vulnerability exposure {id} was not found or already resolved"
                    ),
                }),
            },
            IpcRequest::VulnerabilityUpdate { id } => {
                let now = unix_now();
                let Some(exposure) = self
                    .vulnerability
                    .authorise(&id, now)
                    .map_err(DaemonError::from)?
                else {
                    return Ok(IpcResponse::Error {
                        message: format!(
                            "vulnerability exposure {id} was not found or already resolved"
                        ),
                    });
                };
                if exposure.fixed_version.is_none() {
                    return Ok(IpcResponse::Error {
                        message: format!(
                            "vulnerability exposure {id} has no known fixed version; Dendrite will not mutate the package"
                        ),
                    });
                }

                let action = self
                    .core
                    .execute_authorised_vulnerability_update(&exposure, now)?;
                if action.proposal.status == "completed" {
                    let refreshed_at = unix_now();
                    self.vulnerability
                        .refresh_inventory(refreshed_at)
                        .map_err(DaemonError::from)?;
                    let active = self
                        .vulnerability
                        .assess(refreshed_at)
                        .map_err(DaemonError::from)?;
                    for current in &active {
                        self.core
                            .record_vulnerability_exposure(current, refreshed_at)?;
                    }
                } else {
                    self.vulnerability
                        .clear_authorisation(&id, unix_now())
                        .map_err(DaemonError::from)?;
                }
                let current = self
                    .vulnerability
                    .exposure(&id)
                    .map_err(DaemonError::from)?
                    .unwrap_or(exposure);
                Ok(IpcResponse::VulnerabilityRemediation(Box::new(
                    VulnerabilityRemediationDto {
                        exposure: current,
                        action,
                    },
                )))
            }
            IpcRequest::VulnerabilityIgnore { id } => {
                match self.vulnerability.ignore_exposure(&id, unix_now()) {
                    Ok(exposure) => Ok(IpcResponse::Vulnerability { exposure }),
                    Err(error) => Ok(IpcResponse::Error {
                        message: error.to_string(),
                    }),
                }
            }
            IpcRequest::VulnerabilityDelete { id } => {
                let deleted = self
                    .vulnerability
                    .delete_exposure(&id)
                    .map_err(DaemonError::from)?;
                Ok(IpcResponse::VulnerabilityDeleted { deleted })
            }

            IpcRequest::DebugGuardState { state } => {
                #[cfg(debug_assertions)]
                {
                    if TrustState::from_str(&state).is_err() {
                        return Ok(IpcResponse::Error {
                            message: format!(
                                "invalid trust state '{state}': expected one of trusted, degraded, suspected, quarantined, compromised, recovering"
                            ),
                        });
                    }
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
                    if IntegritySeverity::from_str(&severity).is_err() {
                        return Ok(IpcResponse::Error {
                            message: format!(
                                "invalid integrity severity '{severity}': expected one of informational, warning, high, critical"
                            ),
                        });
                    }
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
            IpcRequest::DebugInjectPriority { label } => {
                #[cfg(debug_assertions)]
                {
                    let now = unix_now();
                    let suffix = format!("{now}:{}", uuid::Uuid::new_v4());
                    let label = label.as_deref().unwrap_or("Synthetic priority-lane test");
                    // Severity::Critical alone is enough for ingestion_lane() to route
                    // this to the priority channel — no Threat-kind target needed, but
                    // one is included anyway so it also exercises the same
                    // threat-relatedness check real priority traffic would hit.
                    let source = ObjectDescriptor {
                        id: ObjectId(format!("debug:process:{suffix}")),
                        kind: EntityKind::Process,
                        label: format!("{label} process"),
                    };
                    let target = ObjectDescriptor {
                        id: ObjectId(format!("debug:threat:{suffix}")),
                        kind: EntityKind::Threat,
                        label: format!("{label} threat"),
                    };
                    let observation = Observation {
                        id: ObservationId(format!("debug:priority-inject:{suffix}")),
                        kind: ObservationKind::Associated,
                        source,
                        target: Some(target),
                        observed_at: now,
                        expires_at: None,
                        severity: Severity::Critical,
                        confidence: Confidence::new(100).expect("100 is a valid confidence"),
                    };
                    let collected = CollectedObservation {
                        source: crate::telemetry::TelemetrySource::Fanotify,
                        event: "debug_priority_inject".into(),
                        process_id: None,
                        observation,
                        related_observations: Vec::new(),
                    };
                    let job = IngestionJob {
                        scope: TelemetryScope::Host,
                        collected,
                        queued_at: Instant::now(),
                    };
                    let lane = ingestion_lane(&job);
                    self.pipeline.received(lane);
                    let sender = match lane {
                        IngestionLane::Priority => &self.priority_tx,
                        IngestionLane::Routine => &self.routine_tx,
                    };
                    let queued = match sender.try_send(job) {
                        Ok(()) => {
                            self.pipeline.queued(lane);
                            true
                        }
                        Err(TrySendError::Full(_)) => {
                            self.pipeline.dropped(lane);
                            false
                        }
                        Err(TrySendError::Disconnected(_)) => {
                            return Err(DaemonError::Debug(
                                "priority ingestion worker has stopped".into(),
                            ));
                        }
                    };
                    Ok(IpcResponse::DebugInjectPriority { queued })
                }

                #[cfg(not(debug_assertions))]
                {
                    let _ = label;
                    Ok(IpcResponse::Error {
                        message: "debug commands are disabled in release builds".into(),
                    })
                }
            }
            IpcRequest::Health => Ok(IpcResponse::Health(self.core.health_check()?)),
        }
    }
}

fn live_kind_for_ipc_request(request: &IpcRequest) -> Option<&'static str> {
    match request {
        IpcRequest::CreateAction { .. } | IpcRequest::EvaluateAction { .. } => Some("control"),
        IpcRequest::DebugGuardState { .. } | IpcRequest::DebugGuardFinding { .. } => {
            Some("control")
        }
        IpcRequest::DebugSeedIncident { .. } => Some("incidents"),
        IpcRequest::VulnerabilityRefresh
        | IpcRequest::VulnerabilityImport { .. }
        | IpcRequest::VulnerabilityManual { .. }
        | IpcRequest::VulnerabilityAuthorise { .. }
        | IpcRequest::VulnerabilityUpdate { .. } => Some("vulnerabilities"),
        _ => None,
    }
}

struct IngestionWorkerStores {
    self_path: String,
    memory: MemoryStore,
    incident_path: String,
    guard_path: String,
}

const ROUTINE_BATCH_SIZE: usize = 200;
/// Threat-path search depth used for routine-lane observations, vs. the
/// full depth of 6 that priority observations always get (via
/// `DaemonCore::ingest_observation`'s default). Routine is the overwhelming
/// majority of volume with a near-zero hit rate; capping its search depth
/// is the direct fix for that cost without weakening priority-lane
/// detection at all — see `ingest_observation_with_max_depth`'s doc comment
/// in core.rs for the full reasoning.
const ROUTINE_THREAT_PATH_MAX_DEPTH: usize = 2;

/// Priority telemetry (threat-related or high/critical severity) gets its
/// own dedicated worker thread, fully independent of routine. This is the
/// direct fix for "a routine flood could delay priority processing too" —
/// previously both lanes shared one thread with only turn-order weighting,
/// so a saturated routine lane still occupied the only processing slot
/// priority had. Separate threads mean routine volume can never delay
/// priority throughput, regardless of how saturated routine gets.
fn spawn_priority_worker(
    priority_rx: Receiver<IngestionJob>,
    completed_tx: SyncSender<TelemetryEventDto>,
    pipeline: Arc<PipelineMetrics>,
    live: LiveBroadcaster,
    stores: IngestionWorkerStores,
) -> Result<(), RuntimeError> {
    let _worker = thread::Builder::new()
        .name("dendrite-ingestion-priority".into())
        .spawn(move || {
            let IngestionWorkerStores {
                self_path,
                memory,
                incident_path,
                guard_path,
            } = stores;
            let mut core = match DaemonCore::open_with_shared_memory(
                &self_path,
                memory,
                &incident_path,
                &guard_path,
            ) {
                Ok(core) => core,
                Err(error) => {
                    eprintln!("priority ingestion worker failed to open stores: {error:?}");
                    return;
                }
            };

            while let Ok(job) = priority_rx.recv() {
                let lane = IngestionLane::Priority;
                pipeline.dequeued(lane);
                pipeline.queue_wait(lane, duration_ms(job.queued_at.elapsed()));

                let started = Instant::now();
                let event = process_job(&mut core, &pipeline, job, 6);
                pipeline.processed(lane, duration_ms(started.elapsed()));

                live.publish("telemetry", &event);
                if !event.incident_ids.is_empty() {
                    live.publish("incidents", &event.incident_ids);
                }
                match completed_tx.try_send(event) {
                    Ok(()) | Err(TrySendError::Full(_)) => {}
                    Err(TrySendError::Disconnected(_)) => break,
                }
            }
        })?;
    Ok(())
}

/// Routine telemetry (the vast majority of raw volume — file/process/network
/// noise) keeps its own worker and queue. In tiered operation `MemoryStore`
/// routes each physical mutation through the dedicated STM or LTM writer
/// actor, so routine and priority workers can process concurrently without
/// opening competing SQLite writers for either database file.
fn spawn_routine_worker(
    routine_rx: Receiver<IngestionJob>,
    completed_tx: SyncSender<TelemetryEventDto>,
    pipeline: Arc<PipelineMetrics>,
    live: LiveBroadcaster,
    stores: IngestionWorkerStores,
) -> Result<(), RuntimeError> {
    let _worker = thread::Builder::new()
        .name("dendrite-ingestion-routine".into())
        .spawn(move || {
            let IngestionWorkerStores {
                self_path,
                memory,
                incident_path,
                guard_path,
            } = stores;
            let mut core = match DaemonCore::open_with_shared_memory(
                &self_path,
                memory,
                &incident_path,
                &guard_path,
            ) {
                Ok(core) => core,
                Err(error) => {
                    eprintln!("routine ingestion worker failed to open stores: {error:?}");
                    return;
                }
            };

            let mut last_lifecycle_sweep = Instant::now();
            loop {
                // Block (with a timeout, so the lifecycle sweep below still runs
                // periodically even under no load at all) for the first job of a
                // batch, then drain whatever else is already queued without
                // waiting, up to the batch cap.
                let first = match routine_rx.recv_timeout(Duration::from_millis(250)) {
                    Ok(job) => job,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if last_lifecycle_sweep.elapsed() >= Duration::from_secs(30) {
                            if let Err(error) = core.expire_memory(unix_now()) {
                                eprintln!("memory lifecycle sweep failed: {error:?}");
                            }
                            last_lifecycle_sweep = Instant::now();
                        }
                        continue;
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                };

                let mut batch = vec![first];
                while batch.len() < ROUTINE_BATCH_SIZE {
                    match routine_rx.try_recv() {
                        Ok(job) => batch.push(job),
                        Err(_) => break,
                    }
                }

                let lane = IngestionLane::Routine;
                for job in &batch {
                    pipeline.dequeued(lane);
                    pipeline.queue_wait(lane, duration_ms(job.queued_at.elapsed()));
                }

                let started = Instant::now();

                // Flatten every job that feeds security reasoning into a
                // single list of observations (a job may carry related
                // observations alongside its primary one - see
                // `CollectedObservation`), so the whole batch's persistence
                // and threat-path search can run as one `run_stm_batch` call
                // instead of one writer round trip per job. `job_ranges`
                // remembers which slice of `flat_observations` belongs to
                // which job so results can be regrouped afterward; a job
                // that doesn't feed security reasoning gets an empty range
                // and is skipped exactly as `process_job` skips it today.
                let mut flat_observations: Vec<(Observation, usize)> = Vec::new();
                let mut job_ranges: Vec<(usize, usize)> = Vec::with_capacity(batch.len());
                for job in &batch {
                    let start = flat_observations.len();
                    if job.scope.feeds_security_reasoning() {
                        flat_observations.push((
                            job.collected.observation.clone(),
                            ROUTINE_THREAT_PATH_MAX_DEPTH,
                        ));
                        for related in &job.collected.related_observations {
                            flat_observations
                                .push((related.clone(), ROUTINE_THREAT_PATH_MAX_DEPTH));
                        }
                    }
                    job_ranges.push((start, flat_observations.len()));
                }

                let mut results = core.ingest_routine_batch(flat_observations).into_iter();

                let mut events = Vec::with_capacity(batch.len());
                for (job, (start, end)) in batch.into_iter().zip(job_ranges) {
                    let mut incident_ids = std::collections::BTreeSet::new();
                    for _ in start..end {
                        // `results` is a plain iterator consumed in lockstep
                        // with `job_ranges`, which was built from the exact
                        // same `flat_observations` push order above, so
                        // `.next()` always lines up with the right job's
                        // slice - `expect` here would only fire on a bug in
                        // that pairing, not on anything ingestion itself can
                        // produce.
                        let result = results
                            .next()
                            .expect("job_ranges must match flat_observations 1:1");
                        match result {
                            Ok(outcome) => {
                                pipeline
                                    .security_observations_ingested
                                    .fetch_add(1, Ordering::Relaxed);
                                incident_ids.extend(
                                    outcome.incidents.into_iter().map(|incident| incident.0),
                                );
                            }
                            Err(error) => {
                                eprintln!("telemetry ingestion failed: {error:?}");
                            }
                        }
                    }
                    events.push(build_telemetry_event(
                        job,
                        incident_ids.into_iter().collect(),
                    ));
                }
                pipeline.processed(lane, duration_ms(started.elapsed()));

                if last_lifecycle_sweep.elapsed() >= Duration::from_secs(30) {
                    if let Err(error) = core.expire_memory(unix_now()) {
                        eprintln!("memory lifecycle sweep failed: {error:?}");
                    }
                    last_lifecycle_sweep = Instant::now();
                }

                let mut disconnected = false;
                for event in events {
                    live.publish("telemetry", &event);
                    if !event.incident_ids.is_empty() {
                        live.publish("incidents", &event.incident_ids);
                    }
                    match completed_tx.try_send(event) {
                        Ok(()) | Err(TrySendError::Full(_)) => {}
                        Err(TrySendError::Disconnected(_)) => {
                            disconnected = true;
                            break;
                        }
                    }
                }
                if disconnected {
                    break;
                }
            }
        })?;
    Ok(())
}

/// Shared per-job processing, used by both dedicated workers: runs
/// `ingest_observation` for the primary observation and any related ones
/// (unless the job's scope doesn't warrant touching the Memory Graph at
/// all), and builds the `TelemetryEventDto` reported over the live feed and
/// the completed-events queue. Deliberately does not publish/send anything
/// itself — the routine worker needs to defer that until after its batch
/// actually commits, so it's left to each caller.
fn process_job(
    core: &mut DaemonCore,
    pipeline: &PipelineMetrics,
    job: IngestionJob,
    max_depth: usize,
) -> TelemetryEventDto {
    let incident_ids = if job.scope.feeds_security_reasoning() {
        let mut incident_ids = std::collections::BTreeSet::new();
        for observation in std::iter::once(&job.collected.observation)
            .chain(job.collected.related_observations.iter())
        {
            match core.ingest_observation_with_max_depth(observation, max_depth) {
                Ok(outcome) => {
                    pipeline
                        .security_observations_ingested
                        .fetch_add(1, Ordering::Relaxed);
                    incident_ids.extend(outcome.incidents.into_iter().map(|incident| incident.0));
                }
                Err(error) => {
                    eprintln!("telemetry ingestion failed: {error:?}");
                }
            }
        }
        incident_ids.into_iter().collect()
    } else {
        Vec::new()
    };

    build_telemetry_event(job, incident_ids)
}

/// Builds the `TelemetryEventDto` reported over the live feed and the
/// completed-events queue for one job, given whatever incident ids its
/// ingestion (however it ran - one job at a time via `process_job`, or as
/// part of a routine batch) produced. Split out of `process_job` so the
/// routine worker's batched path can share it without duplicating the DTO
/// field mapping.
fn build_telemetry_event(job: IngestionJob, incident_ids: Vec<String>) -> TelemetryEventDto {
    TelemetryEventDto {
        id: job.collected.observation.id.0.clone(),
        source: job.collected.source.as_str().into(),
        event: job.collected.event,
        observation_kind: observation_kind_name(job.collected.observation.kind).into(),
        process_id: job.collected.process_id,
        scope: job.scope.as_str().into(),
        source_object: job.collected.observation.source.id.0.clone(),
        source_label: job.collected.observation.source.label.clone(),
        target_object: job
            .collected
            .observation
            .target
            .as_ref()
            .map(|target| target.id.0.clone()),
        target_label: job
            .collected
            .observation
            .target
            .as_ref()
            .map(|target| target.label.clone()),
        observed_at: job.collected.observation.observed_at,
        incident_ids,
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn is_peer_disconnect_kind(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::UnexpectedEof
    )
}

fn is_client_disconnect(error: &RuntimeError) -> bool {
    match error {
        RuntimeError::Io(error) => is_peer_disconnect_kind(error.kind()),
        _ => false,
    }
}

struct SocketPathGuard {
    path: PathBuf,
}

impl SocketPathGuard {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => eprintln!(
                "failed to remove daemon socket {} during shutdown: {error}",
                self.path.display()
            ),
        }
    }
}

#[derive(Debug)]
pub enum RuntimeError {
    Io(io::Error),
    AlreadyRunning(PathBuf),
    InvalidConfig(String),
    Json(serde_json::Error),
    Daemon(DaemonError),
    Vulnerability(VulnerabilityError),
    WorkerStopped,
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
impl From<VulnerabilityError> for RuntimeError {
    fn from(error: VulnerabilityError) -> Self {
        Self::Vulnerability(error)
    }
}

fn set_socket_group(path: &Path, group: &str) -> Result<(), RuntimeError> {
    let group_name = CString::new(group)
        .map_err(|_| RuntimeError::InvalidConfig("socket group contains NUL byte".into()))?;

    // SAFETY: getgrnam reads the provided NUL-terminated group name and returns
    // a pointer to libc-managed storage valid until the next group lookup.
    let entry = unsafe { libc::getgrnam(group_name.as_ptr()) };
    if entry.is_null() {
        return Err(RuntimeError::InvalidConfig(format!(
            "socket group `{group}` does not exist"
        )));
    }

    // SAFETY: entry was checked for null above.
    let gid = unsafe { (*entry).gr_gid };
    let path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| RuntimeError::InvalidConfig("socket path contains NUL byte".into()))?;

    // uid_t::MAX means "do not change owner" for chown.
    // SAFETY: path is NUL-terminated and points to the bound socket path.
    let result = unsafe { libc::chown(path.as_ptr(), u32::MAX as libc::uid_t, gid) };
    if result != 0 {
        return Err(RuntimeError::Io(std::io::Error::last_os_error()));
    }

    Ok(())
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
