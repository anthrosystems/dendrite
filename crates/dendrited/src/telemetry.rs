use aya::{
    Ebpf,
    maps::{MapData, RingBuf},
    programs::{KProbe, TracePoint},
};
use dendrite_ebpf_common::{
    ADDRESS_FAMILY_INET, ADDRESS_FAMILY_INET6, EVENT_NETWORK_CONNECT, EVENT_PROCESS_EXEC, EbpfEvent,
};
use dendrite_protocol::{
    Confidence, EntityKind, ObjectDescriptor, ObjectId, Observation, ObservationId,
    ObservationKind, Severity, TelemetrySourceDto,
};
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_OBSERVATION_TTL_SECONDS: u64 = 300;
const MAX_FILES_PER_SCAN: usize = 10_000;
const FANOTIFY_BUFFER_BYTES: usize = 64 * 1024;
const MAX_EVENTS_PER_COLLECTION: usize = 4_096;
/// How long an unchanged (file, program) pair stays suppressed after being
/// seen once. Deliberately short-ish: this exists to collapse repeat noise
/// from the same program re-touching the same static file (e.g. dozens of
/// short-lived Proxmox Perl workers all re-opening the same module tree —
/// same key across many different PIDs, since it's keyed on the *program*'s
/// identity, not the transient process instance), not to silently blind
/// Dendrite to something for an extended period.
const FILE_TOUCH_CACHE_TTL_SECONDS: u64 = 120;
/// Hard cap so this in-memory cache can never grow unbounded over a long
/// daemon uptime. On overflow the whole cache is cleared rather than doing
/// real LRU eviction — a temporary loss of dedup benefit right after a
/// clear is a fine trade for not pulling in an LRU crate/more bookkeeping
/// for what's meant to be a cheap, best-effort optimisation.
const FILE_TOUCH_CACHE_MAX_ENTRIES: usize = 50_000;
const MAX_FANOTIFY_INCLUDE_DIRECTORIES: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetrySource {
    ProcPolling,
    FilesystemPolling,
    Fanotify,
    Ebpf,
}

impl TelemetrySource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProcPolling => "proc_polling",
            Self::FilesystemPolling => "filesystem_polling",
            Self::Fanotify => "fanotify",
            Self::Ebpf => "ebpf",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TelemetryScope {
    Host,
    DendriteControlPlane,
}

impl TelemetryScope {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::DendriteControlPlane => "dendrite_control_plane",
        }
    }

    pub(crate) fn feeds_security_reasoning(self) -> bool {
        matches!(self, Self::Host)
    }
}

#[derive(Debug, Clone)]
pub struct CollectedObservation {
    pub source: TelemetrySource,
    pub event: String,
    pub process_id: Option<u32>,
    pub observation: Observation,
    pub related_observations: Vec<Observation>,
}

/// How often (in `collect()` calls) the periodic-reconciliation collectors
/// (`/proc` polling, filesystem polling) run while their event-driven
/// counterpart (eBPF, fanotify) is also active. Their job in that mode isn't
/// "same data, worse" — it's cold-start inventory of anything that predates
/// `dendrited` attaching, plus a backstop for anything the event-driven side
/// drops (a full ring buffer, a missed fanotify event) — so it doesn't need
/// to run at the same cadence as the event-driven collector to do that job,
/// and running a full `/proc` or filesystem walk on every single collection
/// tick would be a real, needless cost. When the event-driven counterpart is
/// *not* active, the periodic collector is the only source and runs every
/// tick regardless of this stride (see `should_run_reconciliation_poll`).
const RECONCILIATION_POLL_STRIDE: u64 = 10;

/// Whether a periodic-reconciliation collector should run on this tick.
/// Pulled out as its own pure function so the cadence decision is testable
/// without standing up a real `TelemetryManager` (which needs a working
/// fanotify/eBPF environment to construct meaningfully).
fn should_run_reconciliation_poll(tick: u64, event_driven_active: bool) -> bool {
    !event_driven_active || tick % RECONCILIATION_POLL_STRIDE == 0
}

pub struct TelemetryManager {
    processes: ProcessCollector,
    filesystem: FilesystemCollector,
    fanotify: Option<FanotifyCollector>,
    ebpf: Option<EbpfCollector>,
    fanotify_status: TelemetrySourceDto,
    ebpf_status: TelemetrySourceDto,
    control_plane_addr: SocketAddr,
    poll_tick: u64,
}

impl TelemetryManager {
    pub fn new(
        watch_mounts: Vec<PathBuf>,
        watch_include_paths: Vec<PathBuf>,
        exclude_paths: Vec<PathBuf>,
        fanotify_enabled: bool,
        ebpf_enabled: bool,
        ebpf_object: PathBuf,
        control_plane_addr: SocketAddr,
    ) -> Self {
        // Discovered once and shared: fanotify uses it for its initial marks,
        // and the filesystem-polling fallback uses the same set (plus
        // watch_include_paths) so that "fanotify is off/unavailable" doesn't
        // silently regress from "watch everything real" back down to "watch
        // nothing" — `watch_mounts` (from DENDRITE_WATCH_MOUNTS) only ever
        // narrows this, never expands it.
        let effective_mounts = discover_watchable_mounts(&watch_mounts);
        let mut effective_paths = effective_mounts.clone();
        effective_paths.extend(watch_include_paths.iter().cloned());

        let (fanotify, fanotify_status) = if fanotify_enabled {
            match FanotifyCollector::new(&watch_mounts, &watch_include_paths, &exclude_paths) {
                Ok(collector) => (
                    Some(collector),
                    TelemetrySourceDto {
                        source: TelemetrySource::Fanotify.as_str().into(),
                        status: "active".into(),
                        detail: format!(
                            "Linux fanotify event collection active ({} mount(s), {} extra include path(s) watched)",
                            effective_mounts.len(),
                            watch_include_paths.len()
                        ),
                    },
                ),
                Err(error) => (
                    None,
                    TelemetrySourceDto {
                        source: TelemetrySource::Fanotify.as_str().into(),
                        status: "fallback".into(),
                        detail: format!(
                            "fanotify unavailable ({error}); filesystem polling remains active"
                        ),
                    },
                ),
            }
        } else {
            (
                None,
                TelemetrySourceDto {
                    source: TelemetrySource::Fanotify.as_str().into(),
                    status: "disabled".into(),
                    detail: "Set DENDRITE_FANOTIFY=0 was used to opt out; unset it (or set to 1) to enable".into(),
                },
            )
        };

        let (ebpf, ebpf_status) = if ebpf_enabled {
            match EbpfCollector::new(&ebpf_object) {
                Ok(collector) => (
                    Some(collector),
                    TelemetrySourceDto {
                        source: TelemetrySource::Ebpf.as_str().into(),
                        status: "active".into(),
                        detail: format!(
                            "eBPF process exec + outbound connect collection active ({})",
                            ebpf_object.display()
                        ),
                    },
                ),
                Err(error) => (
                    None,
                    TelemetrySourceDto {
                        source: TelemetrySource::Ebpf.as_str().into(),
                        status: "fallback".into(),
                        detail: format!(
                            "eBPF unavailable ({error}); /proc process fallback remains active"
                        ),
                    },
                ),
            }
        } else {
            (
                None,
                TelemetrySourceDto {
                    source: TelemetrySource::Ebpf.as_str().into(),
                    status: "disabled".into(),
                    detail: "Set DENDRITE_EBPF=1 after building the eBPF object".into(),
                },
            )
        };

        Self {
            processes: ProcessCollector::new(),
            filesystem: FilesystemCollector::new(effective_paths),
            fanotify,
            ebpf,
            fanotify_status,
            ebpf_status,
            control_plane_addr,
            poll_tick: 0,
        }
    }

    /// Re-checks for newly-appeared mounts (a USB drive, a container's
    /// overlay mount, etc.) and extends fanotify's coverage to include them.
    /// Intended to be called on the same cadence as
    /// `DENDRITE_TELEMETRY_INTERVAL_SECONDS`. No-op if fanotify isn't active.
    pub fn rescan_mounts(&mut self) {
        if let Some(fanotify) = self.fanotify.as_mut() {
            fanotify.rescan_mounts();
        }
    }

    pub(crate) fn scope_for(&self, event: &CollectedObservation) -> TelemetryScope {
        if is_dendrite_process(&event.observation.source.label) {
            return TelemetryScope::DendriteControlPlane;
        }

        if event.observation.kind == ObservationKind::NetworkConnection
            && self.control_plane_addr.ip().is_loopback()
            && event
                .observation
                .target
                .as_ref()
                .and_then(|target| target.label.parse::<SocketAddr>().ok())
                .is_some_and(|target| {
                    target.ip().is_loopback() && target.port() == self.control_plane_addr.port()
                })
        {
            return TelemetryScope::DendriteControlPlane;
        }

        TelemetryScope::Host
    }

    /// Event-driven collectors (eBPF, fanotify) run every tick, same as
    /// always. Their periodic-reconciliation counterparts (`/proc`,
    /// filesystem polling) now *also* always run — never fully switched off
    /// just because the event-driven side is available — but at a reduced
    /// cadence in that case (`should_run_reconciliation_poll`), since their
    /// job there is cold-start inventory and a dropped-event backstop, not
    /// a duplicate of the event-driven stream. Each collector's own
    /// `seen`/`known` diffing (`ProcessCollector`, `FilesystemCollector`)
    /// is what keeps this from re-reporting an object the event-driven
    /// collector already reported: a periodic poll only emits for what
    /// wasn't already in its own last-seen set, exec captured by eBPF or
    /// not.
    pub fn collect(&mut self) -> Vec<CollectedObservation> {
        self.poll_tick = self.poll_tick.wrapping_add(1);
        let mut observations = Vec::new();

        if let Some(ebpf) = &mut self.ebpf {
            observations.extend(ebpf.collect());
        }
        if should_run_reconciliation_poll(self.poll_tick, self.ebpf.is_some()) {
            observations.extend(self.processes.collect());
        }

        if let Some(fanotify) = &mut self.fanotify {
            observations.extend(fanotify.collect());
        }
        if should_run_reconciliation_poll(self.poll_tick, self.fanotify.is_some()) {
            observations.extend(self.filesystem.collect());
        }

        observations
    }

    pub fn status(&self) -> Vec<TelemetrySourceDto> {
        vec![
            self.fanotify_status.clone(),
            self.ebpf_status.clone(),
            if self.ebpf.is_some() {
                TelemetrySourceDto {
                    source: TelemetrySource::ProcPolling.as_str().into(),
                    status: "reconciliation".into(),
                    detail: format!(
                        "/proc process discovery runs as a periodic cold-start/backstop reconciliation (every {RECONCILIATION_POLL_STRIDE} collection cycles) while eBPF is active"
                    ),
                }
            } else {
                TelemetrySourceDto {
                    source: TelemetrySource::ProcPolling.as_str().into(),
                    status: "active".into(),
                    detail: "/proc process discovery fallback".into(),
                }
            },
            if self.fanotify.is_some() {
                TelemetrySourceDto {
                    source: TelemetrySource::FilesystemPolling.as_str().into(),
                    status: "reconciliation".into(),
                    detail: format!(
                        "Filesystem metadata polling runs as a periodic cold-start/backstop reconciliation (every {RECONCILIATION_POLL_STRIDE} collection cycles) while fanotify is active"
                    ),
                }
            } else {
                TelemetrySourceDto {
                    source: TelemetrySource::FilesystemPolling.as_str().into(),
                    status: "active".into(),
                    detail: "Filesystem metadata polling fallback".into(),
                }
            },
        ]
    }
}

struct EbpfCollector {
    _bpf: Ebpf,
    events: RingBuf<MapData>,
    /// See `FanotifyCollector::self_pid`'s doc comment for why this is
    /// PID-scoped rather than path- or program-scoped: it exists to keep
    /// Dendrite's own activity from generating telemetry about itself, not
    /// to blind Dendrite to anything.
    self_pid: u32,
}

impl EbpfCollector {
    fn new(object_path: &Path) -> Result<Self, String> {
        if !object_path.exists() {
            return Err(format!("object not found: {}", object_path.display()));
        }

        let mut bpf = Ebpf::load_file(object_path).map_err(|error| error.to_string())?;

        let process: &mut TracePoint = bpf
            .program_mut("dendrite_process_exec")
            .ok_or_else(|| "missing dendrite_process_exec program".to_string())?
            .try_into()
            .map_err(|error: aya::programs::ProgramError| error.to_string())?;
        process.load().map_err(|error| error.to_string())?;
        process
            .attach("sched", "sched_process_exec")
            .map_err(|error| error.to_string())?;

        let connect: &mut KProbe = bpf
            .program_mut("dendrite_connect")
            .ok_or_else(|| "missing dendrite_connect program".to_string())?
            .try_into()
            .map_err(|error: aya::programs::ProgramError| error.to_string())?;
        connect.load().map_err(|error| error.to_string())?;
        connect
            .attach("__sys_connect", 0)
            .map_err(|error| format!("attach __sys_connect: {error}"))?;

        let map = bpf
            .take_map("EVENTS")
            .ok_or_else(|| "missing EVENTS ring buffer".to_string())?;
        let events = RingBuf::try_from(map).map_err(|error| error.to_string())?;

        Ok(Self {
            _bpf: bpf,
            events,
            // SAFETY: getpid() takes no arguments and cannot fail.
            self_pid: unsafe { libc::getpid() } as u32,
        })
    }

    fn collect(&mut self) -> Vec<CollectedObservation> {
        let mut observations = Vec::new();
        while observations.len() < MAX_EVENTS_PER_COLLECTION {
            let Some(item) = self.events.next() else {
                break;
            };
            let bytes = item.as_ref();
            if bytes.len() != std::mem::size_of::<EbpfEvent>() {
                continue;
            }

            let mut event = EbpfEvent::zeroed(0);
            // SAFETY: both regions are valid for exactly size_of::<EbpfEvent>() bytes and do not
            // overlap. EbpfEvent contains only integer/byte-array fields and accepts any bit pattern.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    (&mut event as *mut EbpfEvent).cast::<u8>(),
                    std::mem::size_of::<EbpfEvent>(),
                );
            }

            if let Some(observation) = ebpf_observation(event, self.self_pid) {
                observations.push(observation);
            }
        }
        observations
    }
}

fn ebpf_observation(event: EbpfEvent, self_pid: u32) -> Option<CollectedObservation> {
    let process_id = if event.tgid > 0 {
        event.tgid
    } else {
        event.pid
    };
    // Checked before `read_process()` for the same reason fanotify's
    // self-exclusion runs before its own path resolution: skip the
    // expensive `/proc` lookup entirely for events this collector is about
    // to discard anyway.
    if process_id == self_pid {
        return None;
    }

    let now = unix_time();
    let process = read_process(process_id);
    let source = process
        .as_ref()
        .map(ProcessInfo::descriptor)
        .unwrap_or_else(|| {
            // `read_process()` races the process's own exit and produces
            // nothing when it loses (see its doc comment). `event.start_ticks`
            // being nonzero means the tracepoint's own in-kernel read (see
            // `capture_process_identity` in the eBPF program) beat that race,
            // so a resolved, name+start_ticks-stable identity is still
            // available even though the `/proc` read failed - only when even
            // the kernel-side capture came back empty (an older eBPF build
            // that predates this field, or a kernel-side read failure of its
            // own) does this fall all the way back to the comm-only identity
            // that can't distinguish two same-named processes.
            if event.start_ticks > 0 {
                resolved_process_descriptor_from_event(process_id, &event)
            } else {
                unresolved_process_descriptor(process_id, &event.comm)
            }
        });

    match event.kind {
        EVENT_PROCESS_EXEC => {
            let (observation, related_observations) = match process {
                Some(process) => {
                    let instance = process.descriptor();
                    let mut related = process_context_observations(&process, now, "ebpf", false);

                    if let Some(parent) = process.parent_pid.and_then(read_process) {
                        related.push(Observation {
                            id: ObservationId(format!(
                                "ebpf-spawn:{}:{}",
                                process.pid, process.start_ticks
                            )),
                            kind: ObservationKind::ProcessStarted,
                            source: parent.descriptor(),
                            target: Some(instance.clone()),
                            observed_at: now,
                            expires_at: Some(now.saturating_add(DEFAULT_OBSERVATION_TTL_SECONDS)),
                            severity: Severity::Low,
                            confidence: Confidence::new(100).expect("100 is valid confidence"),
                        });
                    }

                    let (kind, target, confidence) = match process.executable_descriptor() {
                        Some(executable) => (ObservationKind::FileExecuted, Some(executable), 100),
                        None => (ObservationKind::ProcessStarted, None, 90),
                    };
                    (
                        Observation {
                            id: ObservationId(format!(
                                "ebpf-exec:{process_id}:{}",
                                event.timestamp_ns
                            )),
                            kind,
                            source: instance,
                            target,
                            observed_at: now,
                            expires_at: Some(now.saturating_add(DEFAULT_OBSERVATION_TTL_SECONDS)),
                            severity: Severity::Low,
                            confidence: Confidence::new(confidence)
                                .expect("telemetry confidence is valid"),
                        },
                        related,
                    )
                }
                None => (
                    Observation {
                        id: ObservationId(format!("ebpf-exec:{process_id}:{}", event.timestamp_ns)),
                        kind: ObservationKind::ProcessStarted,
                        // 90 when `source` is the resolved (`process:{pid}:{start_ticks}`)
                        // identity the kernel-side capture beat the exit race
                        // for - still short of the 100 the `Some(process)`
                        // arm gets, since no executable path is available
                        // here to also confirm what actually ran. 80 when
                        // even that capture came back empty and `source`
                        // fell all the way back to the comm-only identity.
                        confidence: Confidence::new(if event.start_ticks > 0 { 90 } else { 80 })
                            .expect("70..=100 is valid confidence"),
                        source,
                        target: None,
                        observed_at: now,
                        expires_at: Some(now.saturating_add(DEFAULT_OBSERVATION_TTL_SECONDS)),
                        severity: Severity::Low,
                    },
                    Vec::new(),
                ),
            };

            Some(CollectedObservation {
                source: TelemetrySource::Ebpf,
                event: "process_executed".into(),
                process_id: Some(process_id),
                observation,
                related_observations,
            })
        }
        EVENT_NETWORK_CONNECT => {
            let endpoint = ebpf_endpoint(&event)?;
            let endpoint_label = format_endpoint(endpoint.0, event.port);
            let target = ObjectDescriptor {
                id: ObjectId(format!("network:{endpoint_label}")),
                kind: EntityKind::NetworkEndpoint,
                label: endpoint_label,
                content_hash: None,
            };
            Some(CollectedObservation {
                source: TelemetrySource::Ebpf,
                event: "network_connect".into(),
                process_id: Some(process_id),
                observation: Observation {
                    id: ObservationId(format!(
                        "ebpf-connect:{process_id}:{}:{}:{}",
                        stable_hash(&target.id.0),
                        event.port,
                        event.timestamp_ns
                    )),
                    kind: ObservationKind::NetworkConnection,
                    source,
                    target: Some(target),
                    observed_at: now,
                    expires_at: Some(now.saturating_add(DEFAULT_OBSERVATION_TTL_SECONDS)),
                    severity: Severity::Low,
                    confidence: Confidence::new(100).expect("100 is valid confidence"),
                },
                related_observations: Vec::new(),
            })
        }
        _ => None,
    }
}

fn unresolved_process_descriptor(process_id: u32, comm: &[u8; 16]) -> ObjectDescriptor {
    let label = ebpf_comm(comm).unwrap_or_else(|| format!("pid {process_id}"));
    ObjectDescriptor {
        id: ObjectId(format!("process_identity:comm:{}", stable_hash(&label))),
        kind: EntityKind::Process,
        label,
        content_hash: None,
    }
}

/// Same `process:{pid}:{start_ticks}` identity scheme `ProcessInfo::descriptor()`
/// (`/proc`-derived) uses, built instead from the eBPF event's own
/// `start_ticks` (`capture_process_identity` in the eBPF program) - only
/// called when `read_process()` already lost the race against this
/// process's exit, as the one case where the kernel-side capture still has
/// data the userspace `/proc` read no longer does. Producing the identical
/// id format here (rather than inventing a separate scheme) is what lets
/// this resolve to the *same* memory node id as a `/proc`-reconciliation
/// poll would have produced for this exact process, had it won the race.
fn resolved_process_descriptor_from_event(process_id: u32, event: &EbpfEvent) -> ObjectDescriptor {
    let label = ebpf_comm(&event.comm).unwrap_or_else(|| format!("pid {process_id}"));
    ObjectDescriptor {
        id: ObjectId(format!("process:{process_id}:{}", event.start_ticks)),
        kind: EntityKind::Process,
        label,
        content_hash: None,
    }
}

fn ebpf_comm(bytes: &[u8; 16]) -> Option<String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn format_endpoint(address: IpAddr, port: u16) -> String {
    match address {
        IpAddr::V4(address) => format!("{address}:{port}"),
        IpAddr::V6(address) => format!("[{address}]:{port}"),
    }
}

fn ebpf_endpoint(event: &EbpfEvent) -> Option<(IpAddr, u16)> {
    let address = match event.family {
        ADDRESS_FAMILY_INET => IpAddr::V4(Ipv4Addr::new(
            event.address[0],
            event.address[1],
            event.address[2],
            event.address[3],
        )),
        ADDRESS_FAMILY_INET6 => IpAddr::V6(Ipv6Addr::from(event.address)),
        _ => return None,
    };
    Some((address, event.port))
}

fn is_dendrite_process(label: &str) -> bool {
    matches!(label, "dendrited" | "dendrite-cli" | "dendrite-ui")
}

struct ProcessCollector {
    seen: HashSet<String>,
    initialised: bool,
}

impl ProcessCollector {
    fn new() -> Self {
        Self {
            seen: HashSet::new(),
            initialised: false,
        }
    }

    fn collect(&mut self) -> Vec<CollectedObservation> {
        let now = unix_time();
        let mut current = HashSet::new();
        let mut observations = Vec::new();

        let Ok(entries) = fs::read_dir("/proc") else {
            return observations;
        };

        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            let Some(process) = read_process(pid) else {
                continue;
            };
            current.insert(process.id.clone());

            if self.initialised && !self.seen.contains(&process.id) {
                let parent = process.parent_pid.and_then(read_process);
                let (source, target) = match parent {
                    Some(parent) => (parent.descriptor(), Some(process.descriptor())),
                    None => (process.descriptor(), None),
                };
                observations.push(CollectedObservation {
                    source: TelemetrySource::ProcPolling,
                    event: "process_started".into(),
                    process_id: Some(process.pid),
                    observation: Observation {
                        id: ObservationId(format!(
                            "proc-start:{}:{}",
                            process.pid, process.start_ticks
                        )),
                        kind: ObservationKind::ProcessStarted,
                        source,
                        target,
                        observed_at: now,
                        expires_at: Some(now.saturating_add(DEFAULT_OBSERVATION_TTL_SECONDS)),
                        severity: Severity::Low,
                        confidence: Confidence::new(100).expect("100 is valid confidence"),
                    },
                    related_observations: process_context_observations(&process, now, "proc", true),
                });
            }
        }

        self.seen = current;
        self.initialised = true;
        observations
    }
}

#[derive(Debug, Clone)]
struct ProcessInfo {
    pid: u32,
    parent_pid: Option<u32>,
    start_ticks: u64,
    id: String,
    label: String,
    executable: Option<PathBuf>,
    user_id: Option<u32>,
}

impl ProcessInfo {
    fn descriptor(&self) -> ObjectDescriptor {
        ObjectDescriptor {
            id: ObjectId(self.id.clone()),
            kind: EntityKind::Process,
            label: self.label.clone(),
            content_hash: None,
        }
    }

    fn executable_descriptor(&self) -> Option<ObjectDescriptor> {
        let executable = self.executable.as_ref()?;
        let label = executable.to_string_lossy().into_owned();
        // `content_hash` stays `None` here deliberately: hashing the backing
        // file synchronously on every `/proc` poll would race the same
        // "process may have already exited" problem `read_process()` has
        // for `dev`/`inode` (see ROADMAP.md item 3), just for a much larger
        // read. The eBPF `(dev, inode)` capture is what's meant to feed a
        // decoupled, cached-by-`(dev, inode)` async hasher instead.
        Some(ObjectDescriptor {
            id: ObjectId(format!("file:{label}")),
            kind: EntityKind::File,
            label,
            content_hash: None,
        })
    }

    fn user_descriptor(&self) -> Option<ObjectDescriptor> {
        let user_id = self.user_id?;
        Some(ObjectDescriptor {
            id: ObjectId(format!("user:uid:{user_id}")),
            kind: EntityKind::User,
            label: format!("uid {user_id}"),
            content_hash: None,
        })
    }
}

fn process_context_observations(
    process: &ProcessInfo,
    now: u64,
    prefix: &str,
    include_executable: bool,
) -> Vec<Observation> {
    let instance = process.descriptor();
    let mut observations = Vec::new();

    if include_executable && let Some(executable) = process.executable_descriptor() {
        observations.push(Observation {
            id: ObservationId(format!(
                "{prefix}-executable:{}:{}",
                process.pid, process.start_ticks
            )),
            kind: ObservationKind::FileExecuted,
            source: instance.clone(),
            target: Some(executable),
            observed_at: now,
            expires_at: Some(now.saturating_add(DEFAULT_OBSERVATION_TTL_SECONDS)),
            severity: Severity::Low,
            confidence: Confidence::new(100).expect("100 is valid confidence"),
        });
    }

    if let Some(user) = process.user_descriptor() {
        observations.push(Observation {
            id: ObservationId(format!(
                "{prefix}-user:{}:{}",
                process.pid, process.start_ticks
            )),
            kind: ObservationKind::Associated,
            source: instance,
            target: Some(user),
            observed_at: now,
            expires_at: Some(now.saturating_add(DEFAULT_OBSERVATION_TTL_SECONDS)),
            severity: Severity::Low,
            confidence: Confidence::new(95).expect("95 is valid confidence"),
        });
    }

    observations
}

fn read_process(pid: u32) -> Option<ProcessInfo> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.rfind(')')?;
    let open = stat.find('(')?;
    let label = stat.get(open + 1..close)?.to_string();
    let fields = stat
        .get(close + 2..)?
        .split_whitespace()
        .collect::<Vec<_>>();
    let parent_pid = fields
        .get(1)?
        .parse::<u32>()
        .ok()
        .filter(|value| *value > 0);
    let start_ticks = fields.get(19)?.parse::<u64>().ok()?;
    let executable = fs::read_link(format!("/proc/{pid}/exe")).ok();
    let user_id = fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("Uid:"))
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|value| value.parse::<u32>().ok())
        });

    Some(ProcessInfo {
        pid,
        parent_pid,
        start_ticks,
        id: format!("process:{pid}:{start_ticks}"),
        label,
        executable,
        user_id,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileFingerprint {
    modified_nanos: u128,
    len: u64,
}

struct FilesystemCollector {
    watch_paths: Vec<PathBuf>,
    known: HashMap<PathBuf, FileFingerprint>,
    initialised: bool,
}

impl FilesystemCollector {
    fn new(watch_paths: Vec<PathBuf>) -> Self {
        Self {
            watch_paths,
            known: HashMap::new(),
            initialised: false,
        }
    }

    fn collect(&mut self) -> Vec<CollectedObservation> {
        let now = unix_time();
        let mut current = HashMap::new();
        let mut observations = Vec::new();
        let mut visited = 0usize;

        for root in &self.watch_paths {
            scan_files(root, &mut current, &mut visited);
            if visited >= MAX_FILES_PER_SCAN {
                break;
            }
        }

        if self.initialised {
            for (path, fingerprint) in &current {
                if self
                    .known
                    .get(path)
                    .is_some_and(|known| known == fingerprint)
                {
                    continue;
                }

                let path_text = path.to_string_lossy().into_owned();
                observations.push(CollectedObservation {
                    source: TelemetrySource::FilesystemPolling,
                    event: "file_written".into(),
                    process_id: None,
                    observation: file_observation(
                        local_host(),
                        &path_text,
                        ObservationKind::FileWritten,
                        "poll-file",
                        now,
                        90,
                    ),
                    related_observations: Vec::new(),
                });
            }
        }

        self.known = current;
        self.initialised = true;
        observations
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FanotifyEventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

/// Filesystem types that are never worth marking: kernel-internal/virtual
/// interfaces with no persistent-storage security relevance and, in most
/// cases, enormous synthetic event volume for zero benefit. Deliberately
/// does NOT include `tmpfs` (backs real, security-relevant paths like
/// `/tmp` and `/dev/shm`) or `overlay` (what container filesystems use —
/// exactly what we want to see).
const PSEUDO_FILESYSTEM_TYPES: &[&str] = &[
    "proc",
    "sysfs",
    "cgroup",
    "cgroup2",
    "devpts",
    "devtmpfs",
    "debugfs",
    "tracefs",
    "securityfs",
    "pstore",
    "autofs",
    "mqueue",
    "hugetlbfs",
    "binfmt_misc",
    "configfs",
    "fusectl",
    "bpf",
    "nsfs",
    "rpc_pipefs",
    "sunrpc",
    "efivarfs",
];

/// Undoes the octal-escaping (`\040` for space, etc.) `/proc/self/mountinfo`
/// applies to mount point paths containing whitespace or backslashes — real
/// on removable media mounted at a label-derived path.
fn unescape_mountinfo_path(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && let Ok(value) = u8::from_str_radix(&raw[i + 1..i + 4], 8)
        {
            out.push(value as char);
            i += 4;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Parses `/proc/self/mountinfo` into (mount point, filesystem type) pairs.
/// Format per proc(5): a variable number of optional fields between the
/// mount options and a literal `-` separator, then filesystem type, mount
/// source, and superblock options. We only need field 5 (mount point) and
/// the field immediately after the `-` separator (filesystem type).
fn parse_mountinfo(contents: &str) -> Vec<(PathBuf, String)> {
    let mut mounts = Vec::new();
    for line in contents.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        let Some(dash) = fields.iter().position(|field| *field == "-") else {
            continue;
        };
        let (Some(mount_point), Some(fstype)) = (fields.get(4), fields.get(dash + 1)) else {
            continue;
        };
        mounts.push((
            PathBuf::from(unescape_mountinfo_path(mount_point)),
            (*fstype).to_string(),
        ));
    }
    mounts
}

/// Discovers every currently-mounted, non-pseudo filesystem — this is the
/// full default watch scope: `DENDRITE_FANOTIFY` is opt-out, not opt-in, and
/// once it's on, coverage should look like a real EDR/AV product (watch
/// everything real by default), not require a hand-maintained path list.
/// `restrict_to` (from `DENDRITE_WATCH_MOUNTS`, if set) narrows this down to
/// just the listed mount points instead of every discovered one.
fn discover_watchable_mounts(restrict_to: &[PathBuf]) -> Vec<PathBuf> {
    let Ok(contents) = fs::read_to_string("/proc/self/mountinfo") else {
        return Vec::new();
    };
    parse_mountinfo(&contents)
        .into_iter()
        .filter(|(_, fstype)| !PSEUDO_FILESYSTEM_TYPES.contains(&fstype.as_str()))
        .map(|(mount_point, _)| mount_point)
        .filter(|mount_point| restrict_to.is_empty() || restrict_to.contains(mount_point))
        .collect()
}

/// Whether an observed path falls under any of `exclude_paths` and should be
/// dropped before it ever becomes an observation. Prefix match on path
/// components, not a raw string prefix (so `/etc-backup` is not excluded by
/// an exclude entry of `/etc`).
fn is_excluded(path: &Path, exclude_paths: &[PathBuf]) -> bool {
    exclude_paths
        .iter()
        .any(|excluded| path.starts_with(excluded))
}

/// Whether any entry in `include_paths` and `exclude_paths` contradict each
/// other — equal, or one a path-component ancestor of the other in either
/// direction. Rejected outright rather than silently resolved one way:
/// picking a winner (e.g. "exclude always wins") would make it easy to
/// believe a path is covered when it silently isn't, or vice versa — a
/// security-relevant footgun this codebase consistently rejects rather than
/// papers over (see `validate_behaviour_condition` in `vulnerability.rs` for
/// the same philosophy applied elsewhere).
fn find_watch_path_collision(
    include_paths: &[PathBuf],
    exclude_paths: &[PathBuf],
) -> Option<(PathBuf, PathBuf)> {
    for include in include_paths {
        for exclude in exclude_paths {
            if include.starts_with(exclude) || exclude.starts_with(include) {
                return Some((include.clone(), exclude.clone()));
            }
        }
    }
    None
}

/// Recursively collects directories under `path` (following the same
/// pattern as the pre-`FAN_MARK_FILESYSTEM` design), up to `remaining`
/// entries — used only for `DENDRITE_WATCH_INCLUDE_PATHS`, which adds
/// specific extra paths rather than an entire mount, so a directory-by-
/// directory walk (bounded by a cap, since an include path could still be
/// large) is the right tool here, unlike for mount-level coverage.
fn collect_directories(path: &Path, output: &mut Vec<PathBuf>, remaining: usize) {
    if output.len() >= remaining {
        return;
    }

    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };

    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return;
    }

    output.push(path.to_path_buf());
    if output.len() >= remaining {
        return;
    }

    let Ok(entries) = fs::read_dir(path) else {
        return;
    };

    for entry in entries.flatten() {
        collect_directories(&entry.path(), output, remaining);
        if output.len() >= remaining {
            break;
        }
    }
}

/// A single entry in `FanotifyCollector`'s file-touch cache — see
/// `FILE_TOUCH_CACHE_TTL_SECONDS` for why this exists. Deliberately plain
/// in-memory state (a bare `HashMap`, no locking): `collect()` only ever
/// runs on the single runtime thread that owns the collector, so there's no
/// concurrent access to guard against, and — the actual point of this cache
/// — nothing here ever touches disk. A DB-backed or cross-thread version
/// would reintroduce exactly the I/O cost this exists to avoid.
struct FileTouchEntry {
    mtime: i64,
    size: i64,
    last_seen: u64,
}

struct FanotifyCollector {
    fd: RawFd,
    exclude_paths: Vec<PathBuf>,
    restrict_to: Vec<PathBuf>,
    include_paths: Vec<PathBuf>,
    marked_devices: HashSet<u64>,
    /// Dendrite's own PID — events generated by Dendrite's own writes to its
    /// own database files are filtered out by *who wrote it*, not by path.
    /// A path-based exclude would also blind Dendrite to some other process
    /// tampering with those same files, which is exactly the kind of thing
    /// a security tool's own threat model should care about most — PID
    /// scoping keeps the noise reduction without that blind spot, since a
    /// write from any other process to these paths is still seen.
    self_pid: i32,
    /// Keyed on (device, inode, program executable path) — *not* PID/process
    /// instance, deliberately: many short-lived processes running the same
    /// program (e.g. one-shot Perl workers) should collapse into the same
    /// key, since what matters for "is this spam" is whether the same kind
    /// of actor is re-touching the same unchanged file, not which specific
    /// process instance did it. A process with no resolvable executable path
    /// always misses the cache (never suppressed) rather than being grouped
    /// under some shared fallback bucket that could wrongly conflate
    /// unrelated processes.
    file_touch_cache: HashMap<(u64, u64, PathBuf), FileTouchEntry>,
}

impl FanotifyCollector {
    const MASK: u64 =
        libc::FAN_OPEN | libc::FAN_MODIFY | libc::FAN_CLOSE_WRITE | libc::FAN_EVENT_ON_CHILD;

    fn new(
        restrict_to: &[PathBuf],
        include_paths: &[PathBuf],
        exclude_paths: &[PathBuf],
    ) -> Result<Self, String> {
        if let Some((include, exclude)) = find_watch_path_collision(include_paths, exclude_paths) {
            return Err(format!(
                "DENDRITE_WATCH_INCLUDE_PATHS entry {include:?} conflicts with \
                 DENDRITE_WATCH_EXCLUDE_PATHS entry {exclude:?} (one contains the other) — \
                 fix the overlap before fanotify can start"
            ));
        }

        // FAN_UNLIMITED_QUEUE/FAN_UNLIMITED_MARKS: always on, not a config
        // option — there's no legitimate reason a user would want the
        // smaller kernel defaults (16,384-event queue, 8,192-mark cap) over
        // these, and both already require CAP_SYS_ADMIN, which is already
        // mandatory for fanotify at all. Without FAN_UNLIMITED_QUEUE
        // specifically, the kernel can silently drop events once its queue
        // fills — invisible to every metric Dendrite reports, since those
        // only see what actually made it into userspace.
        let flags = libc::FAN_CLASS_NOTIF
            | libc::FAN_CLOEXEC
            | libc::FAN_NONBLOCK
            | libc::FAN_UNLIMITED_QUEUE
            | libc::FAN_UNLIMITED_MARKS;
        let event_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_LARGEFILE;

        // SAFETY: fanotify_init is called with kernel-defined constants and returns an owned fd.
        let fd = unsafe { libc::fanotify_init(flags, event_flags as u32) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }

        let mut collector = Self {
            fd,
            exclude_paths: exclude_paths.to_vec(),
            restrict_to: restrict_to.to_vec(),
            include_paths: include_paths.to_vec(),
            marked_devices: HashSet::new(),
            // SAFETY: getpid() takes no arguments and cannot fail.
            self_pid: unsafe { libc::getpid() },
            file_touch_cache: HashMap::new(),
        };

        let mounts = discover_watchable_mounts(&collector.restrict_to);
        let mut marked = collector.mark_new_mounts(&mounts);
        marked += collector.mark_include_paths();

        if marked == 0 {
            // SAFETY: fd was returned by fanotify_init and is owned here.
            unsafe { libc::close(fd) };
            return Err("no filesystem mounts or include paths could be marked".into());
        }

        Ok(collector)
    }

    /// Marks every `DENDRITE_WATCH_INCLUDE_PATHS` entry whose underlying
    /// device isn't already covered by an existing filesystem-wide mark —
    /// directory-by-directory (see `collect_directories`), since these are
    /// meant to add specific extra coverage, not an entire mount. Skips an
    /// include path entirely if its device is already marked, to avoid a
    /// redundant walk over ground already covered.
    fn mark_include_paths(&mut self) -> usize {
        let mut newly_marked = 0usize;
        let mut remaining = MAX_FANOTIFY_INCLUDE_DIRECTORIES;
        for include_path in self.include_paths.clone() {
            if remaining == 0 {
                break;
            }
            if let Ok(meta) = fs::metadata(&include_path)
                && self.marked_devices.contains(&meta.dev())
            {
                continue;
            }

            let mut directories = Vec::new();
            collect_directories(&include_path, &mut directories, remaining);

            for directory in directories {
                let Some(path) = directory.to_str() else {
                    continue;
                };
                let Ok(c_path) = CString::new(path) else {
                    continue;
                };
                // SAFETY: self.fd is an owned fanotify fd and c_path is NUL-terminated for this call.
                let result = unsafe {
                    libc::fanotify_mark(
                        self.fd,
                        libc::FAN_MARK_ADD,
                        Self::MASK,
                        libc::AT_FDCWD,
                        c_path.as_ptr(),
                    )
                };
                if result == 0 {
                    newly_marked += 1;
                    remaining -= 1;
                }
                if remaining == 0 {
                    break;
                }
            }
        }
        newly_marked
    }

    /// Marks any of `mount_points` whose underlying device isn't already
    /// covered by an existing mark. Called once at startup with every
    /// discovered mount, and again periodically (piggybacking on the
    /// telemetry polling interval) to pick up mounts that appeared after
    /// startup — a USB drive, a newly-started container's overlay mount,
    /// etc. This purely extends fanotify's coverage; it does not itself
    /// generate an observation about the mount appearing (that's a
    /// potential future signal in its own right, not implemented here).
    /// Returns how many new marks were actually added.
    fn mark_new_mounts(&mut self, mount_points: &[PathBuf]) -> usize {
        let mut newly_marked = 0usize;
        for mount_point in mount_points {
            let Ok(meta) = fs::metadata(mount_point) else {
                continue;
            };
            if self.marked_devices.contains(&meta.dev()) {
                continue;
            }
            let Some(path) = mount_point.to_str() else {
                continue;
            };
            let Ok(c_path) = CString::new(path) else {
                continue;
            };
            // SAFETY: self.fd is an owned fanotify fd and c_path is NUL-terminated for this call.
            let result = unsafe {
                libc::fanotify_mark(
                    self.fd,
                    libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
                    Self::MASK,
                    libc::AT_FDCWD,
                    c_path.as_ptr(),
                )
            };
            if result == 0 {
                self.marked_devices.insert(meta.dev());
                newly_marked += 1;
            }
        }
        newly_marked
    }

    /// Re-reads `/proc/self/mountinfo` and marks any newly-appeared mount.
    /// Intended to be called on the same cadence as
    /// `DENDRITE_TELEMETRY_INTERVAL_SECONDS`. Logs to stderr when it picks
    /// up something new, purely for operator visibility — this is
    /// deliberately just coverage maintenance, not a security signal in
    /// its own right.
    fn rescan_mounts(&mut self) {
        let mounts = discover_watchable_mounts(&self.restrict_to);
        let newly_marked = self.mark_new_mounts(&mounts);
        if newly_marked > 0 {
            eprintln!(
                "fanotify: detected and began watching {newly_marked} newly-appeared mount(s)"
            );
        }
    }

    fn collect(&mut self) -> Vec<CollectedObservation> {
        let mut buffer = vec![0u8; FANOTIFY_BUFFER_BYTES];
        let mut observations = Vec::new();
        let mut dedup = HashSet::new();

        loop {
            // SAFETY: buffer is valid writable memory for the supplied length.
            let bytes = unsafe { libc::read(self.fd, buffer.as_mut_ptr().cast(), buffer.len()) };

            if bytes < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    break;
                }
                break;
            }

            if bytes == 0 {
                break;
            }

            let bytes = bytes as usize;
            let mut offset = 0usize;

            // Deliberately NOT gated on `observations.len() < MAX_EVENTS_PER_COLLECTION`:
            // every record parsed out of this buffer owns a kernel-allocated fd (fanotify
            // hands one out per event at read() time, not at close() time), and it MUST be
            // closed here regardless of whether the observation cap has already been hit.
            // Exiting this loop early while records with un-closed fds still remain in the
            // buffer leaks every one of them permanently — this is the exact cause of the
            // "too many open files" crash under heavy activity bursts: a 64KB read() can
            // return 2,700+ raw records, the observation cap (4096) can be reached mid-way
            // through a later buffer once several reads have accumulated, and every record
            // after that point used to be abandoned here with its fd never closed.
            while offset + std::mem::size_of::<FanotifyEventMetadata>() <= bytes {
                // SAFETY: bounds above guarantee enough bytes; read_unaligned handles buffer alignment.
                let metadata = unsafe {
                    std::ptr::read_unaligned(
                        buffer.as_ptr().add(offset).cast::<FanotifyEventMetadata>(),
                    )
                };

                if metadata.event_len == 0 {
                    break;
                }

                let event_len = metadata.event_len as usize;
                if offset + event_len > bytes {
                    break;
                }

                if metadata.fd >= 0 {
                    let event_fd = metadata.fd;

                    // Skip building an observation once the cap is hit — there's no point
                    // doing the work just to discard it — but `fanotify_event()` never
                    // closes `event_fd` itself on any path (see its own doc comment), so
                    // closing below is unconditional and independent of this check.
                    if observations.len() < MAX_EVENTS_PER_COLLECTION
                        && let Some(event) = fanotify_event(
                            metadata,
                            event_fd,
                            &self.exclude_paths,
                            self.self_pid,
                            &mut self.file_touch_cache,
                        )
                    {
                        let key = (
                            event.process_id,
                            event.event.clone(),
                            event
                                .observation
                                .target
                                .as_ref()
                                .map(|target| target.id.0.clone()),
                            event.observation.observed_at,
                        );
                        if dedup.insert(key) {
                            observations.push(event);
                        }
                    }

                    // SAFETY: event_fd is transferred by fanotify metadata and must be
                    // closed, whether or not an observation was built from it above.
                    unsafe { libc::close(event_fd) };
                }

                offset += event_len;
            }

            if observations.len() >= MAX_EVENTS_PER_COLLECTION {
                // Every fd in this buffer has already been closed by the loop above —
                // this only stops re-reading for more, it never abandons unclosed fds
                // the way the old cap-in-the-while-condition version did.
                break;
            }
        }

        observations
    }
}

impl Drop for FanotifyCollector {
    fn drop(&mut self) {
        // SAFETY: fd is owned by this collector and closed exactly once here.
        unsafe { libc::close(self.fd) };
    }
}

fn fanotify_event(
    metadata: FanotifyEventMetadata,
    event_fd: RawFd,
    exclude_paths: &[PathBuf],
    self_pid: i32,
    file_touch_cache: &mut HashMap<(u64, u64, PathBuf), FileTouchEntry>,
) -> Option<CollectedObservation> {
    // Checked first, before path resolution — skips that syscall too for the
    // common case (Dendrite's own routine writes to its own STM/LTM/
    // incidents/guard databases). Filtered by *who wrote it*, not by path:
    // see FanotifyCollector::self_pid's doc comment for why a path-based
    // exclude would also blind Dendrite to a different process tampering
    // with these same files.
    if metadata.pid == self_pid {
        return None;
    }
    let path = fs::read_link(format!("/proc/self/fd/{event_fd}")).ok()?;
    if is_excluded(&path, exclude_paths) {
        return None;
    }
    let path_text = path.to_string_lossy().into_owned();
    let now = unix_time();
    let pid = u32::try_from(metadata.pid).ok();

    let (kind, event, confidence) =
        if metadata.mask & (libc::FAN_MODIFY | libc::FAN_CLOSE_WRITE) != 0 {
            (ObservationKind::FileWritten, "file_written", 100)
        } else if metadata.mask & libc::FAN_OPEN != 0 {
            (ObservationKind::FileRead, "file_opened", 95)
        } else {
            return None;
        };

    // Cache dedup only applies to read opens of an unchanged file by a
    // program that's already touched it recently — see FILE_TOUCH_CACHE_TTL_SECONDS.
    // A write is always let through regardless: something changing is
    // inherently more relevant than a stale-file check can capture, and a
    // genuine content change would miss the cache anyway (mtime/size
    // wouldn't match), so scoping to reads only is a belt-and-suspenders
    // choice for something that's meant to filter noise, not decide
    // relevance.
    //
    // Deliberately uses a single, cheap `/proc/{pid}/exe` readlink here —
    // *not* the full read_process() below, which does three separate /proc
    // reads (stat, exe, status). Checking the cache first means a hit never
    // pays for process info it's about to discard; read_process() is only
    // called once we already know we're emitting an observation (a write,
    // or a read that missed the cache). This ordering is itself the fix for
    // a real cost found in practice: without it, every event pays the full
    // process-resolution cost regardless of whether the cache would have
    // suppressed it — the cache existing doesn't help if the expensive part
    // already ran before it's ever consulted.
    let mut pending_cache_entry = None;
    if kind == ObservationKind::FileRead
        && let Some(pid) = pid
        && let Ok(executable) = fs::read_link(format!("/proc/{pid}/exe"))
    {
        // SAFETY: event_fd is a valid, currently-open file descriptor for
        // the duration of this call — owned by the caller, which closes
        // it after fanotify_event returns. ManuallyDrop stops this
        // temporary File from closing it early (no double-close).
        let stat = {
            let file = std::mem::ManuallyDrop::new(unsafe { fs::File::from_raw_fd(event_fd) });
            file.metadata().ok()
        };
        if let Some(stat) = stat {
            let cache_key = (stat.dev(), stat.ino(), executable);
            let mtime = stat.mtime();
            let size = stat.size() as i64;
            if let Some(entry) = file_touch_cache.get(&cache_key)
                && entry.mtime == mtime
                && entry.size == size
                && now.saturating_sub(entry.last_seen) < FILE_TOUCH_CACHE_TTL_SECONDS
            {
                return None;
            }
            pending_cache_entry = Some((cache_key, mtime, size));
        }
    }

    // Only reached for writes, or reads that missed the cache above — i.e.
    // only when an observation is actually going to be emitted and the real
    // process descriptor (label, user_id, start_ticks, not just its
    // executable path) is genuinely needed.
    let process = pid.and_then(read_process);
    let source = process
        .as_ref()
        .map(ProcessInfo::descriptor)
        .unwrap_or_else(local_host);

    if let Some((cache_key, mtime, size)) = pending_cache_entry {
        if file_touch_cache.len() >= FILE_TOUCH_CACHE_MAX_ENTRIES {
            file_touch_cache.clear();
        }
        file_touch_cache.insert(
            cache_key,
            FileTouchEntry {
                mtime,
                size,
                last_seen: now,
            },
        );
    }

    Some(CollectedObservation {
        source: TelemetrySource::Fanotify,
        event: event.into(),
        process_id: pid,
        observation: file_observation(source, &path_text, kind, "fanotify", now, confidence),
        related_observations: Vec::new(),
    })
}

fn file_observation(
    source: ObjectDescriptor,
    path: &str,
    kind: ObservationKind,
    prefix: &str,
    now: u64,
    confidence: u8,
) -> Observation {
    Observation {
        id: ObservationId(format!(
            "{prefix}:{}:{}:{}",
            stable_hash(&source.id.0),
            stable_hash(path),
            now
        )),
        kind,
        source,
        target: Some(ObjectDescriptor {
            id: ObjectId(format!("file:{path}")),
            kind: EntityKind::File,
            label: path.into(),
            content_hash: None,
        }),
        observed_at: now,
        expires_at: Some(now.saturating_add(DEFAULT_OBSERVATION_TTL_SECONDS)),
        severity: Severity::Low,
        confidence: Confidence::new(confidence).expect("telemetry confidence is valid"),
    }
}

fn scan_files(path: &Path, files: &mut HashMap<PathBuf, FileFingerprint>, visited: &mut usize) {
    if *visited >= MAX_FILES_PER_SCAN {
        return;
    }

    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };

    if metadata.file_type().is_symlink() {
        return;
    }

    if metadata.is_file() {
        *visited += 1;
        let modified_nanos = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |duration| duration.as_nanos());

        files.insert(
            path.to_path_buf(),
            FileFingerprint {
                modified_nanos,
                len: metadata.len(),
            },
        );
        return;
    }

    if !metadata.is_dir() {
        return;
    }

    let Ok(entries) = fs::read_dir(path) else {
        return;
    };

    for entry in entries.flatten() {
        scan_files(&entry.path(), files, visited);
        if *visited >= MAX_FILES_PER_SCAN {
            break;
        }
    }
}

fn local_host() -> ObjectDescriptor {
    ObjectDescriptor {
        id: ObjectId("host:local".into()),
        kind: EntityKind::Host,
        label: "local host".into(),
        content_hash: None,
    }
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn stable_hash(value: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconciliation_poll_always_runs_when_its_event_driven_counterpart_is_absent() {
        for tick in 0..(RECONCILIATION_POLL_STRIDE * 3) {
            assert!(should_run_reconciliation_poll(tick, false));
        }
    }

    #[test]
    fn reconciliation_poll_runs_on_a_bounded_stride_when_its_counterpart_is_active() {
        let mut runs = 0u64;
        let ticks = RECONCILIATION_POLL_STRIDE * 5;
        for tick in 0..ticks {
            if should_run_reconciliation_poll(tick, true) {
                runs += 1;
            }
        }
        // Exactly one run per stride, never zero and never every tick - it's
        // a backstop, not a duplicate of the event-driven stream.
        assert_eq!(runs, ticks / RECONCILIATION_POLL_STRIDE);
        assert!(runs > 0);
        assert!(runs < ticks);
    }

    #[test]
    fn process_stat_parser_can_read_current_process() {
        let process =
            read_process(std::process::id()).expect("current process must exist in /proc");
        assert_eq!(process.pid, std::process::id());
        assert!(process.start_ticks > 0);
    }

    #[test]
    fn mountinfo_parser_extracts_mount_point_and_fstype() {
        let sample = "36 35 98:0 / /mnt1 rw,noatime master:1 - ext3 /dev/root rw,errors=continue\n\
                       21 25 0:19 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw";
        let mounts = parse_mountinfo(sample);
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0], (PathBuf::from("/mnt1"), "ext3".to_string()));
        assert_eq!(mounts[1], (PathBuf::from("/proc"), "proc".to_string()));
    }

    #[test]
    fn mountinfo_paths_with_escaped_whitespace_are_unescaped() {
        // A USB drive labelled "My Drive" mounts with the space escaped as \040.
        assert_eq!(
            unescape_mountinfo_path(r"/media/user/My\040Drive"),
            "/media/user/My Drive"
        );
    }

    #[test]
    fn discover_watchable_mounts_excludes_pseudo_filesystems_and_reads_the_real_root() {
        // Reads this sandbox's own real /proc/self/mountinfo — not a fixture — so this
        // doubles as a smoke test that discovery works against a genuine kernel-provided file.
        let mounts = discover_watchable_mounts(&[]);
        assert!(
            mounts.contains(&PathBuf::from("/")),
            "root filesystem must be discovered: {mounts:?}"
        );
        assert!(
            !mounts.iter().any(|mount| mount == Path::new("/proc")),
            "a pseudo-filesystem must not be in the discovered set: {mounts:?}"
        );
    }

    #[test]
    fn discover_watchable_mounts_respects_a_restrict_list() {
        let restrict = vec![PathBuf::from("/this-mount-point-does-not-exist")];
        let mounts = discover_watchable_mounts(&restrict);
        assert!(
            mounts.is_empty(),
            "restricting to an unmounted path must yield nothing"
        );
    }

    #[test]
    fn exclude_paths_match_by_path_component_not_raw_string_prefix() {
        let excluded = vec![PathBuf::from("/etc")];
        assert!(is_excluded(Path::new("/etc/passwd"), &excluded));
        assert!(is_excluded(Path::new("/etc"), &excluded));
        // A raw string prefix match would incorrectly exclude this; a path-component match must not.
        assert!(!is_excluded(Path::new("/etc-backup/passwd"), &excluded));
        assert!(!is_excluded(Path::new("/var/log"), &excluded));
    }

    #[test]
    fn watch_path_collision_detects_exclude_containing_include() {
        let include = vec![PathBuf::from("/etc/important")];
        let exclude = vec![PathBuf::from("/etc")];
        assert!(find_watch_path_collision(&include, &exclude).is_some());
    }

    #[test]
    fn watch_path_collision_detects_include_containing_exclude() {
        let include = vec![PathBuf::from("/data")];
        let exclude = vec![PathBuf::from("/data/cache")];
        assert!(find_watch_path_collision(&include, &exclude).is_some());
    }

    #[test]
    fn watch_path_collision_detects_exact_equality() {
        let include = vec![PathBuf::from("/srv/app")];
        let exclude = vec![PathBuf::from("/srv/app")];
        assert!(find_watch_path_collision(&include, &exclude).is_some());
    }

    #[test]
    fn watch_path_collision_is_none_for_genuinely_unrelated_paths() {
        let include = vec![PathBuf::from("/srv/app")];
        let exclude = vec![PathBuf::from("/etc"), PathBuf::from("/tmp")];
        assert!(find_watch_path_collision(&include, &exclude).is_none());
        // A sibling with a shared string prefix but a different path component must not collide.
        let include = vec![PathBuf::from("/etc-backup")];
        let exclude = vec![PathBuf::from("/etc")];
        assert!(find_watch_path_collision(&include, &exclude).is_none());
    }

    #[test]
    fn stable_hash_is_deterministic() {
        assert_eq!(stable_hash("/tmp/example"), stable_hash("/tmp/example"));
        assert_ne!(stable_hash("/tmp/example"), stable_hash("/tmp/other"));
    }

    #[test]
    fn unresolved_ebpf_processes_collapse_to_stable_command_identity() {
        let mut comm = [0u8; 16];
        comm[..3].copy_from_slice(b"cat");
        let first = unresolved_process_descriptor(101, &comm);
        let second = unresolved_process_descriptor(202, &comm);
        assert_eq!(first.id, second.id);
        assert_eq!(first.label, "cat");
        assert!(first.id.0.starts_with("process_identity:comm:"));
    }

    #[test]
    fn resolved_process_descriptor_from_event_distinguishes_same_name_different_processes() {
        let mut comm = [0u8; 16];
        comm[..3].copy_from_slice(b"cat");
        let mut real = EbpfEvent::zeroed(EVENT_PROCESS_EXEC);
        real.comm = comm;
        real.start_ticks = 12_345;
        let mut malicious = EbpfEvent::zeroed(EVENT_PROCESS_EXEC);
        malicious.comm = comm;
        malicious.start_ticks = 67_890;

        let first = resolved_process_descriptor_from_event(101, &real);
        let second = resolved_process_descriptor_from_event(202, &malicious);

        // Unlike unresolved_process_descriptor (same comm always collapses
        // to the same id), two different real processes never collide here
        // - this is the actual fix for the masquerade gap: a same-named
        // process on a different pid/start_ticks is a different identity.
        assert_ne!(first.id, second.id);
        assert_eq!(first.id.0, "process:101:12345");
        assert_eq!(first.label, "cat");
    }

    #[test]
    fn resolved_process_descriptor_from_event_matches_proc_derived_id_scheme() {
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"bash");
        let mut event = EbpfEvent::zeroed(EVENT_PROCESS_EXEC);
        event.comm = comm;
        event.start_ticks = 555;

        let descriptor = resolved_process_descriptor_from_event(42, &event);

        // Must be the identical scheme ProcessInfo::descriptor() (the
        // /proc-derived path) produces, so an eBPF-resolved node and a
        // later /proc-reconciliation poll of the same real process land on
        // the same MemoryNodeId rather than two separate nodes for one
        // process.
        assert_eq!(descriptor.id.0, "process:42:555");
    }

    #[test]
    fn ebpf_observation_falls_back_to_unresolved_identity_when_kernel_capture_is_absent() {
        // A pid picked to (overwhelmingly likely) not exist, so
        // read_process() inside ebpf_observation() returns None - this
        // isolates the fallback-selection logic itself rather than
        // depending on the state of any real running process.
        let bogus_pid = u32::MAX - 17;
        let mut comm = [0u8; 16];
        comm[..2].copy_from_slice(b"sh");
        let mut event = EbpfEvent::zeroed(EVENT_PROCESS_EXEC);
        event.pid = bogus_pid;
        event.tgid = bogus_pid;
        event.comm = comm;
        // start_ticks left at 0: simulates an older eBPF build, or a
        // kernel-side capture failure, that predates/lacks this field.

        let collected =
            ebpf_observation(event, 0).expect("EVENT_PROCESS_EXEC always yields an observation");

        assert!(
            collected
                .observation
                .source
                .id
                .0
                .starts_with("process_identity:comm:")
        );
    }

    #[test]
    fn ebpf_observation_uses_resolved_identity_when_kernel_capture_beat_the_proc_race() {
        let bogus_pid = u32::MAX - 18;
        let mut comm = [0u8; 16];
        comm[..2].copy_from_slice(b"sh");
        let mut event = EbpfEvent::zeroed(EVENT_PROCESS_EXEC);
        event.pid = bogus_pid;
        event.tgid = bogus_pid;
        event.comm = comm;
        event.start_ticks = 999;

        let collected =
            ebpf_observation(event, 0).expect("EVENT_PROCESS_EXEC always yields an observation");

        assert_eq!(
            collected.observation.source.id.0,
            format!("process:{bogus_pid}:999")
        );
    }

    #[test]
    fn ebpf_event_layout_is_stable() {
        // Grew from 64 to 96 bytes when parent_pid/start_ticks/uid/exe_dev/
        // exe_ino were added (sched_process_exec capture extension) - this
        // pin exists so a future field addition/reordering is a deliberate,
        // reviewed change to this test, not a silent layout shift between
        // what the kernel side emits and what this parser expects.
        assert_eq!(std::mem::size_of::<EbpfEvent>(), 96);
        assert_eq!(std::mem::align_of::<EbpfEvent>(), 8);
    }

    #[test]
    fn ebpf_endpoint_formats_ipv4_and_ipv6() {
        assert_eq!(
            format_endpoint(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8766),
            "127.0.0.1:8766"
        );
        assert_eq!(
            format_endpoint(IpAddr::V6(Ipv6Addr::LOCALHOST), 8766),
            "[::1]:8766"
        );
    }

    #[test]
    fn ebpf_command_trims_nul_padding() {
        let mut command = [0u8; 16];
        command[..4].copy_from_slice(b"curl");
        assert_eq!(ebpf_comm(&command).as_deref(), Some("curl"));
    }

    #[test]
    fn source_names_are_stable() {
        assert_eq!(TelemetrySource::ProcPolling.as_str(), "proc_polling");
        assert_eq!(
            TelemetrySource::FilesystemPolling.as_str(),
            "filesystem_polling"
        );
        assert_eq!(TelemetrySource::Fanotify.as_str(), "fanotify");
        assert_eq!(TelemetrySource::Ebpf.as_str(), "ebpf");
    }

    #[test]
    fn scope_names_and_reasoning_policy_are_stable() {
        assert_eq!(TelemetryScope::Host.as_str(), "host");
        assert_eq!(
            TelemetryScope::DendriteControlPlane.as_str(),
            "dendrite_control_plane"
        );
        assert!(TelemetryScope::Host.feeds_security_reasoning());
        assert!(!TelemetryScope::DendriteControlPlane.feeds_security_reasoning());
    }

    #[test]
    fn dendrite_process_classification_is_exact() {
        assert!(is_dendrite_process("dendrited"));
        assert!(is_dendrite_process("dendrite-cli"));
        assert!(is_dendrite_process("dendrite-ui"));
        assert!(!is_dendrite_process("dendrited-malware"));
        assert!(!is_dendrite_process("firefox"));
    }
}
