use dendrite_protocol::{
    Confidence, EntityKind, ObjectDescriptor, ObjectId, Observation, ObservationId,
    ObservationKind, Severity, TelemetrySourceDto,
};
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_OBSERVATION_TTL_SECONDS: u64 = 3_600;
const MAX_FILES_PER_SCAN: usize = 10_000;
const MAX_FANOTIFY_DIRECTORIES: usize = 4_096;
const FANOTIFY_BUFFER_BYTES: usize = 64 * 1024;

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

#[derive(Debug, Clone)]
pub struct CollectedObservation {
    pub source: TelemetrySource,
    pub event: String,
    pub process_id: Option<u32>,
    pub observation: Observation,
}

pub struct TelemetryManager {
    processes: ProcessCollector,
    filesystem: FilesystemCollector,
    fanotify: Option<FanotifyCollector>,
    fanotify_status: TelemetrySourceDto,
}

impl TelemetryManager {
    pub fn new(watch_paths: Vec<PathBuf>, fanotify_enabled: bool) -> Self {
        let (fanotify, fanotify_status) = if fanotify_enabled && !watch_paths.is_empty() {
            match FanotifyCollector::new(&watch_paths) {
                Ok(collector) => (
                    Some(collector),
                    TelemetrySourceDto {
                        source: TelemetrySource::Fanotify.as_str().into(),
                        status: "active".into(),
                        detail: "Linux fanotify event collection active".into(),
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
                    detail: if fanotify_enabled {
                        "No filesystem watch paths configured".into()
                    } else {
                        "Set DENDRITE_FANOTIFY=1 to enable".into()
                    },
                },
            )
        };

        Self {
            processes: ProcessCollector::new(),
            filesystem: FilesystemCollector::new(watch_paths),
            fanotify,
            fanotify_status,
        }
    }

    pub fn collect(&mut self) -> Vec<CollectedObservation> {
        let mut observations = self.processes.collect();

        if let Some(fanotify) = &mut self.fanotify {
            observations.extend(fanotify.collect());
        } else {
            observations.extend(self.filesystem.collect());
        }

        observations
    }

    pub fn status(&self) -> Vec<TelemetrySourceDto> {
        vec![
            TelemetrySourceDto {
                source: TelemetrySource::ProcPolling.as_str().into(),
                status: "active".into(),
                detail: "/proc process discovery fallback".into(),
            },
            if self.fanotify.is_some() {
                TelemetrySourceDto {
                    source: TelemetrySource::FilesystemPolling.as_str().into(),
                    status: "standby".into(),
                    detail: "Polling fallback is not used while fanotify is active".into(),
                }
            } else {
                TelemetrySourceDto {
                    source: TelemetrySource::FilesystemPolling.as_str().into(),
                    status: "active".into(),
                    detail: "Filesystem metadata polling fallback".into(),
                }
            },
            self.fanotify_status.clone(),
            TelemetrySourceDto {
                source: TelemetrySource::Ebpf.as_str().into(),
                status: "not_built".into(),
                detail: "eBPF collector is reserved for Batch 5B".into(),
            },
        ]
    }
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
}

impl ProcessInfo {
    fn descriptor(&self) -> ObjectDescriptor {
        ObjectDescriptor {
            id: ObjectId(self.id.clone()),
            kind: EntityKind::Process,
            label: self.label.clone(),
        }
    }
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

    Some(ProcessInfo {
        pid,
        parent_pid,
        start_ticks,
        id: format!("process:{pid}:{start_ticks}"),
        label,
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

struct FanotifyCollector {
    fd: RawFd,
}

impl FanotifyCollector {
    fn new(watch_paths: &[PathBuf]) -> Result<Self, String> {
        let flags = libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK;
        let event_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_LARGEFILE;

        // SAFETY: fanotify_init is called with kernel-defined constants and returns an owned fd.
        let fd = unsafe { libc::fanotify_init(flags, event_flags as u32) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }

        let mut marked = 0usize;
        for root in watch_paths {
            let mut directories = Vec::new();
            collect_directories(root, &mut directories, MAX_FANOTIFY_DIRECTORIES - marked);

            for directory in directories {
                let Some(path) = directory.to_str() else {
                    continue;
                };
                let Ok(c_path) = CString::new(path) else {
                    continue;
                };

                let mask = libc::FAN_OPEN
                    | libc::FAN_MODIFY
                    | libc::FAN_CLOSE_WRITE
                    | libc::FAN_EVENT_ON_CHILD;

                // SAFETY: fd is an owned fanotify fd and c_path is NUL-terminated for this call.
                let result = unsafe {
                    libc::fanotify_mark(
                        fd,
                        libc::FAN_MARK_ADD,
                        mask,
                        libc::AT_FDCWD,
                        c_path.as_ptr(),
                    )
                };

                if result == 0 {
                    marked += 1;
                }

                if marked >= MAX_FANOTIFY_DIRECTORIES {
                    break;
                }
            }

            if marked >= MAX_FANOTIFY_DIRECTORIES {
                break;
            }
        }

        if marked == 0 {
            // SAFETY: fd was returned by fanotify_init and is owned here.
            unsafe { libc::close(fd) };
            return Err("no watch directories could be marked".into());
        }

        Ok(Self { fd })
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
                    if let Some(event) = fanotify_event(metadata, event_fd) {
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

                    // SAFETY: event_fd is transferred by fanotify metadata and must be closed.
                    unsafe { libc::close(event_fd) };
                }

                offset += event_len;
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
) -> Option<CollectedObservation> {
    let path = fs::read_link(format!("/proc/self/fd/{event_fd}")).ok()?;
    let path_text = path.to_string_lossy().into_owned();
    let now = unix_time();
    let pid = u32::try_from(metadata.pid).ok();

    let process = pid.and_then(read_process);
    let source = process
        .as_ref()
        .map(ProcessInfo::descriptor)
        .unwrap_or_else(local_host);

    let (kind, event, confidence) =
        if metadata.mask & (libc::FAN_MODIFY | libc::FAN_CLOSE_WRITE) != 0 {
            (ObservationKind::FileWritten, "file_written", 100)
        } else if metadata.mask & libc::FAN_OPEN != 0 {
            (ObservationKind::FileRead, "file_opened", 95)
        } else {
            return None;
        };

    Some(CollectedObservation {
        source: TelemetrySource::Fanotify,
        event: event.into(),
        process_id: pid,
        observation: file_observation(source, &path_text, kind, "fanotify", now, confidence),
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
        }),
        observed_at: now,
        expires_at: Some(now.saturating_add(DEFAULT_OBSERVATION_TTL_SECONDS)),
        severity: Severity::Low,
        confidence: Confidence::new(confidence).expect("telemetry confidence is valid"),
    }
}

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
    fn process_stat_parser_can_read_current_process() {
        let process =
            read_process(std::process::id()).expect("current process must exist in /proc");
        assert_eq!(process.pid, std::process::id());
        assert!(process.start_ticks > 0);
    }

    #[test]
    fn stable_hash_is_deterministic() {
        assert_eq!(stable_hash("/tmp/example"), stable_hash("/tmp/example"));
        assert_ne!(stable_hash("/tmp/example"), stable_hash("/tmp/other"));
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
}
