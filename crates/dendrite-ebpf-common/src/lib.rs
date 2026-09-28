#![no_std]

pub const EVENT_PROCESS_EXEC: u8 = 1;
pub const EVENT_NETWORK_CONNECT: u8 = 2;
pub const ADDRESS_FAMILY_INET: u8 = 2;
pub const ADDRESS_FAMILY_INET6: u8 = 10;
pub const COMM_LEN: usize = 16;

/// Fields below `comm` (`parent_pid` through `exe_ino`) are only populated
/// on `EVENT_PROCESS_EXEC` and only when the corresponding kernel read at
/// the `sched_process_exec` tracepoint succeeds — a null `real_parent`,
/// `mm`, `real_cred`, `exe_file`, or `f_inode` along that chain simply
/// leaves the field at `0`. `0` is never a valid value for any of these in
/// practice (pid 0 is swapper/idle, uid 0 read failure vs. genuine root is
/// disambiguated downstream by parent_pid/start_ticks also being present),
/// so callers treat `0` as "unavailable," not as a real reading.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EbpfEvent {
    pub kind: u8,
    pub family: u8,
    pub _reserved0: [u8; 2],
    pub pid: u32,
    pub tgid: u32,
    /// `task_struct->real_cred->uid.val`, read synchronously at exec — see
    /// `read_process()` in `dendrited`'s `telemetry.rs` for the `/proc`
    /// equivalent this replaces (which races the process's own exit).
    pub uid: u32,
    pub timestamp_ns: u64,
    pub port: u16,
    pub _reserved2: [u8; 6],
    pub address: [u8; 16],
    pub comm: [u8; COMM_LEN],
    /// `task_struct->real_parent->tgid`.
    pub parent_pid: u32,
    pub _reserved3: [u8; 4],
    /// `task_struct->start_boottime`, converted from kernel nanoseconds to
    /// `USER_HZ` (100) clock ticks — the same unit and meaning as field 22
    /// ("starttime") of `/proc/<pid>/stat`, so a `process:{pid}:{start_ticks}`
    /// identity computed from this matches one computed by `read_process()`
    /// for the same real process. Deliberately hardcodes `USER_HZ = 100`:
    /// it is technically a configurable kernel constant, but has been fixed
    /// at 100 on every mainstream Linux distribution for ABI-stability
    /// reasons for decades, and `/proc/<pid>/stat` itself offers no way to
    /// discover a different value at runtime either.
    pub start_ticks: u64,
    /// `(dev, inode)` of the executable backing this exec, from
    /// `task_struct->mm->exe_file->f_inode`: `inode->i_sb->s_dev` and
    /// `inode->i_ino`. Identifies the file on disk, not the process, so a
    /// content hash keyed on this pair can be computed and cached
    /// independently of whether this process is still alive by the time
    /// the hash job runs. Not yet consumed by a hasher — plumbed through
    /// now so that work has a race-free key to build on.
    pub exe_dev: u32,
    pub _reserved4: [u8; 4],
    pub exe_ino: u64,
}

impl EbpfEvent {
    pub const fn zeroed(kind: u8) -> Self {
        Self {
            kind,
            family: 0,
            _reserved0: [0; 2],
            pid: 0,
            tgid: 0,
            uid: 0,
            timestamp_ns: 0,
            port: 0,
            _reserved2: [0; 6],
            address: [0; 16],
            comm: [0; COMM_LEN],
            parent_pid: 0,
            _reserved3: [0; 4],
            start_ticks: 0,
            exe_dev: 0,
            _reserved4: [0; 4],
            exe_ino: 0,
        }
    }
}
