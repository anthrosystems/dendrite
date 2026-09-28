#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_comm, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
        bpf_probe_read_user,
    },
    macros::{kprobe, map, tracepoint},
    maps::RingBuf,
    programs::{ProbeContext, TracePointContext},
};
use dendrite_ebpf_common::{
    ADDRESS_FAMILY_INET, ADDRESS_FAMILY_INET6, EVENT_NETWORK_CONNECT, EVENT_PROCESS_EXEC, EbpfEvent,
};
use vmlinux::task_struct;

/// `USER_HZ` — technically a configurable kernel constant, but fixed at 100
/// on every mainstream Linux distribution for ABI-stability reasons. See
/// `EbpfEvent::start_ticks`'s doc comment (`dendrite-ebpf-common`) for why
/// this has to match `/proc/<pid>/stat`'s own units exactly.
const NANOS_PER_TICK: u64 = 1_000_000_000 / 100;

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

// Bumped from 256 KiB alongside `EbpfEvent` growing by `MAX_EXE_PATH_LEN`
// (256) bytes for `exe_path` - keeping the byte size fixed would have cut
// buffered-event headroom by more than 3x (96 -> 352 bytes/event) for free,
// which matters given `dendrited`'s own routine-lane ingestion has been
// observed falling behind under load (see the routine-lane backlog
// discussion in ROADMAP.md / the telemetry-overhaul commit history) - a
// smaller effective buffer means events start getting dropped sooner during
// exactly that kind of backlog, not just theoretically. 1 MiB keeps
// buffered-event count roughly at parity with the original 256 KiB / 96
// bytes sizing rather than regressing it.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn {
    family: u16,
    port: u16,
    address: [u8; 4],
    zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn6 {
    family: u16,
    port: u16,
    flowinfo: u32,
    address: [u8; 16],
    scope_id: u32,
}

#[tracepoint(category = "sched", name = "sched_process_exec")]
pub fn dendrite_process_exec(ctx: TracePointContext) -> u32 {
    match try_process_exec(ctx) {
        Ok(()) => 0,
        Err(code) => code,
    }
}

fn try_process_exec(ctx: TracePointContext) -> Result<(), u32> {
    let mut event = base_event(EVENT_PROCESS_EXEC, &ctx);
    event.comm = bpf_get_current_comm().unwrap_or([0; 16]);
    capture_process_identity(&mut event);
    capture_exec_path(&ctx, &mut event);
    EVENTS.output::<EbpfEvent>(&event, 0).map_err(|_| 1u32)
}

/// Byte offset of the `filename` `__data_loc` field within the
/// `sched:sched_process_exec` tracepoint's own record. Verified directly
/// against a running kernel's own
/// `/sys/kernel/tracing/events/sched/sched_process_exec/format`:
///
/// ```text
/// field:unsigned short common_type;          offset:0;  size:2;
/// field:unsigned char common_flags;          offset:2;  size:1;
/// field:unsigned char common_preempt_count;  offset:3;  size:1;
/// field:int common_pid;                      offset:4;  size:4;
/// field:__data_loc char[] filename;          offset:8;  size:4;
/// field:pid_t pid;                           offset:12; size:4;
/// field:pid_t old_pid;                       offset:16; size:4;
/// ```
///
/// Unlike `vmlinux.rs`'s `task_struct`/`mm_struct`/`file` bindings (see
/// that file's own doc comment and the eBPF README's "src/vmlinux.rs"
/// section), this is *not* a fragile internal-struct-layout dependency:
/// tracepoint record formats are part of the kernel's documented,
/// user-facing tracing ABI - that's the entire reason the `format` file
/// under tracefs exists and is readable without special privilege beyond
/// tracefs access. This specific field has sat at this offset, in this
/// common-header-then-filename order, essentially unchanged for the
/// lifetime of this tracepoint. Still, if `capture_exec_path` ever starts
/// coming back consistently empty after a kernel upgrade, re-verify with
/// `cat /sys/kernel/tracing/events/sched/sched_process_exec/format` before
/// assuming anything else is wrong.
const SCHED_PROCESS_EXEC_FILENAME_DATA_LOC_OFFSET: usize = 8;

/// Reads the executable's absolute path directly out of the
/// `sched_process_exec` tracepoint's own `filename` argument, into
/// `event.exe_path`. A `__data_loc` field doesn't hold the string itself at
/// its fixed offset - only a `(relative_offset: u16, length: u16)` pair (packed
/// into one `u32`, low bits first) pointing at where the string actually
/// lives further into the same tracepoint record. This is a different
/// mechanism from `capture_process_identity`'s `task_struct` walk above -
/// no pointer chasing, no null checks along a chain: the whole record,
/// filename included, is already sitting in the tracepoint's own buffer
/// (`ctx.as_ptr()`), synchronously, at exec time - which is what makes this
/// just as race-free against the process's own exit as `parent_pid`/
/// `start_ticks`/`uid` are.
///
/// Best-effort like every other field this program captures: a failed read
/// at either step just leaves `event.exe_path` at its `EbpfEvent::zeroed()`
/// all-zero default rather than discarding the whole event.
fn capture_exec_path(ctx: &TracePointContext, event: &mut EbpfEvent) {
    let Ok(data_loc) =
        (unsafe { ctx.read_at::<u32>(SCHED_PROCESS_EXEC_FILENAME_DATA_LOC_OFFSET) })
    else {
        return;
    };

    // The kernel's own `__data_loc` encoding (not specific to this
    // tracepoint): low 16 bits are the string's byte offset from the start
    // of this tracepoint's record, high 16 bits are its length (unused
    // here - `bpf_probe_read_kernel_str_bytes` below finds its own NUL
    // terminator, bounded by `event.exe_path`'s fixed size regardless).
    let rel_offset = (data_loc & 0xffff) as usize;

    // SAFETY: `ctx.as_ptr()` points at this tracepoint's own record, which
    // `read_at` above already read from successfully; `rel_offset` came
    // from that same record's own `__data_loc` field, so this stays within
    // the record `bpf_probe_read_kernel_str_bytes` is allowed to read from.
    let _ = unsafe {
        bpf_probe_read_kernel_str_bytes(
            ctx.as_ptr().add(rel_offset).cast::<u8>(),
            &mut event.exe_path,
        )
    };
}

/// Reads identity fields directly out of the current task's `task_struct`
/// (and whatever it points to) at exec time, synchronously and in-kernel -
/// this is what lets `dendrited` stop relying on a later `/proc/<pid>/...`
/// read that races the process's own exit and silently produces nothing
/// when it loses (see `read_process()` in `telemetry.rs`).
///
/// Every step is independently best-effort: a null pointer or a failed
/// `bpf_probe_read_kernel` anywhere along a chain just leaves the
/// remaining fields at `EbpfEvent::zeroed()`'s `0` rather than discarding
/// the whole event - `comm` alone is still useful even when, say, this
/// process has no backing executable file to read `exe_dev`/`exe_ino`
/// from. Each `bpf_probe_read_kernel` call here only ever copies a single
/// pointer or small scalar field (never a whole struct by value), which is
/// what keeps this within the eBPF stack's tight size limit.
fn capture_process_identity(event: &mut EbpfEvent) {
    // SAFETY: bpf_get_current_task() always returns a valid pointer to the
    // task_struct currently executing this program - guaranteed by the
    // helper's own contract, not something this code can get wrong.
    let task =
        unsafe { aya_ebpf::helpers::generated::bpf_get_current_task() } as *const task_struct;

    if let Ok(start_boottime) =
        unsafe { bpf_probe_read_kernel(core::ptr::addr_of!((*task).start_boottime)) }
    {
        event.start_ticks = start_boottime / NANOS_PER_TICK;
    }

    if let Ok(real_parent) =
        unsafe { bpf_probe_read_kernel(core::ptr::addr_of!((*task).real_parent)) }
        && !real_parent.is_null()
        && let Ok(parent_tgid) =
            unsafe { bpf_probe_read_kernel(core::ptr::addr_of!((*real_parent).tgid)) }
    {
        event.parent_pid = parent_tgid as u32;
    }

    if let Ok(real_cred) = unsafe { bpf_probe_read_kernel(core::ptr::addr_of!((*task).real_cred)) }
        && !real_cred.is_null()
        && let Ok(uid) = unsafe { bpf_probe_read_kernel(core::ptr::addr_of!((*real_cred).uid)) }
    {
        event.uid = uid.val;
    }

    capture_executable_identity(task, event);
}

/// The `mm -> exe_file -> f_inode -> (i_sb->s_dev, i_ino)` chain, split out
/// of `capture_process_identity` purely for readability - it's the deepest
/// and least likely to resolve (a kernel thread or a process past its own
/// `mm` teardown has no `mm` at all), so it's worth being able to see it
/// fail independently of the parent/uid reads above.
fn capture_executable_identity(task: *const task_struct, event: &mut EbpfEvent) {
    let Ok(mm) = (unsafe { bpf_probe_read_kernel(core::ptr::addr_of!((*task).mm)) }) else {
        return;
    };
    if mm.is_null() {
        return;
    }

    let Ok(exe_file) =
        (unsafe { bpf_probe_read_kernel(core::ptr::addr_of!((*mm).__bindgen_anon_1.exe_file)) })
    else {
        return;
    };
    if exe_file.is_null() {
        return;
    }

    let Ok(f_inode) = (unsafe { bpf_probe_read_kernel(core::ptr::addr_of!((*exe_file).f_inode)) })
    else {
        return;
    };
    if f_inode.is_null() {
        return;
    }

    if let Ok(i_ino) = unsafe { bpf_probe_read_kernel(core::ptr::addr_of!((*f_inode).i_ino)) } {
        // `i_ino`'s bound type (`c_ulong`) is 64 bits on this target but is
        // not fixed-width in general - the cast is deliberate, not
        // redundant, even where clippy sees it as a same-type no-op today.
        #[allow(clippy::unnecessary_cast)]
        {
            event.exe_ino = i_ino as u64;
        }
    }

    if let Ok(i_sb) = unsafe { bpf_probe_read_kernel(core::ptr::addr_of!((*f_inode).i_sb)) }
        && !i_sb.is_null()
        && let Ok(s_dev) = unsafe { bpf_probe_read_kernel(core::ptr::addr_of!((*i_sb).s_dev)) }
    {
        event.exe_dev = s_dev;
    }
}

#[kprobe]
pub fn dendrite_connect(ctx: ProbeContext) -> u32 {
    match try_connect(ctx) {
        Ok(()) => 0,
        Err(code) => code,
    }
}

fn try_connect(ctx: ProbeContext) -> Result<(), u32> {
    let sockaddr: *const u8 = ctx.arg(1).ok_or(1u32)?;
    let family = unsafe { bpf_probe_read_user(sockaddr.cast::<u16>()) }.map_err(|_| 2u32)?;

    let mut event = base_event(EVENT_NETWORK_CONNECT, &ctx);
    event.comm = bpf_get_current_comm().unwrap_or([0; 16]);

    match family as u8 {
        ADDRESS_FAMILY_INET => {
            let value =
                unsafe { bpf_probe_read_user(sockaddr.cast::<SockAddrIn>()) }.map_err(|_| 3u32)?;
            event.family = ADDRESS_FAMILY_INET;
            event.port = u16::from_be(value.port);
            event.address[..4].copy_from_slice(&value.address);
        }
        ADDRESS_FAMILY_INET6 => {
            let value =
                unsafe { bpf_probe_read_user(sockaddr.cast::<SockAddrIn6>()) }.map_err(|_| 4u32)?;
            event.family = ADDRESS_FAMILY_INET6;
            event.port = u16::from_be(value.port);
            event.address = value.address;
        }
        _ => return Ok(()),
    }

    EVENTS.output::<EbpfEvent>(&event, 0).map_err(|_| 5u32)
}

fn base_event<C: EbpfContext>(kind: u8, ctx: &C) -> EbpfEvent {
    let mut event = EbpfEvent::zeroed(kind);
    event.pid = ctx.pid();
    event.tgid = ctx.tgid();
    // bpf_ktime_get_ns is represented by the helper behind context-independent kernel time.
    event.timestamp_ns = unsafe { aya_ebpf::helpers::generated::bpf_ktime_get_ns() };
    event
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
