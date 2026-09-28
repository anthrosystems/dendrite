#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{
    EbpfContext,
    helpers::{bpf_get_current_comm, bpf_probe_read_kernel, bpf_probe_read_user},
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

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

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
    EVENTS.output::<EbpfEvent>(&event, 0).map_err(|_| 1u32)
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
