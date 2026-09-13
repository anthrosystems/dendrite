#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_probe_read_user},
    macros::{kprobe, map, tracepoint},
    maps::RingBuf,
    programs::{ProbeContext, TracePointContext},
    EbpfContext,
};
use dendrite_ebpf_common::{
    EbpfEvent, ADDRESS_FAMILY_INET, ADDRESS_FAMILY_INET6, EVENT_NETWORK_CONNECT, EVENT_PROCESS_EXEC,
};

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
    EVENTS.output::<EbpfEvent>(&event, 0).map_err(|_| 1u32)
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
