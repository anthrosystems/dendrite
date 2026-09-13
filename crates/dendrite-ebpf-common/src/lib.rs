#![no_std]

pub const EVENT_PROCESS_EXEC: u8 = 1;
pub const EVENT_NETWORK_CONNECT: u8 = 2;
pub const ADDRESS_FAMILY_INET: u8 = 2;
pub const ADDRESS_FAMILY_INET6: u8 = 10;
pub const COMM_LEN: usize = 16;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EbpfEvent {
    pub kind: u8,
    pub family: u8,
    pub _reserved0: [u8; 2],
    pub pid: u32,
    pub tgid: u32,
    pub _reserved1: u32,
    pub timestamp_ns: u64,
    pub port: u16,
    pub _reserved2: [u8; 6],
    pub address: [u8; 16],
    pub comm: [u8; COMM_LEN],
}

impl EbpfEvent {
    pub const fn zeroed(kind: u8) -> Self {
        Self {
            kind,
            family: 0,
            _reserved0: [0; 2],
            pid: 0,
            tgid: 0,
            _reserved1: 0,
            timestamp_ns: 0,
            port: 0,
            _reserved2: [0; 6],
            address: [0; 16],
            comm: [0; COMM_LEN],
        }
    }
}
