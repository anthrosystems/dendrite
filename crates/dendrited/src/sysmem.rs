//! Heap-trimming helper for the long-running daemon process.
//!
//! Rust's default allocator on Linux is glibc's `malloc`, which does not
//! return freed heap back to the kernel as a matter of course — freed
//! arenas are kept around so future allocations of similar size can be
//! satisfied without another `brk`/`mmap` round trip. That's the right
//! default for most processes, but it means a daemon whose live memory
//! usage genuinely goes up and back down (e.g. the Memory Graph growing
//! to several thousand STM nodes under a burst of activity, then decaying
//! back down at the next lifecycle sweep) can show RSS that climbs to the
//! peak and then plateaus there indefinitely, even though the actual
//! live data shrank back down. That's allocator retention, not a leak —
//! but it looks identical to one from the outside (`systemctl status`'s
//! `Memory:` figure never coming back down), so it's worth actively
//! releasing the freed-but-retained heap back to the OS on a schedule,
//! rather than leaving it to look unexplained.
//!
//! `malloc_trim(0)` asks glibc to give back whatever contiguous freed
//! space at the top of the heap (and freed mmap'd chunks) it can. It's
//! a real (if coarse) syscall-driven operation — walking arenas and doing
//! the `brk`/`munmap` calls — so this is called on the same cadence as
//! the memory lifecycle sweep (every 30s) rather than after every
//! ingestion batch.

#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub fn trim_heap() {
    // Safety: `malloc_trim` is glibc's own maintenance entry point, takes
    // no ownership of anything, and is safe to call from any thread at
    // any time — it only ever frees memory already returned to the
    // allocator, never memory still reachable from live Rust values.
    unsafe {
        libc::malloc_trim(0);
    }
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub fn trim_heap() {
    // No-op on non-glibc targets (musl statically returns freed pages far
    // more eagerly already, and has no malloc_trim to call).
}
