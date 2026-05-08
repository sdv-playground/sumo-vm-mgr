//! QNX 7.1 default `SensorReader` — best-effort generic metrics.
//!
//! QNX doesn't expose a Linux-style `/proc/stat` or `/sys/class/hwmon`,
//! so the generic reader is intentionally thin. It emits:
//!
//! - `host_cpu_count` from `sysconf(_SC_NPROCESSORS_ONLN)`
//! - `host_uptime_seconds` from `clock_gettime(CLOCK_MONOTONIC)` since
//!   process start (close enough — most QNX consumers care about elapsed
//!   time, not wall-clock-since-boot)
//! - `host_memory_bytes{state}` derived from `sysconf(_SC_PHYS_PAGES)` and
//!   `sysconf(_SC_PAGE_SIZE)` when both are positive
//!
//! Load average is intentionally **not** in the default — `getloadavg(3)`
//! lives in QNX's libutil (not libc), and the rust `libc` crate's QNX
//! bindings don't expose it. A board-specific reader can pull it in via
//! libutil if needed.
//!
//! Per-CPU usage, hardware temperatures, voltages, fan speeds, and eMMC
//! wear levels are **not** in the default — they require board-specific
//! drivers / `devctl()` calls. Production hardware readers (e.g. NXP
//! S32G3) live in `supernova-machine-manager` and emit those on top.
//!
//! ## Compile-target awareness
//!
//! This module is `#[cfg(target_os = "nto")]`. It compiles against the
//! `libc` crate's QNX bindings and links against libc on the QNX SDK
//! sysroot. Most parsing logic is platform-portable so the unit tests
//! exercise it on any host (the syscall wrappers themselves are thin
//! and not unit-tested here — they're trivially-correct one-liners).

use std::sync::Mutex;
use std::time::Instant;

use crate::{Sensor, SensorKind, SensorReader};

/// QNX default reader. Holds a process-start `Instant` so `uptime`
/// is a relative measure of how long *this vm-service / supernova
/// process* has been alive — useful for crash-loop debugging.
pub struct QnxSensorReader {
    process_start: Instant,
    /// Reserved for future use (per-CPU usage diffing, like Linux).
    /// Currently unused; kept so the field exists when we wire QNX-specific
    /// CPU usage queries.
    #[allow(dead_code)]
    state: Mutex<()>,
}

impl QnxSensorReader {
    pub fn new() -> Self {
        Self {
            process_start: Instant::now(),
            state: Mutex::new(()),
        }
    }
}

impl Default for QnxSensorReader {
    fn default() -> Self {
        Self::new()
    }
}

impl SensorReader for QnxSensorReader {
    fn read(&self) -> Vec<Sensor> {
        let mut out = Vec::new();

        if let Some(n) = read_cpu_count() {
            out.push(Sensor {
                name: "host_cpu_count",
                help: "Number of online CPUs",
                kind: SensorKind::Gauge,
                value: n as f64,
                labels: vec![],
            });
        }

        out.extend(read_memory_from_sysconf().unwrap_or_default());

        let uptime_secs = self.process_start.elapsed().as_secs_f64();
        out.push(Sensor {
            name: "host_uptime_seconds",
            help: "Seconds since this metrics process started",
            kind: SensorKind::Gauge,
            value: uptime_secs,
            labels: vec![],
        });

        out
    }
}

fn read_cpu_count() -> Option<i64> {
    // _SC_NPROCESSORS_ONLN is non-POSIX but QNX 7.1 has it.
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if n > 0 { Some(n) } else { None }
}

/// Memory total derived from `sysconf(_SC_PHYS_PAGES) * _SC_PAGE_SIZE`.
/// Free / available aren't directly available via sysconf on QNX —
/// they need procnto-specific calls (`mem_offset()` family) which we'll
/// add when supernova's hardware reader needs it.
fn read_memory_from_sysconf() -> Option<Vec<Sensor>> {
    let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) };
    memory_samples_from_sysconf(pages, page_size)
}

/// Pure helper — emits `host_memory_bytes{state="total"}` if both inputs
/// are positive. Returns `None` otherwise so callers cleanly skip.
fn memory_samples_from_sysconf(pages: i64, page_size: i64) -> Option<Vec<Sensor>> {
    if pages <= 0 || page_size <= 0 {
        return None;
    }
    let total = (pages as u64).checked_mul(page_size as u64)?;
    Some(vec![Sensor {
        name: "host_memory_bytes",
        help: "Memory in bytes by state",
        kind: SensorKind::Gauge,
        value: total as f64,
        labels: vec![("state", "total".into())],
    }])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_samples_returns_none_for_unavailable_sysconf() {
        // sysconf returns -1 when the param is unsupported.
        assert!(memory_samples_from_sysconf(-1, 4096).is_none());
        assert!(memory_samples_from_sysconf(1024, -1).is_none());
        assert!(memory_samples_from_sysconf(0, 4096).is_none());
    }

    #[test]
    fn memory_samples_computes_total_bytes() {
        // 1024 pages * 4 KiB = 4 MiB
        let s = memory_samples_from_sysconf(1024, 4096).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].value, (1024u64 * 4096) as f64);
        assert_eq!(s[0].labels[0], ("state", "total".into()));
    }

    #[test]
    fn memory_samples_handles_overflow_gracefully() {
        // Forces u64::checked_mul to return None.
        let s = memory_samples_from_sysconf(i64::MAX, i64::MAX);
        assert!(s.is_none());
    }
}
