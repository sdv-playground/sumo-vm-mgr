/// Health monitoring via ivshmem shared memory.
///
/// Protocol from guest-vm-spec vhealth_regs.h:
///   [0x800..0x83F]  Guest→Host heartbeat (magic, state, seq, flags)
///   [0x840..0x85F]  Host→Guest power commands (shutdown)
///
/// The monitor tracks `hb_seq` between calls to `status()`. If the
/// sequence number hasn't changed within the configured timeout the
/// guest is declared unhealthy (crashed or CPU-starved).

use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::Serialize;

// Guest heartbeat layout at BAR2 + 0x800:
//   +0x00  hb_magic     u32  = 0x48425448 ("HBTH")
//   +0x04  hb_version   u32
//   +0x08  hb_seq       u32  (incremented every ~1s by guest)
//   +0x0C  guest_state  u32  (0=booting, 1=running, 2=degraded, 3=shutting_down)
//   +0x10  hb_mono_ns   u64
//   +0x18  hb_flags     u32  (bit 0 = SERVICES_READY)
const HB_OFFSET: usize = 0x800;
const HB_MAGIC: u32 = 0x48425448; // "HBTH"
const HB_MAGIC_OFF: usize = HB_OFFSET;
const HB_SEQ_OFF: usize = HB_OFFSET + 0x08;
const HB_GUEST_STATE_OFF: usize = HB_OFFSET + 0x0C;
const HB_FLAGS_OFF: usize = HB_OFFSET + 0x18;

const GUEST_STATE_RUNNING: u32 = 1;
const GUEST_STATE_SHUTTING_DOWN: u32 = 3;
// Reserved for future use — guest can set bit 0 (SERVICES_READY) in hb_flags
#[allow(dead_code)]
const HB_FLAG_SERVICES_READY: u32 = 1;

// Host power commands
const CMD_OFFSET: usize = 0x840;
const CMD_SEQ_OFF: usize = CMD_OFFSET;
const CMD_CMD_OFF: usize = CMD_OFFSET + 0x04;
const CMD_SHUTDOWN: u32 = 1;

/// How long a stale heartbeat is tolerated before declaring unhealthy.
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(5);

#[allow(dead_code)]
const POLL_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Starting,
    Running,
    Unhealthy,
    ShuttingDown,
    Stopped,
    Unknown,
}

/// Detailed health information including raw guest heartbeat values.
#[derive(Debug, Clone, Serialize)]
pub struct HealthDetail {
    pub status: HealthStatus,
    /// Guest state from heartbeat register (0=booting, 1=running, 2=degraded, 3=shutting_down).
    pub guest_state: Option<u32>,
    /// Heartbeat sequence number (incremented ~1s by guest).
    pub hb_seq: Option<u32>,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Starting => write!(f, "starting"),
            HealthStatus::Running => write!(f, "running"),
            HealthStatus::Unhealthy => write!(f, "unhealthy"),
            HealthStatus::ShuttingDown => write!(f, "shutting_down"),
            HealthStatus::Stopped => write!(f, "stopped"),
            HealthStatus::Unknown => write!(f, "unknown"),
        }
    }
}

/// Monitors VM health via ivshmem shared memory heartbeat.
///
/// Tracks the guest's `hb_seq` counter. If the counter stops advancing
/// for longer than `HEARTBEAT_TIMEOUT` the VM is declared unhealthy.
pub struct HealthMonitor {
    shm_path: PathBuf,
    /// Last observed heartbeat sequence number.
    last_seq: Option<u32>,
    /// When `last_seq` was last seen to change.
    last_seq_change: Option<Instant>,
}

impl HealthMonitor {
    pub fn new(vm_name: &str) -> Self {
        Self {
            shm_path: Self::default_shm_path(vm_name),
            last_seq: None,
            last_seq_change: None,
        }
    }

    /// Platform-specific default shared memory path for health device.
    fn default_shm_path(vm_name: &str) -> PathBuf {
        #[cfg(target_os = "linux")]
        { PathBuf::from(format!("/dev/shm/ivshmem-{vm_name}-health")) }
        #[cfg(not(target_os = "linux"))]
        { PathBuf::from(format!("/dev/shmem/vm-{vm_name}-health")) }
    }

    /// Read detailed health from shared memory, including raw guest_state and hb_seq.
    pub fn detail(&mut self) -> HealthDetail {
        let data = match std::fs::read(&self.shm_path) {
            Ok(d) => d,
            Err(_) => return HealthDetail { status: HealthStatus::Unknown, guest_state: None, hb_seq: None },
        };

        if data.len() < HB_FLAGS_OFF + 4 {
            return HealthDetail { status: HealthStatus::Unknown, guest_state: None, hb_seq: None };
        }

        let magic = u32::from_le_bytes(
            data[HB_MAGIC_OFF..HB_MAGIC_OFF + 4].try_into().unwrap(),
        );
        if magic != HB_MAGIC {
            return HealthDetail { status: HealthStatus::Starting, guest_state: None, hb_seq: None };
        }

        let seq = u32::from_le_bytes(
            data[HB_SEQ_OFF..HB_SEQ_OFF + 4].try_into().unwrap(),
        );
        let guest_state = u32::from_le_bytes(
            data[HB_GUEST_STATE_OFF..HB_GUEST_STATE_OFF + 4].try_into().unwrap(),
        );
        let _flags = u32::from_le_bytes(
            data[HB_FLAGS_OFF..HB_FLAGS_OFF + 4].try_into().unwrap(),
        );

        // Track heartbeat liveness
        let now = Instant::now();
        match self.last_seq {
            Some(prev) if prev == seq => {
                if let Some(last_change) = self.last_seq_change {
                    if now.duration_since(last_change) > HEARTBEAT_TIMEOUT {
                        return HealthDetail {
                            status: HealthStatus::Unhealthy,
                            guest_state: Some(guest_state),
                            hb_seq: Some(seq),
                        };
                    }
                }
            }
            _ => {
                self.last_seq = Some(seq);
                self.last_seq_change = Some(now);
            }
        }

        let status = if guest_state == GUEST_STATE_SHUTTING_DOWN {
            HealthStatus::ShuttingDown
        } else if guest_state == GUEST_STATE_RUNNING {
            HealthStatus::Running
        } else {
            HealthStatus::Unhealthy
        };

        HealthDetail { status, guest_state: Some(guest_state), hb_seq: Some(seq) }
    }

    /// Read current health status from shared memory.
    pub fn status(&mut self) -> HealthStatus {
        self.detail().status
    }

    /// Wait until the VM signals readiness.
    #[allow(dead_code)]
    pub fn wait_ready(&mut self, timeout: Duration, is_running: impl Fn() -> bool) -> Result<(), String> {
        if !self.shm_path.exists() {
            // No health device configured — consider immediately ready
            return Ok(());
        }

        let start = Instant::now();
        while start.elapsed() < timeout {
            if !is_running() {
                return Err("VM exited before becoming ready".into());
            }
            if self.status() == HealthStatus::Running {
                return Ok(());
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        Err(format!("VM not ready after {}s", timeout.as_secs()))
    }

    /// Request graceful shutdown via shared memory command region.
    /// Returns true if the command was written successfully.
    pub fn request_shutdown(&self) -> bool {
        let mut data = match std::fs::read(&self.shm_path) {
            Ok(d) => d,
            Err(_) => return false,
        };

        if data.len() < CMD_CMD_OFF + 4 {
            return false;
        }

        // Increment cmd_seq
        let old_seq = u32::from_le_bytes(
            data[CMD_SEQ_OFF..CMD_SEQ_OFF + 4].try_into().unwrap(),
        );
        let new_seq = old_seq.wrapping_add(1);
        data[CMD_SEQ_OFF..CMD_SEQ_OFF + 4].copy_from_slice(&new_seq.to_le_bytes());
        // Write CMD_SHUTDOWN
        data[CMD_CMD_OFF..CMD_CMD_OFF + 4].copy_from_slice(&CMD_SHUTDOWN.to_le_bytes());

        std::fs::write(&self.shm_path, &data).is_ok()
    }

    /// Wait for VM to exit after sending shutdown, with timeout.
    #[allow(dead_code)]
    pub fn wait_shutdown(&self, timeout: Duration, is_running: impl Fn() -> bool) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if !is_running() {
                return true;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        false
    }
}
