/// QNX qvm runner — manages guest VMs via the QNX hypervisor.
///
/// Start flow:
///   1. Create health shared memory (POSIX shm_open)
///   2. Spawn HealthSim thread (writes sensor data, monitors heartbeat)
///   3. devb-loopback maps rootfs file → /dev/qvmdiskN
///   4. qvm @<config> launches the guest VM
///   5. Track qvm PID for is_running/stop/wait
///
/// Cleanup kills processes and stops sim threads.

use std::path::Path;
use std::process::{Child, Command};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use crate::config::DeviceConfig;
use crate::health::HealthMonitor;
use super::*;

/// Default device path created by devb-loopback.
const LOOPBACK_DEVICE: &str = "/dev/qvmdisk0";

/// Timeout waiting for devb-loopback to create the device node.
const LOOPBACK_TIMEOUT: Duration = Duration::from_secs(5);

/// Size of the health device shared memory region (4 KiB).
#[cfg(feature = "qnx")]
const HEALTH_SHM_SIZE: usize = 4096;

pub struct QnxRunner {
    /// devb-loopback process (maps rootfs file → /dev/qvmdiskN).
    loopback_child: Option<Child>,
    /// qvm process (the guest VM).
    qvm_child: Option<Child>,
    /// Health monitor for reading guest heartbeat.
    health_monitor: Option<HealthMonitor>,
    /// Cancel flags for simulator threads.
    sim_cancellers: Vec<Arc<AtomicBool>>,
}

impl QnxRunner {
    pub fn new() -> Self {
        Self {
            loopback_child: None,
            qvm_child: None,
            health_monitor: None,
            sim_cancellers: Vec::new(),
        }
    }

    /// Kill a child process if it's still alive.
    fn kill_child(child: &mut Child) {
        let _ = child.kill();
        let _ = child.wait();
    }

    /// Start the health simulator on a background thread using QNX shared memory.
    #[cfg(feature = "qnx")]
    fn start_health_sim(&mut self, vm_name: &str) -> Result<(), RunnerError> {
        use vm_devices::transport::posix::{PosixSharedMemory, NullDoorbell};
        use vm_devices::clock::system::SystemClock;
        use vm_devices::health;

        let shm_name = format!("/vm-{vm_name}-health");
        let shm = PosixSharedMemory::create(&shm_name, HEALTH_SHM_SIZE)
            .map_err(|e| RunnerError::ProcessFailed(format!("health shm create: {e}")))?;

        let clock = Arc::new(SystemClock::new());
        let sim = health::HealthSim::new(shm, NullDoorbell, clock, health::default_sensors());
        sim.init();

        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_clone = cancel.clone();
        std::thread::Builder::new()
            .name("health-sim".into())
            .spawn(move || sim.run(&cancel_clone))
            .map_err(|e| RunnerError::ProcessFailed(format!("health-sim thread: {e}")))?;
        self.sim_cancellers.push(cancel);
        tracing::info!("started health-sim for {vm_name} (shm: {shm_name})");
        Ok(())
    }

    #[cfg(not(feature = "qnx"))]
    fn start_health_sim(&mut self, _vm_name: &str) -> Result<(), RunnerError> {
        Err(RunnerError::Config("health-sim requires 'qnx' feature".into()))
    }
}

/// Poll for a device node to appear, with timeout.
fn wait_for_device(path: &str, timeout: Duration) -> Result<(), RunnerError> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if Path::new(path).exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(RunnerError::ProcessFailed(format!(
        "{path} did not appear within {}s",
        timeout.as_secs()
    )))
}

impl VmRunner for QnxRunner {
    fn start(&mut self, name: &str, def: &VmDefinition) -> Result<VmHandle, RunnerError> {
        let qvm_config = def.qvm_config.as_ref().ok_or_else(|| {
            RunnerError::Config(format!("VM {name}: qvm_config not set"))
        })?;

        if !qvm_config.exists() {
            return Err(RunnerError::Config(format!(
                "VM {name}: qvm config not found: {}",
                qvm_config.display()
            )));
        }

        // Start health simulator if health device configured (non-fatal)
        let has_health = def.devices.iter().any(|d| matches!(d, DeviceConfig::Health { .. }));
        if has_health {
            match self.start_health_sim(name) {
                Ok(()) => self.health_monitor = Some(HealthMonitor::new(name)),
                Err(e) => tracing::warn!("health sim unavailable for {name}: {e}"),
            }
        }

        // Start devb-loopback to map rootfs file → /dev/qvmdiskN
        if let Some(rootfs) = def.rootfs_path() {
            if rootfs.exists() {
                tracing::info!("starting devb-loopback for {name}: {}", rootfs.display());
                let child = Command::new("devb-loopback")
                    .arg("loopback")
                    .arg(format!("prefix=qvmdisk,fd={}", rootfs.display()))
                    .spawn()
                    .map_err(|e| RunnerError::ProcessFailed(format!("devb-loopback: {e}")))?;
                self.loopback_child = Some(child);

                wait_for_device(LOOPBACK_DEVICE, LOOPBACK_TIMEOUT)?;
                tracing::info!("{LOOPBACK_DEVICE} ready");
            } else {
                tracing::warn!("VM {name}: rootfs not found: {} — skipping loopback", rootfs.display());
            }
        }

        // Launch qvm with the config file
        tracing::info!("starting qvm for {name}: @{}", qvm_config.display());
        let child = Command::new("qvm")
            .arg(format!("@{}", qvm_config.display()))
            .spawn()
            .map_err(|e| RunnerError::ProcessFailed(format!("qvm: {e}")))?;

        let pid = child.id();
        self.qvm_child = Some(child);

        tracing::info!("VM {name} started (qvm pid: {pid})");
        Ok(VmHandle {
            name: name.to_string(),
            pid: Some(pid),
        })
    }

    fn stop(&mut self, _handle: &VmHandle) -> Result<(), RunnerError> {
        if let Some(ref mut child) = self.qvm_child {
            Self::kill_child(child);
        }
        Ok(())
    }

    fn is_running(&self, handle: &VmHandle) -> bool {
        if let Some(pid) = handle.pid {
            unsafe { libc::kill(pid as i32, 0) == 0 }
        } else {
            false
        }
    }

    fn wait(&mut self, _handle: &VmHandle) -> Result<Option<i32>, RunnerError> {
        if let Some(ref mut child) = self.qvm_child {
            let status = child.wait()?;
            return Ok(status.code());
        }
        Err(RunnerError::ProcessFailed("qvm process not found".into()))
    }

    fn cleanup(&mut self) {
        // Signal simulator threads to stop
        for cancel in &self.sim_cancellers {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        self.sim_cancellers.clear();

        // Kill qvm first, then loopback
        if let Some(ref mut child) = self.qvm_child {
            Self::kill_child(child);
        }
        self.qvm_child = None;

        if let Some(ref mut child) = self.loopback_child {
            Self::kill_child(child);
        }
        self.loopback_child = None;

        self.health_monitor = None;
    }

    fn wait_ready(&mut self, handle: &VmHandle, timeout: Duration) -> Result<(), RunnerError> {
        if let Some(ref mut monitor) = self.health_monitor {
            let pid = handle.pid;
            monitor.wait_ready(timeout, || {
                pid.map(|p| unsafe { libc::kill(p as i32, 0) == 0 }).unwrap_or(false)
            }).map_err(RunnerError::ProcessFailed)
        } else {
            Ok(())
        }
    }

    fn graceful_shutdown(&mut self, handle: &VmHandle, timeout: Duration) -> Result<(), RunnerError> {
        if let Some(ref monitor) = self.health_monitor {
            if monitor.request_shutdown() {
                let pid = handle.pid;
                if monitor.wait_shutdown(timeout, || {
                    pid.map(|p| unsafe { libc::kill(p as i32, 0) == 0 }).unwrap_or(false)
                }) {
                    return Ok(());
                }
            }
        }
        self.stop(handle)
    }
}

impl Drop for QnxRunner {
    fn drop(&mut self) {
        self.cleanup();
    }
}
