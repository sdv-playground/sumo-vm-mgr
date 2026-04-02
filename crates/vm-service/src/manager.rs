/// VM lifecycle manager — maps VM names to runners and tracks running state.

use std::collections::HashMap;
use std::time::Duration;

use crate::config::{BackendType, VmDefinition, VmServiceConfig};
use crate::health::{HealthDetail, HealthMonitor, HealthStatus};
use crate::runner::dummy::DummyRunner;
use crate::runner::qemu::QemuRunner;
use crate::runner::qnx::QnxRunner;
use crate::runner::{RunnerError, VmHandle, VmRunner};

/// Information about a single VM for API responses.
pub struct VmInfo {
    pub name: String,
    pub status: HealthStatus,
    pub pid: Option<u32>,
    pub backend: BackendType,
}

struct ManagedVm {
    def: VmDefinition,
    runner: Box<dyn VmRunner>,
    handle: Option<VmHandle>,
    health_monitor: Option<HealthMonitor>,
}

pub struct VmManager {
    vms: HashMap<String, ManagedVm>,
}

/// Returned by `initiate_stop` — carries enough info to wait for exit
/// without holding the manager lock.
pub struct StopHandle {
    #[allow(dead_code)]
    pub name: String,
    pub pid: Option<u32>,
    pub timeout_secs: u64,
}

/// Wait for a process to exit, polling with a timeout. No locks held.
pub fn wait_for_exit(pid: u32, timeout_secs: u64) {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        if unsafe { libc::kill(pid as i32, 0) != 0 } {
            return; // process gone
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[derive(Debug)]
pub enum ManagerError {
    NotFound(String),
    AlreadyRunning(String),
    NotRunning(String),
    Runner(RunnerError),
}

impl std::fmt::Display for ManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagerError::NotFound(name) => write!(f, "VM not found: {name}"),
            ManagerError::AlreadyRunning(name) => write!(f, "VM already running: {name}"),
            ManagerError::NotRunning(name) => write!(f, "VM not running: {name}"),
            ManagerError::Runner(e) => write!(f, "runner error: {e}"),
        }
    }
}

impl From<RunnerError> for ManagerError {
    fn from(e: RunnerError) -> Self {
        ManagerError::Runner(e)
    }
}

impl VmManager {
    pub fn new(config: VmServiceConfig) -> Self {
        let mut vms = HashMap::new();

        for (name, def) in config.vms {
            let runner: Box<dyn VmRunner> = match def.backend {
                BackendType::Qemu => {
                    let mut r = QemuRunner::new();
                    if let Some(ref sim_dir) = def.sim_dir {
                        r = r.ivshmem_bin(
                            sim_dir.join("ivshmem-server")
                                .exists()
                                .then(|| sim_dir.join("ivshmem-server"))
                                .unwrap_or_else(|| "ivshmem-server".into()),
                        );
                    }
                    Box::new(r)
                }
                BackendType::Qnx => Box::new(QnxRunner::new()),
                BackendType::Dummy => Box::new(DummyRunner::new()),
            };

            let has_health = def.devices.iter()
                .any(|d| matches!(d, crate::config::DeviceConfig::Health { .. }));
            let health_monitor = if has_health {
                Some(HealthMonitor::new(&name))
            } else {
                None
            };

            vms.insert(name, ManagedVm {
                def,
                runner,
                handle: None,
                health_monitor,
            });
        }

        Self { vms }
    }

    pub fn start_vm(&mut self, name: &str) -> Result<(), ManagerError> {
        let vm = self.vms.get_mut(name)
            .ok_or_else(|| ManagerError::NotFound(name.to_string()))?;

        if vm.handle.is_some() {
            // Check if still actually running
            if let Some(ref handle) = vm.handle {
                if vm.runner.is_running(handle) {
                    return Err(ManagerError::AlreadyRunning(name.to_string()));
                }
            }
            // Was running but exited — clean up
            vm.runner.cleanup();
            vm.handle = None;
        }

        let handle = vm.runner.start(name, &vm.def)?;
        tracing::info!("started VM {name} (pid: {:?})", handle.pid);
        vm.handle = Some(handle);
        Ok(())
    }

    /// Signal a VM to stop. Returns the PID and timeout for the caller to
    /// wait on *without* holding the manager lock. Call `finalize_stop` after.
    pub fn initiate_stop(&mut self, name: &str) -> Result<StopHandle, ManagerError> {
        let vm = self.vms.get_mut(name)
            .ok_or_else(|| ManagerError::NotFound(name.to_string()))?;

        let handle = vm.handle.as_ref()
            .ok_or_else(|| ManagerError::NotRunning(name.to_string()))?;

        if !vm.runner.is_running(handle) {
            vm.runner.cleanup();
            vm.handle = None;
            return Ok(StopHandle { name: name.to_string(), pid: None, timeout_secs: 0 });
        }

        // Send shutdown signal via health monitor (writes CMD_SHUTDOWN to shm)
        if let Some(ref monitor) = vm.health_monitor {
            monitor.request_shutdown();
        }

        let pid = handle.pid;
        let timeout_secs = vm.def.shutdown_timeout_secs();
        tracing::info!("signalled shutdown for VM {name} (pid: {pid:?}, timeout: {timeout_secs}s)");

        Ok(StopHandle { name: name.to_string(), pid, timeout_secs })
    }

    /// Finalize stop: force-kill if still running, clean up resources.
    /// Call after waiting for the process to exit (outside the lock).
    pub fn finalize_stop(&mut self, name: &str) {
        if let Some(vm) = self.vms.get_mut(name) {
            if let Some(ref handle) = vm.handle {
                if vm.runner.is_running(handle) {
                    let _ = vm.runner.stop(handle);
                }
            }
            vm.runner.cleanup();
            vm.handle = None;
            tracing::info!("stopped VM {name}");
        }
    }

    /// Blocking stop (for daemon shutdown and restart). Holds the lock
    /// for the full duration — only use when lock contention doesn't matter.
    pub fn stop_vm(&mut self, name: &str) -> Result<(), ManagerError> {
        let sh = self.initiate_stop(name)?;
        if let Some(pid) = sh.pid {
            wait_for_exit(pid, sh.timeout_secs);
        }
        self.finalize_stop(name);
        Ok(())
    }

    #[allow(dead_code)]
    pub fn restart_vm(&mut self, name: &str) -> Result<(), ManagerError> {
        // Stop if running (ignore NotRunning)
        match self.stop_vm(name) {
            Ok(()) | Err(ManagerError::NotRunning(_)) => {}
            Err(e) => return Err(e),
        }
        self.start_vm(name)
    }

    #[allow(dead_code)]
    pub fn health(&mut self, name: &str) -> Result<HealthStatus, ManagerError> {
        Ok(self.health_detail(name)?.status)
    }

    pub fn health_detail(&mut self, name: &str) -> Result<HealthDetail, ManagerError> {
        let vm = self.vms.get_mut(name)
            .ok_or_else(|| ManagerError::NotFound(name.to_string()))?;

        let handle = match &vm.handle {
            Some(h) => h,
            None => return Ok(HealthDetail { status: HealthStatus::Stopped, guest_state: None, hb_seq: None }),
        };

        if !vm.runner.is_running(handle) {
            return Ok(HealthDetail { status: HealthStatus::Stopped, guest_state: None, hb_seq: None });
        }

        if let Some(ref mut monitor) = vm.health_monitor {
            Ok(monitor.detail())
        } else {
            Ok(HealthDetail { status: HealthStatus::Running, guest_state: None, hb_seq: None })
        }
    }

    pub fn list(&mut self) -> Vec<VmInfo> {
        self.vms.iter_mut().map(|(name, vm)| {
            let (status, pid) = match &vm.handle {
                Some(handle) if vm.runner.is_running(handle) => {
                    let s = vm.health_monitor.as_mut()
                        .map(|m| m.status())
                        .unwrap_or(HealthStatus::Running);
                    (s, handle.pid)
                }
                Some(_) => (HealthStatus::Stopped, None),
                None => (HealthStatus::Stopped, None),
            };
            VmInfo {
                name: name.clone(),
                status,
                pid,
                backend: vm.def.backend,
            }
        }).collect()
    }

    /// Stop all running VMs (for graceful daemon shutdown).
    pub fn stop_all(&mut self) {
        let names: Vec<String> = self.vms.keys().cloned().collect();
        for name in names {
            if let Err(e) = self.stop_vm(&name) {
                tracing::warn!("failed to stop VM {name}: {e}");
            }
        }
    }
}
