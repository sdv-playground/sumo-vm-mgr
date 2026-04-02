/// VM lifecycle manager — maps VM names to runners and tracks running state.

use std::collections::HashMap;
use std::time::Duration;

use crate::config::{BackendType, VmDefinition, VmServiceConfig};
use crate::health::{HealthMonitor, HealthStatus};
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

    pub fn stop_vm(&mut self, name: &str) -> Result<(), ManagerError> {
        let vm = self.vms.get_mut(name)
            .ok_or_else(|| ManagerError::NotFound(name.to_string()))?;

        let handle = vm.handle.as_ref()
            .ok_or_else(|| ManagerError::NotRunning(name.to_string()))?;

        if !vm.runner.is_running(handle) {
            vm.runner.cleanup();
            vm.handle = None;
            return Ok(());
        }

        let timeout = Duration::from_secs(vm.def.shutdown_timeout_secs());
        vm.runner.graceful_shutdown(handle, timeout)?;
        vm.runner.cleanup();
        vm.handle = None;
        tracing::info!("stopped VM {name}");
        Ok(())
    }

    pub fn restart_vm(&mut self, name: &str) -> Result<(), ManagerError> {
        // Stop if running (ignore NotRunning)
        match self.stop_vm(name) {
            Ok(()) | Err(ManagerError::NotRunning(_)) => {}
            Err(e) => return Err(e),
        }
        self.start_vm(name)
    }

    pub fn health(&mut self, name: &str) -> Result<HealthStatus, ManagerError> {
        let vm = self.vms.get_mut(name)
            .ok_or_else(|| ManagerError::NotFound(name.to_string()))?;

        let handle = match &vm.handle {
            Some(h) => h,
            None => return Ok(HealthStatus::Stopped),
        };

        if !vm.runner.is_running(handle) {
            return Ok(HealthStatus::Stopped);
        }

        if let Some(ref mut monitor) = vm.health_monitor {
            Ok(monitor.status())
        } else {
            Ok(HealthStatus::Running)
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
