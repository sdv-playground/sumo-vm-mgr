/// Boot backend trait — platform abstraction for starting/stopping VMs.
///
/// Implementations:
/// - QemuBackend: builds QEMU command line, manages ivshmem-server + simulators
/// - QnxBackend: stub for QNX qvm integration (future)

use nv_store::types::{Bank, BankSet};
use crate::config::VmProfile;

#[derive(Debug)]
pub enum BackendError {
    Io(std::io::Error),
    Config(String),
    ProcessFailed(String),
}

impl From<std::io::Error> for BackendError {
    fn from(e: std::io::Error) -> Self {
        BackendError::Io(e)
    }
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendError::Io(e) => write!(f, "I/O error: {e}"),
            BackendError::Config(s) => write!(f, "config error: {s}"),
            BackendError::ProcessFailed(s) => write!(f, "process failed: {s}"),
        }
    }
}

/// Information about a running VM.
pub struct VmHandle {
    pub set: BankSet,
    pub bank: Bank,
    pub pid: Option<u32>,
}

pub trait BootBackend {
    /// Prepare and start a VM for the given bank set and active bank.
    ///
    /// The backend is responsible for:
    /// 1. Resolving the correct image path for the bank
    /// 2. Starting any required host-side processes (ivshmem-server, simulators)
    /// 3. Building and executing the VM launch command
    fn start_vm(
        &mut self,
        profile: &VmProfile,
        set: BankSet,
        bank: Bank,
        image_dir: &std::path::Path,
    ) -> Result<VmHandle, BackendError>;

    /// Stop a running VM.
    fn stop_vm(&mut self, handle: &VmHandle) -> Result<(), BackendError>;

    /// Check if a VM is still running.
    fn is_running(&self, handle: &VmHandle) -> bool;

    /// Get the QEMU/qvm command that would be executed (for dry-run/debugging).
    fn build_command(
        &self,
        profile: &VmProfile,
        set: BankSet,
        bank: Bank,
        image_dir: &std::path::Path,
    ) -> Result<Vec<String>, BackendError>;

    /// Block until the VM exits. Returns the exit code, or None if unknown.
    fn wait_vm(&mut self, handle: &VmHandle) -> Result<Option<i32>, BackendError>;

    /// Clean up all host-side resources (ivshmem servers, simulators, sockets).
    fn cleanup(&mut self);
}
