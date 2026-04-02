/// VM runner trait — platform abstraction for starting/stopping VMs.
///
/// Implementations:
/// - QemuRunner: builds QEMU command line, manages ivshmem-server + simulators
/// - DummyRunner: instant no-ops for components without a real VM
/// - QnxRunner: stub for QNX qvm integration (future)

pub mod qemu;
pub mod qnx;
pub mod dummy;

use std::time::Duration;
use crate::config::VmDefinition;

#[derive(Debug)]
pub enum RunnerError {
    Io(std::io::Error),
    Config(String),
    ProcessFailed(String),
}

impl From<std::io::Error> for RunnerError {
    fn from(e: std::io::Error) -> Self {
        RunnerError::Io(e)
    }
}

impl std::fmt::Display for RunnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunnerError::Io(e) => write!(f, "I/O error: {e}"),
            RunnerError::Config(s) => write!(f, "config error: {s}"),
            RunnerError::ProcessFailed(s) => write!(f, "process failed: {s}"),
        }
    }
}

impl std::error::Error for RunnerError {}

/// Handle to a running VM.
pub struct VmHandle {
    pub name: String,
    pub pid: Option<u32>,
}

pub trait VmRunner: Send {
    /// Start a VM with the given definition.
    fn start(&mut self, name: &str, def: &VmDefinition) -> Result<VmHandle, RunnerError>;

    /// Stop a running VM (force kill).
    fn stop(&mut self, handle: &VmHandle) -> Result<(), RunnerError>;

    /// Check if a VM is still running.
    fn is_running(&self, handle: &VmHandle) -> bool;

    /// Block until the VM exits. Returns the exit code, or None if unknown.
    fn wait(&mut self, handle: &VmHandle) -> Result<Option<i32>, RunnerError>;

    /// Clean up all host-side resources (ivshmem servers, simulators, sockets).
    fn cleanup(&mut self);

    /// Wait until the VM signals it is ready (e.g., health device heartbeat).
    /// Default: returns immediately (always ready).
    fn wait_ready(&mut self, _handle: &VmHandle, _timeout: Duration) -> Result<(), RunnerError> {
        Ok(())
    }

    /// Attempt graceful shutdown, then force-kill if still running after timeout.
    /// Default: calls stop() immediately.
    fn graceful_shutdown(&mut self, handle: &VmHandle, _timeout: Duration) -> Result<(), RunnerError> {
        self.stop(handle)
    }
}
