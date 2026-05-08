//! QNX qvm runner — thin wrapper around the qvm hypervisor process.
//!
//! Lifecycle:
//!   1. devb-loopback maps the rootfs file to `/dev/qvmdiskN`
//!   2. `qvm @<config>` launches the guest VM
//!   3. Track the qvm PID for is_running / stop / wait
//!
//! Health monitoring (heartbeat read, shutdown command) is owned by
//! `VmManager` via `HeartbeatDevice` + `PowerCommandDevice` over the
//! configured `DeviceTransport`. The runner has nothing to do with it.

use std::path::Path;
use std::process::{Child, Command};
use std::time::Duration;

use super::*;

/// Default device path created by devb-loopback.
const LOOPBACK_DEVICE: &str = "/dev/qvmdisk0";

/// Timeout waiting for devb-loopback to create the device node.
const LOOPBACK_TIMEOUT: Duration = Duration::from_secs(5);

pub struct QnxRunner {
    /// devb-loopback process (maps rootfs file → /dev/qvmdiskN).
    loopback_child: Option<Child>,
    /// qvm process (the guest VM).
    qvm_child: Option<Child>,
}

impl QnxRunner {
    pub fn new() -> Self {
        Self {
            loopback_child: None,
            qvm_child: None,
        }
    }

    /// Kill a child process if it's still alive.
    fn kill_child(child: &mut Child) {
        let _ = child.kill();
        let _ = child.wait();
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
        // Kill qvm first, then loopback
        if let Some(ref mut child) = self.qvm_child {
            Self::kill_child(child);
        }
        self.qvm_child = None;

        if let Some(ref mut child) = self.loopback_child {
            Self::kill_child(child);
        }
        self.loopback_child = None;
    }
}

impl Drop for QnxRunner {
    fn drop(&mut self) {
        self.cleanup();
    }
}
