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

/// Timeout waiting for devb-loopback to create the device node.
const LOOPBACK_TIMEOUT: Duration = Duration::from_secs(5);

pub struct QnxRunner {
    /// devb-loopback process (maps rootfs file → /dev/qvmdisk-<vm>N).
    /// The held `Child` is just the spawn parent — devb-loopback
    /// double-forks. Track the actual daemon pid in `loopback_pid`
    /// instead and use libc::kill on it at cleanup.
    loopback_child: Option<Child>,
    loopback_pid: Option<u32>,
    /// VM name remembered from start() so cleanup can re-find the
    /// daemon pid by `prefix=qvmdisk-<vm_name>` if `loopback_pid`
    /// is None (e.g. find raced ahead of devb-loopback's daemonize).
    vm_name: Option<String>,
    /// qvm process (the guest VM).
    qvm_child: Option<Child>,
}

impl QnxRunner {
    pub fn new() -> Self {
        Self {
            loopback_child: None,
            loopback_pid: None,
            vm_name: None,
            qvm_child: None,
        }
    }

    /// Kill a child process if it's still alive.
    fn kill_child(child: &mut Child) {
        let _ = child.kill();
        let _ = child.wait();
    }

    /// devb-loopback's `prefix` arg becomes the device-node prefix in /dev.
    /// We bake the VM name in so multi-VM hosts get distinct devices and
    /// can target each daemon individually for kill — see find_loopback_pid.
    fn loopback_prefix(vm_name: &str) -> String {
        format!("qvmdisk-{vm_name}")
    }

    /// Path of the rootfs device the per-VM devb-loopback exposes.
    fn loopback_device(vm_name: &str) -> String {
        format!("/dev/{}0", Self::loopback_prefix(vm_name))
    }

    /// Find the live devb-loopback daemon pid for this VM, or None.
    ///
    /// `Command::spawn`'s child pid points at the (long-dead) fork
    /// parent because devb-loopback daemonizes. The actual driver
    /// shows up with the same argv vector, so scan `pidin` for the
    /// process whose args contain our VM's prefix.
    fn find_loopback_pid(vm_name: &str) -> Option<u32> {
        let needle = format!("prefix={},", Self::loopback_prefix(vm_name));
        let out = std::process::Command::new("pidin")
            .args(["-F", "%p %a"])
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            if line.contains("devb-loopback") && line.contains(&needle) {
                if let Some(pid_tok) = line.split_whitespace().next() {
                    if let Ok(pid) = pid_tok.parse::<u32>() {
                        return Some(pid);
                    }
                }
            }
        }
        None
    }

    /// Kill the devb-loopback daemon owning this VM's prefix, if any.
    /// SIGTERM first, brief grace period, then SIGKILL — devb's drivers
    /// usually exit cleanly on SIGTERM, but we don't want to wait on a
    /// stuck one.
    fn slay_loopback_for_vm(vm_name: &str) {
        if let Some(pid) = Self::find_loopback_pid(vm_name) {
            tracing::info!(vm = %vm_name, pid, "killing stale devb-loopback");
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
            std::thread::sleep(Duration::from_millis(100));
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
        }
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
        let raw_path = def.qvm_config.as_ref().ok_or_else(|| {
            RunnerError::Config(format!("VM {name}: qvm_config not set"))
        })?;

        // Relative paths resolve against image_dir (follows active bank symlink)
        let qvm_config = if raw_path.is_relative() {
            def.image_dir.join(raw_path)
        } else {
            raw_path.clone()
        };

        if !qvm_config.exists() {
            return Err(RunnerError::Config(format!(
                "VM {name}: qvm config not found: {}",
                qvm_config.display()
            )));
        }

        // Start devb-loopback to map rootfs file → /dev/qvmdisk-<vm>N.
        // Per-VM prefix lets multiple VMs run concurrently (each with
        // its own /dev/qvmdisk-vmX0) and lets us pid-target the daemon
        // at cleanup without slaying every devb-loopback on the host.
        if let Some(rootfs) = def.rootfs_path() {
            if rootfs.exists() {
                // Defense in depth — kill any devb-loopback for THIS VM
                // that didn't get cleaned up by a previous stop. Other
                // VMs' daemons are untouched.
                Self::slay_loopback_for_vm(name);
                std::thread::sleep(Duration::from_millis(100));

                let prefix = Self::loopback_prefix(name);
                let device = Self::loopback_device(name);
                tracing::info!("starting devb-loopback for {name}: {} → {}", rootfs.display(), device);
                let child = Command::new("devb-loopback")
                    .arg("loopback")
                    .arg(format!("prefix={prefix},fd={}", rootfs.display()))
                    .spawn()
                    .map_err(|e| RunnerError::ProcessFailed(format!("devb-loopback: {e}")))?;
                self.loopback_child = Some(child);
                self.vm_name = Some(name.to_string());

                wait_for_device(&device, LOOPBACK_TIMEOUT)?;
                self.loopback_pid = Self::find_loopback_pid(name);
                tracing::info!(
                    "{device} ready (devb-loopback pid: {:?})",
                    self.loopback_pid
                );
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
        // Kill qvm first so it stops accessing /dev/qvmdisk-<vm>N
        // before we tear down devb-loopback under it.
        if let Some(ref mut child) = self.qvm_child {
            Self::kill_child(child);
        }
        self.qvm_child = None;

        // The held Child for devb-loopback only points at the spawn
        // parent (the daemon double-forks); kill_child on it is a
        // no-op. Use the pid we resolved from pidin at start time;
        // re-scan as a fallback if start() raced ahead of the
        // daemon being visible in pidin.
        if let Some(ref mut child) = self.loopback_child {
            Self::kill_child(child);
        }
        self.loopback_child = None;

        let pid = self.loopback_pid.take().or_else(|| {
            self.vm_name.as_deref().and_then(Self::find_loopback_pid)
        });
        if let Some(pid) = pid {
            tracing::info!(
                vm = ?self.vm_name,
                pid,
                "killing devb-loopback daemon"
            );
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
            std::thread::sleep(Duration::from_millis(100));
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
        }
        self.vm_name = None;
    }
}

impl Drop for QnxRunner {
    fn drop(&mut self) {
        self.cleanup();
    }
}
