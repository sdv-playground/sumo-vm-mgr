/// QEMU runner — translates VM definitions into QEMU command lines
/// and manages host-side processes (ivshmem-server, simulators).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::config::*;
use crate::health::HealthMonitor;
use crate::ivshmem::{self, HostProcess, IvshmemSockets};
use super::*;

pub struct QemuRunner {
    /// Override QEMU binary path. If None, resolved from arch.
    qemu_bin: Option<PathBuf>,
    /// Path to ivshmem-server binary.
    ivshmem_bin: PathBuf,
    /// Use KVM if available.
    try_kvm: bool,
    /// Running host-side processes.
    host_processes: Vec<HostProcess>,
    /// Socket paths to clean up.
    sockets: Vec<PathBuf>,
    /// Health monitor for the current VM.
    health_monitor: Option<HealthMonitor>,
}

impl QemuRunner {
    pub fn new() -> Self {
        Self {
            qemu_bin: None,
            ivshmem_bin: PathBuf::from("ivshmem-server"),
            try_kvm: true,
            host_processes: Vec::new(),
            sockets: Vec::new(),
            health_monitor: None,
        }
    }

    #[allow(dead_code)]
    pub fn qemu_bin(mut self, path: impl Into<PathBuf>) -> Self {
        self.qemu_bin = Some(path.into());
        self
    }

    pub fn ivshmem_bin(mut self, path: impl Into<PathBuf>) -> Self {
        self.ivshmem_bin = path.into();
        self
    }

    #[allow(dead_code)]
    pub fn try_kvm(mut self, enable: bool) -> Self {
        self.try_kvm = enable;
        self
    }

    fn resolve_qemu_bin(&self, arch: Arch) -> String {
        self.qemu_bin.as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| arch.qemu_binary().to_string())
    }

    fn sim_binary(&self, name: &str, sim_dir: Option<&Path>) -> Result<PathBuf, RunnerError> {
        if let Some(dir) = sim_dir {
            let path = dir.join(name);
            if path.exists() {
                return Ok(path);
            }
        }
        // Fall back to PATH lookup
        match Command::new("which").arg(name).output() {
            Ok(out) if out.status.success() => {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                Ok(PathBuf::from(s))
            }
            _ => Err(RunnerError::Config(format!(
                "simulator binary not found: {name} (not in sim_dir or PATH)",
            ))),
        }
    }

    fn start_process(&mut self, name: &str, cmd: &mut Command) -> Result<u32, RunnerError> {
        let child = cmd
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| RunnerError::ProcessFailed(format!("{name}: {e}")))?;
        let pid = child.id();
        self.host_processes.push(HostProcess {
            name: name.to_string(),
            child,
        });
        Ok(pid)
    }

    /// Build the QEMU command line from a VM definition.
    fn build_qemu_args(
        &self,
        name: &str,
        def: &VmDefinition,
        ivshmem_sockets: &IvshmemSockets,
    ) -> Result<Vec<String>, RunnerError> {
        let arch = def.arch();
        let mut args: Vec<String> = Vec::new();
        let use_kvm = self.try_kvm && arch.kvm_available();

        let cpu = if use_kvm {
            "host".to_string()
        } else {
            def.cpu_model.clone()
                .unwrap_or_else(|| arch.default_cpu().to_string())
        };

        args.extend_from_slice(&[
            self.resolve_qemu_bin(arch),
            "-machine".into(), arch.machine_type().into(),
            "-cpu".into(), cpu,
        ]);

        if use_kvm {
            args.push("-enable-kvm".into());
        }

        args.extend_from_slice(&[
            "-m".into(), format!("{}M", def.ram_mb),
            "-smp".into(), def.cpus.to_string(),
            "-nographic".into(),
            "-no-reboot".into(),
        ]);

        // Kernel — resolved from image_dir + images.kernel
        if let Some(kernel_path) = def.kernel_path() {
            args.extend_from_slice(&[
                "-kernel".into(),
                kernel_path.to_string_lossy().into_owned(),
            ]);
        }

        // Build kernel cmdline
        let mut cmdline_parts: Vec<String> = vec![
            "root=/dev/vda".into(),
            "rw".into(),
            format!("console={}", arch.console_device()),
            "earlycon".into(),
            "no_console_suspend".into(),
            "pm_debug_messages".into(),
        ];

        let can_count = def.can_count();
        if can_count > 0 {
            cmdline_parts.push("vcan_shm.backend=ivshmem".into());
            cmdline_parts.push(format!("vcan_shm.num_devices={can_count}"));
        }

        if let Some(ref extra) = def.extra_cmdline {
            cmdline_parts.push(extra.clone());
        }

        // Extra disks (data, swap — from def.disks, not banked)
        let blk_device = arch.virtio_device("blk");
        let mut disk_args: Vec<Vec<String>> = Vec::new();

        for disk in &def.disks {
            let drive_id = format!("hd_{}", disk.role);
            let ro = if disk.readonly { ",readonly=on" } else { "" };
            disk_args.push(vec![
                "-drive".into(),
                format!("file={},format=raw,if=none,id={drive_id}{ro}", disk.path.display()),
                "-device".into(),
                format!("{blk_device},drive={drive_id}"),
            ]);

            if disk.role == "swap" {
                cmdline_parts.push("resume=/dev/vdc".into());
            }
        }

        // Rootfs image — resolved from image_dir + images.rootfs
        let rootfs = def.rootfs_path()
            .ok_or_else(|| RunnerError::Config(format!(
                "{name}: no rootfs image configured (set images.rootfs in config)"
            )))?;
        let rootfs_args = vec![
            "-drive".into(),
            format!("file={},format=raw,if=none,id=hd_rootfs", rootfs.display()),
            "-device".into(),
            format!("{blk_device},drive=hd_rootfs"),
        ];

        // Disk ordering depends on architecture:
        //   aarch64 (reverse): extra disks first, rootfs last → rootfs = /dev/vda
        //   x86_64  (forward): rootfs first, extra disks after → rootfs = /dev/vda
        if arch.reverse_disk_order() {
            for disk in &disk_args {
                args.extend_from_slice(disk);
            }
            args.push("-device".into());
            args.push(arch.virtio_device("rng"));
            args.extend_from_slice(&rootfs_args);
        } else {
            args.extend_from_slice(&rootfs_args);
            args.push("-device".into());
            args.push(arch.virtio_device("rng"));
            for disk in &disk_args {
                args.extend_from_slice(disk);
            }
        }

        // Network devices
        let networks: Vec<_> = def.devices.iter()
            .filter(|d| matches!(d, DeviceConfig::Network { .. }))
            .collect();
        let net_device = arch.virtio_device("net");

        let net_iter: Box<dyn Iterator<Item = (usize, &&DeviceConfig)>> = if arch.reverse_disk_order() {
            Box::new(networks.iter().enumerate().rev())
        } else {
            Box::new(networks.iter().enumerate())
        };

        let mut net_idx = 0;
        for (i, dev) in net_iter {
            if let DeviceConfig::Network { mac, ssh_port } = dev {
                let id = format!("net{net_idx}");
                let mut netdev = format!("user,id={id}");
                if let Some(port) = ssh_port {
                    netdev.push_str(&format!(",hostfwd=tcp::{port}-:22"));
                }
                if i > 0 {
                    let subnet = i + 2;
                    netdev.push_str(&format!(",net=10.0.{subnet}.0/24,dhcpstart=10.0.{subnet}.15"));
                }
                args.extend_from_slice(&["-netdev".into(), netdev]);
                let mut dev_str = format!("{net_device},netdev={id}");
                if let Some(m) = mac {
                    dev_str.push_str(&format!(",mac={m}"));
                }
                args.extend_from_slice(&["-device".into(), dev_str]);
                net_idx += 1;
            }
        }

        // vsock for HSM (required — no TCP fallback)
        let vsock_device = match arch {
            Arch::Aarch64 => "vhost-vsock-device",
            Arch::X86_64 => "vhost-vsock-pci",
        };
        for dev in &def.devices {
            if matches!(dev, DeviceConfig::Hsm { .. }) {
                if !Path::new("/dev/vhost-vsock").exists() {
                    return Err(RunnerError::Config(
                        "/dev/vhost-vsock not found — load vhost_vsock module".into(),
                    ));
                }
                args.extend_from_slice(&[
                    "-device".into(),
                    format!("{vsock_device},guest-cid=3"),
                ]);
            }
        }

        // ivshmem devices (time, health, CAN)
        for dev in &def.devices {
            if !dev.needs_ivshmem() { continue; }
            match dev {
                DeviceConfig::Time { .. } => {
                    if let Some(sock) = &ivshmem_sockets.time {
                        args.extend_from_slice(&[
                            "-chardev".into(),
                            format!("socket,path={},id=ivshmem_time", sock.display()),
                            "-device".into(),
                            "ivshmem-doorbell,chardev=ivshmem_time,vectors=2".into(),
                        ]);
                    }
                }
                DeviceConfig::Health { .. } => {
                    if let Some(sock) = &ivshmem_sockets.health {
                        args.extend_from_slice(&[
                            "-chardev".into(),
                            format!("socket,path={},id=ivshmem_health", sock.display()),
                            "-device".into(),
                            "ivshmem-doorbell,chardev=ivshmem_health,vectors=2".into(),
                        ]);
                    }
                }
                _ => {}
            }
        }

        // CAN interfaces in reverse order (so can0 gets lowest PCI address)
        let mut can_devs: Vec<(u8, &Option<String>)> = Vec::new();
        for dev in &def.devices {
            if let DeviceConfig::Can { index, interface, .. } = dev {
                if dev.needs_ivshmem() {
                    can_devs.push((*index, interface));
                }
            }
        }
        can_devs.sort_by(|a, b| b.0.cmp(&a.0));
        for (idx, _) in &can_devs {
            if let Some(sock) = ivshmem_sockets.can.get(idx) {
                args.extend_from_slice(&[
                    "-chardev".into(),
                    format!("socket,path={},id=ivshmem_can{idx}", sock.display()),
                    "-device".into(),
                    format!("ivshmem-doorbell,chardev=ivshmem_can{idx},vectors=2"),
                ]);
            }
        }

        // Append kernel cmdline
        let cmdline = cmdline_parts.join(" ");
        args.extend_from_slice(&["-append".into(), cmdline]);

        Ok(args)
    }
}

impl VmRunner for QemuRunner {
    fn start(&mut self, name: &str, def: &VmDefinition) -> Result<VmHandle, RunnerError> {
        let sim_dir = def.sim_dir.as_deref();
        let mut ivshmem = IvshmemSockets::default();

        // Start ivshmem servers for devices that need shared memory
        for dev in &def.devices {
            if !dev.needs_ivshmem() { continue; }
            match dev {
                DeviceConfig::Can { index, .. } => {
                    let sock = ivshmem::start_ivshmem(
                        name, &format!("can{index}"), "1M",
                        &self.ivshmem_bin, &mut self.host_processes, &mut self.sockets,
                    )?;
                    ivshmem.can.insert(*index, sock);
                }
                DeviceConfig::Health { .. } => {
                    let sock = ivshmem::start_ivshmem(
                        name, "health", "4K",
                        &self.ivshmem_bin, &mut self.host_processes, &mut self.sockets,
                    )?;
                    ivshmem.health = Some(sock);
                }
                DeviceConfig::Time { .. } => {
                    let sock = ivshmem::start_ivshmem(
                        name, "time", "4K",
                        &self.ivshmem_bin, &mut self.host_processes, &mut self.sockets,
                    )?;
                    ivshmem.time = Some(sock);
                }
                _ => {}
            }
        }

        // Write magic values to shared memory for non-simulated devices
        for dev in &def.devices {
            if dev.needs_ivshmem() && !dev.needs_simulator() {
                if let (Some(magic), Some(label)) = (dev.ivshmem_magic(), dev.ivshmem_label()) {
                    ivshmem::write_shm_magic(name, &label, magic);
                }
            }
        }

        // Start host-side simulators
        for dev in &def.devices {
            if dev.needs_simulator() {
                match dev {
                    DeviceConfig::Health { .. } => {
                        if let Some(sock) = &ivshmem.health {
                            let bin = self.sim_binary("health-sim", sim_dir)?;
                            self.start_process(
                                "health-sim",
                                Command::new(&bin).arg(sock),
                            )?;
                        }
                    }
                    DeviceConfig::Time { .. } => {
                        if let Some(sock) = &ivshmem.time {
                            let bin = self.sim_binary("time-sim", sim_dir)?;
                            self.start_process(
                                "time-sim",
                                Command::new(&bin)
                                    .arg(sock)
                                    .arg("--sync-guest-id").arg("1")
                                    .arg("--min-adjust-interval").arg("2"),
                            )?;
                        }
                    }
                    DeviceConfig::Can { index, .. } => {
                        if let Some(sock) = ivshmem.can.get(index) {
                            let bin = self.sim_binary("qnx-host-sim", sim_dir)?;
                            let can_id = format!("0x{:X}", (*index as u32 + 1) * 0x100);
                            self.start_process(
                                &format!("qnx-host-sim-can{index}"),
                                Command::new(&bin).arg(sock).arg(&can_id),
                            )?;
                        }
                    }
                    _ => {}
                }
            }

            // HSM uses vsock only — no TCP fallback
            if let DeviceConfig::Hsm { keystore } = dev {
                let bin = self.sim_binary("vhsm-test-ssd", sim_dir)?;
                let ks = keystore.as_deref().unwrap_or("/tmp/vhsm-keys");
                let mut cmd = Command::new(&bin);
                cmd.arg("--keystore").arg(ks).arg("--port").arg("5555");
                self.start_process("vhsm-test-ssd", &mut cmd)?;
            }
        }

        // Small delay for processes to initialize
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Build and launch QEMU
        let args = self.build_qemu_args(name, def, &ivshmem)?;

        let child = Command::new(&args[0])
            .args(&args[1..])
            .spawn()
            .map_err(|e| RunnerError::ProcessFailed(format!("QEMU: {e}")))?;

        let pid = child.id();
        self.host_processes.push(HostProcess {
            name: "qemu".to_string(),
            child,
        });

        // Set up health monitor if health device is configured
        let has_health = def.devices.iter().any(|d| matches!(d, DeviceConfig::Health { .. }));
        if has_health {
            self.health_monitor = Some(HealthMonitor::new(name));
        }

        Ok(VmHandle { name: name.to_string(), pid: Some(pid) })
    }

    fn wait(&mut self, handle: &VmHandle) -> Result<Option<i32>, RunnerError> {
        if let Some(pid) = handle.pid {
            for proc in &mut self.host_processes {
                if proc.name == "qemu" && proc.pid() == pid {
                    let status = proc.child.wait()?;
                    return Ok(status.code());
                }
            }
        }
        Err(RunnerError::ProcessFailed("QEMU process not found".into()))
    }

    fn stop(&mut self, handle: &VmHandle) -> Result<(), RunnerError> {
        if let Some(pid) = handle.pid {
            for proc in &mut self.host_processes {
                if proc.name == "qemu" && proc.pid() == pid {
                    let _ = proc.child.kill();
                    let _ = proc.child.wait();
                    break;
                }
            }
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

    fn cleanup(&mut self) {
        for proc in self.host_processes.iter_mut().rev() {
            let _ = proc.child.kill();
            let _ = proc.child.wait();
        }
        self.host_processes.clear();

        for sock in &self.sockets {
            let _ = std::fs::remove_file(sock);
        }
        self.sockets.clear();

        self.health_monitor = None;
    }

    fn wait_ready(&mut self, handle: &VmHandle, timeout: Duration) -> Result<(), RunnerError> {
        if let Some(ref mut monitor) = self.health_monitor {
            let pid = handle.pid;
            monitor.wait_ready(timeout, || {
                pid.map(|p| unsafe { libc::kill(p as i32, 0) == 0 }).unwrap_or(false)
            }).map_err(|e| RunnerError::ProcessFailed(e))
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
        // Graceful failed or no health device — force kill
        self.stop(handle)
    }
}

impl Drop for QemuRunner {
    fn drop(&mut self) {
        self.cleanup();
    }
}
