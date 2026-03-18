/// QEMU boot backend — translates VM profiles into QEMU command lines
/// and manages host-side processes (ivshmem-server, simulators).

use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use nv_store::types::{Bank, BankSet};
use crate::backend::*;
use crate::config::*;

/// Tracks a host-side process launched by the backend.
struct HostProcess {
    name: String,
    child: Child,
}

impl HostProcess {
    fn pid(&self) -> u32 {
        self.child.id()
    }
}

pub struct QemuBackend {
    /// Path to qemu-system-aarch64 binary
    qemu_bin: PathBuf,
    /// Path to ivshmem-server binary
    ivshmem_bin: PathBuf,
    /// Directory for host simulator binaries
    sim_dir: Option<PathBuf>,
    /// Use KVM if available
    try_kvm: bool,
    /// Running host-side processes
    host_processes: Vec<HostProcess>,
    /// Socket paths to clean up
    sockets: Vec<PathBuf>,
}

impl QemuBackend {
    pub fn new() -> Self {
        Self {
            qemu_bin: PathBuf::from("qemu-system-aarch64"),
            ivshmem_bin: PathBuf::from("ivshmem-server"),
            sim_dir: None,
            try_kvm: true,
            host_processes: Vec::new(),
            sockets: Vec::new(),
        }
    }

    pub fn qemu_bin(mut self, path: impl Into<PathBuf>) -> Self {
        self.qemu_bin = path.into();
        self
    }

    pub fn ivshmem_bin(mut self, path: impl Into<PathBuf>) -> Self {
        self.ivshmem_bin = path.into();
        self
    }

    pub fn sim_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.sim_dir = Some(path.into());
        self
    }

    pub fn try_kvm(mut self, enable: bool) -> Self {
        self.try_kvm = enable;
        self
    }

    fn kvm_available(&self) -> bool {
        self.try_kvm
            && cfg!(target_arch = "aarch64")
            && Path::new("/dev/kvm").exists()
    }

    fn sim_binary(&self, name: &str) -> Result<PathBuf, BackendError> {
        match &self.sim_dir {
            Some(dir) => {
                let path = dir.join(name);
                if path.exists() {
                    Ok(path)
                } else {
                    Err(BackendError::Config(format!(
                        "simulator binary not found: {}",
                        path.display()
                    )))
                }
            }
            None => Err(BackendError::Config(
                "sim_dir not set — cannot start simulators".into(),
            )),
        }
    }

    fn start_process(&mut self, name: &str, cmd: &mut Command) -> Result<u32, BackendError> {
        let child = cmd
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| BackendError::ProcessFailed(format!("{name}: {e}")))?;
        let pid = child.id();
        self.host_processes.push(HostProcess {
            name: name.to_string(),
            child,
        });
        Ok(pid)
    }

    fn start_ivshmem(
        &mut self,
        label: &str,
        size: &str,
    ) -> Result<PathBuf, BackendError> {
        let sock = PathBuf::from(format!("/tmp/bali-ivshmem-{label}.sock"));
        let pid_file = PathBuf::from(format!("/tmp/bali-ivshmem-{label}.pid"));

        // Clean stale
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_file(&pid_file);
        let shm_path = format!("/dev/shm/ivshmem-{label}");
        let _ = std::fs::remove_file(&shm_path);

        self.start_process(
            &format!("ivshmem-{label}"),
            Command::new(&self.ivshmem_bin)
                .arg("-S")
                .arg(&sock)
                .arg("-l")
                .arg(size)
                .arg("-n")
                .arg("2")
                .arg("-M")
                .arg(format!("ivshmem-{label}"))
                .arg("-F"),
        )?;

        // Wait for socket to appear
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if !sock.exists() {
            return Err(BackendError::ProcessFailed(format!(
                "ivshmem-server {label}: socket not created at {}",
                sock.display()
            )));
        }

        self.sockets.push(sock.clone());
        Ok(sock)
    }

    /// Resolve the image path for a bank set + bank.
    /// Convention: {image_dir}/{set}-{bank}.img (e.g., os1-a.img, os1-b.img)
    fn image_path(image_dir: &Path, set: BankSet, bank: Bank) -> PathBuf {
        let set_name = match set {
            BankSet::Hypervisor => "hyp",
            BankSet::Os1 => "os1",
            BankSet::Os2 => "os2",
        };
        let bank_name = match bank {
            Bank::A => "a",
            Bank::B => "b",
        };
        image_dir.join(format!("{set_name}-{bank_name}.img"))
    }

    /// Build the QEMU command line from a profile.
    fn build_qemu_args(
        &self,
        profile: &VmProfile,
        set: BankSet,
        bank: Bank,
        image_dir: &Path,
        ivshmem_sockets: &IvshmemSockets,
    ) -> Result<Vec<String>, BackendError> {
        let mut args: Vec<String> = Vec::new();
        let use_kvm = self.kvm_available();

        let cpu = if use_kvm { "host" } else { &profile.vm.cpu_model };

        args.extend_from_slice(&[
            self.qemu_bin.to_string_lossy().into_owned(),
            "-machine".into(), "virt,gic-version=3".into(),
            "-cpu".into(), cpu.into(),
        ]);

        if use_kvm {
            args.push("-enable-kvm".into());
        }

        args.extend_from_slice(&[
            "-m".into(), format!("{}M", profile.vm.ram_mb),
            "-smp".into(), profile.vm.cpus.to_string(),
            "-nographic".into(),
            "-no-reboot".into(),
        ]);

        // Kernel
        if let Some(ref kernel) = profile.vm.kernel {
            let kernel_path = if Path::new(kernel).is_absolute() {
                PathBuf::from(kernel)
            } else {
                image_dir.join(kernel)
            };
            args.extend_from_slice(&[
                "-kernel".into(),
                kernel_path.to_string_lossy().into_owned(),
            ]);
        }

        // Build kernel cmdline
        let mut cmdline_parts: Vec<String> = vec![
            "root=/dev/vda".into(),
            "rw".into(),
            "console=ttyAMA0".into(),
            "earlycon".into(),
            "no_console_suspend".into(),
            "pm_debug_messages".into(),
        ];

        // Count CAN interfaces for kernel param
        let can_count = profile.can_count();
        if can_count > 0 {
            cmdline_parts.push(format!("vcan_shm.backend=ivshmem"));
            cmdline_parts.push(format!("vcan_shm.num_devices={can_count}"));
        }

        if let Some(ref extra) = profile.vm.extra_cmdline {
            cmdline_parts.push(extra.clone());
        }

        // Disks — collect and add in reverse order (QEMU virt reverse enumeration)
        // Convention: swap first (vdc), data second (vdb), rootfs last (vda)
        let mut disk_args: Vec<Vec<String>> = Vec::new();

        for dev in &profile.devices {
            if let DeviceConfig::Disk { role, path, readonly } = dev {
                let disk_path = if Path::new(path).is_absolute() {
                    PathBuf::from(path)
                } else {
                    image_dir.join(path)
                };
                let drive_id = format!("hd_{role}");
                let ro = if *readonly { ",readonly=on" } else { "" };
                disk_args.push(vec![
                    "-drive".into(),
                    format!("file={},format=raw,if=none,id={drive_id}{ro}", disk_path.display()),
                    "-device".into(),
                    format!("virtio-blk-device,drive={drive_id}"),
                ]);

                if role == "swap" {
                    cmdline_parts.push(format!(
                        "resume={}",
                        // The actual device depends on enumeration order,
                        // but swap is typically /dev/vdc
                        "/dev/vdc"
                    ));
                }
            }
        }

        // Disks go first (reverse enumeration: first in args = highest /dev/vdX)
        for disk in &disk_args {
            args.extend_from_slice(disk);
        }

        args.push("-device".into());
        args.push("virtio-rng-device".into());

        // Bank-specific rootfs image (always last disk → /dev/vda)
        let rootfs = Self::image_path(image_dir, set, bank);
        args.extend_from_slice(&[
            "-drive".into(),
            format!("file={},format=raw,if=none,id=hd_rootfs", rootfs.display()),
            "-device".into(),
            "virtio-blk-device,drive=hd_rootfs".into(),
        ]);

        // Network devices
        let mut net_idx = 0;
        // Extra networks first (reverse enumeration)
        let networks: Vec<_> = profile.devices.iter().filter(|d| matches!(d, DeviceConfig::Network { .. })).collect();
        for (i, dev) in networks.iter().enumerate().rev() {
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
                let mut dev_str = format!("virtio-net-device,netdev={id}");
                if let Some(m) = mac {
                    dev_str.push_str(&format!(",mac={m}"));
                }
                args.extend_from_slice(&["-device".into(), dev_str]);
                net_idx += 1;
            }
        }

        // vsock for HSM
        for dev in &profile.devices {
            if let DeviceConfig::Hsm { backend, .. } = dev {
                if backend == "vsock" && Path::new("/dev/vhost-vsock").exists() {
                    args.extend_from_slice(&[
                        "-device".into(),
                        "vhost-vsock-device,guest-cid=3".into(),
                    ]);
                }
            }
        }

        // ivshmem devices (time, health, CAN — in this order, reverse enumeration)
        for dev in &profile.devices {
            if let DeviceConfig::Time { backend } = dev {
                if backend == "simulated" {
                    if let Some(sock) = &ivshmem_sockets.time {
                        args.extend_from_slice(&[
                            "-chardev".into(),
                            format!("socket,path={},id=ivshmem_time", sock.display()),
                            "-device".into(),
                            "ivshmem-doorbell,chardev=ivshmem_time,vectors=2".into(),
                        ]);
                    }
                }
            }
        }

        for dev in &profile.devices {
            if let DeviceConfig::Health { backend } = dev {
                if backend == "simulated" {
                    if let Some(sock) = &ivshmem_sockets.health {
                        args.extend_from_slice(&[
                            "-chardev".into(),
                            format!("socket,path={},id=ivshmem_health", sock.display()),
                            "-device".into(),
                            "ivshmem-doorbell,chardev=ivshmem_health,vectors=2".into(),
                        ]);
                    }
                }
            }
        }

        // CAN interfaces in reverse order (so can0 gets lowest PCI address)
        let mut can_devs: Vec<(u8, &Option<String>)> = Vec::new();
        for dev in &profile.devices {
            if let DeviceConfig::Can { index, backend, interface } = dev {
                if backend == "simulated" {
                    can_devs.push((*index, interface));
                }
            }
        }
        can_devs.sort_by(|a, b| b.0.cmp(&a.0)); // reverse order
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

/// Collected ivshmem socket paths, populated during start_vm.
#[derive(Default)]
struct IvshmemSockets {
    can: std::collections::HashMap<u8, PathBuf>,
    health: Option<PathBuf>,
    time: Option<PathBuf>,
}

impl BootBackend for QemuBackend {
    fn start_vm(
        &mut self,
        profile: &VmProfile,
        set: BankSet,
        bank: Bank,
        image_dir: &Path,
    ) -> Result<VmHandle, BackendError> {
        let mut ivshmem = IvshmemSockets::default();

        // Start ivshmem servers for simulated devices
        for dev in &profile.devices {
            match dev {
                DeviceConfig::Can { index, backend, .. } if backend == "simulated" => {
                    let sock = self.start_ivshmem(&format!("can{index}"), "1M")?;
                    ivshmem.can.insert(*index, sock);
                }
                DeviceConfig::Health { backend } if backend == "simulated" => {
                    let sock = self.start_ivshmem("health", "4K")?;
                    ivshmem.health = Some(sock);
                }
                DeviceConfig::Time { backend } if backend == "simulated" => {
                    let sock = self.start_ivshmem("time", "4K")?;
                    ivshmem.time = Some(sock);
                }
                _ => {}
            }
        }

        // Start simulators for simulated devices
        for dev in &profile.devices {
            match dev {
                DeviceConfig::Health { backend } if backend == "simulated" => {
                    if let Some(sock) = &ivshmem.health {
                        let bin = self.sim_binary("health-sim")?;
                        self.start_process(
                            "health-sim",
                            Command::new(&bin).arg(sock),
                        )?;
                    }
                }
                DeviceConfig::Time { backend } if backend == "simulated" => {
                    if let Some(sock) = &ivshmem.time {
                        let bin = self.sim_binary("time-sim")?;
                        self.start_process(
                            "time-sim",
                            Command::new(&bin)
                                .arg(sock)
                                .arg("--sync-guest-id").arg("1")
                                .arg("--min-adjust-interval").arg("2"),
                        )?;
                    }
                }
                DeviceConfig::Can { index, backend, .. } if backend == "simulated" => {
                    if let Some(sock) = ivshmem.can.get(index) {
                        let bin = self.sim_binary("qnx-host-sim")?;
                        let can_id = format!("0x{:X}", (*index as u32 + 1) * 0x100);
                        self.start_process(
                            &format!("qnx-host-sim-can{index}"),
                            Command::new(&bin).arg(sock).arg(&can_id),
                        )?;
                    }
                }
                DeviceConfig::Hsm { backend, keystore } if backend == "vsock" || backend == "tcp" => {
                    let bin = self.sim_binary("vhsm-test-ssd")?;
                    let ks = keystore.as_deref().unwrap_or("/tmp/vhsm-keys");
                    let mut cmd = Command::new(&bin);
                    cmd.arg("--keystore").arg(ks).arg("--tcp").arg("127.0.0.1:5555");
                    if backend == "vsock" && Path::new("/dev/vhost-vsock").exists() {
                        cmd.arg("--port").arg("5555");
                    }
                    self.start_process("vhsm-test-ssd", &mut cmd)?;
                }
                _ => {}
            }
        }

        // Small delay for processes to initialize
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Build and launch QEMU
        let args = self.build_qemu_args(profile, set, bank, image_dir, &ivshmem)?;

        let child = Command::new(&args[0])
            .args(&args[1..])
            .spawn()
            .map_err(|e| BackendError::ProcessFailed(format!("QEMU: {e}")))?;

        let pid = child.id();
        self.host_processes.push(HostProcess {
            name: "qemu".to_string(),
            child,
        });

        Ok(VmHandle { set, bank, pid: Some(pid) })
    }

    fn wait_vm(&mut self, handle: &VmHandle) -> Result<Option<i32>, BackendError> {
        if let Some(pid) = handle.pid {
            for proc in &mut self.host_processes {
                if proc.name == "qemu" && proc.pid() == pid {
                    let status = proc.child.wait()?;
                    return Ok(status.code());
                }
            }
        }
        Err(BackendError::ProcessFailed("QEMU process not found".into()))
    }

    fn stop_vm(&mut self, handle: &VmHandle) -> Result<(), BackendError> {
        if let Some(pid) = handle.pid {
            // Find and kill the QEMU process
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
            // Check if process exists via kill(0)
            unsafe { libc::kill(pid as i32, 0) == 0 }
        } else {
            false
        }
    }

    fn build_command(
        &self,
        profile: &VmProfile,
        set: BankSet,
        bank: Bank,
        image_dir: &Path,
    ) -> Result<Vec<String>, BackendError> {
        // For dry-run, use empty ivshmem sockets (paths shown as placeholders)
        let mut ivshmem = IvshmemSockets::default();
        for dev in &profile.devices {
            match dev {
                DeviceConfig::Can { index, backend, .. } if backend == "simulated" => {
                    ivshmem.can.insert(*index, PathBuf::from(format!("/tmp/bali-ivshmem-can{index}.sock")));
                }
                DeviceConfig::Health { backend } if backend == "simulated" => {
                    ivshmem.health = Some(PathBuf::from("/tmp/bali-ivshmem-health.sock"));
                }
                DeviceConfig::Time { backend } if backend == "simulated" => {
                    ivshmem.time = Some(PathBuf::from("/tmp/bali-ivshmem-time.sock"));
                }
                _ => {}
            }
        }
        self.build_qemu_args(profile, set, bank, image_dir, &ivshmem)
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

        // Clean shared memory
        let _ = std::fs::read_dir("/dev/shm").map(|entries| {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().starts_with("ivshmem-") {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        });
    }
}

impl Drop for QemuBackend {
    fn drop(&mut self) {
        self.cleanup();
    }
}
