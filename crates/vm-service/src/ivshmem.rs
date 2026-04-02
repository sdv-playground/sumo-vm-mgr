/// ivshmem-server management — launches and cleans up ivshmem shared memory
/// servers for host-guest communication (CAN, health, time).

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command};

use crate::runner::RunnerError;

/// Tracks a host-side process launched by the runner.
pub(crate) struct HostProcess {
    pub name: String,
    pub child: Child,
}

impl HostProcess {
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
}

/// Collected ivshmem socket paths, populated during VM startup.
#[derive(Default)]
pub(crate) struct IvshmemSockets {
    pub can: HashMap<u8, PathBuf>,
    pub health: Option<PathBuf>,
    pub time: Option<PathBuf>,
}

/// Socket path for an ivshmem device, namespaced by VM name.
pub(crate) fn socket_path(vm_name: &str, label: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/vm-svc-{vm_name}-ivshmem-{label}.sock"))
}

/// PID file path for an ivshmem server.
fn pid_path(vm_name: &str, label: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/vm-svc-{vm_name}-ivshmem-{label}.pid"))
}

/// Shared memory name and path for an ivshmem device.
pub(crate) fn shm_name(vm_name: &str, label: &str) -> String {
    format!("ivshmem-{vm_name}-{label}")
}

pub(crate) fn shm_path(vm_name: &str, label: &str) -> PathBuf {
    PathBuf::from(format!("/dev/shm/{}", shm_name(vm_name, label)))
}

/// Start an ivshmem-server for the given VM + device label.
pub(crate) fn start_ivshmem(
    vm_name: &str,
    label: &str,
    size: &str,
    ivshmem_bin: &std::path::Path,
    host_processes: &mut Vec<HostProcess>,
    sockets: &mut Vec<PathBuf>,
) -> Result<PathBuf, RunnerError> {
    let sock = socket_path(vm_name, label);
    let pid_file = pid_path(vm_name, label);
    let mem_name = shm_name(vm_name, label);

    // Clean stale files
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(&pid_file);
    let _ = std::fs::remove_file(shm_path(vm_name, label));

    let child = Command::new(ivshmem_bin)
        .arg("-S").arg(&sock)
        .arg("-l").arg(size)
        .arg("-n").arg("2")
        .arg("-M").arg(&mem_name)
        .arg("-F")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| RunnerError::ProcessFailed(format!("ivshmem-{label}: {e}")))?;

    host_processes.push(HostProcess {
        name: format!("ivshmem-{label}"),
        child,
    });

    // Wait for socket to appear
    for _ in 0..50 {
        if sock.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if !sock.exists() {
        return Err(RunnerError::ProcessFailed(format!(
            "ivshmem-server {label}: socket not created at {}",
            sock.display()
        )));
    }

    sockets.push(sock.clone());
    Ok(sock)
}

/// Write device header to shared memory so guest drivers can identify and probe.
///
/// Writes the full header (vhealth_regs.h layout): magic, version, num_sensors,
/// flags, and a dummy sensor entry. Guest drivers validate all of these during
/// probe — missing fields cause probe failure.
pub(crate) fn write_shm_magic(vm_name: &str, label: &str, magic: u32) {
    let path = shm_path(vm_name, label);
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&path) {
        use std::io::Write;
        // Header: 32 bytes at offset 0x00
        //   0x00: magic       (u32)
        //   0x04: version     (u32) — must be 1
        //   0x08: num_sensors (u32) — must be >= 1
        //   0x0C: update_seq  (u32)
        //   0x10: mono_ns     (u64)
        //   0x18: flags       (u32) — 1 = ACTIVE
        //   0x1C: reserved    (u32)
        let _ = f.write_all(&magic.to_le_bytes());
        let _ = f.write_all(&1u32.to_le_bytes());  // version = 1
        let _ = f.write_all(&1u32.to_le_bytes());  // num_sensors = 1
        let _ = f.write_all(&0u32.to_le_bytes());  // update_seq
        let _ = f.write_all(&0u64.to_le_bytes());  // mono_ns
        let _ = f.write_all(&1u32.to_le_bytes());  // flags = ACTIVE
        let _ = f.write_all(&0u32.to_le_bytes());  // reserved

        // Sensor entry 0: 32 bytes at offset 0x20 — dummy SoC temp
        //   0x00: sensor_type (u16)
        //   0x02: sensor_id   (u16)
        //   0x04: value       (i32) — millidegrees C
        //   0x08: value_min   (i32)
        //   0x0C: value_max   (i32)
        //   0x10: thresh_warn (i32)
        //   0x14: thresh_crit (i32)
        //   0x18: flags       (u32) — 1 = VALID
        //   0x1C: reserved    (u32)
        let _ = f.write_all(&1u16.to_le_bytes());   // VHEALTH_TYPE_TEMP_SOC
        let _ = f.write_all(&0u16.to_le_bytes());   // sensor_id = 0
        let _ = f.write_all(&45000i32.to_le_bytes()); // 45.0°C
        let _ = f.write_all(&0i32.to_le_bytes());   // min
        let _ = f.write_all(&100000i32.to_le_bytes()); // max 100°C
        let _ = f.write_all(&85000i32.to_le_bytes());  // warn 85°C
        let _ = f.write_all(&95000i32.to_le_bytes());  // crit 95°C
        let _ = f.write_all(&1u32.to_le_bytes());   // flags = VALID
        let _ = f.write_all(&0u32.to_le_bytes());   // reserved
    }
}

/// Clean up ivshmem shared memory files for a VM.
#[allow(dead_code)]
pub(crate) fn cleanup_shm(vm_name: &str) {
    let prefix = format!("ivshmem-{vm_name}-");
    let _ = std::fs::read_dir("/dev/shm").map(|entries| {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with(&prefix) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    });
}
