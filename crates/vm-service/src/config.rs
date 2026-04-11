/// Static YAML configuration for vm-service.
///
/// Loaded once at startup. Declares which VMs can exist and their hardware
/// setup. Lifecycle control (start/stop/restart) comes via the HTTP API.
/// Bank selection is invisible — `image_dir` is typically a symlink that
/// the diagnostic stack flips before calling restart.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use serde::Deserialize;

/// Top-level service configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct VmServiceConfig {
    /// Unix socket path for the control API.
    pub socket: PathBuf,
    /// VM definitions, keyed by name (e.g., "os1", "os2").
    pub vms: HashMap<String, VmDefinition>,
}

/// Everything needed to run a single VM.
#[derive(Debug, Clone, Deserialize)]
pub struct VmDefinition {
    /// Backend type: qemu, qnx, or dummy.
    pub backend: BackendType,
    /// Target architecture (default: aarch64).
    #[serde(default)]
    pub arch: Option<String>,
    /// Number of virtual CPUs (default: 4).
    #[serde(default = "default_cpus")]
    pub cpus: u32,
    /// RAM in MB (default: 2048).
    #[serde(default = "default_ram")]
    pub ram_mb: u32,
    /// CPU model override. If unset, uses arch default.
    #[serde(default)]
    pub cpu_model: Option<String>,
    /// Directory containing kernel + rootfs. Typically a symlink
    /// (e.g., /var/lib/vms/os1/current → bank_a/).
    pub image_dir: PathBuf,
    /// Image filenames relative to image_dir.
    #[serde(default)]
    pub images: ImagePaths,
    /// Devices attached to this VM.
    #[serde(default)]
    pub devices: Vec<DeviceConfig>,
    /// Extra disks (data, swap) — not part of the banked image set.
    #[serde(default)]
    pub disks: Vec<DiskConfig>,
    /// Health monitoring configuration.
    #[serde(default)]
    #[allow(dead_code)]
    pub health: Option<HealthConfig>,
    /// Shutdown configuration.
    #[serde(default)]
    pub shutdown: Option<ShutdownConfig>,
    /// Extra kernel command-line arguments.
    #[serde(default)]
    pub extra_cmdline: Option<String>,
    /// Directory for host simulator binaries.
    #[serde(default)]
    pub sim_dir: Option<PathBuf>,
}

fn default_cpus() -> u32 { 4 }
fn default_ram() -> u32 { 2048 }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendType {
    Qemu,
    Qnx,
    Dummy,
}

/// Paths to boot images, relative to image_dir.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ImagePaths {
    /// Kernel image filename (e.g., "kernel", "Image").
    #[serde(default)]
    pub kernel: Option<String>,
    /// Root filesystem filename (e.g., "rootfs.qcow2").
    #[serde(default)]
    pub rootfs: Option<String>,
}

/// Extra disk not managed by the banking system.
#[derive(Debug, Clone, Deserialize)]
pub struct DiskConfig {
    /// Role name: "data", "swap", etc.
    pub role: String,
    /// Absolute path to disk image.
    pub path: PathBuf,
    /// Mount read-only.
    #[serde(default)]
    pub readonly: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct HealthConfig {
    /// Seconds before declaring VM unhealthy.
    #[serde(default = "default_health_timeout")]
    pub timeout_secs: u64,
}

fn default_health_timeout() -> u64 { 10 }

#[derive(Debug, Clone, Deserialize)]
pub struct ShutdownConfig {
    /// Seconds to wait for graceful shutdown before force-kill.
    #[serde(default = "default_shutdown_timeout")]
    pub timeout_secs: u64,
}

fn default_shutdown_timeout() -> u64 { 10 }

impl VmServiceConfig {
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        serde_yaml::from_str(&content)
            .map_err(|e| format!("failed to parse {}: {e}", path.display()))
    }
}

impl VmDefinition {
    /// Resolve target architecture (defaults to Aarch64).
    pub fn arch(&self) -> Arch {
        self.arch.as_deref()
            .and_then(Arch::from_str)
            .unwrap_or(Arch::Aarch64)
    }

    /// Count CAN interfaces.
    pub fn can_count(&self) -> u8 {
        self.devices.iter()
            .filter(|d| matches!(d, DeviceConfig::Can { .. }))
            .count() as u8
    }

    /// Get SSH port if any network device has one.
    #[allow(dead_code)]
    pub fn ssh_port(&self) -> Option<u16> {
        self.devices.iter().find_map(|d| match d {
            DeviceConfig::Network { ssh_port, .. } => *ssh_port,
            _ => None,
        })
    }

    /// Resolve the kernel path (image_dir + images.kernel).
    pub fn kernel_path(&self) -> Option<PathBuf> {
        self.images.kernel.as_ref().map(|k| {
            if Path::new(k).is_absolute() {
                PathBuf::from(k)
            } else {
                self.image_dir.join(k)
            }
        })
    }

    /// Resolve the rootfs path (image_dir + images.rootfs).
    pub fn rootfs_path(&self) -> Option<PathBuf> {
        self.images.rootfs.as_ref().map(|r| {
            if Path::new(r).is_absolute() {
                PathBuf::from(r)
            } else {
                self.image_dir.join(r)
            }
        })
    }

    /// Shutdown timeout in seconds (default 10).
    pub fn shutdown_timeout_secs(&self) -> u64 {
        self.shutdown.as_ref().map(|s| s.timeout_secs).unwrap_or(10)
    }
}

// =============================================================================
// Architecture abstraction (copied from boot crate — pure data, no nv-store dep)
// =============================================================================

/// Target architecture for a VM. Drives QEMU binary selection, machine type,
/// console device, virtio transport, and disk enumeration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    Aarch64,
    X86_64,
}

impl Arch {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "aarch64" | "arm64" => Some(Arch::Aarch64),
            "x86_64" | "amd64" => Some(Arch::X86_64),
            _ => None,
        }
    }

    pub fn qemu_binary(&self) -> &'static str {
        match self {
            Arch::Aarch64 => "qemu-system-aarch64",
            Arch::X86_64 => "qemu-system-x86_64",
        }
    }

    pub fn machine_type(&self) -> &'static str {
        match self {
            Arch::Aarch64 => "virt,gic-version=3",
            Arch::X86_64 => "q35",
        }
    }

    pub fn console_device(&self) -> &'static str {
        match self {
            Arch::Aarch64 => "ttyAMA0",
            Arch::X86_64 => "ttyS0",
        }
    }

    pub fn default_cpu(&self) -> &'static str {
        match self {
            Arch::Aarch64 => "cortex-a76",
            Arch::X86_64 => "max",
        }
    }

    pub fn virtio_device(&self, kind: &str) -> String {
        match self {
            Arch::Aarch64 => format!("virtio-{kind}-device"),
            Arch::X86_64 => format!("virtio-{kind}-pci"),
        }
    }

    pub fn reverse_disk_order(&self) -> bool {
        match self {
            Arch::Aarch64 => true,
            Arch::X86_64 => false,
        }
    }

    pub fn kvm_available(&self) -> bool {
        if !Path::new("/dev/kvm").exists() {
            return false;
        }
        match self {
            Arch::Aarch64 => cfg!(target_arch = "aarch64"),
            Arch::X86_64 => cfg!(target_arch = "x86_64"),
        }
    }
}

// =============================================================================
// Device configuration (adapted from boot crate)
// =============================================================================

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum DeviceConfig {
    #[serde(rename = "can")]
    Can {
        #[serde(default)]
        index: u8,
        #[serde(default = "default_device_backend")]
        backend: String,
        #[serde(default)]
        interface: Option<String>,
    },
    #[serde(rename = "health")]
    Health {
        #[serde(default = "default_device_backend")]
        backend: String,
    },
    #[serde(rename = "time")]
    Time {
        #[serde(default = "default_device_backend")]
        backend: String,
    },
    #[serde(rename = "hsm")]
    Hsm {
        #[serde(default)]
        keystore: Option<String>,
        #[serde(default)]
        keygen_bin: Option<String>,
        #[serde(default = "default_hsm_port")]
        port: u16,
    },
    #[serde(rename = "network")]
    Network {
        #[serde(default)]
        mac: Option<String>,
        #[serde(default)]
        ssh_port: Option<u16>,
    },
    #[serde(rename = "console")]
    Console,
}

fn default_device_backend() -> String { "simulated".to_string() }
fn default_hsm_port() -> u16 { 5100 }

impl DeviceConfig {
    pub fn needs_ivshmem(&self) -> bool {
        match self {
            DeviceConfig::Health { .. } => true,
            DeviceConfig::Time { .. } => true,
            DeviceConfig::Can { backend, .. } => backend != "host-passthrough",
            _ => false,
        }
    }

    pub fn needs_simulator(&self) -> bool {
        match self {
            DeviceConfig::Health { backend }
            | DeviceConfig::Time { backend }
            | DeviceConfig::Can { backend, .. } => backend == "simulated",
            _ => false,
        }
    }

    pub fn ivshmem_label(&self) -> Option<String> {
        match self {
            DeviceConfig::Health { .. } if self.needs_ivshmem() => Some("health".into()),
            DeviceConfig::Time { .. } if self.needs_ivshmem() => Some("time".into()),
            DeviceConfig::Can { index, .. } if self.needs_ivshmem() => Some(format!("can{index}")),
            _ => None,
        }
    }

    pub fn ivshmem_magic(&self) -> Option<u32> {
        match self {
            DeviceConfig::Health { .. } => Some(0x48544C48), // "HLTH"
            DeviceConfig::Time { .. } => Some(0x54494D45),   // "TIME"
            DeviceConfig::Can { .. } => Some(0x4E414356),    // "VCAN"
            _ => None,
        }
    }
}
