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
    /// VM definitions, keyed by name (e.g., "vm1", "vm2").
    pub vms: HashMap<String, VmDefinition>,
}

/// Everything needed to run a single VM.
#[derive(Debug, Clone, Deserialize)]
pub struct VmDefinition {
    /// Human-readable display name (e.g., "VM1 — Debian Linux").
    /// Used in SOVD component listing if available.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Backend type: qemu, qnx, or dummy.
    pub backend: BackendType,
    /// Guest operating system type. Affects boot method, disk layout, device setup.
    #[serde(default)]
    pub os_type: OsType,
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
    /// (e.g., /var/lib/vms/vm1/current → bank_a/).
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

/// Guest OS type — affects boot method, disk layout, and device setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OsType {
    /// Linux guest: boots with -kernel + -append + rootfs as virtio-blk.
    /// Supports vcan-shm, vtime, vhealth kernel modules.
    #[default]
    Linux,
    /// QNX guest: boots from disk image (IFS + QNX6 filesystem).
    /// No separate kernel — bootloader in the disk image.
    Qnx,
}

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

    /// Merge per-bank overrides into this definition. Only present fields are overridden.
    pub fn with_bank_overrides(&self, overrides: &VmBankConfig) -> Self {
        let mut merged = self.clone();
        if let Some(ref name) = overrides.display_name {
            merged.display_name = Some(name.clone());
        }
        if let Some(cpus) = overrides.cpus {
            merged.cpus = cpus;
        }
        if let Some(ram) = overrides.ram_mb {
            merged.ram_mb = ram;
        }
        if let Some(ref model) = overrides.cpu_model {
            merged.cpu_model = Some(model.clone());
        }
        if let Some(ref cmd) = overrides.extra_cmdline {
            merged.extra_cmdline = Some(cmd.clone());
        }
        if let Some(ref imgs) = overrides.images {
            if imgs.kernel.is_some() {
                merged.images.kernel = imgs.kernel.clone();
            }
            if imgs.rootfs.is_some() {
                merged.images.rootfs = imgs.rootfs.clone();
            }
        }
        merged
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
        #[allow(dead_code)] // parsed from YAML config
        #[serde(default = "default_device_backend")]
        backend: String,
    },
    #[serde(rename = "time")]
    Time {
        #[allow(dead_code)] // parsed from YAML config
        #[serde(default = "default_device_backend")]
        backend: String,
    },
    #[serde(rename = "hsm")]
    Hsm {
        #[allow(dead_code)] // parsed from YAML config
        #[serde(default)]
        keystore: Option<String>,
        #[allow(dead_code)] // parsed from YAML config
        #[serde(default)]
        keygen_bin: Option<String>,
        #[allow(dead_code)] // parsed from YAML config
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
}

// =============================================================================
// Per-bank VM config (delivered alongside firmware during OTA)
// =============================================================================

/// Per-bank VM config — lives in bank directories, overrides base VmDefinition fields.
/// Delivered alongside firmware during OTA updates. All fields Optional — only present
/// fields override the base VmDefinition.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct VmBankConfig {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub cpus: Option<u32>,
    #[serde(default)]
    pub ram_mb: Option<u32>,
    #[serde(default)]
    pub cpu_model: Option<String>,
    #[serde(default)]
    pub extra_cmdline: Option<String>,
    #[serde(default)]
    pub images: Option<ImagePaths>,
}

impl VmBankConfig {
    /// Load per-bank config from image directory. Returns None if the file
    /// doesn't exist or can't be parsed (backward-compatible default).
    pub fn from_dir(image_dir: &Path) -> Option<Self> {
        let path = image_dir.join("vm-config.yaml");
        let content = std::fs::read_to_string(&path).ok()?;
        match serde_yaml::from_str(&content) {
            Ok(config) => Some(config),
            Err(e) => {
                tracing::warn!("failed to parse {}: {e}", path.display());
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn base_def() -> VmDefinition {
        VmDefinition {
            display_name: Some("Base VM".into()),
            backend: BackendType::Dummy,
            os_type: OsType::Linux,
            arch: None,
            cpus: 4,
            ram_mb: 2048,
            cpu_model: None,
            image_dir: PathBuf::from("/tmp/test"),
            images: ImagePaths { kernel: Some("bzImage".into()), rootfs: Some("rootfs.img".into()) },
            devices: vec![],
            disks: vec![],
            health: None,
            shutdown: None,
            extra_cmdline: Some("console=ttyS0".into()),
            sim_dir: None,
        }
    }

    #[test]
    fn bank_config_partial_override() {
        let base = base_def();
        let overrides = VmBankConfig {
            cpus: Some(2),
            ram_mb: Some(4096),
            ..Default::default()
        };

        let merged = base.with_bank_overrides(&overrides);
        assert_eq!(merged.cpus, 2);
        assert_eq!(merged.ram_mb, 4096);
        // Unchanged fields
        assert_eq!(merged.display_name.as_deref(), Some("Base VM"));
        assert_eq!(merged.extra_cmdline.as_deref(), Some("console=ttyS0"));
        assert_eq!(merged.images.kernel.as_deref(), Some("bzImage"));
    }

    #[test]
    fn bank_config_full_override() {
        let base = base_def();
        let overrides = VmBankConfig {
            display_name: Some("VM1 — Debian v2.0".into()),
            cpus: Some(8),
            ram_mb: Some(8192),
            cpu_model: Some("max".into()),
            extra_cmdline: Some("console=ttyS0 debug".into()),
            images: Some(ImagePaths {
                kernel: Some("vmlinuz".into()),
                rootfs: Some("root.ext4".into()),
            }),
        };

        let merged = base.with_bank_overrides(&overrides);
        assert_eq!(merged.display_name.as_deref(), Some("VM1 — Debian v2.0"));
        assert_eq!(merged.cpus, 8);
        assert_eq!(merged.ram_mb, 8192);
        assert_eq!(merged.cpu_model.as_deref(), Some("max"));
        assert_eq!(merged.extra_cmdline.as_deref(), Some("console=ttyS0 debug"));
        assert_eq!(merged.images.kernel.as_deref(), Some("vmlinuz"));
        assert_eq!(merged.images.rootfs.as_deref(), Some("root.ext4"));
    }

    #[test]
    fn bank_config_empty_override_is_noop() {
        let base = base_def();
        let overrides = VmBankConfig::default();

        let merged = base.with_bank_overrides(&overrides);
        assert_eq!(merged.cpus, 4);
        assert_eq!(merged.ram_mb, 2048);
        assert_eq!(merged.display_name.as_deref(), Some("Base VM"));
    }

    #[test]
    fn bank_config_deserialize_yaml() {
        let yaml = r#"
cpus: 2
ram_mb: 1024
display_name: "Test VM v1.0"
extra_cmdline: "debug"
"#;
        let config: VmBankConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.cpus, Some(2));
        assert_eq!(config.ram_mb, Some(1024));
        assert_eq!(config.display_name.as_deref(), Some("Test VM v1.0"));
        assert_eq!(config.extra_cmdline.as_deref(), Some("debug"));
        assert!(config.cpu_model.is_none());
        assert!(config.images.is_none());
    }

    #[test]
    fn bank_config_from_dir_missing_file() {
        let dir = std::env::temp_dir().join("vm-bank-config-test-missing");
        let _ = std::fs::create_dir_all(&dir);
        assert!(VmBankConfig::from_dir(&dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bank_config_from_dir_valid_file() {
        let dir = std::env::temp_dir().join("vm-bank-config-test-valid");
        let _ = std::fs::create_dir_all(&dir);

        let mut f = std::fs::File::create(dir.join("vm-config.yaml")).unwrap();
        writeln!(f, "cpus: 6\nram_mb: 3072").unwrap();

        let config = VmBankConfig::from_dir(&dir).unwrap();
        assert_eq!(config.cpus, Some(6));
        assert_eq!(config.ram_mb, Some(3072));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bank_config_images_partial_override() {
        let base = base_def();
        // Override only kernel, keep rootfs from base
        let overrides = VmBankConfig {
            images: Some(ImagePaths {
                kernel: Some("vmlinuz-new".into()),
                rootfs: None,
            }),
            ..Default::default()
        };

        let merged = base.with_bank_overrides(&overrides);
        assert_eq!(merged.images.kernel.as_deref(), Some("vmlinuz-new"));
        assert_eq!(merged.images.rootfs.as_deref(), Some("rootfs.img")); // unchanged
    }
}
