/// VM profile configuration — declares what a VM needs, independent of platform.
///
/// Parsed from TOML. The boot backend translates this into platform-specific
/// actions (QEMU args, qvm config, host-side processes).

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct VmProfile {
    pub vm: VmConfig,
    #[serde(default)]
    pub devices: Vec<DeviceConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VmConfig {
    pub bank_set: String, // "hyp", "os1", "os2"
    #[serde(default = "default_ram")]
    pub ram_mb: u32,
    #[serde(default = "default_cpus")]
    pub cpus: u32,
    #[serde(default = "default_cpu_model")]
    pub cpu_model: String,
    /// Kernel image path (relative to output dir or absolute)
    #[serde(default)]
    pub kernel: Option<String>,
    /// Extra kernel cmdline arguments
    #[serde(default)]
    pub extra_cmdline: Option<String>,
}

fn default_ram() -> u32 { 2048 }
fn default_cpus() -> u32 { 4 }
fn default_cpu_model() -> String { "cortex-a76".to_string() }

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum DeviceConfig {
    #[serde(rename = "can")]
    Can {
        #[serde(default)]
        index: u8,
        #[serde(default = "default_backend")]
        backend: String,
        /// Host CAN interface for passthrough mode
        #[serde(default)]
        interface: Option<String>,
    },
    #[serde(rename = "health")]
    Health {
        #[serde(default = "default_backend")]
        backend: String,
    },
    #[serde(rename = "time")]
    Time {
        #[serde(default = "default_backend")]
        backend: String,
    },
    #[serde(rename = "hsm")]
    Hsm {
        #[serde(default = "default_hsm_backend")]
        backend: String,
        /// Keystore path
        #[serde(default)]
        keystore: Option<String>,
    },
    #[serde(rename = "network")]
    Network {
        #[serde(default)]
        mac: Option<String>,
        #[serde(default)]
        ssh_port: Option<u16>,
    },
    #[serde(rename = "disk")]
    Disk {
        role: String, // "rootfs", "data", "swap"
        path: String,
        #[serde(default)]
        readonly: bool,
    },
    #[serde(rename = "console")]
    Console,
}

fn default_backend() -> String { "simulated".to_string() }
fn default_hsm_backend() -> String { "vsock".to_string() }

impl VmProfile {
    pub fn from_toml(content: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(content)
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        Self::from_toml(&content)
            .map_err(|e| format!("failed to parse {}: {e}", path.display()))
    }

    /// Count CAN interfaces
    pub fn can_count(&self) -> u8 {
        self.devices.iter().filter(|d| matches!(d, DeviceConfig::Can { .. })).count() as u8
    }

    /// Get SSH port if any network device has one
    pub fn ssh_port(&self) -> Option<u16> {
        self.devices.iter().find_map(|d| match d {
            DeviceConfig::Network { ssh_port, .. } => *ssh_port,
            _ => None,
        })
    }
}
