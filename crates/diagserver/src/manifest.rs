/// SUIT-inspired firmware manifest and bundle format.
///
/// Manifest: YAML file describing a firmware image (version, DIDs, etc.)
/// Bundle: manifest + image packed into a single uploadable blob.
///
/// Bundle wire format:
///   [0..4]   magic "VMFB"
///   [4..8]   version (u32 LE, currently 1)
///   [8..12]  manifest YAML length N (u32 LE)
///   [12..12+N] manifest YAML (UTF-8)
///   [12+N..] image bytes

use crate::ota::ImageMeta;
use nv_store::types::BankSet;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Firmware manifest (YAML)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareManifest {
    pub component_id: Vec<String>,
    #[serde(default)]
    pub vendor_id: Option<String>,
    #[serde(default)]
    pub class_id: Option<String>,

    pub sequence_number: u32,
    pub version: String,

    #[serde(default)]
    pub image_size: Option<u64>,
    #[serde(default)]
    pub image_sha256: Option<String>,

    // UDS DID identity fields
    #[serde(default)]
    pub spare_part_number: Option<String>,
    #[serde(default)]
    pub ecu_sw_number: Option<String>,
    #[serde(default)]
    pub supplier_sw_number: Option<String>,
    #[serde(default)]
    pub supplier_sw_version: Option<String>,
    #[serde(default)]
    pub system_name: Option<String>,
    #[serde(default)]
    pub odx_file_id: Option<String>,
    #[serde(default)]
    pub programming_date: Option<String>,
    #[serde(default)]
    pub tester_serial: Option<String>,
}

impl FirmwareManifest {
    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        serde_yaml::from_str(yaml).map_err(|e| format!("manifest parse error: {e}"))
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::from_yaml(&content)
    }

    /// Resolve the BankSet from component_id.
    /// Accepts ["os1"], ["hyp"], or ["vendor", "os1"], etc.
    pub fn resolve_bank_set(&self) -> Option<BankSet> {
        let tag = self.component_id.last()?;
        BankSet::from_str(tag)
    }

    /// Convert to the existing ImageMeta type used by ota::install().
    pub fn to_image_meta(&self) -> ImageMeta {
        let mut meta = ImageMeta::default();
        copy_str_to_array(&self.version, &mut meta.fw_version);
        meta.fw_seq = self.sequence_number;
        meta.fw_secver = self.sequence_number;
        if let Some(ref s) = self.spare_part_number {
            copy_str_to_array(s, &mut meta.spare_part_number);
        }
        if let Some(ref s) = self.ecu_sw_number {
            copy_str_to_array(s, &mut meta.ecu_sw_number);
        }
        if let Some(ref s) = self.supplier_sw_number {
            copy_str_to_array(s, &mut meta.supplier_sw_number);
        }
        if let Some(ref s) = self.supplier_sw_version {
            copy_str_to_array(s, &mut meta.supplier_sw_version);
        }
        if let Some(ref s) = self.system_name {
            copy_str_to_array(s, &mut meta.system_name);
        }
        if let Some(ref s) = self.odx_file_id {
            copy_str_to_array(s, &mut meta.odx_file_id);
        }
        if let Some(ref s) = self.programming_date {
            let n = s.len().min(8);
            meta.programming_date[..n].copy_from_slice(&s.as_bytes()[..n]);
        }
        if let Some(ref s) = self.tester_serial {
            copy_str_to_array(s, &mut meta.tester_serial);
        }
        meta
    }
}

fn copy_str_to_array(s: &str, dst: &mut [u8]) {
    let n = s.len().min(dst.len());
    dst[..n].copy_from_slice(&s.as_bytes()[..n]);
}

// ---------------------------------------------------------------------------
// Factory manifest (YAML)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactoryManifest {
    pub serial_number: String,
    pub vin: String,
    #[serde(default)]
    pub manufacturing_date: Option<String>,
    #[serde(default)]
    pub ecu_hw_number: Option<String>,
    #[serde(default)]
    pub supplier_hw_number: Option<String>,
    #[serde(default)]
    pub supplier_hw_version: Option<String>,
    #[serde(default)]
    pub supplier_id: Option<String>,
    #[serde(default)]
    pub device_type: Option<u8>,
}

impl FactoryManifest {
    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        serde_yaml::from_str(yaml).map_err(|e| format!("factory manifest parse error: {e}"))
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::from_yaml(&content)
    }

    pub fn to_nv_factory(&self) -> nv_store::types::NvFactory {
        let mut f = nv_store::types::NvFactory::default();
        copy_str_to_array(&self.serial_number, &mut f.serial_number);
        let vlen = self.vin.len().min(17);
        f.vin[..vlen].copy_from_slice(&self.vin.as_bytes()[..vlen]);
        if let Some(ref s) = self.manufacturing_date {
            let n = s.len().min(8);
            f.manufacturing_date[..n].copy_from_slice(&s.as_bytes()[..n]);
        }
        if let Some(ref s) = self.ecu_hw_number {
            copy_str_to_array(s, &mut f.ecu_hw_number);
        }
        if let Some(ref s) = self.supplier_hw_number {
            copy_str_to_array(s, &mut f.supplier_hw_number);
        }
        if let Some(ref s) = self.supplier_hw_version {
            copy_str_to_array(s, &mut f.supplier_hw_version);
        }
        if let Some(ref s) = self.supplier_id {
            copy_str_to_array(s, &mut f.supplier_id);
        }
        if let Some(dt) = self.device_type {
            f.device_type = dt;
        }
        f
    }
}

// ---------------------------------------------------------------------------
// Firmware bundle (VMFB)
// ---------------------------------------------------------------------------

pub const BUNDLE_MAGIC: [u8; 4] = *b"VMFB";
pub const BUNDLE_VERSION: u32 = 1;
pub const HEADER_SIZE: usize = 12;

#[derive(Debug)]
pub enum BundleError {
    TooSmall,
    BadMagic,
    BadVersion(u32),
    ManifestTruncated,
    Yaml(String),
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BundleError::TooSmall => write!(f, "bundle too small (< 12 bytes)"),
            BundleError::BadMagic => write!(f, "bad bundle magic (expected VMFB)"),
            BundleError::BadVersion(v) => write!(f, "unsupported bundle version {v}"),
            BundleError::ManifestTruncated => write!(f, "manifest extends past bundle end"),
            BundleError::Yaml(e) => write!(f, "manifest YAML: {e}"),
        }
    }
}

pub struct FirmwareBundle {
    pub manifest: FirmwareManifest,
    pub image: Vec<u8>,
}

impl FirmwareBundle {
    /// Pack a manifest + image into the VMFB wire format.
    pub fn pack(manifest: &FirmwareManifest, image: &[u8]) -> Vec<u8> {
        let yaml = serde_yaml::to_string(manifest).expect("manifest serialization");
        let yaml_bytes = yaml.as_bytes();
        let mut buf = Vec::with_capacity(HEADER_SIZE + yaml_bytes.len() + image.len());
        buf.extend_from_slice(&BUNDLE_MAGIC);
        buf.extend_from_slice(&BUNDLE_VERSION.to_le_bytes());
        buf.extend_from_slice(&(yaml_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(yaml_bytes);
        buf.extend_from_slice(image);
        buf
    }

    /// Unpack a VMFB bundle from raw bytes.
    pub fn unpack(data: &[u8]) -> Result<Self, BundleError> {
        if data.len() < HEADER_SIZE {
            return Err(BundleError::TooSmall);
        }
        if data[0..4] != BUNDLE_MAGIC {
            return Err(BundleError::BadMagic);
        }
        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if version != BUNDLE_VERSION {
            return Err(BundleError::BadVersion(version));
        }
        let manifest_len =
            u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let manifest_end = HEADER_SIZE + manifest_len;
        if manifest_end > data.len() {
            return Err(BundleError::ManifestTruncated);
        }
        let yaml_str = std::str::from_utf8(&data[HEADER_SIZE..manifest_end])
            .map_err(|e| BundleError::Yaml(e.to_string()))?;
        let manifest =
            FirmwareManifest::from_yaml(yaml_str).map_err(BundleError::Yaml)?;
        let image = data[manifest_end..].to_vec();
        Ok(FirmwareBundle { manifest, image })
    }

    /// Unpack from a file path.
    pub fn from_file(path: &std::path::Path) -> Result<Self, String> {
        let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::unpack(&data).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_parse_full() {
        let yaml = r#"
component_id: ["os1"]
vendor_id: "fa6b4a53-d5ad-5fdf-be9d-e4e97d85cd2b"
class_id: "1492af14-2569-5e48-bf42-9b2d51f2ab45"
sequence_number: 3
version: "1.2.0"
image_size: 67108864
spare_part_number: "SP-OS1"
ecu_sw_number: "ECU-SW-001"
system_name: "OS1-Linux"
"#;
        let m = FirmwareManifest::from_yaml(yaml).unwrap();
        assert_eq!(m.component_id, vec!["os1"]);
        assert_eq!(m.sequence_number, 3);
        assert_eq!(m.version, "1.2.0");
        assert_eq!(m.resolve_bank_set(), Some(BankSet::Os1));
    }

    #[test]
    fn manifest_parse_minimal() {
        let yaml = r#"
component_id: ["hyp"]
sequence_number: 1
version: "1.0.0"
"#;
        let m = FirmwareManifest::from_yaml(yaml).unwrap();
        assert_eq!(m.resolve_bank_set(), Some(BankSet::Hypervisor));
        assert!(m.spare_part_number.is_none());
    }

    #[test]
    fn manifest_to_image_meta() {
        let yaml = r#"
component_id: ["os1"]
sequence_number: 5
version: "2.0.0"
spare_part_number: "SP-001"
ecu_sw_number: "ECU-001"
"#;
        let m = FirmwareManifest::from_yaml(yaml).unwrap();
        let meta = m.to_image_meta();
        assert_eq!(meta.fw_seq, 5);
        assert_eq!(meta.fw_secver, 5);
        assert_eq!(&meta.fw_version[..5], b"2.0.0");
        assert_eq!(&meta.spare_part_number[..6], b"SP-001");
        assert_eq!(&meta.ecu_sw_number[..7], b"ECU-001");
    }

    #[test]
    fn factory_manifest_parse() {
        let yaml = r#"
serial_number: "SN-001"
vin: "WBALI00000TEST001"
manufacturing_date: "20260323"
ecu_hw_number: "HW-001"
device_type: 1
"#;
        let f = FactoryManifest::from_yaml(yaml).unwrap();
        assert_eq!(f.serial_number, "SN-001");
        assert_eq!(f.device_type, Some(1));
        let nv = f.to_nv_factory();
        assert_eq!(&nv.serial_number[..6], b"SN-001");
        assert_eq!(&nv.vin[..17], b"WBALI00000TEST001");
    }

    #[test]
    fn bundle_pack_unpack_roundtrip() {
        let yaml = r#"
component_id: ["os1"]
sequence_number: 1
version: "1.0.0"
"#;
        let manifest = FirmwareManifest::from_yaml(yaml).unwrap();
        let image = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03];
        let packed = FirmwareBundle::pack(&manifest, &image);

        // Check header
        assert_eq!(&packed[0..4], b"VMFB");
        assert_eq!(u32::from_le_bytes([packed[4], packed[5], packed[6], packed[7]]), 1);

        // Unpack
        let bundle = FirmwareBundle::unpack(&packed).unwrap();
        assert_eq!(bundle.manifest.version, "1.0.0");
        assert_eq!(bundle.manifest.sequence_number, 1);
        assert_eq!(bundle.image, image);
    }

    #[test]
    fn bundle_unpack_bad_magic() {
        let data = b"BAAD\x01\x00\x00\x00\x00\x00\x00\x00";
        assert!(matches!(
            FirmwareBundle::unpack(data),
            Err(BundleError::BadMagic)
        ));
    }

    #[test]
    fn bundle_unpack_too_small() {
        assert!(matches!(
            FirmwareBundle::unpack(b"VMFB"),
            Err(BundleError::TooSmall)
        ));
    }

    #[test]
    fn bundle_unpack_truncated_manifest() {
        let mut data = Vec::new();
        data.extend_from_slice(b"VMFB");
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&999u32.to_le_bytes()); // claims 999 bytes of YAML
        data.extend_from_slice(b"short");
        assert!(matches!(
            FirmwareBundle::unpack(&data),
            Err(BundleError::ManifestTruncated)
        ));
    }
}
