use serde::{Deserialize, Serialize};

use crate::did;

// --- Component models ---

#[derive(Serialize)]
pub struct Capabilities {
    pub read_data: bool,
    pub write_data: bool,
    pub faults: bool,
    pub clear_faults: bool,
    pub software_update: bool,
    pub io_control: bool,
    pub sessions: bool,
    pub security: bool,
    pub sub_entities: bool,
    pub subscriptions: bool,
    pub logs: bool,
    pub operations: bool,
}

impl Capabilities {
    pub fn vm_bank_set() -> Self {
        Self {
            read_data: true,
            write_data: true,
            faults: true,
            clear_faults: true,
            software_update: true,
            io_control: false,
            sessions: true,
            security: true,
            sub_entities: false,
            subscriptions: false,
            logs: false,
            operations: false,
        }
    }
}

#[derive(Serialize)]
pub struct ComponentInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    #[serde(rename = "type")]
    pub entity_type: String,
    pub capabilities: Capabilities,
    pub href: String,
}

#[derive(Serialize)]
pub struct ComponentList {
    pub items: Vec<ComponentInfo>,
}

// --- Parameter models ---

#[derive(Serialize, Clone)]
pub struct ParameterInfo {
    pub id: String,
    pub did: String,
    pub name: String,
    pub data_type: String,
    pub writable: bool,
    pub href: String,
}

#[derive(Serialize)]
pub struct ParameterList {
    pub count: usize,
    pub items: Vec<ParameterInfo>,
}

#[derive(Serialize)]
pub struct DataValue {
    pub id: String,
    pub did: String,
    pub value: serde_json::Value,
    pub raw: String,
    pub length: usize,
}

#[derive(Deserialize)]
pub struct WriteRequest {
    pub value: String,
}

#[derive(Serialize)]
pub struct WriteResponse {
    pub success: bool,
    pub message: String,
}

// --- Fault models ---

#[derive(Serialize)]
pub struct FaultInfo {
    pub id: String,
    pub dtc_code: String,
    pub status: u8,
    pub active: bool,
    pub href: String,
}

#[derive(Serialize)]
pub struct FaultList {
    pub items: Vec<FaultInfo>,
    pub total_count: usize,
}

#[derive(Serialize)]
pub struct ClearFaultsResponse {
    pub success: bool,
    pub cleared_count: usize,
}

// --- Flash/activation models ---

#[derive(Serialize)]
pub struct ActivationState {
    pub supports_rollback: bool,
    pub state: String,
    pub active_version: Option<String>,
    pub previous_version: Option<String>,
}

#[derive(Serialize)]
pub struct CommitRollbackResponse {
    pub success: bool,
    pub message: String,
}

// --- Flash file/transfer models ---

#[derive(Serialize)]
pub struct FileUploadResponse {
    pub upload_id: String,
    pub state: String,
}

#[derive(Serialize)]
pub struct FileStatusResponse {
    pub upload_id: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub upload_id: String,
    pub state: String,
    pub image_sha256: String,
    pub image_size: u64,
}

#[derive(Deserialize)]
pub struct TransferRequest {
    pub file_id: String,
}

#[derive(Serialize)]
pub struct TransferResponse {
    pub transfer_id: String,
    pub state: String,
}

#[derive(Serialize)]
pub struct TransferProgress {
    pub transfer_id: String,
    pub state: String,
    pub blocks_transferred: u32,
    pub blocks_total: u32,
    pub percent: u8,
}

#[derive(Serialize)]
pub struct FinalizeResponse {
    pub success: bool,
    pub message: String,
}

// --- Health ---

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub components: usize,
}

// --- Session / security models ---

#[derive(Deserialize)]
pub struct SessionModeRequest {
    pub value: String,
}

#[derive(Serialize)]
pub struct SessionModeResponse {
    pub id: String,
    pub value: String,
}

#[derive(Deserialize)]
pub struct SecurityModeRequest {
    pub value: String,
    #[serde(default)]
    pub key: Option<String>,
}

#[derive(Serialize)]
pub struct SecurityModeGetResponse {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Serialize)]
pub struct SecuritySeedResponse {
    pub id: String,
    pub seed: SovdSeed,
}

#[derive(Serialize)]
pub struct SovdSeed {
    #[serde(rename = "Request_Seed")]
    pub request_seed: String,
}

#[derive(Serialize)]
pub struct SecurityKeyResponse {
    pub id: String,
    pub value: String,
}

// --- DID parameter registry ---

pub struct DidParam {
    pub id: &'static str,
    pub did: u16,
    pub name: &'static str,
    pub data_type: &'static str,
    pub writable: bool,
}

pub static PARAM_REGISTRY: &[DidParam] = &[
    DidParam { id: "spare_part_number", did: did::DID_SPARE_PART_NUMBER, name: "Spare Part Number", data_type: "string", writable: false },
    DidParam { id: "ecu_sw_number", did: did::DID_ECU_SW_NUMBER, name: "ECU Software Number", data_type: "string", writable: false },
    DidParam { id: "fw_version", did: did::DID_FW_VERSION, name: "Firmware Version", data_type: "string", writable: false },
    DidParam { id: "supplier_id", did: did::DID_SUPPLIER_ID, name: "Supplier ID", data_type: "string", writable: false },
    DidParam { id: "manufacturing_date", did: did::DID_MANUFACTURING_DATE, name: "Manufacturing Date", data_type: "string", writable: false },
    DidParam { id: "serial_number", did: did::DID_SERIAL_NUMBER, name: "Serial Number", data_type: "string", writable: false },
    DidParam { id: "vin", did: did::DID_VIN, name: "VIN", data_type: "string", writable: false },
    DidParam { id: "ecu_hw_number", did: did::DID_ECU_HW_NUMBER, name: "ECU Hardware Number", data_type: "string", writable: false },
    DidParam { id: "supplier_hw_number", did: did::DID_SUPPLIER_HW_NUMBER, name: "Supplier HW Number", data_type: "string", writable: false },
    DidParam { id: "supplier_hw_version", did: did::DID_SUPPLIER_HW_VERSION, name: "Supplier HW Version", data_type: "string", writable: false },
    DidParam { id: "supplier_sw_number", did: did::DID_SUPPLIER_SW_NUMBER, name: "Supplier SW Number", data_type: "string", writable: false },
    DidParam { id: "supplier_sw_version", did: did::DID_SUPPLIER_SW_VERSION, name: "Supplier SW Version", data_type: "string", writable: false },
    DidParam { id: "system_name", did: did::DID_SYSTEM_NAME, name: "System Name", data_type: "string", writable: false },
    DidParam { id: "tester_serial", did: did::DID_TESTER_SERIAL, name: "Tester Serial", data_type: "string", writable: false },
    DidParam { id: "programming_date", did: did::DID_PROGRAMMING_DATE, name: "Programming Date", data_type: "string", writable: false },
    DidParam { id: "odx_file_id", did: did::DID_ODX_FILE_ID, name: "ODX File ID", data_type: "string", writable: false },
    DidParam { id: "active_bank", did: did::DID_ACTIVE_BANK, name: "Active Bank", data_type: "string", writable: false },
    DidParam { id: "committed", did: did::DID_COMMITTED, name: "Committed", data_type: "bool", writable: false },
    DidParam { id: "min_security_ver", did: did::DID_MIN_SECURITY_VER, name: "Min Security Version", data_type: "uint32", writable: false },
    DidParam { id: "current_security_ver", did: did::DID_CURRENT_SECURITY_VER, name: "Current Security Version", data_type: "uint32", writable: false },
    DidParam { id: "boot_count", did: did::DID_BOOT_COUNT, name: "Boot Count", data_type: "uint8", writable: false },
];

/// Resolve a parameter ID to a DID number. Accepts either a registry name
/// (e.g. "fw_version") or a hex DID (e.g. "F189" or "0xF189").
pub fn resolve_param(param_id: &str) -> Option<(u16, Option<&'static DidParam>)> {
    // Check registry first
    if let Some(p) = PARAM_REGISTRY.iter().find(|p| p.id == param_id) {
        return Some((p.did, Some(p)));
    }
    // Try hex DID
    let hex_str = param_id
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    if let Ok(did) = u16::from_str_radix(hex_str, 16) {
        let reg = PARAM_REGISTRY.iter().find(|p| p.did == did);
        return Some((did, reg));
    }
    None
}
