/// VmBackend — DiagnosticBackend implementation for vm-mgr bank sets.
///
/// Each instance manages one bank set (hyp, os1, os2) and provides:
/// - Parameter read/write via NV DIDs
/// - Fault (DTC) management
/// - SUIT-based firmware flash with A/B banking
/// - Session/security mode control

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::Utc;

use nv_store::block::BlockDevice;
use nv_store::store::NvStore;
use nv_store::types::*;

use sovd_core::backend::*;
use sovd_core::error::{BackendError, BackendResult};
use sovd_core::models::*;

use crate::did;
use crate::manifest_provider::{ManifestProvider, ValidatedFirmware};
use crate::ota;
use crate::sovd::security::SecurityProvider;

// ---------------------------------------------------------------------------
// Session / security state (per backend instance)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionState {
    Default,
    Programming,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecurityPhase {
    Locked,
    SeedAvailable,
    Unlocked,
}

#[derive(Debug, Clone)]
struct SecurityAccessState {
    phase: SecurityPhase,
    level: u8,
    pending_seed: Option<Vec<u8>>,
}

impl Default for SecurityAccessState {
    fn default() -> Self {
        Self {
            phase: SecurityPhase::Locked,
            level: 0,
            pending_seed: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Stored package (validated SUIT envelope)
// ---------------------------------------------------------------------------

struct StoredPackage {
    id: String,
    validated: ValidatedFirmware,
    status: PackageStatus,
}

// ---------------------------------------------------------------------------
// VmBackend
// ---------------------------------------------------------------------------

pub struct VmBackend<D: BlockDevice + Send + 'static> {
    entity_info: EntityInfo,
    capabilities: Capabilities,
    bank_set: BankSet,
    nv: Arc<Mutex<NvStore<D>>>,
    manifest_provider: Arc<dyn ManifestProvider>,
    security_provider: Arc<dyn SecurityProvider>,
    packages: Mutex<HashMap<String, StoredPackage>>,
    session: Mutex<SessionState>,
    security: Mutex<SecurityAccessState>,
    next_id: Mutex<u64>,
}

impl<D: BlockDevice + Send + 'static> VmBackend<D> {
    pub fn new(
        bank_set: BankSet,
        nv: Arc<Mutex<NvStore<D>>>,
        manifest_provider: Arc<dyn ManifestProvider>,
        security_provider: Arc<dyn SecurityProvider>,
    ) -> Self {
        let (id, name, desc) = match bank_set {
            BankSet::Hypervisor => ("hyp", "Hypervisor", "Hypervisor A/B bank set"),
            BankSet::Os1 => ("os1", "OS1", "Primary OS VM A/B bank set"),
            BankSet::Os2 => ("os2", "OS2", "Secondary OS VM A/B bank set"),
        };

        Self {
            entity_info: EntityInfo {
                id: id.to_string(),
                name: name.to_string(),
                entity_type: "vm".to_string(),
                description: Some(desc.to_string()),
                href: format!("/vehicle/v1/components/{id}"),
                status: None,
            },
            capabilities: Capabilities {
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
            },
            bank_set,
            nv,
            manifest_provider,
            security_provider,
            packages: Mutex::new(HashMap::new()),
            session: Mutex::new(SessionState::Default),
            security: Mutex::new(SecurityAccessState::default()),
            next_id: Mutex::new(1),
        }
    }

    fn next_id(&self) -> String {
        let mut id = self.next_id.lock().unwrap();
        let v = *id;
        *id += 1;
        v.to_string()
    }

    fn require_flash_access(&self) -> BackendResult<()> {
        let session = self.session.lock().unwrap();
        if *session != SessionState::Programming {
            return Err(BackendError::SessionRequired("programming".to_string()));
        }
        let security = self.security.lock().unwrap();
        if security.phase != SecurityPhase::Unlocked {
            return Err(BackendError::SecurityRequired(1));
        }
        Ok(())
    }

    fn nv_bytes_to_string(data: &[u8]) -> String {
        let end = data.iter().position(|&c| c == 0).unwrap_or(data.len());
        String::from_utf8_lossy(&data[..end]).to_string()
    }
}

// ---------------------------------------------------------------------------
// DiagnosticBackend implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl<D: BlockDevice + Send + 'static> DiagnosticBackend for VmBackend<D> {
    fn entity_info(&self) -> &EntityInfo {
        &self.entity_info
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    // --- Data ---

    async fn list_parameters(&self) -> BackendResult<Vec<ParameterInfo>> {
        let nv = self.nv.lock().map_err(|_| BackendError::Internal("lock".into()))?;
        let comp_id = &self.entity_info.id;

        let mut params: Vec<ParameterInfo> = DID_REGISTRY
            .iter()
            .map(|d| ParameterInfo {
                id: d.id.to_string(),
                name: d.name.to_string(),
                description: None,
                unit: None,
                data_type: Some(d.data_type.to_string()),
                read_only: !d.writable,
                href: format!("/vehicle/v1/components/{comp_id}/data/{}", d.id),
                did: Some(format!("{:04X}", d.did)),
            })
            .collect();

        // Add runtime DIDs
        if let Some(bs) = nv.read_boot_state() {
            let active = bs.banks[self.bank_set as usize].active_bank;
            if let Some(runtime) = nv.read_runtime(self.bank_set, active) {
                for i in 0..runtime.did_count as usize {
                    let did_num = runtime.dids[i].did;
                    if DID_REGISTRY.iter().any(|d| d.did == did_num) {
                        continue;
                    }
                    let id = format!("runtime_{:04X}", did_num);
                    params.push(ParameterInfo {
                        id: id.clone(),
                        name: format!("Runtime DID 0x{:04X}", did_num),
                        description: None,
                        unit: None,
                        data_type: Some("bytes".to_string()),
                        read_only: false,
                        href: format!("/vehicle/v1/components/{comp_id}/data/{id}"),
                        did: Some(format!("{:04X}", did_num)),
                    });
                }
            }
        }

        Ok(params)
    }

    async fn read_data(&self, param_ids: &[String]) -> BackendResult<Vec<DataValue>> {
        let nv = self.nv.lock().map_err(|_| BackendError::Internal("lock".into()))?;
        let mut values = Vec::new();

        for param_id in param_ids {
            let (did_num, reg) = resolve_param(param_id)
                .ok_or_else(|| BackendError::ParameterNotFound(param_id.clone()))?;

            let result = did::read_did(&*nv, self.bank_set, did_num);
            match result {
                did::DidValue::Bytes(bytes) => {
                    let value = did_value_to_json(did_num, &bytes, reg);
                    let raw_hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                    let name = reg.map(|r| r.name).unwrap_or(param_id.as_str());
                    values.push(DataValue {
                        id: param_id.clone(),
                        name: name.to_string(),
                        value,
                        unit: None,
                        timestamp: Utc::now(),
                        raw: Some(raw_hex),
                        did: Some(format!("{:04X}", did_num)),
                        length: Some(bytes.len()),
                    });
                }
                did::DidValue::NotFound => {
                    return Err(BackendError::ParameterNotFound(param_id.clone()));
                }
            }
        }

        Ok(values)
    }

    async fn write_data(&self, param_id: &str, value: &[u8]) -> BackendResult<()> {
        let (did_num, reg) = resolve_param(param_id)
            .ok_or_else(|| BackendError::ParameterNotFound(param_id.to_string()))?;

        if let Some(r) = reg {
            if !r.writable {
                return Err(BackendError::InvalidRequest(format!(
                    "DID 0x{:04X} ({}) is read-only",
                    did_num, r.name
                )));
            }
        }

        let mut nv = self.nv.lock().map_err(|_| BackendError::Internal("lock".into()))?;
        match did::write_did(&mut *nv, self.bank_set, did_num, value) {
            Ok(true) => Ok(()),
            Ok(false) => Err(BackendError::Internal("runtime DID store full".into())),
            Err(e) => Err(BackendError::Internal(e.to_string())),
        }
    }

    // --- Faults ---

    async fn get_faults(&self, _filter: Option<&FaultFilter>) -> BackendResult<FaultsResult> {
        let nv = self.nv.lock().map_err(|_| BackendError::Internal("lock".into()))?;
        let bs = nv.read_boot_state().ok_or_else(|| BackendError::Internal("no boot state".into()))?;
        let active = bs.banks[self.bank_set as usize].active_bank;
        let runtime = nv.read_runtime(self.bank_set, active).unwrap_or_default();

        let faults: Vec<Fault> = (0..runtime.dtc_count as usize)
            .map(|i| {
                let dtc = &runtime.dtcs[i];
                let code = format!("{:06X}", dtc.dtc_number);
                let active = dtc.status & 0x01 != 0;
                Fault {
                    id: format!("dtc_{code}"),
                    code: code.clone(),
                    severity: if active { FaultSeverity::Error } else { FaultSeverity::Warning },
                    message: format!("DTC {code}"),
                    category: None,
                    first_occurrence: None,
                    last_occurrence: None,
                    occurrence_count: None,
                    active,
                    status: Some(serde_json::json!(dtc.status)),
                    href: format!("/vehicle/v1/components/{}/faults/dtc_{code}", self.entity_info.id),
                }
            })
            .collect();

        Ok(FaultsResult {
            faults,
            status_availability_mask: None,
        })
    }

    async fn clear_faults(&self, _group: Option<u32>) -> BackendResult<ClearFaultsResult> {
        let mut nv = self.nv.lock().map_err(|_| BackendError::Internal("lock".into()))?;
        let bs = nv.read_boot_state().ok_or_else(|| BackendError::Internal("no boot state".into()))?;
        let active = bs.banks[self.bank_set as usize].active_bank;
        let mut runtime = nv.read_runtime(self.bank_set, active).unwrap_or_default();

        let cleared = runtime.dtc_count as u32;
        runtime.dtc_count = 0;
        runtime.dtcs = std::array::from_fn(|_| DtcEntry::default());

        nv.write_runtime(self.bank_set, active, &mut runtime)
            .map_err(|e| BackendError::Internal(e.to_string()))?;

        Ok(ClearFaultsResult {
            success: true,
            cleared_count: cleared,
            message: format!("Cleared {cleared} faults"),
        })
    }

    // --- Operations (stub) ---

    async fn list_operations(&self) -> BackendResult<Vec<OperationInfo>> {
        Ok(vec![])
    }

    async fn start_operation(
        &self,
        operation_id: &str,
        _params: &[u8],
    ) -> BackendResult<OperationExecution> {
        Err(BackendError::OperationNotFound(operation_id.to_string()))
    }

    // --- Package management ---

    async fn receive_package(&self, data: &[u8]) -> BackendResult<String> {
        self.require_flash_access()?;

        let min_security_ver = {
            let nv = self.nv.lock().map_err(|_| BackendError::Internal("lock".into()))?;
            nv.read_boot_state()
                .and_then(|bs| {
                    let active = bs.banks[self.bank_set as usize].active_bank;
                    nv.read_fw_meta(self.bank_set, active).map(|m| m.min_security_ver)
                })
                .unwrap_or(0)
        };

        let validated = self
            .manifest_provider
            .validate(data, min_security_ver)
            .map_err(|e| BackendError::InvalidRequest(format!("manifest validation: {e}")))?;

        if validated.bank_set != self.bank_set {
            return Err(BackendError::InvalidRequest(format!(
                "manifest targets {:?}, but this is {:?}",
                validated.bank_set, self.bank_set
            )));
        }

        let id = self.next_id();
        let mut packages = self.packages.lock().unwrap();
        packages.insert(
            id.clone(),
            StoredPackage {
                id: id.clone(),
                validated,
                status: PackageStatus::Verified,
            },
        );

        Ok(id)
    }

    async fn list_packages(&self) -> BackendResult<Vec<PackageInfo>> {
        let packages = self.packages.lock().unwrap();
        Ok(packages
            .values()
            .map(|p| PackageInfo {
                id: p.id.clone(),
                size: p.validated.image_data.len(),
                target_ecu: Some(self.entity_info.id.clone()),
                version: Some(p.validated.version_display.clone()),
                status: p.status,
                created_at: None,
            })
            .collect())
    }

    async fn get_package(&self, package_id: &str) -> BackendResult<PackageInfo> {
        let packages = self.packages.lock().unwrap();
        let p = packages
            .get(package_id)
            .ok_or_else(|| BackendError::EntityNotFound(package_id.to_string()))?;
        Ok(PackageInfo {
            id: p.id.clone(),
            size: p.validated.image_data.len(),
            target_ecu: Some(self.entity_info.id.clone()),
            version: Some(p.validated.version_display.clone()),
            status: p.status,
            created_at: None,
        })
    }

    async fn verify_package(&self, package_id: &str) -> BackendResult<VerifyResult> {
        let packages = self.packages.lock().unwrap();
        let p = packages
            .get(package_id)
            .ok_or_else(|| BackendError::EntityNotFound(package_id.to_string()))?;

        use sha2::{Sha256, Digest};
        let hash: [u8; 32] = Sha256::digest(&p.validated.image_data).into();
        let hash_hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();

        Ok(VerifyResult {
            valid: true,
            checksum: Some(hash_hex),
            algorithm: Some("sha256".to_string()),
            error: None,
        })
    }

    async fn delete_package(&self, package_id: &str) -> BackendResult<()> {
        let mut packages = self.packages.lock().unwrap();
        packages
            .remove(package_id)
            .ok_or_else(|| BackendError::EntityNotFound(package_id.to_string()))?;
        Ok(())
    }

    // --- Flash ---

    async fn start_flash(&self, package_id: &str) -> BackendResult<String> {
        self.require_flash_access()?;

        let (meta, image_data) = {
            let packages = self.packages.lock().unwrap();
            let p = packages
                .get(package_id)
                .ok_or_else(|| BackendError::EntityNotFound(package_id.to_string()))?;
            (p.validated.image_meta.clone(), p.validated.image_data.clone())
        };

        let mut nv = self.nv.lock().map_err(|_| BackendError::Internal("lock".into()))?;
        let _result = ota::install(&mut *nv, self.bank_set, &image_data, &meta)
            .map_err(|e| BackendError::Internal(format!("ota install: {e}")))?;

        Ok(self.next_id())
    }

    async fn get_flash_status(&self, transfer_id: &str) -> BackendResult<FlashStatus> {
        Ok(FlashStatus {
            transfer_id: transfer_id.to_string(),
            package_id: String::new(),
            state: FlashState::AwaitingReset,
            progress: Some(FlashProgress {
                bytes_transferred: 1,
                bytes_total: 1,
                blocks_transferred: 1,
                blocks_total: 1,
                percent: 100.0,
            }),
            error: None,
        })
    }

    async fn finalize_flash(&self) -> BackendResult<()> {
        Ok(())
    }

    async fn get_activation_state(&self) -> BackendResult<ActivationState> {
        let nv = self.nv.lock().map_err(|_| BackendError::Internal("lock".into()))?;
        let status = ota::status(&*nv, self.bank_set)
            .ok_or_else(|| BackendError::Internal("no boot state".into()))?;

        let state = if status.committed {
            FlashState::Committed
        } else {
            FlashState::Activated
        };

        let active_version = status.fw_version.map(|v| Self::nv_bytes_to_string(&v));
        let previous_bank = status.active_bank.other();
        let previous_version = nv
            .read_fw_meta(self.bank_set, previous_bank)
            .map(|m| Self::nv_bytes_to_string(&m.fw_version));

        Ok(ActivationState {
            supports_rollback: true,
            state,
            active_version,
            previous_version,
        })
    }

    async fn commit_flash(&self) -> BackendResult<()> {
        let mut nv = self.nv.lock().map_err(|_| BackendError::Internal("lock".into()))?;
        ota::commit(&mut *nv, self.bank_set)
            .map_err(|e| BackendError::Internal(format!("commit: {e}")))
    }

    async fn rollback_flash(&self) -> BackendResult<()> {
        let mut nv = self.nv.lock().map_err(|_| BackendError::Internal("lock".into()))?;
        ota::rollback(&mut *nv, self.bank_set)
            .map_err(|e| BackendError::Internal(format!("rollback: {e}")))?;
        Ok(())
    }

    // --- Session ---

    async fn get_session_mode(&self) -> BackendResult<SessionMode> {
        let session = self.session.lock().unwrap();
        let (name, id) = match *session {
            SessionState::Default => ("default", 0x01),
            SessionState::Programming => ("programming", 0x02),
        };
        Ok(SessionMode {
            mode: "session".to_string(),
            session: name.to_string(),
            session_id: id,
        })
    }

    async fn set_session_mode(&self, session: &str) -> BackendResult<SessionMode> {
        let new_state = match session.to_lowercase().as_str() {
            "default" => SessionState::Default,
            "programming" => SessionState::Programming,
            _ => return Err(BackendError::InvalidRequest(format!("unknown session: {session}"))),
        };

        {
            let mut s = self.session.lock().unwrap();
            *s = new_state;
        }
        // Security resets on session change (ISO 14229)
        {
            let mut sec = self.security.lock().unwrap();
            *sec = SecurityAccessState::default();
        }

        self.get_session_mode().await
    }

    // --- Security ---

    async fn get_security_mode(&self) -> BackendResult<SecurityMode> {
        let sec = self.security.lock().unwrap();
        let (state, level, seed) = match sec.phase {
            SecurityPhase::Locked => (SecurityState::Locked, None, None),
            SecurityPhase::SeedAvailable => {
                let seed_hex = sec
                    .pending_seed
                    .as_ref()
                    .map(|s| s.iter().map(|b| format!("{b:02x}")).collect::<String>());
                (SecurityState::SeedAvailable, Some(sec.level), seed_hex)
            }
            SecurityPhase::Unlocked => (SecurityState::Unlocked, Some(sec.level), None),
        };
        Ok(SecurityMode {
            mode: "security".to_string(),
            state,
            level,
            available_levels: Some(vec![1]),
            seed,
        })
    }

    async fn set_security_mode(
        &self,
        value: &str,
        key: Option<&[u8]>,
    ) -> BackendResult<SecurityMode> {
        let value_lower = value.to_lowercase();

        if value_lower.ends_with("_requestseed") {
            let level_str = value_lower.trim_end_matches("_requestseed");
            let level = parse_security_level(level_str)?;

            let seed = self.security_provider.generate_seed(self.bank_set, level);
            {
                let mut sec = self.security.lock().unwrap();
                sec.phase = SecurityPhase::SeedAvailable;
                sec.level = level;
                sec.pending_seed = Some(seed);
            }

            self.get_security_mode().await
        } else {
            let level = parse_security_level(&value_lower)?;
            let key_bytes = key.ok_or_else(|| {
                BackendError::InvalidRequest("missing key — required when sending key".into())
            })?;

            let pending_seed = {
                let sec = self.security.lock().unwrap();
                if sec.phase != SecurityPhase::SeedAvailable || sec.level != level {
                    return Err(BackendError::InvalidRequest(
                        "no pending seed — call requestseed first".into(),
                    ));
                }
                sec.pending_seed.clone().ok_or_else(|| {
                    BackendError::Internal("seed state inconsistency".into())
                })?
            };

            if !self
                .security_provider
                .validate_key(self.bank_set, level, &pending_seed, key_bytes)
            {
                let mut sec = self.security.lock().unwrap();
                sec.phase = SecurityPhase::Locked;
                sec.pending_seed = None;
                return Err(BackendError::SecurityRequired(level));
            }

            {
                let mut sec = self.security.lock().unwrap();
                sec.phase = SecurityPhase::Unlocked;
                sec.pending_seed = None;
            }

            self.get_security_mode().await
        }
    }
}

// ---------------------------------------------------------------------------
// DID helpers (adapted from old models.rs)
// ---------------------------------------------------------------------------

struct DidEntry {
    id: &'static str,
    did: u16,
    name: &'static str,
    data_type: &'static str,
    writable: bool,
}

static DID_REGISTRY: &[DidEntry] = &[
    DidEntry { id: "spare_part_number", did: did::DID_SPARE_PART_NUMBER, name: "Spare Part Number", data_type: "string", writable: false },
    DidEntry { id: "ecu_sw_number", did: did::DID_ECU_SW_NUMBER, name: "ECU Software Number", data_type: "string", writable: false },
    DidEntry { id: "fw_version", did: did::DID_FW_VERSION, name: "Firmware Version", data_type: "string", writable: false },
    DidEntry { id: "supplier_id", did: did::DID_SUPPLIER_ID, name: "Supplier ID", data_type: "string", writable: false },
    DidEntry { id: "manufacturing_date", did: did::DID_MANUFACTURING_DATE, name: "Manufacturing Date", data_type: "string", writable: false },
    DidEntry { id: "serial_number", did: did::DID_SERIAL_NUMBER, name: "Serial Number", data_type: "string", writable: false },
    DidEntry { id: "vin", did: did::DID_VIN, name: "VIN", data_type: "string", writable: false },
    DidEntry { id: "ecu_hw_number", did: did::DID_ECU_HW_NUMBER, name: "ECU Hardware Number", data_type: "string", writable: false },
    DidEntry { id: "supplier_hw_number", did: did::DID_SUPPLIER_HW_NUMBER, name: "Supplier HW Number", data_type: "string", writable: false },
    DidEntry { id: "supplier_hw_version", did: did::DID_SUPPLIER_HW_VERSION, name: "Supplier HW Version", data_type: "string", writable: false },
    DidEntry { id: "supplier_sw_number", did: did::DID_SUPPLIER_SW_NUMBER, name: "Supplier SW Number", data_type: "string", writable: false },
    DidEntry { id: "supplier_sw_version", did: did::DID_SUPPLIER_SW_VERSION, name: "Supplier SW Version", data_type: "string", writable: false },
    DidEntry { id: "system_name", did: did::DID_SYSTEM_NAME, name: "System Name", data_type: "string", writable: false },
    DidEntry { id: "tester_serial", did: did::DID_TESTER_SERIAL, name: "Tester Serial", data_type: "string", writable: false },
    DidEntry { id: "programming_date", did: did::DID_PROGRAMMING_DATE, name: "Programming Date", data_type: "string", writable: false },
    DidEntry { id: "odx_file_id", did: did::DID_ODX_FILE_ID, name: "ODX File ID", data_type: "string", writable: false },
    DidEntry { id: "active_bank", did: did::DID_ACTIVE_BANK, name: "Active Bank", data_type: "string", writable: false },
    DidEntry { id: "committed", did: did::DID_COMMITTED, name: "Committed", data_type: "bool", writable: false },
    DidEntry { id: "min_security_ver", did: did::DID_MIN_SECURITY_VER, name: "Min Security Version", data_type: "uint32", writable: false },
    DidEntry { id: "current_security_ver", did: did::DID_CURRENT_SECURITY_VER, name: "Current Security Version", data_type: "uint32", writable: false },
    DidEntry { id: "boot_count", did: did::DID_BOOT_COUNT, name: "Boot Count", data_type: "uint8", writable: false },
];

fn resolve_param(param_id: &str) -> Option<(u16, Option<&'static DidEntry>)> {
    if let Some(entry) = DID_REGISTRY.iter().find(|d| d.id == param_id) {
        return Some((entry.did, Some(entry)));
    }
    let hex_str = param_id
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .trim_start_matches("runtime_");
    if let Ok(did) = u16::from_str_radix(hex_str, 16) {
        let reg = DID_REGISTRY.iter().find(|d| d.did == did);
        return Some((did, reg));
    }
    None
}

fn did_value_to_json(_did_num: u16, value: &[u8], reg: Option<&DidEntry>) -> serde_json::Value {
    let data_type = reg.map(|r| r.data_type).unwrap_or("bytes");
    match data_type {
        "bool" => serde_json::Value::Bool(value.first().copied().unwrap_or(0) != 0),
        "uint8" => serde_json::json!(value.first().copied().unwrap_or(0)),
        "uint32" => {
            let v = if value.len() >= 4 {
                u32::from_le_bytes([value[0], value[1], value[2], value[3]])
            } else {
                0
            };
            serde_json::json!(v)
        }
        "string" => {
            let s = VmBackend::<nv_store::block::MemBlockDevice>::nv_bytes_to_string(value);
            serde_json::Value::String(s)
        }
        _ => {
            let end = value.iter().position(|&c| c == 0).unwrap_or(value.len());
            if let Ok(s) = std::str::from_utf8(&value[..end]) {
                if !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                    return serde_json::Value::String(s.to_string());
                }
            }
            let hex: String = value.iter().map(|b| format!("{b:02x}")).collect();
            serde_json::Value::String(format!("0x{hex}"))
        }
    }
}

fn parse_security_level(s: &str) -> BackendResult<u8> {
    let digits = s.trim_start_matches("level");
    digits
        .parse::<u8>()
        .map_err(|_| BackendError::InvalidRequest(format!("invalid security level: {s}")))
}
