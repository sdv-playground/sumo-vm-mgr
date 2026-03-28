use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::Json;
use sha2::{Sha256, Digest};

use nv_store::block::BlockDevice;
use nv_store::types::*;

use crate::did;
use crate::ota;
use crate::sovd::error::ApiError;
use crate::sovd::models::*;
use crate::sovd::state::{AppState, TransferPhase, TransferState, UploadEntry, UploadPhase};

// --- Helpers ---

fn resolve_component(id: &str) -> Result<BankSet, ApiError> {
    BankSet::from_str(id).ok_or_else(|| {
        ApiError::NotFound(format!("Component not found: {id}. Use: hyp, os1, os2"))
    })
}

fn nv_bytes_to_string(data: &[u8]) -> String {
    let end = data.iter().position(|&c| c == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).to_string()
}

fn nv_bytes_to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn did_value_to_json(_did_num: u16, value: &[u8], reg: Option<&DidParam>) -> serde_json::Value {
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
            let s = nv_bytes_to_string(value);
            serde_json::Value::String(s)
        }
        _ => {
            // For unknown types or runtime DIDs, try string then fall back to hex
            let end = value.iter().position(|&c| c == 0).unwrap_or(value.len());
            if let Ok(s) = std::str::from_utf8(&value[..end]) {
                if !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                    return serde_json::Value::String(s.to_string());
                }
            }
            serde_json::Value::String(format!("0x{}", nv_bytes_to_hex(value)))
        }
    }
}

fn component_info(id: &str, name: &str, description: &str) -> ComponentInfo {
    ComponentInfo {
        id: id.to_string(),
        name: name.to_string(),
        description: description.to_string(),
        entity_type: "vm".to_string(),
        capabilities: Capabilities::vm_bank_set(),
        href: format!("/vehicle/v1/components/{id}"),
    }
}

fn all_components() -> Vec<ComponentInfo> {
    vec![
        component_info("hyp", "Hypervisor", "Hypervisor A/B bank set"),
        component_info("os1", "OS1", "Primary OS VM A/B bank set"),
        component_info("os2", "OS2", "Secondary OS VM A/B bank set"),
    ]
}

// --- Health ---

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        components: 3,
    })
}

// --- Components ---

pub async fn list_components() -> Json<ComponentList> {
    Json(ComponentList {
        items: all_components(),
    })
}

pub async fn get_component(
    Path(component_id): Path<String>,
) -> Result<Json<ComponentInfo>, ApiError> {
    let _ = resolve_component(&component_id)?;
    let comps = all_components();
    let comp = comps
        .into_iter()
        .find(|c| c.id == component_id)
        .ok_or_else(|| ApiError::NotFound(format!("Component not found: {component_id}")))?;
    Ok(Json(comp))
}

// --- Data/Parameters ---

pub async fn list_parameters<D: BlockDevice + Send + 'static>(
    State(state): State<AppState<D>>,
    Path(component_id): Path<String>,
) -> Result<Json<ParameterList>, ApiError> {
    let set = resolve_component(&component_id)?;
    let nv = state.nv.lock().map_err(|_| ApiError::Internal("lock poisoned".into()))?;

    let mut items: Vec<ParameterInfo> = PARAM_REGISTRY
        .iter()
        .map(|p| ParameterInfo {
            id: p.id.to_string(),
            did: format!("{:04X}", p.did),
            name: p.name.to_string(),
            data_type: p.data_type.to_string(),
            writable: p.writable,
            href: format!("/vehicle/v1/components/{component_id}/data/{}", p.id),
        })
        .collect();

    // Add runtime DIDs not in the static registry
    let boot_state = nv.read_boot_state();
    if let Some(bs) = &boot_state {
        let active = bs.banks[set as usize].active_bank;
        if let Some(runtime) = nv.read_runtime(set, active) {
            for i in 0..runtime.did_count as usize {
                let did_num = runtime.dids[i].did;
                if PARAM_REGISTRY.iter().any(|p| p.did == did_num) {
                    continue;
                }
                let id = format!("runtime_{:04X}", did_num);
                items.push(ParameterInfo {
                    id: id.clone(),
                    did: format!("{:04X}", did_num),
                    name: format!("Runtime DID 0x{:04X}", did_num),
                    data_type: "bytes".to_string(),
                    writable: true,
                    href: format!("/vehicle/v1/components/{component_id}/data/{id}"),
                });
            }
        }
    }

    let count = items.len();
    Ok(Json(ParameterList { count, items }))
}

pub async fn read_parameter<D: BlockDevice + Send + 'static>(
    State(state): State<AppState<D>>,
    Path((component_id, param_id)): Path<(String, String)>,
) -> Result<Json<DataValue>, ApiError> {
    let set = resolve_component(&component_id)?;
    let (did_num, reg) = resolve_param(&param_id)
        .ok_or_else(|| ApiError::NotFound(format!("Parameter not found: {param_id}")))?;

    let nv = state.nv.lock().map_err(|_| ApiError::Internal("lock poisoned".into()))?;
    let result = did::read_did(&*nv, set, did_num);

    match result {
        did::DidValue::Bytes(bytes) => {
            let value = did_value_to_json(did_num, &bytes, reg);
            let raw = nv_bytes_to_hex(&bytes);
            let id = reg.map(|r| r.id).unwrap_or(&param_id);
            Ok(Json(DataValue {
                id: id.to_string(),
                did: format!("{:04X}", did_num),
                value,
                raw,
                length: bytes.len(),
            }))
        }
        did::DidValue::NotFound => {
            Err(ApiError::NotFound(format!("DID 0x{did_num:04X} not found")))
        }
    }
}

pub async fn write_parameter<D: BlockDevice + Send + 'static>(
    State(state): State<AppState<D>>,
    Path((component_id, param_id)): Path<(String, String)>,
    Json(body): Json<WriteRequest>,
) -> Result<Json<WriteResponse>, ApiError> {
    let set = resolve_component(&component_id)?;
    let (did_num, reg) = resolve_param(&param_id)
        .ok_or_else(|| ApiError::NotFound(format!("Parameter not found: {param_id}")))?;

    // Check if writable — static registry DIDs marked read-only cannot be written
    if let Some(p) = reg {
        if !p.writable {
            return Err(ApiError::Forbidden(format!(
                "DID 0x{:04X} ({}) is read-only",
                did_num, p.name
            )));
        }
    }

    let mut nv = state.nv.lock().map_err(|_| ApiError::Internal("lock poisoned".into()))?;
    let data = body.value.as_bytes();

    match did::write_did(&mut *nv, set, did_num, data) {
        Ok(true) => Ok(Json(WriteResponse {
            success: true,
            message: format!("DID 0x{did_num:04X} written"),
        })),
        Ok(false) => Err(ApiError::Conflict("Runtime DID store full".into())),
        Err(e) => Err(ApiError::Internal(e.to_string())),
    }
}

// --- Faults ---

pub async fn list_faults<D: BlockDevice + Send + 'static>(
    State(state): State<AppState<D>>,
    Path(component_id): Path<String>,
) -> Result<Json<FaultList>, ApiError> {
    let set = resolve_component(&component_id)?;
    let nv = state.nv.lock().map_err(|_| ApiError::Internal("lock poisoned".into()))?;

    let boot_state = nv
        .read_boot_state()
        .ok_or_else(|| ApiError::Internal("No boot state".into()))?;
    let active = boot_state.banks[set as usize].active_bank;
    let runtime = nv.read_runtime(set, active).unwrap_or_default();

    let items: Vec<FaultInfo> = (0..runtime.dtc_count as usize)
        .map(|i| {
            let dtc = &runtime.dtcs[i];
            let code = format!("{:06X}", dtc.dtc_number);
            let active = dtc.status & 0x01 != 0; // testFailed bit
            FaultInfo {
                id: format!("dtc_{code}"),
                dtc_code: code.clone(),
                status: dtc.status,
                active,
                href: format!("/vehicle/v1/components/{component_id}/faults/dtc_{code}"),
            }
        })
        .collect();

    let total_count = items.len();
    Ok(Json(FaultList { items, total_count }))
}

pub async fn clear_faults<D: BlockDevice + Send + 'static>(
    State(state): State<AppState<D>>,
    Path(component_id): Path<String>,
) -> Result<Json<ClearFaultsResponse>, ApiError> {
    let set = resolve_component(&component_id)?;
    let mut nv = state.nv.lock().map_err(|_| ApiError::Internal("lock poisoned".into()))?;

    let boot_state = nv
        .read_boot_state()
        .ok_or_else(|| ApiError::Internal("No boot state".into()))?;
    let active = boot_state.banks[set as usize].active_bank;
    let mut runtime = nv.read_runtime(set, active).unwrap_or_default();

    let cleared = runtime.dtc_count as usize;
    runtime.dtc_count = 0;
    runtime.dtcs = std::array::from_fn(|_| DtcEntry::default());

    nv.write_runtime(set, active, &mut runtime)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(ClearFaultsResponse {
        success: true,
        cleared_count: cleared,
    }))
}

// --- Flash/Activation ---

pub async fn get_activation_state<D: BlockDevice + Send + 'static>(
    State(state): State<AppState<D>>,
    Path(component_id): Path<String>,
) -> Result<Json<ActivationState>, ApiError> {
    let set = resolve_component(&component_id)?;
    let nv = state.nv.lock().map_err(|_| ApiError::Internal("lock poisoned".into()))?;

    let status = ota::status(&*nv, set)
        .ok_or_else(|| ApiError::Internal("No boot state".into()))?;

    let state_str = if status.committed {
        "committed"
    } else {
        "trial"
    };

    let active_version = status.fw_version.map(|v| nv_bytes_to_string(&v));

    let previous_bank = status.active_bank.other();
    let previous_version = nv
        .read_fw_meta(set, previous_bank)
        .map(|m| nv_bytes_to_string(&m.fw_version));

    Ok(Json(ActivationState {
        supports_rollback: true,
        state: state_str.to_string(),
        active_version,
        previous_version,
    }))
}

pub async fn commit_flash<D: BlockDevice + Send + 'static>(
    State(state): State<AppState<D>>,
    Path(component_id): Path<String>,
) -> Result<Json<CommitRollbackResponse>, ApiError> {
    let set = resolve_component(&component_id)?;
    let mut nv = state.nv.lock().map_err(|_| ApiError::Internal("lock poisoned".into()))?;

    ota::commit(&mut *nv, set)?;

    Ok(Json(CommitRollbackResponse {
        success: true,
        message: "Firmware committed".to_string(),
    }))
}

pub async fn rollback_flash<D: BlockDevice + Send + 'static>(
    State(state): State<AppState<D>>,
    Path(component_id): Path<String>,
) -> Result<Json<CommitRollbackResponse>, ApiError> {
    let set = resolve_component(&component_id)?;
    let mut nv = state.nv.lock().map_err(|_| ApiError::Internal("lock poisoned".into()))?;

    let bank = ota::rollback(&mut *nv, set)?;
    let letter = match bank {
        Bank::A => "A",
        Bank::B => "B",
    };

    Ok(Json(CommitRollbackResponse {
        success: true,
        message: format!("Rolled back to bank {letter}"),
    }))
}

// --- Flash file upload/transfer ---

pub async fn upload_file<D: BlockDevice + Send + 'static>(
    State(state): State<AppState<D>>,
    Path(component_id): Path<String>,
    body: Bytes,
) -> Result<Json<FileUploadResponse>, ApiError> {
    let set = resolve_component(&component_id)?;

    // Look up current min_security_ver for anti-rollback validation
    let min_security_ver = {
        let nv = state.nv.lock().map_err(|_| ApiError::Internal("lock poisoned".into()))?;
        let boot = nv.read_boot_state();
        boot.and_then(|bs| {
            let active = bs.banks[set as usize].active_bank;
            nv.read_fw_meta(set, active).map(|m| m.min_security_ver)
        })
        .unwrap_or(0)
    };

    // Validate envelope via the pluggable manifest provider
    let validated = state
        .manifest_provider
        .validate(&body, min_security_ver)
        .map_err(|e| ApiError::BadRequest(format!("Manifest validation failed: {e}")))?;

    // Verify the resolved component matches the URL
    if validated.bank_set != set {
        return Err(ApiError::BadRequest(format!(
            "Manifest component resolves to {:?}, but uploaded to {component_id}",
            validated.bank_set
        )));
    }

    let mut uploads = state.uploads.lock().map_err(|_| ApiError::Internal("lock poisoned".into()))?;
    let id = uploads.next_id();

    uploads.files.insert(
        id.clone(),
        UploadEntry {
            id: id.clone(),
            component: set,
            state: UploadPhase::Uploaded,
            validated,
        },
    );

    Ok(Json(FileUploadResponse {
        upload_id: id,
        state: "uploaded".to_string(),
    }))
}

pub async fn get_upload_status<D: BlockDevice + Send + 'static>(
    State(state): State<AppState<D>>,
    Path((_component_id, upload_id)): Path<(String, String)>,
) -> Result<Json<FileStatusResponse>, ApiError> {
    let uploads = state.uploads.lock().map_err(|_| ApiError::Internal("lock poisoned".into()))?;
    let entry = uploads
        .files
        .get(&upload_id)
        .ok_or_else(|| ApiError::NotFound(format!("Upload not found: {upload_id}")))?;

    Ok(Json(FileStatusResponse {
        upload_id: entry.id.clone(),
        state: entry.state.as_str().to_string(),
        version: Some(entry.validated.version_display.clone()),
        component: Some(format!("{:?}", entry.validated.bank_set)),
    }))
}

pub async fn verify_file<D: BlockDevice + Send + 'static>(
    State(state): State<AppState<D>>,
    Path((_component_id, upload_id)): Path<(String, String)>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let mut uploads = state.uploads.lock().map_err(|_| ApiError::Internal("lock poisoned".into()))?;
    let entry = uploads
        .files
        .get_mut(&upload_id)
        .ok_or_else(|| ApiError::NotFound(format!("Upload not found: {upload_id}")))?;

    // Signature and digest were already verified during upload by the ManifestProvider.
    // Recompute hash for the response.
    let hash: [u8; 32] = Sha256::digest(&entry.validated.image_data).into();
    let size = entry.validated.image_data.len() as u64;

    entry.state = UploadPhase::Verified;

    let hash_hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    Ok(Json(VerifyResponse {
        upload_id: upload_id.clone(),
        state: "verified".to_string(),
        image_sha256: hash_hex,
        image_size: size,
    }))
}

pub async fn start_transfer<D: BlockDevice + Send + 'static>(
    State(state): State<AppState<D>>,
    Path(component_id): Path<String>,
    Json(body): Json<TransferRequest>,
) -> Result<Json<TransferResponse>, ApiError> {
    let set = resolve_component(&component_id)?;

    // Extract what we need from the upload, then drop the lock
    let (meta, version, image_data) = {
        let uploads = state.uploads.lock().map_err(|_| ApiError::Internal("lock poisoned".into()))?;
        let entry = uploads
            .files
            .get(&body.file_id)
            .ok_or_else(|| ApiError::NotFound(format!("Upload not found: {}", body.file_id)))?;
        (
            entry.validated.image_meta.clone(),
            entry.validated.version_display.clone(),
            entry.validated.image_data.clone(),
        )
    };

    // Install via OTA engine
    let mut nv = state.nv.lock().map_err(|_| ApiError::Internal("lock poisoned".into()))?;
    let result = ota::install(&mut *nv, set, &image_data, &meta)?;
    drop(nv);

    let target_bank = match result.target_bank {
        Bank::A => "A",
        Bank::B => "B",
    };

    // Create transfer record
    let mut uploads = state.uploads.lock().map_err(|_| ApiError::Internal("lock poisoned".into()))?;
    let tid = uploads.next_id();
    uploads.transfers.insert(
        tid.clone(),
        TransferState {
            id: tid.clone(),
            upload_id: body.file_id.clone(),
            component: set,
            state: TransferPhase::Completed,
            version,
            target_bank: target_bank.to_string(),
        },
    );

    Ok(Json(TransferResponse {
        transfer_id: tid,
        state: "completed".to_string(),
    }))
}

pub async fn transfer_progress<D: BlockDevice + Send + 'static>(
    State(state): State<AppState<D>>,
    Path((_component_id, transfer_id)): Path<(String, String)>,
) -> Result<Json<TransferProgress>, ApiError> {
    let uploads = state.uploads.lock().map_err(|_| ApiError::Internal("lock poisoned".into()))?;
    let transfer = uploads
        .transfers
        .get(&transfer_id)
        .ok_or_else(|| ApiError::NotFound(format!("Transfer not found: {transfer_id}")))?;

    Ok(Json(TransferProgress {
        transfer_id: transfer.id.clone(),
        state: transfer.state.as_str().to_string(),
        blocks_transferred: 1,
        blocks_total: 1,
        percent: 100,
    }))
}

pub async fn finalize_transfer<D: BlockDevice + Send + 'static>(
    State(state): State<AppState<D>>,
    Path((_component_id, transfer_id)): Path<(String, String)>,
) -> Result<Json<FinalizeResponse>, ApiError> {
    let uploads = state.uploads.lock().map_err(|_| ApiError::Internal("lock poisoned".into()))?;
    let transfer = uploads
        .transfers
        .get(&transfer_id)
        .ok_or_else(|| ApiError::NotFound(format!("Transfer not found: {transfer_id}")))?;

    Ok(Json(FinalizeResponse {
        success: true,
        message: format!(
            "Transfer complete: {} v{} -> bank {}",
            transfer.component as u8, transfer.version, transfer.target_bank
        ),
    }))
}
