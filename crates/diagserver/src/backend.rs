/// VmBackend — DiagnosticBackend implementation for vm-mgr bank sets.
///
/// Each instance manages one bank set (hyp, os1, os2) and provides:
/// - Parameter read/write via NV DIDs
/// - Fault (DTC) management
/// - SUIT-based firmware flash with A/B banking
/// - Session/security mode control

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::Utc;

use nv_store::block::BlockDevice;
use nv_store::store::NvStore;
use nv_store::types::*;

use sovd_core::backend::*;
use sovd_core::error::{BackendError, BackendResult};
use sovd_core::models::*;
use sovd_core::PackageStream;

use crate::did;
use crate::manifest_provider::{ManifestProvider, ManifestType, ValidatedFirmware};
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

/// A validated manifest (uploaded separately from payloads).
struct StoredManifest {
    id: String,
    raw_bytes: Vec<u8>,
    validated: ValidatedFirmware,
}

/// A raw payload saved to disk (uploaded separately from manifest).
struct StoredPayload {
    id: String,
    path: std::path::PathBuf,
    size: u64,
    sha256: [u8; 32],
}

// ---------------------------------------------------------------------------
// Flash transfer tracking
// ---------------------------------------------------------------------------

struct FlashTransferState {
    transfer_id: String,
    package_id: String,
    state: FlashState,
    image_size: u64,
}

// ---------------------------------------------------------------------------
// Component configuration
// ---------------------------------------------------------------------------

/// Per-component configuration for VmBackend behavior.
pub struct ComponentConfig {
    /// Whether this component supports rollback (false for HSM).
    pub supports_rollback: bool,
    /// Whether this component is single-banked (true for HSM — always bank A).
    pub single_bank: bool,
    /// SOVD entity_type for component identity.
    pub entity_type: String,
}

impl Default for ComponentConfig {
    fn default() -> Self {
        Self {
            supports_rollback: true,
            single_bank: false,
            entity_type: "vm".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// VmBackend
// ---------------------------------------------------------------------------

pub struct VmBackend<D: BlockDevice + Send + 'static> {
    entity_info: EntityInfo,
    capabilities: Capabilities,
    bank_set: BankSet,
    config: ComponentConfig,
    nv: Arc<Mutex<NvStore<D>>>,
    manifest_provider: Arc<dyn ManifestProvider>,
    security_provider: Arc<dyn SecurityProvider>,
    packages: Mutex<HashMap<String, StoredPackage>>,
    manifests: Mutex<HashMap<String, StoredManifest>>,
    payloads: Mutex<HashMap<String, StoredPayload>>,
    flash_transfer: Mutex<Option<FlashTransferState>>,
    /// The bank the ECU is actually running on. Only changes on ecu_reset().
    /// NV active_bank may differ after install (it's the "next boot" bank).
    running_bank: Mutex<Bank>,
    session: Mutex<SessionState>,
    security: Mutex<SecurityAccessState>,
    next_id: Mutex<u64>,
    /// Optional Unix socket path for vm-service control API.
    /// When set, ecu_reset() POSTs to vm-service to restart the VM.
    vm_service_socket: Option<PathBuf>,
    /// Optional images directory — when set, firmware payloads are written
    /// to {images_dir}/{set}-{bank}.img during flash. Required for real
    /// image-based OTA (e.g. QEMU rootfs swap).
    images_dir: Option<PathBuf>,
    /// Tracks upload phase for activation state reporting.
    /// Set to Transferring during receive_package_stream so the campaign
    /// viewer can see that a firmware download is in progress.
    upload_phase: Mutex<Option<FlashState>>,
    /// Optional HSM provider — when set, HSM key material manifests
    /// (component_id `["hsm", "keys"]`) are routed to this provider
    /// instead of being written as a disk image.
    hsm_provider: Option<Arc<Mutex<dyn hsm::HsmProvider>>>,
}

impl<D: BlockDevice + Send + 'static> VmBackend<D> {
    pub fn new(
        bank_set: BankSet,
        nv: Arc<Mutex<NvStore<D>>>,
        manifest_provider: Arc<dyn ManifestProvider>,
        security_provider: Arc<dyn SecurityProvider>,
        config: ComponentConfig,
    ) -> Self {
        Self::with_options(bank_set, nv, manifest_provider, security_provider, config, None, None)
    }

    pub fn with_vm_service(
        bank_set: BankSet,
        nv: Arc<Mutex<NvStore<D>>>,
        manifest_provider: Arc<dyn ManifestProvider>,
        security_provider: Arc<dyn SecurityProvider>,
        config: ComponentConfig,
        vm_service_socket: Option<PathBuf>,
    ) -> Self {
        Self::with_options(bank_set, nv, manifest_provider, security_provider, config, vm_service_socket, None)
    }

    pub fn with_options(
        bank_set: BankSet,
        nv: Arc<Mutex<NvStore<D>>>,
        manifest_provider: Arc<dyn ManifestProvider>,
        security_provider: Arc<dyn SecurityProvider>,
        config: ComponentConfig,
        vm_service_socket: Option<PathBuf>,
        images_dir: Option<PathBuf>,
    ) -> Self {
        let (id, name, desc) = match bank_set {
            BankSet::Hypervisor => ("hyp", "Hypervisor", "Hypervisor A/B bank set"),
            BankSet::Os1 => ("os1", "OS1", "Primary OS VM A/B bank set"),
            BankSet::Os2 => ("os2", "OS2", "Secondary OS VM A/B bank set"),
            BankSet::Hsm => ("hsm", "HSM", "Hardware Security Module"),
            BankSet::Qtd => ("qtd", "QTD", "QNX Target Partition A/B bank set"),
        };

        // Read the current active bank at startup — this is what we're running on.
        let running_bank = if config.single_bank {
            Bank::A // single-banked components always run on bank A
        } else {
            let nv_guard = nv.lock().unwrap();
            nv_guard.read_boot_state()
                .map(|s| s.banks[bank_set as usize].active_bank)
                .unwrap_or(Bank::A)
        };

        Self {
            entity_info: EntityInfo {
                id: id.to_string(),
                name: name.to_string(),
                entity_type: config.entity_type.clone(),
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
            config,
            nv,
            manifest_provider,
            security_provider,
            packages: Mutex::new(HashMap::new()),
            manifests: Mutex::new(HashMap::new()),
            payloads: Mutex::new(HashMap::new()),
            flash_transfer: Mutex::new(None),
            running_bank: Mutex::new(running_bank),
            session: Mutex::new(SessionState::Default),
            security: Mutex::new(SecurityAccessState::default()),
            next_id: Mutex::new(1),
            vm_service_socket,
            images_dir,
            upload_phase: Mutex::new(None),
            hsm_provider: None,
        }
    }

    /// Set an HSM provider for routing key material manifests.
    pub fn with_hsm_provider(mut self, provider: Arc<Mutex<dyn hsm::HsmProvider>>) -> Self {
        self.hsm_provider = Some(provider);
        self
    }

    fn next_id(&self) -> String {
        let mut id = self.next_id.lock().unwrap();
        let v = *id;
        *id += 1;
        v.to_string()
    }

    // =================================================================
    // Separate manifest + payload upload methods (new flash path)
    // =================================================================

    /// Upload a manifest (small CBOR envelope without integrated payloads).
    /// Validates signature + anti-rollback. Returns manifest_id.
    pub fn receive_manifest(&self, data: &[u8]) -> BackendResult<String> {
        self.require_flash_access()?;

        let min_security_ver = {
            let nv = self.nv.lock().map_err(|_| BackendError::Internal("lock".into()))?;
            let rb = *self.running_bank.lock().unwrap();
            nv.read_fw_meta(self.bank_set, rb)
                .map(|m| m.min_security_ver)
                .unwrap_or(0)
        };

        let validated = crate::streaming::validate_manifest(
            data,
            self.manifest_provider.as_ref(),
            min_security_ver,
        )?;

        let id = self.next_id();
        let mut manifests = self.manifests.lock().unwrap();
        manifests.insert(id.clone(), StoredManifest {
            id: id.clone(),
            raw_bytes: data.to_vec(),
            validated,
        });

        tracing::info!(manifest_id = %id, "manifest uploaded and validated");
        Ok(id)
    }

    /// Upload a raw payload (encrypted bytes, no CBOR).
    /// Streams to disk + computes SHA256. Returns payload_id.
    pub async fn receive_payload_stream(
        &self,
        stream: PackageStream,
        filename: Option<&str>,
    ) -> BackendResult<String> {
        let id = self.next_id();
        let dir = self.images_dir.as_ref()
            .ok_or_else(|| BackendError::Internal("no images_dir configured".into()))?;

        let fname = filename.unwrap_or("payload");
        let path = dir.join(format!("upload-{id}-{fname}"));

        let (size, sha256) = crate::streaming::save_raw_payload(stream, &path).await?;

        let mut payloads = self.payloads.lock().unwrap();
        payloads.insert(id.clone(), StoredPayload {
            id: id.clone(),
            path,
            size,
            sha256,
        });

        tracing::info!(payload_id = %id, size, "payload uploaded to disk");
        Ok(id)
    }

    /// Flash using a pre-uploaded manifest + payload(s).
    /// Processes each payload through decrypt → decompress → verify → write.
    pub fn start_flash_multi(
        &self,
        manifest_id: &str,
        payload_ids: &std::collections::HashMap<String, String>, // uri → payload_id
    ) -> BackendResult<String> {
        let manifests = self.manifests.lock().unwrap();
        let manifest = manifests.get(manifest_id)
            .ok_or_else(|| BackendError::InvalidRequest(format!("manifest {manifest_id} not found")))?;

        let payloads = self.payloads.lock().unwrap();

        // Parse manifest to get component info
        let envelope = sumo_codec::decode::decode_envelope(&manifest.raw_bytes)
            .map_err(|e| BackendError::Internal(format!("decode manifest: {e:?}")))?;
        let suit_manifest = sumo_onboard::manifest::Manifest { envelope };

        let device_key = self.manifest_provider.device_decryption_key();

        let set_name = match self.bank_set {
            BankSet::Hypervisor => "hyp",
            BankSet::Os1 => "os1",
            BankSet::Os2 => "os2",
            BankSet::Hsm => "hsm",
            BankSet::Qtd => "qtd",
        };

        let images_dir = self.images_dir.as_ref()
            .ok_or_else(|| BackendError::Internal("no images_dir configured".into()))?;

        // Process each payload
        for (uri, payload_id) in payload_ids {
            let stored_payload = payloads.get(payload_id)
                .ok_or_else(|| BackendError::InvalidRequest(format!("payload {payload_id} not found")))?;

            // Find component index by URI
            let comp_count = suit_manifest.component_count();
            let comp_idx = (0..comp_count)
                .find(|&i| suit_manifest.uri(i).map(|u| u == uri.as_str()).unwrap_or(false))
                .ok_or_else(|| BackendError::InvalidRequest(format!(
                    "no component with uri={uri} in manifest"
                )))?;

            let expected_digest = suit_manifest.image_digest(comp_idx)
                .map(|d| d.0.bytes.clone())
                .ok_or_else(|| BackendError::Internal(format!(
                    "no digest for component {comp_idx}"
                )))?;

            let output_suffix = match uri.as_str() {
                "#kernel" => format!("{set_name}-kernel-staged.img"),
                "#firmware" => format!("{set_name}-staged.img"),
                other => format!("{set_name}-{}-staged.img", other.trim_start_matches('#')),
            };
            let output_path = images_dir.join(&output_suffix);

            tracing::info!(
                uri = %uri,
                component = comp_idx,
                payload = %stored_payload.path.display(),
                output = %output_path.display(),
                "processing payload"
            );

            let (size, hash) = crate::streaming::process_raw_payload(
                &stored_payload.path,
                &manifest.raw_bytes,
                comp_idx,
                device_key.as_deref(),
                &expected_digest,
                &output_path,
            ).map_err(|e| BackendError::Internal(format!(
                "payload processing ({uri}): {e}"
            )))?;

            tracing::info!(uri = %uri, size, "payload written: {}", output_path.display());
        }

        // Create a validated result for the OTA install
        let transfer_id = self.next_id();
        Ok(transfer_id)
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

    /// Send a restart request to vm-service over its Unix socket.
    async fn notify_vm_service(socket_path: &std::path::Path, vm_name: &str) -> Result<(), String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::UnixStream::connect(socket_path)
            .await
            .map_err(|e| format!("connect to vm-service: {e}"))?;

        let request = format!(
            "POST /vms/{vm_name}/restart HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Length: 0\r\n\
             Connection: close\r\n\
             \r\n"
        );

        stream.write_all(request.as_bytes())
            .await
            .map_err(|e| format!("write to vm-service: {e}"))?;

        // Read response (just check status line)
        let mut buf = vec![0u8; 256];
        let n = stream.read(&mut buf)
            .await
            .map_err(|e| format!("read from vm-service: {e}"))?;

        let response = String::from_utf8_lossy(&buf[..n]);
        if response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200") {
            Ok(())
        } else {
            Err(format!("vm-service returned: {}", response.lines().next().unwrap_or("empty")))
        }
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

        let has_health = self.vm_service_socket.is_some();
        let mut params: Vec<ParameterInfo> = DID_REGISTRY
            .iter()
            .filter(|d| has_health || (d.did != did::DID_GUEST_STATE && d.did != did::DID_HEARTBEAT_SEQ))
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
        {
            let active = *self.running_bank.lock().unwrap();
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

            // Health DIDs — query vm-service HTTP API
            if did_num == did::DID_GUEST_STATE || did_num == did::DID_HEARTBEAT_SEQ {
                let health = self.vm_service_socket.as_ref()
                    .and_then(|sock| query_vm_health(sock, &self.entity_info.id));
                let (value, raw) = match (did_num, &health) {
                    (did::DID_GUEST_STATE, Some(h)) => {
                        let s = guest_state_str(h.guest_state);
                        (serde_json::Value::String(s.to_string()), format!("{:08x}", h.guest_state))
                    }
                    (did::DID_GUEST_STATE, None) => {
                        (serde_json::Value::String("offline".to_string()), "ffffffff".to_string())
                    }
                    (did::DID_HEARTBEAT_SEQ, Some(h)) => {
                        (serde_json::json!(h.hb_seq), format!("{:08x}", h.hb_seq))
                    }
                    (did::DID_HEARTBEAT_SEQ, None) => {
                        (serde_json::json!(0), "00000000".to_string())
                    }
                    _ => unreachable!(),
                };
                let name = reg.map(|r| r.name).unwrap_or(param_id.as_str());
                values.push(DataValue {
                    id: param_id.clone(),
                    name: name.to_string(),
                    value,
                    unit: None,
                    timestamp: Utc::now(),
                    raw: Some(raw),
                    did: Some(format!("{:04X}", did_num)),
                    length: Some(4),
                });
                continue;
            }

            let rb = *self.running_bank.lock().unwrap();
            let result = did::read_did(&*nv, self.bank_set, did_num, Some(rb));
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
        let active = *self.running_bank.lock().unwrap();
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
        let active = *self.running_bank.lock().unwrap();
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
            let rb = *self.running_bank.lock().unwrap();
            nv.read_fw_meta(self.bank_set, rb)
                .map(|m| m.min_security_ver)
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

    async fn receive_package_stream(
        &self,
        stream: PackageStream,
        content_length: Option<u64>,
    ) -> BackendResult<String> {
        self.require_flash_access()?;

        let min_security_ver = {
            let nv = self.nv.lock().map_err(|_| BackendError::Internal("lock".into()))?;
            let rb = *self.running_bank.lock().unwrap();
            nv.read_fw_meta(self.bank_set, rb)
                .map(|m| m.min_security_ver)
                .unwrap_or(0)
        };

        tracing::info!(
            bank_set = ?self.bank_set,
            content_length = ?content_length,
            "streaming package upload started"
        );

        // Create a transfer entry so the viewer can see the upload in progress
        let transfer_id = self.next_id();
        {
            let mut ft = self.flash_transfer.lock().unwrap();
            *ft = Some(FlashTransferState {
                transfer_id: transfer_id.clone(),
                package_id: String::new(), // not yet known
                state: FlashState::Transferring,
                image_size: content_length.unwrap_or(0),
            });
        }

        // Signal upload in progress so activation state shows Transferring
        *self.upload_phase.lock().unwrap() = Some(FlashState::Transferring);

        let validated = match crate::streaming::process_envelope_stream(
            stream,
            self.manifest_provider.as_ref(),
            min_security_ver,
            self.images_dir.as_deref(),
            self.bank_set,
        )
        .await {
            Ok(v) => v,
            Err(e) => {
                *self.upload_phase.lock().unwrap() = None;
                let mut ft = self.flash_transfer.lock().unwrap();
                if let Some(ref mut t) = *ft {
                    t.state = FlashState::Failed;
                }
                return Err(e);
            }
        };

        // Upload complete — clear upload phase, update transfer to Preparing
        *self.upload_phase.lock().unwrap() = None;
        {
            let mut ft = self.flash_transfer.lock().unwrap();
            if let Some(ref mut t) = *ft {
                t.state = FlashState::Preparing;
            }
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

    async fn start_flash(&self) -> BackendResult<String> {
        self.require_flash_access()?;

        // Find the most recent verified package
        let package_id = {
            let packages = self.packages.lock().unwrap();
            packages.iter()
                .find(|(_, p)| p.status == PackageStatus::Verified)
                .map(|(id, _)| id.clone())
                .ok_or_else(|| BackendError::InvalidRequest("no verified package".into()))?
        };
        let (meta, image_data, image_size, pre_sha256, pre_size, manifest_type, raw_envelope) = {
            let packages = self.packages.lock().unwrap();
            let p = packages
                .get(&package_id)
                .ok_or_else(|| BackendError::EntityNotFound(package_id.to_string()))?;
            let size = if let Some(s) = p.validated.image_size {
                s
            } else {
                p.validated.image_data.len() as u64
            };
            (
                p.validated.image_meta.clone(),
                p.validated.image_data.clone(),
                size,
                p.validated.image_sha256,
                p.validated.image_size,
                p.validated.manifest_type,
                p.validated.raw_envelope.clone(),
            )
        };

        // HSM key material — route to HsmProvider, skip normal image write
        if manifest_type == ManifestType::HsmKeys {
            let envelope = raw_envelope.as_deref().ok_or_else(|| {
                BackendError::Internal("HSM key manifest missing raw envelope".into())
            })?;
            let hsm = self.hsm_provider.as_ref().ok_or_else(|| {
                BackendError::Internal("no HSM provider configured for key provisioning".into())
            })?;
            {
                let mut hsm_guard = hsm.lock()
                    .map_err(|_| BackendError::Internal("HSM provider lock".into()))?;
                hsm_guard
                    .provision(envelope)
                    .map_err(|e| BackendError::Internal(format!("HSM provision: {e}")))?;

                // After provisioning, load software authority + device key from HSM
                match (
                    hsm_guard.get_public_key(hsm::KeyRole::SoftwareAuthority),
                    hsm_guard.get_private_key(hsm::KeyRole::DeviceDecryption),
                ) {
                    (Ok(sw_key), Ok(dk)) => {
                        self.manifest_provider.update_keys(sw_key, Some(dk));
                        tracing::info!("loaded software authority and device key from HSM");
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        tracing::warn!("HSM provisioned but failed to load keys: {e}");
                    }
                }
            }

            // Update NV metadata (security_version, fw_version) via single-bank path
            let mut nv = self.nv.lock().map_err(|_| BackendError::Internal("lock".into()))?;
            let _result = ota::install(&mut *nv, self.bank_set, &[], &meta, true)
                .map_err(map_ota_error)?;

            let transfer_id = self.next_id();
            let mut ft = self.flash_transfer.lock().unwrap();
            *ft = Some(FlashTransferState {
                transfer_id: transfer_id.clone(),
                package_id: package_id.to_string(),
                state: FlashState::AwaitingExit,
                image_size: 0,
            });
            return Ok(transfer_id);
        }

        // Streaming path: image_data is empty but image was already written to disk
        let is_streamed = image_data.is_empty() && pre_sha256.is_some();
        let is_crl = image_data.is_empty() && pre_sha256.is_none();

        if is_crl {
            // CRL / security-floor-only manifest — raise floor without flashing.
            let mut nv = self.nv.lock().map_err(|_| BackendError::Internal("lock".into()))?;
            let active = *self.running_bank.lock().unwrap();
            if let Some(mut fw_meta) = nv.read_fw_meta(self.bank_set, active) {
                if meta.fw_secver > fw_meta.min_security_ver {
                    fw_meta.min_security_ver = meta.fw_secver;
                    nv.write_fw_meta(self.bank_set, active, &mut fw_meta)
                        .map_err(|e| BackendError::Internal(format!("NV write: {e}")))?;
                }
            }
        } else if is_streamed {
            // Streaming path — image already written to staged file, use pre-computed hash
            let mut nv = self.nv.lock().map_err(|_| BackendError::Internal("lock".into()))?;
            let result = ota::install_precomputed(
                &mut *nv,
                self.bank_set,
                pre_sha256.unwrap(),
                pre_size.unwrap_or(0),
                &meta,
                self.config.single_bank,
            )
            .map_err(map_ota_error)?;

            // Rename staged file to target bank image
            if let Some(ref images_dir) = self.images_dir {
                let set_name = match self.bank_set {
                    BankSet::Hypervisor => "hyp",
                    BankSet::Os1 => "os1",
                    BankSet::Os2 => "os2",
                    BankSet::Hsm => "hsm",
                    BankSet::Qtd => "qtd",
                };
                let bank_name = match result.target_bank {
                    Bank::A => "a",
                    Bank::B => "b",
                };
                // Rename staged files to target bank (rootfs + kernel if present)
                for suffix in ["staged.img", "kernel-staged.img"] {
                    let staged_path = images_dir.join(format!("{set_name}-{suffix}"));
                    if staged_path.exists() {
                        let target_name = suffix.replace("staged", bank_name);
                        let target_path = images_dir.join(format!("{set_name}-{target_name}"));
                        std::fs::rename(&staged_path, &target_path).map_err(|e| {
                            BackendError::Internal(format!(
                                "failed to rename {} → {}: {e}",
                                staged_path.display(),
                                target_path.display()
                            ))
                        })?;
                        tracing::info!(
                            "renamed {} → {}",
                            staged_path.display(),
                            target_path.display()
                        );
                    }
                }
            }
        } else {
            // Buffered path — install from memory
            let mut nv = self.nv.lock().map_err(|_| BackendError::Internal("lock".into()))?;
            let result = ota::install(&mut *nv, self.bank_set, &image_data, &meta, self.config.single_bank)
                .map_err(map_ota_error)?;

            // Write firmware payload to bank image file (real rootfs OTA)
            if let Some(ref images_dir) = self.images_dir {
                let set_name = match self.bank_set {
                    BankSet::Hypervisor => "hyp",
                    BankSet::Os1 => "os1",
                    BankSet::Os2 => "os2",
                    BankSet::Hsm => "hsm",
                    BankSet::Qtd => "qtd",
                };
                let bank_name = match result.target_bank {
                    Bank::A => "a",
                    Bank::B => "b",
                };
                let image_path = images_dir.join(format!("{set_name}-{bank_name}.img"));
                tracing::info!(
                    "writing {} bytes to {}",
                    image_data.len(),
                    image_path.display()
                );
                std::fs::write(&image_path, &image_data).map_err(|e| {
                    BackendError::Internal(format!(
                        "failed to write image to {}: {e}",
                        image_path.display()
                    ))
                })?;
            }
        }

        if !is_crl {
            let mut ft = self.flash_transfer.lock().unwrap();
            if let Some(ref mut t) = *ft {
                // Reuse existing transfer from streaming upload path
                t.package_id = package_id.to_string();
                t.state = FlashState::AwaitingExit;
                t.image_size = image_size;
                return Ok(t.transfer_id.clone());
            }
            // Buffered path — create new transfer
            let transfer_id = self.next_id();
            *ft = Some(FlashTransferState {
                transfer_id: transfer_id.clone(),
                package_id: package_id.to_string(),
                state: FlashState::AwaitingExit,
                image_size,
            });
            return Ok(transfer_id);
        }
        // CRL: no flash transfer state — floor already applied, nothing to poll/finalize/commit

        Ok(self.next_id())
    }

    async fn get_flash_status(&self, transfer_id: &str) -> BackendResult<FlashStatus> {
        let ft = self.flash_transfer.lock().unwrap();
        let t = ft.as_ref().ok_or_else(|| BackendError::EntityNotFound(transfer_id.to_string()))?;

        Ok(FlashStatus {
            transfer_id: t.transfer_id.clone(),
            package_id: t.package_id.clone(),
            state: t.state,
            progress: Some(FlashProgress {
                bytes_transferred: t.image_size,
                bytes_total: t.image_size,
                blocks_transferred: 1,
                blocks_total: 1,
                percent: 100.0,
            }),
            error: None,
        })
    }

    async fn finalize_flash(&self) -> BackendResult<()> {
        let mut ft = self.flash_transfer.lock().unwrap();
        if let Some(ref mut t) = *ft {
            t.state = FlashState::AwaitingReset;
        }
        Ok(())
    }

    async fn ecu_reset(&self, _reset_type: u8) -> BackendResult<Option<u8>> {
        // VM "reset" — simulate reboot:
        // 1. Switch running_bank to NV active_bank (the bank install() staged)
        // 2. Increment boot_count for trial mode (like process_boot())
        // 3. Advance flash state to Activated
        // 4. Reset session and security (ISO 14229)

        if !self.config.single_bank {
            let idx = self.bank_set as usize;
            let mut nv = self.nv.lock().unwrap();
            if let Some(mut state) = nv.read_boot_state() {
                // Switch to the staged bank
                *self.running_bank.lock().unwrap() = state.banks[idx].active_bank;

                // Simulate process_boot(): increment boot_count in trial mode
                if !state.banks[idx].committed {
                    state.banks[idx].boot_count += 1;
                    let _ = nv.write_boot_state(&mut state);
                }
            }
        }
        // Single-bank components: no bank switch, always bank A, always committed

        // Advance flash state
        {
            let mut ft = self.flash_transfer.lock().unwrap();
            if let Some(ref mut t) = *ft {
                t.state = FlashState::Activated;
            }
        }

        // Reset session and security (ISO 14229)
        *self.session.lock().unwrap() = SessionState::Default;
        *self.security.lock().unwrap() = SecurityAccessState::default();

        // Flip the `current` symlink so vm-service boots the right bank
        if let (Some(ref images_dir), Some(ref socket_path)) = (&self.images_dir, &self.vm_service_socket) {
            let set_name = match self.bank_set {
                BankSet::Hypervisor => "hyp",
                BankSet::Os1 => "os1",
                BankSet::Os2 => "os2",
                BankSet::Hsm => "hsm",
                BankSet::Qtd => "qtd",
            };
            let target_bank = *self.running_bank.lock().unwrap();
            let bank_dir_name = match target_bank {
                Bank::A => "bank_a",
                Bank::B => "bank_b",
            };
            let symlink_path = images_dir.join(set_name).join("current");
            let target = images_dir.join(set_name).join(bank_dir_name);
            // Atomic symlink swap: create temp, rename over existing
            let tmp_link = symlink_path.with_extension("tmp");
            let _ = std::fs::remove_file(&tmp_link);
            if let Err(e) = std::os::unix::fs::symlink(&target, &tmp_link)
                .and_then(|()| std::fs::rename(&tmp_link, &symlink_path))
            {
                tracing::warn!("failed to flip current symlink for {set_name}: {e}");
            } else {
                tracing::info!("flipped {set_name}/current -> {bank_dir_name}");
            }

            // Signal vm-service to restart the VM
            let id = &self.entity_info.id;
            match Self::notify_vm_service(socket_path, id).await {
                Ok(()) => tracing::info!("vm-service restart requested for {id}"),
                Err(e) => tracing::warn!("failed to notify vm-service for {id}: {e}"),
            }
        } else if let Some(ref socket_path) = self.vm_service_socket {
            // No images_dir — just restart without symlink flip
            let id = &self.entity_info.id;
            match Self::notify_vm_service(socket_path, id).await {
                Ok(()) => tracing::info!("vm-service restart requested for {id}"),
                Err(e) => tracing::warn!("failed to notify vm-service for {id}: {e}"),
            }
        }

        Ok(None)
    }

    async fn list_flash_transfers(&self) -> BackendResult<Vec<FlashStatus>> {
        let ft = self.flash_transfer.lock().unwrap();
        match ft.as_ref() {
            Some(t) => Ok(vec![FlashStatus {
                transfer_id: t.transfer_id.clone(),
                package_id: t.package_id.clone(),
                state: t.state,
                progress: Some(FlashProgress {
                    bytes_transferred: t.image_size,
                    bytes_total: t.image_size,
                    blocks_transferred: 1,
                    blocks_total: 1,
                    percent: 100.0,
                }),
                error: None,
            }]),
            None => Ok(vec![]),
        }
    }

    async fn get_activation_state(&self) -> BackendResult<ActivationState> {
        // Check upload phase first (streaming firmware download in progress)
        let upload_state = self.upload_phase.lock().unwrap().clone();

        let flash_state = {
            let ft = self.flash_transfer.lock().unwrap();
            ft.as_ref().map(|t| t.state)
        };

        let nv = self.nv.lock().map_err(|_| BackendError::Internal("lock".into()))?;
        let status = ota::status(&*nv, self.bank_set)
            .ok_or_else(|| BackendError::Internal("no boot state".into()))?;

        // Priority: upload phase > flash transfer > NV state
        let state = match upload_state {
            Some(s) => s, // Transferring during firmware download
            None => match flash_state {
                Some(s) => s,
                None if !status.committed => FlashState::Activated, // trial without transfer (e.g. after restart)
                None => FlashState::Complete, // idle — no active update
            },
        };

        // Use running_bank for versions (not NV active_bank which may be staged)
        let rb = *self.running_bank.lock().unwrap();
        let active_version = nv
            .read_fw_meta(self.bank_set, rb)
            .map(|m| Self::nv_bytes_to_string(&m.fw_version));
        let previous_version = nv
            .read_fw_meta(self.bank_set, rb.other())
            .map(|m| Self::nv_bytes_to_string(&m.fw_version));

        Ok(ActivationState {
            supports_rollback: self.config.supports_rollback,
            state,
            active_version,
            previous_version,
        })
    }

    async fn commit_flash(&self) -> BackendResult<()> {
        let mut nv = self.nv.lock().map_err(|_| BackendError::Internal("lock".into()))?;
        match ota::commit(&mut *nv, self.bank_set) {
            Ok(()) => {}
            Err(ota::OtaError::AlreadyCommitted) => {} // CRL or idempotent commit — OK
            Err(e) => return Err(map_ota_error(e)),
        }
        // Clear flash transfer state
        *self.flash_transfer.lock().unwrap() = None;
        Ok(())
    }

    async fn rollback_flash(&self) -> BackendResult<()> {
        if !self.config.supports_rollback {
            return Err(BackendError::InvalidRequest(
                "rollback not supported for this component".into(),
            ));
        }
        let mut nv = self.nv.lock().map_err(|_| BackendError::Internal("lock".into()))?;
        ota::rollback(&mut *nv, self.bank_set).map_err(map_ota_error)?;
        // Clear flash transfer state after rollback
        *self.flash_transfer.lock().unwrap() = None;
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
            let changed = *s != new_state;
            *s = new_state;
            if changed {
                // Security resets on session change (ISO 14229)
                let mut sec = self.security.lock().unwrap();
                *sec = SecurityAccessState::default();
            }
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
    DidEntry { id: "guest_state", did: did::DID_GUEST_STATE, name: "Guest State", data_type: "string", writable: false },
    DidEntry { id: "heartbeat_seq", did: did::DID_HEARTBEAT_SEQ, name: "Heartbeat Seq", data_type: "uint32", writable: false },
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

fn map_ota_error(e: ota::OtaError) -> BackendError {
    match e {
        ota::OtaError::InTrial => BackendError::Busy("bank set is in trial mode".into()),
        ota::OtaError::AlreadyCommitted => BackendError::Busy("already committed".into()),
        ota::OtaError::NotInTrial => BackendError::Busy("not in trial mode".into()),
        ota::OtaError::SecurityVersionTooLow { image, floor } => {
            BackendError::InvalidRequest(format!(
                "security version {image} below anti-rollback floor {floor}"
            ))
        }
        other => BackendError::Internal(format!("{other}")),
    }
}

// ---------------------------------------------------------------------------
// Guest health (via vm-service HTTP API)
// ---------------------------------------------------------------------------

struct GuestHealth {
    guest_state: u32,
    hb_seq: u32,
}

/// Query vm-service health endpoint via Unix socket.
/// Returns guest_state and hb_seq from the JSON response.
fn query_vm_health(socket_path: &std::path::Path, vm_name: &str) -> Option<GuestHealth> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path).ok()?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).ok()?;

    let request = format!(
        "GET /vms/{vm_name}/health HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n"
    );
    stream.write_all(request.as_bytes()).ok()?;

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).ok()?;
    let response = std::str::from_utf8(&buf[..n]).ok()?;

    let body = response.split("\r\n\r\n").nth(1)?;
    let json: serde_json::Value = serde_json::from_str(body).ok()?;

    let guest_state = json.get("guest_state")?.as_u64()? as u32;
    let hb_seq = json.get("hb_seq")?.as_u64()? as u32;

    Some(GuestHealth { guest_state, hb_seq })
}

fn guest_state_str(state: u32) -> &'static str {
    match state {
        0 => "booting",
        1 => "running",
        2 => "degraded",
        3 => "shutting_down",
        _ => "unknown",
    }
}

fn parse_security_level(s: &str) -> BackendResult<u8> {
    let digits = s.trim_start_matches("level");
    digits
        .parse::<u8>()
        .map_err(|_| BackendError::InvalidRequest(format!("invalid security level: {s}")))
}
