/// SUIT manifest provider — validates RFC 9124 SUIT envelopes via sumo-rs.
///
/// Uses sumo-onboard's orchestrator for the payload pipeline:
/// fetch → decrypt → decompress → verify → write
///
/// Two trust stores:
/// - **Provisioning authority** (fixed at startup): validates HSM key envelopes.
///   This is the authority *over* the HSM — cannot live inside the HSM.
/// - **Software authority** (loaded from HSM after provisioning): validates
///   firmware SUIT envelopes. None until HSM is provisioned.
///
/// No file-based fallbacks for software authority or device key.

use std::cell::RefCell;
use std::sync::{Arc, RwLock};

use nv_store::types::BankSet;
use sumo_crypto::RustCryptoBackend;
use sumo_onboard::error::Sum2Error;
use sumo_onboard::platform::PlatformOps;
use sumo_onboard::Validator;
use sumo_onboard::orchestrator;

use crate::manifest_provider::{ManifestError, ManifestProvider, ManifestType, ValidatedFirmware};
use crate::ota::ImageMeta;

/// URI key for the integrated firmware payload inside the SUIT envelope.
const INTEGRATED_PAYLOAD_KEY: &str = "#firmware";

pub struct SuitProvider {
    /// Provisioning authority — validates HSM key envelopes only.
    /// Set at startup, never changes.
    provisioning_authority: Vec<u8>,
    /// Software authority — validates firmware SUIT envelopes.
    /// Loaded from HSM after provisioning. None until HSM is provisioned.
    software_authority: Arc<RwLock<Option<Vec<u8>>>>,
    /// Device decryption key — ECDH for firmware decryption.
    /// Loaded from HSM after provisioning. None until HSM is provisioned.
    device_key: Arc<RwLock<Option<Vec<u8>>>>,
}

impl SuitProvider {
    pub fn new(provisioning_authority: Vec<u8>) -> Self {
        Self {
            provisioning_authority,
            software_authority: Arc::new(RwLock::new(None)),
            device_key: Arc::new(RwLock::new(None)),
        }
    }

    /// Load software authority and device key from HSM after provisioning.
    pub fn update_keys(&self, sw_authority: Vec<u8>, device_key: Option<Vec<u8>>) {
        *self.software_authority.write().unwrap() = Some(sw_authority);
        *self.device_key.write().unwrap() = device_key;
        tracing::info!("SuitProvider: loaded software authority and device key from HSM");
    }

    /// Check if software authority keys have been loaded.
    pub fn has_software_authority(&self) -> bool {
        self.software_authority.read().unwrap().is_some()
    }

    /// Select the trust anchor based on manifest type.
    fn trust_anchor_for(&self, manifest_type: ManifestType) -> Result<Vec<u8>, ManifestError> {
        match manifest_type {
            ManifestType::HsmKeys => Ok(self.provisioning_authority.clone()),
            ManifestType::Firmware => {
                self.software_authority
                    .read()
                    .unwrap()
                    .clone()
                    .ok_or_else(|| ManifestError::ParseError(
                        "no software authority key — HSM not yet provisioned".into(),
                    ))
            }
        }
    }

    /// Get the current device key (if loaded from HSM).
    fn current_device_key(&self) -> Option<Vec<u8>> {
        self.device_key.read().unwrap().clone()
    }
}

impl SuitProvider {
    /// Validate envelope header only (no payload processing).
    /// Used by the streaming processor which handles the payload separately.
    pub fn validate_header_only(
        &self,
        data: &[u8],
        min_security_ver: u32,
    ) -> Result<ValidatedFirmware, ManifestError> {
        // First pass: extract metadata to determine manifest type.
        // Use provisioning authority for initial parse — if it's firmware,
        // we'll re-validate with software authority.
        let crypto = RustCryptoBackend::new();

        // Peek at component_id to determine manifest type before full validation
        let manifest_type = peek_manifest_type(data)?;
        let trust_anchor = self.trust_anchor_for(manifest_type)?;

        // Diagnostic: log the trust anchor bytes so we can verify the loaded
        // key matches what the manifest is signed with. Hex-encoded so it's
        // easy to byte-compare against signing.pub on disk.
        tracing::info!(
            manifest_type = ?manifest_type,
            trust_anchor_len = trust_anchor.len(),
            trust_anchor_hex = %hex::encode(&trust_anchor),
            "validating envelope"
        );

        let mut validator = Validator::new(&trust_anchor, None);
        if manifest_type == ManifestType::Firmware {
            if let Some(dk) = self.current_device_key() {
                validator.add_device_key(&dk).map_err(|e| {
                    ManifestError::ParseError(format!("invalid device key: {e:?}"))
                })?;
            }
        }

        let manifest = validator
            .validate_envelope(data, &crypto, 0)
            .map_err(|e| match e {
                Sum2Error::AuthFailed => {
                    ManifestError::SignatureInvalid("COSE_Sign1 verification failed".into())
                }
                other => ManifestError::ParseError(format!("{other:?}")),
            })?;

        let secver = manifest.security_version(0).unwrap_or(0);
        if secver < min_security_ver as u64 {
            return Err(ManifestError::RollbackRejected {
                seq: secver,
                min: min_security_ver as u64,
            });
        }

        Self::extract_metadata(&manifest, secver)
    }

    /// Extract metadata from a validated manifest (shared by validate and validate_header_only).
    fn extract_metadata(
        manifest: &sumo_onboard::manifest::Manifest,
        secver: u64,
    ) -> Result<ValidatedFirmware, ManifestError> {
        let segments = manifest.component_id(0).ok_or_else(|| {
            ManifestError::ComponentUnknown("missing component_id".into())
        })?;

        // Resolve bank_set from the first segment that matches a BankSet.
        let bank_set = segments
            .iter()
            .find_map(|seg| {
                std::str::from_utf8(seg).ok().and_then(BankSet::from_str)
            })
            .ok_or_else(|| {
                let comp_str = segments
                    .iter()
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .collect::<Vec<_>>()
                    .join("/");
                ManifestError::ComponentUnknown(comp_str)
            })?;

        // Detect manifest sub-type from component_id path.
        let manifest_type = {
            let seg_strs: Vec<&str> = segments
                .iter()
                .filter_map(|s| std::str::from_utf8(s).ok())
                .collect();
            if seg_strs == ["hsm", "keys"] {
                ManifestType::HsmKeys
            } else {
                ManifestType::Firmware
            }
        };

        let seq = manifest.sequence_number();
        let seq_u32 = if seq > u32::MAX as u64 { u32::MAX } else { seq as u32 };

        let mut meta = ImageMeta::default();
        meta.fw_seq = seq_u32;
        meta.fw_secver = if secver > u32::MAX as u64 { u32::MAX } else { secver as u32 };

        let version_display = manifest
            .text_version(0)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("seq-{seq}"));
        copy_to_nv(&version_display, &mut meta.fw_version);

        if let Some(s) = manifest.text_vendor_name(0) {
            copy_to_nv(s, &mut meta.supplier_sw_number);
            copy_to_nv(&version_display, &mut meta.supplier_sw_version);
        }
        if let Some(s) = manifest.text_model_name(0) {
            copy_to_nv(s, &mut meta.system_name);
        }
        if let Some(s) = manifest.text_model_info(0) {
            copy_to_nv(s, &mut meta.ecu_sw_number);
        }
        if let Some(s) = manifest.text_description() {
            copy_to_nv(s, &mut meta.spare_part_number);
        }

        let now = chrono::Utc::now().format("%Y%m%d").to_string();
        copy_to_nv(&now, &mut meta.programming_date);
        copy_to_nv("SOVD-OTA", &mut meta.tester_serial);

        Ok(ValidatedFirmware {
            bank_set,
            manifest_type,
            image_meta: meta,
            image_data: Vec::new(),
            version_display,
            image_sha256: None,
            image_size: None,
            raw_envelope: None,
        })
    }
}

impl ManifestProvider for SuitProvider {
    fn validate(
        &self,
        data: &[u8],
        min_security_ver: u32,
    ) -> Result<ValidatedFirmware, ManifestError> {
        let crypto = RustCryptoBackend::new();

        // Peek at component_id to select trust store
        let manifest_type = peek_manifest_type(data)?;
        let trust_anchor = self.trust_anchor_for(manifest_type)?;

        let mut validator = Validator::new(&trust_anchor, None);
        if manifest_type == ManifestType::Firmware {
            if let Some(dk) = self.current_device_key() {
                validator.add_device_key(&dk).map_err(|e| {
                    ManifestError::ParseError(format!("invalid device key: {e:?}"))
                })?;
            }
        }

        // Validate envelope: signature, digest
        let manifest = validator
            .validate_envelope(data, &crypto, 0)
            .map_err(|e| match e {
                Sum2Error::AuthFailed => {
                    ManifestError::SignatureInvalid("COSE_Sign1 verification failed".into())
                }
                other => ManifestError::ParseError(format!("{other:?}")),
            })?;

        // Check security_version against floor
        let secver = manifest.security_version(0).unwrap_or(0);
        if secver < min_security_ver as u64 {
            return Err(ManifestError::RollbackRejected {
                seq: secver,
                min: min_security_ver as u64,
            });
        }

        let mut validated = Self::extract_metadata(&manifest, secver)?;

        // HSM key manifests: pass raw envelope through — HSM handles
        // decrypt/decompress internally (matches production HSM firmware).
        if validated.manifest_type == ManifestType::HsmKeys {
            validated.raw_envelope = Some(data.to_vec());
            return Ok(validated);
        }

        // Determine update type from manifest command sequences
        let has_payload = manifest.has_firmware();

        let image_data = if has_payload {
            // Extract integrated payload for the orchestrator's fetch
            let raw_payload = manifest
                .integrated_payload(INTEGRATED_PAYLOAD_KEY)
                .ok_or_else(|| {
                    ManifestError::ParseError(format!(
                        "manifest has image_digest but no integrated payload at \"{INTEGRATED_PAYLOAD_KEY}\""
                    ))
                })?
                .to_vec();

            // Run the SUIT orchestrator — handles fetch, decrypt, decompress, verify
            let ops = VmPlatformOps::new(raw_payload);
            orchestrator::process_image(&validator, &manifest, &ops, &crypto)
                .map_err(|e| match e {
                    Sum2Error::DigestMismatch => ManifestError::DigestMismatch,
                    other => ManifestError::ParseError(format!("orchestrator: {other:?}")),
                })?;

            ops.take_written()
        } else {
            // CRL / policy-only manifest — no payload
            Vec::new()
        };

        validated.image_data = image_data;
        Ok(validated)
    }

    fn validate_header_only(
        &self,
        data: &[u8],
        min_security_ver: u32,
    ) -> Result<ValidatedFirmware, ManifestError> {
        SuitProvider::validate_header_only(self, data, min_security_ver)
    }

    fn software_authority_key(&self) -> Option<Vec<u8>> {
        self.software_authority.read().unwrap().clone()
    }

    fn device_decryption_key(&self) -> Option<Vec<u8>> {
        self.device_key.read().unwrap().clone()
    }

    fn update_keys(&self, sw_authority: Vec<u8>, device_key: Option<Vec<u8>>) {
        SuitProvider::update_keys(self, sw_authority, device_key);
    }
}

// ---------------------------------------------------------------------------
// Peek at manifest type from raw envelope bytes
// ---------------------------------------------------------------------------

/// Quick parse of envelope to determine ManifestType from component_id.
/// Does a full decode — used before signature validation to select trust store.
fn peek_manifest_type(data: &[u8]) -> Result<ManifestType, ManifestError> {
    let envelope = sumo_codec::decode::decode_envelope(data)
        .map_err(|e| ManifestError::ParseError(format!("decode envelope: {e:?}")))?;
    let manifest = sumo_onboard::manifest::Manifest { envelope };

    if let Some(segments) = manifest.component_id(0) {
        let seg_strs: Vec<&str> = segments
            .iter()
            .filter_map(|s| std::str::from_utf8(s).ok())
            .collect();
        if seg_strs == ["hsm", "keys"] {
            return Ok(ManifestType::HsmKeys);
        }
    }
    Ok(ManifestType::Firmware)
}

// ---------------------------------------------------------------------------
// VmPlatformOps — PlatformOps for the SUIT orchestrator
// ---------------------------------------------------------------------------

struct VmPlatformOps {
    /// Pre-staged payload (from integrated envelope)
    staged_payload: Vec<u8>,
    /// Accumulated plaintext written by orchestrator
    written: RefCell<Vec<u8>>,
}

impl VmPlatformOps {
    fn new(staged_payload: Vec<u8>) -> Self {
        Self {
            staged_payload,
            written: RefCell::new(Vec::new()),
        }
    }

    fn take_written(self) -> Vec<u8> {
        self.written.into_inner()
    }
}

impl PlatformOps for VmPlatformOps {
    fn fetch(&self, _uri: &str, buf: &mut [u8]) -> Result<usize, Sum2Error> {
        // Payload is pre-staged from the integrated envelope
        let n = self.staged_payload.len().min(buf.len());
        buf[..n].copy_from_slice(&self.staged_payload[..n]);
        Ok(n)
    }

    fn write(&self, _component_id: &[u8], offset: usize, data: &[u8]) -> Result<(), Sum2Error> {
        let mut written = self.written.borrow_mut();
        let end = offset + data.len();
        if written.len() < end {
            written.resize(end, 0);
        }
        written[offset..end].copy_from_slice(data);
        Ok(())
    }

    fn invoke(&self, _component_id: &[u8]) -> Result<(), Sum2Error> {
        // No-op — VM boot happens at ecu_reset, not here
        Ok(())
    }

    fn swap(&self, _comp_a: &[u8], _comp_b: &[u8]) -> Result<(), Sum2Error> {
        // A/B switching handled by ota::install()
        Ok(())
    }

    fn persist_sequence(&self, _component_id: &[u8], _seq: u64) -> Result<(), Sum2Error> {
        // Security version floor managed by ota::commit()
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn copy_to_nv(s: &str, dst: &mut [u8]) {
    let n = s.len().min(dst.len());
    dst[..n].copy_from_slice(&s.as_bytes()[..n]);
}
