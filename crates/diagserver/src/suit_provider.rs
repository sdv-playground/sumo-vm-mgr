/// SUIT manifest provider — validates RFC 9124 SUIT envelopes via sumo-rs.
///
/// Uses sumo-onboard's orchestrator for the payload pipeline:
/// fetch → decrypt → decompress → verify → write
///
/// CRL manifests (no payload) are handled separately — security_version
/// floor is extracted, no orchestrator needed.

use std::cell::RefCell;

use nv_store::types::BankSet;
use sumo_crypto::RustCryptoBackend;
use sumo_onboard::error::Sum2Error;
use sumo_onboard::platform::PlatformOps;
use sumo_onboard::Validator;
use sumo_onboard::orchestrator;

use crate::manifest_provider::{ManifestError, ManifestProvider, ValidatedFirmware};
use crate::ota::ImageMeta;

/// URI key for the integrated firmware payload inside the SUIT envelope.
const INTEGRATED_PAYLOAD_KEY: &str = "#firmware";

pub struct SuitProvider {
    trust_anchor: Vec<u8>,
    device_key: Option<Vec<u8>>,
}

impl SuitProvider {
    pub fn new(trust_anchor: Vec<u8>) -> Self {
        Self { trust_anchor, device_key: None }
    }

    pub fn with_device_key(mut self, key: Vec<u8>) -> Self {
        self.device_key = Some(key);
        self
    }
}

impl ManifestProvider for SuitProvider {
    fn validate(
        &self,
        data: &[u8],
        min_security_ver: u32,
    ) -> Result<ValidatedFirmware, ManifestError> {
        let crypto = RustCryptoBackend::new();

        // Build validator with trust anchor and optional device key
        let mut validator = Validator::new(&self.trust_anchor, None);
        if let Some(ref dk) = self.device_key {
            validator.add_device_key(dk).map_err(|e| {
                ManifestError::ParseError(format!("invalid device key: {e:?}"))
            })?;
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

        // Determine if this has a payload (firmware update vs CRL/policy)
        let has_payload = manifest.image_digest(0).is_some();

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

            // Run the SUIT orchestrator — handles decrypt, decompress, verify
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

        // --- Map SUIT fields to ImageMeta ---
        let bank_set = manifest
            .component_id(0)
            .and_then(|segments| segments.last())
            .and_then(|seg| std::str::from_utf8(seg).ok())
            .and_then(BankSet::from_str)
            .ok_or_else(|| {
                let comp_str = manifest
                    .component_id(0)
                    .map(|segs| {
                        segs.iter()
                            .map(|s| String::from_utf8_lossy(s).to_string())
                            .collect::<Vec<_>>()
                            .join("/")
                    })
                    .unwrap_or_default();
                ManifestError::ComponentUnknown(comp_str)
            })?;

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
            image_meta: meta,
            image_data,
            version_display,
        })
    }
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
