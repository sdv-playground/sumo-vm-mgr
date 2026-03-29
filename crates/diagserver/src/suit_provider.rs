/// SUIT manifest provider — validates RFC 9124 SUIT envelopes via sumo-rs.

use nv_store::types::BankSet;
use sumo_crypto::{CryptoBackend, RustCryptoBackend};
use sumo_onboard::Validator;

use crate::manifest_provider::{ManifestError, ManifestProvider, ValidatedFirmware};
use crate::ota::ImageMeta;

/// URI key for the integrated firmware payload inside the SUIT envelope.
const INTEGRATED_PAYLOAD_KEY: &str = "#firmware";

pub struct SuitProvider {
    trust_anchor: Vec<u8>,
}

impl SuitProvider {
    pub fn new(trust_anchor: Vec<u8>) -> Self {
        Self { trust_anchor }
    }
}

impl ManifestProvider for SuitProvider {
    fn validate(
        &self,
        data: &[u8],
        min_security_ver: u32,
    ) -> Result<ValidatedFirmware, ManifestError> {
        let crypto = RustCryptoBackend::new();

        let mut validator = Validator::new(&self.trust_anchor, None);
        validator.set_min_sequence(min_security_ver as u64);

        let manifest = validator
            .validate_envelope(data, &crypto, 0)
            .map_err(|e| match e {
                sumo_onboard::Sum2Error::RollbackRejected => ManifestError::RollbackRejected {
                    seq: 0,
                    min: min_security_ver as u64,
                },
                sumo_onboard::Sum2Error::AuthFailed => {
                    ManifestError::SignatureInvalid("COSE_Sign1 verification failed".into())
                }
                other => ManifestError::ParseError(format!("{other:?}")),
            })?;

        // Extract integrated payload (firmware image) — optional for floor-only manifests
        let image_data = manifest
            .integrated_payload(INTEGRATED_PAYLOAD_KEY)
            .map(|p| p.to_vec())
            .unwrap_or_default();

        // Verify image digest if present and image is non-empty
        if !image_data.is_empty() {
            if let Some((digest_info,)) = manifest.image_digest(0) {
                let actual_hash = crypto.sha256(&image_data);
                if actual_hash[..] != digest_info.bytes[..] {
                    return Err(ManifestError::DigestMismatch);
                }
            }

            if let Some(expected_size) = manifest.image_size(0) {
                if image_data.len() as u64 != expected_size {
                    return Err(ManifestError::SizeMismatch {
                        expected: expected_size,
                        actual: image_data.len() as u64,
                    });
                }
            }
        }

        // Map component_id to BankSet
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

        // --- Map SUIT fields to ImageMeta ---
        let seq = manifest.sequence_number();
        let seq_u32 = if seq > u32::MAX as u64 { u32::MAX } else { seq as u32 };

        let mut meta = ImageMeta::default();
        meta.fw_seq = seq_u32;

        // Security version from custom parameter -257, defaults to 0 if absent.
        // When 0, commit won't advance the anti-rollback floor — enabling A/B testing.
        let secver = manifest.security_version(0).unwrap_or(0);
        meta.fw_secver = if secver > u32::MAX as u64 { u32::MAX } else { secver as u32 };

        // Feature version from text field (human-readable display)
        let version_display = manifest
            .text_version(0)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("seq-{seq}"));
        copy_to_nv(&version_display, &mut meta.fw_version);

        // Map SUIT text fields to UDS DID identity fields
        if let Some(s) = manifest.text_vendor_name(0) {
            copy_to_nv(s, &mut meta.supplier_sw_number);
        }
        if let Some(s) = manifest.text_model_name(0) {
            copy_to_nv(s, &mut meta.system_name);
        }
        if let Some(s) = manifest.text_model_info(0) {
            copy_to_nv(s, &mut meta.ecu_sw_number);
        }

        Ok(ValidatedFirmware {
            bank_set,
            image_meta: meta,
            image_data,
            version_display,
        })
    }
}

fn copy_to_nv(s: &str, dst: &mut [u8]) {
    let n = s.len().min(dst.len());
    dst[..n].copy_from_slice(&s.as_bytes()[..n]);
}
