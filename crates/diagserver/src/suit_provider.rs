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
    /// Create a new provider with a trust anchor (COSE_Key public key, CBOR bytes).
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

        // Build validator with trust anchor and anti-rollback floor
        let mut validator = Validator::new(&self.trust_anchor, None);
        validator.set_min_sequence(min_security_ver as u64);

        // Validate envelope: checks signature, digest, sequence number
        let manifest = validator
            .validate_envelope(data, &crypto, 0)
            .map_err(|e| match e {
                sumo_onboard::Sum2Error::RollbackRejected => ManifestError::RollbackRejected {
                    seq: 0, // we don't have access to the rejected seq here
                    min: min_security_ver as u64,
                },
                sumo_onboard::Sum2Error::AuthFailed => {
                    ManifestError::SignatureInvalid("COSE_Sign1 verification failed".into())
                }
                other => ManifestError::ParseError(format!("{other:?}")),
            })?;

        // Extract integrated payload (firmware image)
        let image_data = manifest
            .integrated_payload(INTEGRATED_PAYLOAD_KEY)
            .ok_or_else(|| {
                ManifestError::ParseError(format!(
                    "no integrated payload at key \"{INTEGRATED_PAYLOAD_KEY}\""
                ))
            })?
            .to_vec();

        // Verify image digest if present
        if let Some((digest_info,)) = manifest.image_digest(0) {
            let actual_hash = crypto.sha256(&image_data);
            if actual_hash[..] != digest_info.bytes[..] {
                return Err(ManifestError::DigestMismatch);
            }
        }

        // Verify image size if present
        if let Some(expected_size) = manifest.image_size(0) {
            let actual_size = image_data.len() as u64;
            if actual_size != expected_size {
                return Err(ManifestError::SizeMismatch {
                    expected: expected_size,
                    actual: actual_size,
                });
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

        // Map SUIT fields to ImageMeta
        let seq = manifest.sequence_number();
        let seq_u32 = if seq > u32::MAX as u64 { u32::MAX } else { seq as u32 };

        let mut meta = ImageMeta::default();
        meta.fw_seq = seq_u32;
        meta.fw_secver = seq_u32;

        // Use sequence number as version display, or text version if available
        let version_display = manifest
            .text_version(0)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("seq-{seq}"));

        let ver_bytes = version_display.as_bytes();
        let n = ver_bytes.len().min(meta.fw_version.len());
        meta.fw_version[..n].copy_from_slice(&ver_bytes[..n]);

        Ok(ValidatedFirmware {
            bank_set,
            image_meta: meta,
            image_data,
            version_display,
        })
    }
}
