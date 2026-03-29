/// SUIT manifest provider — validates RFC 9124 SUIT envelopes via sumo-rs.

use coset::CborSerializable;
use nv_store::types::BankSet;
use sumo_crypto::{CryptoBackend, RustCryptoBackend};
use sumo_onboard::Validator;
use sumo_onboard::decryptor::StreamingDecryptor;
use sumo_onboard::decompressor::StreamingDecompressor;

use crate::manifest_provider::{ManifestError, ManifestProvider, ValidatedFirmware};
use crate::ota::ImageMeta;

/// URI key for the integrated firmware payload inside the SUIT envelope.
const INTEGRATED_PAYLOAD_KEY: &str = "#firmware";

pub struct SuitProvider {
    trust_anchor: Vec<u8>,
    device_key: Option<Vec<u8>>,  // COSE_Key CBOR (private, for decryption)
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

        // Don't use SUIT validator's set_min_sequence for anti-rollback.
        // The SUIT sequence_number is for replay ordering; security_version
        // (custom param -257) is the anti-rollback floor, checked by ota::install.
        let validator = Validator::new(&self.trust_anchor, None);

        let manifest = validator
            .validate_envelope(data, &crypto, 0)
            .map_err(|e| match e {
                sumo_onboard::Sum2Error::AuthFailed => {
                    ManifestError::SignatureInvalid("COSE_Sign1 verification failed".into())
                }
                other => ManifestError::ParseError(format!("{other:?}")),
            })?;

        // Check security_version against floor (if manifest provides one)
        let secver = manifest.security_version(0).unwrap_or(0);
        if secver < min_security_ver as u64 {
            return Err(ManifestError::RollbackRejected {
                seq: secver,
                min: min_security_ver as u64,
            });
        }

        // Extract integrated payload — optional for floor-only manifests
        let raw_payload = manifest
            .integrated_payload(INTEGRATED_PAYLOAD_KEY)
            .map(|p| p.to_vec())
            .unwrap_or_default();

        // Decrypt + decompress if encryption_info is present
        let image_data = if !raw_payload.is_empty() && manifest.encryption_info(0).is_some() {
            let device_key_bytes = self.device_key.as_ref().ok_or_else(|| {
                ManifestError::ParseError("encrypted payload but no device key configured".into())
            })?;
            let device_coset_key = coset::CoseKey::from_slice(device_key_bytes)
                .map_err(|e| ManifestError::ParseError(format!("invalid device key: {e}")))?;

            // Decrypt (AES-GCM, CEK unwrapped via ECDH-ES+A128KW)
            let mut decryptor = StreamingDecryptor::new(&manifest, 0, &device_coset_key, &crypto)
                .map_err(|e| ManifestError::ParseError(format!("decryption init: {e:?}")))?;

            let mut buf = vec![0u8; raw_payload.len() + 256];
            let mut total = 0;
            total += decryptor.update(&raw_payload, &mut buf[total..])
                .map_err(|e| ManifestError::ParseError(format!("decryption: {e:?}")))?;
            total += decryptor.finalize(&mut buf[total..])
                .map_err(|e| ManifestError::ParseError(format!("decryption finalize: {e:?}")))?;
            let decrypted = buf[..total].to_vec();

            // Decompress (zstd)
            let mut decompressor = StreamingDecompressor::new()
                .map_err(|e| ManifestError::ParseError(format!("decompressor init: {e:?}")))?;
            let mut out = [0u8; 0];
            decompressor.update(&decrypted, &mut out)
                .map_err(|e| ManifestError::ParseError(format!("decompress: {e:?}")))?;
            decompressor.finalize_to_vec()
                .map_err(|e| ManifestError::ParseError(format!("decompress finalize: {e:?}")))?
        } else {
            raw_payload
        };

        // Verify plaintext image digest if present and image is non-empty
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
            // Also use as supplier_sw_version if not separately provided
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

        // Device-local fields — set at install time
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

fn copy_to_nv(s: &str, dst: &mut [u8]) {
    let n = s.len().min(dst.len());
    dst[..n].copy_from_slice(&s.as_bytes()[..n]);
}
