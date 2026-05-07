/// Pluggable manifest validation trait.
///
/// Default implementation: [`SuitProvider`](crate::suit_provider::SuitProvider)
/// using sumo-rs for RFC 9124 SUIT envelope validation.

use nv_store::types::BankSet;
use crate::ota::ImageMeta;

/// Manifest sub-type — determines how the payload is handled after validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestType {
    /// Normal firmware image — write to bank (vm1, vm2, hypervisor, hsm).
    Firmware,
    /// HSM key material — route to HsmProvider::provision() with raw envelope.
    HsmKeys,
}

/// Result of successful manifest validation — ready for OTA install.
#[derive(Clone)]
pub struct ValidatedFirmware {
    pub bank_set: BankSet,
    /// Manifest sub-type (firmware image vs HSM key material).
    pub manifest_type: ManifestType,
    pub image_meta: ImageMeta,
    pub image_data: Vec<u8>,
    pub version_display: String,
    /// Pre-computed image SHA-256 (set by streaming path where image is written to disk directly).
    pub image_sha256: Option<[u8; 32]>,
    /// Image size in bytes (set by streaming path).
    pub image_size: Option<u64>,
    /// Raw SUIT envelope bytes — passed through for HSM key manifests
    /// so the HSM provider can handle decrypt/decompress internally.
    pub raw_envelope: Option<Vec<u8>>,
}

#[derive(Debug)]
pub enum ManifestError {
    ParseError(String),
    SignatureInvalid(String),
    RollbackRejected { seq: u64, min: u64 },
    DigestMismatch,
    SizeMismatch { expected: u64, actual: u64 },
    ComponentUnknown(String),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestError::ParseError(e) => write!(f, "manifest parse error: {e}"),
            ManifestError::SignatureInvalid(e) => write!(f, "signature invalid: {e}"),
            ManifestError::RollbackRejected { seq, min } => {
                write!(f, "rollback rejected: sequence {seq} < minimum {min}")
            }
            ManifestError::DigestMismatch => write!(f, "image digest mismatch"),
            ManifestError::SizeMismatch { expected, actual } => {
                write!(f, "image size mismatch: expected {expected}, got {actual}")
            }
            ManifestError::ComponentUnknown(c) => write!(f, "unknown component: {c}"),
        }
    }
}

/// Trait for manifest validation. Implementors parse and validate an uploaded
/// firmware blob, returning the extracted image and metadata on success.
pub trait ManifestProvider: Send + Sync {
    fn validate(
        &self,
        data: &[u8],
        min_security_ver: u32,
    ) -> Result<ValidatedFirmware, ManifestError>;

    /// Validate envelope header only (auth + manifest, no payload processing).
    /// Used by the streaming upload path which processes the payload separately.
    /// Default implementation falls back to full `validate()`.
    fn validate_header_only(
        &self,
        data: &[u8],
        min_security_ver: u32,
    ) -> Result<ValidatedFirmware, ManifestError> {
        self.validate(data, min_security_ver)
    }

    /// Snapshot the software authority trust anchor for streaming decryptor setup.
    /// Returns owned bytes — callers may hold these across async boundaries.
    fn software_authority_key(&self) -> Option<Vec<u8>> {
        None
    }

    /// Snapshot the device decryption key for streaming decryptor setup.
    /// Returns owned bytes — callers may hold these across async boundaries.
    fn device_decryption_key(&self) -> Option<Vec<u8>> {
        None
    }

    /// Update keys from HSM after provisioning.
    fn update_keys(&self, _sw_authority: Vec<u8>, _device_key: Option<Vec<u8>>, _key_authority: Option<Vec<u8>>) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_error_display_parse_error() {
        let e = ManifestError::ParseError("bad cbor".into());
        assert_eq!(format!("{e}"), "manifest parse error: bad cbor");
    }

    #[test]
    fn manifest_error_display_signature_invalid() {
        let e = ManifestError::SignatureInvalid("bad sig".into());
        assert_eq!(format!("{e}"), "signature invalid: bad sig");
    }

    #[test]
    fn manifest_error_display_rollback_rejected() {
        let e = ManifestError::RollbackRejected { seq: 3, min: 5 };
        assert_eq!(format!("{e}"), "rollback rejected: sequence 3 < minimum 5");
    }

    #[test]
    fn manifest_error_display_digest_mismatch() {
        let e = ManifestError::DigestMismatch;
        assert_eq!(format!("{e}"), "image digest mismatch");
    }

    #[test]
    fn manifest_error_display_size_mismatch() {
        let e = ManifestError::SizeMismatch { expected: 100, actual: 50 };
        assert_eq!(format!("{e}"), "image size mismatch: expected 100, got 50");
    }

    #[test]
    fn manifest_error_display_component_unknown() {
        let e = ManifestError::ComponentUnknown("os99".into());
        assert_eq!(format!("{e}"), "unknown component: os99");
    }

    #[test]
    fn manifest_type_equality_and_copy() {
        // Ensures Copy + PartialEq derive exists — used by match branches in OTA path.
        let a = ManifestType::Firmware;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_ne!(ManifestType::Firmware, ManifestType::HsmKeys);
    }

    /// Stub provider that returns success with a minimal ValidatedFirmware to
    /// exercise the default trait methods (validate_header_only delegates,
    /// software/device key snapshots default to None, update_keys is a no-op).
    struct StubProvider;
    impl ManifestProvider for StubProvider {
        fn validate(
            &self,
            _data: &[u8],
            _min: u32,
        ) -> Result<ValidatedFirmware, ManifestError> {
            Ok(ValidatedFirmware {
                bank_set: BankSet::Vm1,
                manifest_type: ManifestType::Firmware,
                image_meta: ImageMeta::default(),
                image_data: Vec::new(),
                version_display: "1.0.0".into(),
                image_sha256: None,
                image_size: None,
                raw_envelope: None,
            })
        }
    }

    #[test]
    fn validate_header_only_default_delegates_to_validate() {
        let p = StubProvider;
        let vf = p.validate_header_only(&[], 0).unwrap();
        assert_eq!(vf.bank_set, BankSet::Vm1);
        assert_eq!(vf.version_display, "1.0.0");
    }

    #[test]
    fn key_accessors_default_to_none() {
        let p = StubProvider;
        assert!(p.software_authority_key().is_none());
        assert!(p.device_decryption_key().is_none());
    }

    #[test]
    fn update_keys_default_is_noop() {
        // Just verify it doesn't panic.
        let p = StubProvider;
        p.update_keys(vec![1, 2, 3], Some(vec![4, 5]), None);
    }
}
