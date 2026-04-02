/// Pluggable manifest validation trait.
///
/// Default implementation: [`SuitProvider`](crate::suit_provider::SuitProvider)
/// using sumo-rs for RFC 9124 SUIT envelope validation.

use nv_store::types::BankSet;
use crate::ota::ImageMeta;

/// Result of successful manifest validation — ready for OTA install.
pub struct ValidatedFirmware {
    pub bank_set: BankSet,
    pub image_meta: ImageMeta,
    pub image_data: Vec<u8>,
    pub version_display: String,
    /// Pre-computed image SHA-256 (set by streaming path where image is written to disk directly).
    pub image_sha256: Option<[u8; 32]>,
    /// Image size in bytes (set by streaming path).
    pub image_size: Option<u64>,
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

    /// Access the trust anchor bytes for streaming decryptor setup.
    fn trust_anchor(&self) -> Option<&[u8]> {
        None
    }

    /// Access the device key bytes for streaming decryptor setup.
    fn device_key(&self) -> Option<&[u8]> {
        None
    }
}
