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
}
