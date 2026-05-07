/// HSM error types.
#[derive(Debug)]
pub enum HsmError {
    NotProvisioned,
    AlreadyProvisioned,
    NotRunning,
    AlreadyRunning,
    KeystoreError(String),
    ProcessError(String),
    ConfigError(String),
    EnvelopeInvalid(String),
    PayloadInvalid(String),
    DecryptionFailed(String),
    RollbackRejected { current: u64, attempted: u64 },
    NotSupported(String),
    CryptoError(String),
    KeyNotFound(String),
}

impl std::fmt::Display for HsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HsmError::NotProvisioned => write!(f, "HSM not provisioned"),
            HsmError::AlreadyProvisioned => write!(f, "HSM already provisioned"),
            HsmError::NotRunning => write!(f, "HSM service not running"),
            HsmError::AlreadyRunning => write!(f, "HSM service already running"),
            HsmError::KeystoreError(s) => write!(f, "keystore error: {s}"),
            HsmError::ProcessError(s) => write!(f, "process error: {s}"),
            HsmError::ConfigError(s) => write!(f, "config error: {s}"),
            HsmError::EnvelopeInvalid(s) => write!(f, "invalid SUIT envelope: {s}"),
            HsmError::PayloadInvalid(s) => write!(f, "invalid key material payload: {s}"),
            HsmError::DecryptionFailed(s) => write!(f, "decryption failed: {s}"),
            HsmError::RollbackRejected { current, attempted } => {
                write!(f, "rollback rejected: security_version {attempted} <= current {current}")
            }
            HsmError::NotSupported(s) => write!(f, "not supported: {s}"),
            HsmError::CryptoError(s) => write!(f, "crypto error: {s}"),
            HsmError::KeyNotFound(s) => write!(f, "key not found: {s}"),
        }
    }
}

impl std::error::Error for HsmError {}

/// Well-known HSM key slot roles.
///
/// These define the standard slot indices for keys used by the SOVD
/// update pipeline. Slots beyond these are application keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyRole {
    /// Software authority (EC-P256 public) — verifies firmware SUIT envelopes.
    SoftwareAuthority,
    /// Device decryption key (EC-P256 ECDH) — decrypts all encrypted content.
    DeviceDecryption,
    /// ECU signing key (EC-P256) with certificate.
    EcuSigning,
    /// Key authority (EC-P256 public) — verifies future HSM key envelopes.
    /// After first provisioning, replaces the factory signing key as trust anchor.
    KeyAuthority,
}

impl KeyRole {
    pub fn key_id(self) -> &'static str {
        match self {
            KeyRole::SoftwareAuthority => "sw-authority",
            KeyRole::DeviceDecryption => "device-decrypt",
            KeyRole::EcuSigning => "ecu-signing",
            KeyRole::KeyAuthority => "key-authority",
        }
    }
}

/// Key type supported by the HSM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    EcP256,
    Aes256,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::EcP256 => write!(f, "EC-P256"),
            KeyType::Aes256 => write!(f, "AES-256"),
        }
    }
}

/// Information about a key in the keystore.
#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub key_id: String,
    pub key_type: KeyType,
    pub has_certificate: bool,
    /// Guest IDs allowed to use this key. None = all guests.
    pub allowed_guests: Option<Vec<String>>,
    /// Operations allowed on this key. None = all ops.
    pub allowed_ops: Option<Vec<String>>,
}

/// Provisioning lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisioningState {
    /// Device key exists but no key bundle provisioned yet.
    /// CSR endpoint is available.
    Unprovisioned,
    /// Key bundle installed, all well-known handles populated.
    /// CSR endpoint returns 403.
    Provisioned,
}

/// Status of the HSM subsystem.
#[derive(Debug)]
pub struct HsmStatus {
    pub provisioned: bool,
    pub service_running: bool,
    pub service_pid: Option<u32>,
    pub keystore_path: std::path::PathBuf,
    pub tcp_port: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hsm_error_display_covers_every_variant() {
        // One case per variant — catches accidental duplicate/wrong arm additions.
        assert_eq!(format!("{}", HsmError::NotProvisioned), "HSM not provisioned");
        assert_eq!(format!("{}", HsmError::AlreadyProvisioned), "HSM already provisioned");
        assert_eq!(format!("{}", HsmError::NotRunning), "HSM service not running");
        assert_eq!(format!("{}", HsmError::AlreadyRunning), "HSM service already running");
        assert_eq!(
            format!("{}", HsmError::KeystoreError("disk full".into())),
            "keystore error: disk full"
        );
        assert_eq!(
            format!("{}", HsmError::ProcessError("exited 1".into())),
            "process error: exited 1"
        );
        assert_eq!(
            format!("{}", HsmError::ConfigError("bad toml".into())),
            "config error: bad toml"
        );
        assert_eq!(
            format!("{}", HsmError::EnvelopeInvalid("no tag".into())),
            "invalid SUIT envelope: no tag"
        );
        assert_eq!(
            format!("{}", HsmError::PayloadInvalid("bad cbor".into())),
            "invalid key material payload: bad cbor"
        );
        assert_eq!(
            format!("{}", HsmError::DecryptionFailed("tag mismatch".into())),
            "decryption failed: tag mismatch"
        );
        assert_eq!(
            format!("{}", HsmError::RollbackRejected { current: 7, attempted: 3 }),
            "rollback rejected: security_version 3 <= current 7"
        );
        assert_eq!(
            format!("{}", HsmError::NotSupported("alg".into())),
            "not supported: alg"
        );
        assert_eq!(
            format!("{}", HsmError::CryptoError("sig".into())),
            "crypto error: sig"
        );
        assert_eq!(
            format!("{}", HsmError::KeyNotFound("abc".into())),
            "key not found: abc"
        );
    }

    #[test]
    fn hsm_error_is_std_error() {
        fn assert_err<E: std::error::Error>(_e: &E) {}
        assert_err(&HsmError::NotProvisioned);
    }

    #[test]
    fn keyrole_key_id_is_unique_per_role() {
        use std::collections::HashSet;
        let roles = [
            KeyRole::SoftwareAuthority,
            KeyRole::DeviceDecryption,
            KeyRole::EcuSigning,
            KeyRole::KeyAuthority,
        ];
        let ids: HashSet<_> = roles.iter().map(|r| r.key_id()).collect();
        assert_eq!(ids.len(), roles.len(), "key_id() must be unique per role");

        assert_eq!(KeyRole::SoftwareAuthority.key_id(), "sw-authority");
        assert_eq!(KeyRole::DeviceDecryption.key_id(), "device-decrypt");
        assert_eq!(KeyRole::EcuSigning.key_id(), "ecu-signing");
        assert_eq!(KeyRole::KeyAuthority.key_id(), "key-authority");
    }

    #[test]
    fn keytype_display_matches_crypto_names() {
        assert_eq!(format!("{}", KeyType::EcP256), "EC-P256");
        assert_eq!(format!("{}", KeyType::Aes256), "AES-256");
    }

    #[test]
    fn provisioning_state_equality_and_debug() {
        assert_eq!(ProvisioningState::Unprovisioned, ProvisioningState::Unprovisioned);
        assert_ne!(ProvisioningState::Unprovisioned, ProvisioningState::Provisioned);
        // Debug format is used in logs — make sure it doesn't accidentally silently change.
        assert_eq!(format!("{:?}", ProvisioningState::Provisioned), "Provisioned");
    }
}
