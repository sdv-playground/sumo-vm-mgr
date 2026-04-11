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
#[repr(u8)]
pub enum KeyRole {
    /// Slot 0: KEK (EC-P256) — encrypts future provisioning envelopes.
    Kek = 0,
    /// Slot 1: Software authority (EC-P256 public) — verifies firmware SUIT.
    /// Replaces file-based trust anchor once HSM is provisioned.
    SoftwareAuthority = 1,
    /// Slot 2: Device decryption key (EC-P256 ECDH) — decrypts firmware.
    /// Replaces file-based device.key once HSM is provisioned.
    DeviceDecryption = 2,
    /// Slot 3: ECU signing key (EC-P256) with certificate.
    EcuSigning = 3,
}

impl KeyRole {
    pub fn slot_index(self) -> usize {
        self as usize
    }

    pub fn key_id(self) -> &'static str {
        match self {
            KeyRole::Kek => "kek",
            KeyRole::SoftwareAuthority => "sw-authority",
            KeyRole::DeviceDecryption => "device-decrypt",
            KeyRole::EcuSigning => "ecu-signing",
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
    pub vsock_port: u16,
}
