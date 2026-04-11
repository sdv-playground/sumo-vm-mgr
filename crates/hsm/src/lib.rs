/// HSM provider trait and implementations.
///
/// Defines the management interface for Hardware Security Modules.
/// The trait covers lifecycle and provisioning — not the crypto wire
/// protocol (REGISTER, SIGN, VERIFY, etc.), which is handled by the
/// guest-facing HSM service.
///
/// Implementations:
/// - LinuxSimHsm: manages vhsm-test-ssd + file-based keystore (dev/test)
/// - QnxHsm: stub for real HSM hardware via QNX resource manager

pub mod types;
pub mod payload;
pub mod linux;
pub mod qnx;
#[cfg(feature = "crypto")]
pub mod crypto;

pub use types::*;

/// HSM management provider.
///
/// Implementors manage the HSM keystore and service lifecycle.
/// The crypto wire protocol (vsock) is handled by the underlying
/// service — this trait only covers provisioning and process management.
///
/// # Provisioning model
///
/// Key material arrives as a SUIT envelope (component `["hsm", "keys"]`).
/// - Empty HSM (factory): payload accepted without verification.
/// - Provisioned HSM: envelope verified against current keys,
///   `security_version` must exceed current.
///
/// The key material encoding inside the SUIT payload is opaque to this
/// trait — each implementation unpacks it into its own storage format.
///
/// # For QNX implementors
///
/// On QNX, the "service" is the HSM firmware itself (always running).
/// `start_service`/`stop_service` may be no-ops. Provisioning writes
/// key material to the real secure storage via the QNX resource manager.
pub trait HsmProvider: Send {
    /// Check if the keystore has been provisioned.
    fn is_provisioned(&self) -> Result<bool, HsmError>;

    /// Provision the HSM with key material from a SUIT envelope.
    ///
    /// If the HSM is empty (factory), the payload is accepted without
    /// verification — trust is physical (factory floor).
    ///
    /// If the HSM already has keys, the envelope is verified against
    /// the current key material and `security_version` must exceed
    /// the current value. This prevents rollback to old key sets.
    fn provision(&mut self, suit_envelope: &[u8]) -> Result<(), HsmError>;

    /// List keys currently in the keystore.
    fn list_keys(&self) -> Result<Vec<KeyInfo>, HsmError>;

    /// Start the HSM service so guests can connect via vsock.
    /// Returns the vsock port the service is listening on.
    fn start_service(&mut self) -> Result<u16, HsmError>;

    /// Stop the HSM service.
    fn stop_service(&mut self) -> Result<(), HsmError>;

    /// Check health/status of the HSM subsystem.
    fn status(&self) -> Result<HsmStatus, HsmError>;

    /// Retrieve a public key by role, as COSE_Key CBOR bytes.
    fn get_public_key(&self, role: KeyRole) -> Result<Vec<u8>, HsmError>;

    /// Retrieve a private key by role, as COSE_Key CBOR bytes.
    /// Only supported for simulation — production HSMs never export privates.
    fn get_private_key(&self, role: KeyRole) -> Result<Vec<u8>, HsmError> {
        let _ = role;
        Err(HsmError::NotSupported("private key export".into()))
    }

    /// Get the current provisioning lifecycle state.
    fn provisioning_state(&self) -> Result<ProvisioningState, HsmError>;
}

/// Crypto operations — keys never leave the HSM.
///
/// Guest-facing services (vhsm-ssd) delegate all crypto here.
/// On production hardware, the implementation routes to the HSM
/// firmware — private keys never leave the secure boundary.
///
/// On Linux simulation, `LinuxSimHsm` reads PEM keys from the
/// keystore and performs operations in software via RustCrypto.
pub trait HsmCryptoProvider: Send + Sync {
    /// ECDSA-SHA256 sign with EC-P256 key. Returns DER-encoded signature.
    fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// ECDSA-SHA256 verify with EC-P256 key. Returns true if valid.
    fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> Result<bool, HsmError>;

    /// AES-256-GCM encrypt. Returns `iv(12) || ciphertext || tag(16)`.
    fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// AES-256-GCM decrypt. Input is `iv(12) || ciphertext || tag(16)`.
    fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// HKDF-SHA256 derivation. AES-256 key as IKM, context as info.
    fn derive(&self, key_id: &str, context: &[u8], len: usize) -> Result<Vec<u8>, HsmError>;

    /// OS CSPRNG random bytes.
    fn random(&self, len: usize) -> Result<Vec<u8>, HsmError>;

    /// Retrieve X.509 certificate as raw DER bytes.
    fn get_certificate_der(&self, key_id: &str) -> Result<Vec<u8>, HsmError>;

    /// Retrieve public key as SubjectPublicKeyInfo DER bytes.
    fn get_public_key_der(&self, key_id: &str) -> Result<Vec<u8>, HsmError>;

    /// Get key metadata including ACL information.
    fn get_key_info(&self, key_id: &str) -> Result<KeyInfo, HsmError>;

    /// Generate a PKCS#10 CSR signed by the given key. Returns DER bytes.
    /// Used for CSR-based device provisioning — device proves possession
    /// of its private key without exposing it.
    fn generate_csr(&self, key_id: &str, subject_cn: &str) -> Result<Vec<u8>, HsmError> {
        let _ = (key_id, subject_cn);
        Err(HsmError::NotSupported("CSR generation".into()))
    }
}
