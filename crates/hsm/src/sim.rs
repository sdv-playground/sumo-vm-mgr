/// Simulation HSM provider (portable: Linux + QNX).
///
/// Wraps `vhsm-ssd` / `vhsm-test-ssd` (file-based keystore + TCP service)
/// for dev/test and QNX hypervisor host deployments.
///
/// # Provisioning
///
/// Key material arrives as a SUIT envelope (component `["hsm", "keys"]`).
/// The payload is CBOR-encoded `HsmKeystore` (see `payload.rs`).
///
/// - **Factory** (empty HSM): envelope signed with factory signing key,
///   encrypted to device public key. Verified with built-in factory key.
/// - **Re-provision** (has keys): envelope signed with Key Authority,
///   encrypted to device public key. `security_version` must exceed current.
///
/// # Keystore layout (written by provision)
///
/// ```text
/// <keystore_path>/
///   manifest             — key inventory (vhsm-test-ssd line format)
///   identities           — guest-id → pubkey mapping
///   provision_state       — security_version
///   keys/
///     {key_id}.priv      — EC P-256 private key (PEM)
///     {key_id}.pub       — EC P-256 public key (PEM)
///     {key_id}.cert      — X.509 certificate (PEM, optional)
///     {key_id}.bin       — AES-256 raw key (32 bytes)
/// ```

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use crate::payload::{self, HsmKeystore, KeySlotDef, KEY_TYPE_AES_256, KEY_TYPE_EC_P256};
use crate::{HsmError, HsmProvider, HsmStatus, KeyInfo, KeyRole, KeyType, ProvisioningState};

pub struct SimHsm {
    /// Path to `vhsm-test-ssd` binary.
    daemon_bin: PathBuf,
    /// Keystore directory (e.g. /tmp/vhsm-keys).
    keystore_path: PathBuf,
    /// TCP port the daemon listens on (always bound to 127.0.0.1 in test mode).
    tcp_port: u16,
    /// Running daemon process handle.
    child: Option<Child>,
}

impl SimHsm {
    pub fn new(
        daemon_bin: PathBuf,
        keystore_path: PathBuf,
        tcp_port: u16,
    ) -> Self {
        Self {
            daemon_bin,
            keystore_path,
            tcp_port,
            child: None,
        }
    }

    /// Factory signing public key as COSE_Key CBOR — the built-in provisioning authority.
    fn factory_provisioning_authority() -> Vec<u8> {
        use coset::CborSerializable;
        let pub_key = &payload::FACTORY_SIGNING_PUBLIC;
        let x = &pub_key[1..33];
        let y = &pub_key[33..65];
        coset::CoseKeyBuilder::new_ec2_pub_key(
            coset::iana::EllipticCurve::P_256,
            x.to_vec(),
            y.to_vec(),
        )
        .algorithm(coset::iana::Algorithm::ES256)
        .build()
        .to_vec()
        .expect("COSE_Key serialization")
    }

    /// Path to the manifest file inside the keystore.
    pub(crate) fn manifest_path(&self) -> PathBuf {
        self.keystore_path.join("manifest")
    }

    /// Path to the provision state file.
    fn state_path(&self) -> PathBuf {
        self.keystore_path.join("provision_state")
    }

    /// Keys subdirectory.
    pub(crate) fn keys_dir(&self) -> PathBuf {
        self.keystore_path.join("keys")
    }

    /// Ensure the device key pair exists. Called on first use.
    /// Generates EC-P256 key pair if `keys/device-decrypt.priv` does not exist.
    /// This runs regardless of provisioning state — the device key exists before
    /// any key bundle is installed.
    #[cfg(feature = "crypto")]
    pub fn ensure_device_key(&self) -> Result<(), HsmError> {
        let priv_path = self.keys_dir().join("device-decrypt.priv");
        if priv_path.exists() {
            return Ok(());
        }

        // Create keys directory if needed
        std::fs::create_dir_all(self.keys_dir())
            .map_err(|e| HsmError::KeystoreError(format!("create keys dir: {e}")))?;

        // Generate EC-P256 key pair
        let sk = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let scalar = sk.to_bytes();
        let pk = sk.verifying_key().to_encoded_point(false);

        write_pem_ec_private(&priv_path, &scalar)
            .map_err(|e| HsmError::KeystoreError(format!("write device key: {e}")))?;

        let pub_path = self.keys_dir().join("device-decrypt.pub");
        write_pem_ec_public(&pub_path, pk.as_bytes())
            .map_err(|e| HsmError::KeystoreError(format!("write device pubkey: {e}")))?;

        tracing::info!("device key pair generated (first boot)");
        Ok(())
    }

    /// Load the current security_version from provision_state.
    fn load_security_version(&self) -> Result<u64, HsmError> {
        let path = self.state_path();
        if !path.exists() {
            return Ok(0);
        }
        let content = std::fs::read_to_string(&path)
            .map_err(|e| HsmError::KeystoreError(format!("read provision_state: {e}")))?;
        // First line is security_version
        content
            .lines()
            .next()
            .and_then(|line| line.trim().parse().ok())
            .ok_or_else(|| HsmError::KeystoreError("corrupt provision_state".into()))
    }

    fn save_state(&self, security_version: u64) -> Result<(), HsmError> {
        std::fs::write(self.state_path(), security_version.to_string().as_bytes())
            .map_err(|e| HsmError::KeystoreError(format!("write provision_state: {e}")))?;
        Ok(())
    }

    /// Write the keystore files from a parsed CBOR payload.
    pub fn write_keystore(&self, ks: &HsmKeystore) -> Result<(), HsmError> {
        let keys_dir = self.keys_dir();
        std::fs::create_dir_all(&keys_dir)
            .map_err(|e| HsmError::KeystoreError(format!("create keys dir: {e}")))?;

        // Write key files
        for slot in &ks.slots {
            self.write_key_files(slot, &keys_dir)?;
        }

        // Write manifest (vhsm-test-ssd format)
        self.write_manifest(&ks.slots)?;

        // Write identities
        self.write_identities(ks)?;

        self.save_state(ks.security_version)?;

        Ok(())
    }

    /// Write key material files for a single slot.
    fn write_key_files(&self, slot: &KeySlotDef, keys_dir: &Path) -> Result<(), HsmError> {
        match slot.key_type {
            KEY_TYPE_EC_P256 => {
                let priv_path = keys_dir.join(format!("{}.priv", slot.key_id));
                match &slot.private_key {
                    None => {
                        // Public-key-only trust anchor (key-authority, sw-authority).
                        // No private key to write — device only needs public half.
                        tracing::debug!(key_id = %slot.key_id, "public-key-only slot, no private key");
                    }
                    Some(pk) if pk.is_empty() => {
                        // CSR-based provisioning: device already generated this key.
                        if !priv_path.exists() {
                            return Err(HsmError::KeystoreError(format!(
                                "key bundle has empty private_key for '{}' but no local key exists",
                                slot.key_id
                            )));
                        }
                        tracing::debug!(key_id = %slot.key_id, "preserving locally-generated private key");
                    }
                    Some(pk) => {
                        write_pem_ec_private(&priv_path, pk)?;
                    }
                }

                // Write public key if available
                if let Some(ref pub_key) = slot.public_key {
                    let pub_path = keys_dir.join(format!("{}.pub", slot.key_id));
                    write_pem_ec_public(&pub_path, pub_key)?;
                }

                // Write certificate if available
                if let Some(ref cert) = slot.certificate {
                    let cert_path = keys_dir.join(format!("{}.cert", slot.key_id));
                    write_pem_certificate(&cert_path, cert)?;
                }
            }
            KEY_TYPE_AES_256 => {
                if let Some(ref key_data) = slot.private_key {
                    let path = keys_dir.join(format!("{}.bin", slot.key_id));
                    std::fs::write(&path, key_data)
                        .map_err(|e| HsmError::KeystoreError(format!("write {}: {e}", path.display())))?;
                }
            }
            other => {
                tracing::warn!(key_id = %slot.key_id, key_type = other, "unknown key type, skipping");
            }
        }
        Ok(())
    }

    /// Generate the vhsm-test-ssd manifest file.
    ///
    /// Format: `key_id type key_path cert_path [allowed_guests=...] [allowed_ops=...]`
    fn write_manifest(&self, slots: &[KeySlotDef]) -> Result<(), HsmError> {
        let mut f = std::fs::File::create(self.manifest_path())
            .map_err(|e| HsmError::KeystoreError(format!("create manifest: {e}")))?;

        for slot in slots {
            let type_str = match slot.key_type {
                KEY_TYPE_EC_P256 => "EC-P256",
                KEY_TYPE_AES_256 => "AES-256",
                _ => continue,
            };

            let key_path = match slot.key_type {
                KEY_TYPE_EC_P256 => format!("keys/{}.priv", slot.key_id),
                KEY_TYPE_AES_256 => format!("keys/{}.bin", slot.key_id),
                _ => continue,
            };

            let cert_path = if slot.certificate.is_some() {
                format!("keys/{}.cert", slot.key_id)
            } else {
                "-".to_string()
            };

            write!(f, "{} {} {} {}", slot.key_id, type_str, key_path, cert_path)
                .map_err(|e| HsmError::KeystoreError(format!("write manifest: {e}")))?;

            if let Some(ref guests) = slot.allowed_guests {
                write!(f, " allowed_guests={}", guests.join(","))
                    .map_err(|e| HsmError::KeystoreError(format!("write manifest: {e}")))?;
            }

            if let Some(ops) = slot.ops_as_strings() {
                write!(f, " allowed_ops={}", ops.join(","))
                    .map_err(|e| HsmError::KeystoreError(format!("write manifest: {e}")))?;
            }

            writeln!(f)
                .map_err(|e| HsmError::KeystoreError(format!("write manifest: {e}")))?;
        }

        Ok(())
    }

    /// Write the identities file for guest registration.
    fn write_identities(&self, ks: &HsmKeystore) -> Result<(), HsmError> {
        let path = self.keystore_path.join("identities");
        let mut f = std::fs::File::create(&path)
            .map_err(|e| HsmError::KeystoreError(format!("create identities: {e}")))?;

        for id in &ks.identities {
            // Write identity public key as PEM file
            let pub_path = self.keys_dir().join(format!("{}.pub", id.identity_id));
            write_pem_ec_public(&pub_path, &id.public_key)?;

            writeln!(f, "{} keys/{}.pub", id.identity_id, id.identity_id)
                .map_err(|e| HsmError::KeystoreError(format!("write identities: {e}")))?;
        }

        Ok(())
    }

    /// Parse the manifest file to extract key information.
    pub(crate) fn parse_manifest(&self) -> Result<Vec<KeyInfo>, HsmError> {
        let manifest = std::fs::read_to_string(self.manifest_path())
            .map_err(|e| HsmError::KeystoreError(format!("read manifest: {e}")))?;

        let mut keys = Vec::new();
        for line in manifest.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            let key_type = match parts[1] {
                "EC-P256" => KeyType::EcP256,
                "AES-256" => KeyType::Aes256,
                other => {
                    tracing::warn!(key_type = other, "unknown key type in manifest, skipping");
                    continue;
                }
            };
            let has_certificate = parts[3] != "-";

            // Parse optional ACL fields (index 4+)
            let mut allowed_guests = None;
            let mut allowed_ops = None;
            for part in parts.iter().skip(4) {
                if let Some(guests) = part.strip_prefix("allowed_guests=") {
                    allowed_guests = Some(
                        guests.split(',').map(|s| s.to_string()).collect(),
                    );
                } else if let Some(ops) = part.strip_prefix("allowed_ops=") {
                    allowed_ops = Some(
                        ops.split(',').map(|s| s.to_string()).collect(),
                    );
                }
            }

            keys.push(KeyInfo {
                key_id: parts[0].to_string(),
                key_type,
                has_certificate,
                allowed_guests,
                allowed_ops,
            });
        }
        Ok(keys)
    }

    /// Check if the daemon process is still alive.
    fn is_running(&mut self) -> bool {
        let Some(child) = self.child.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(Some(_)) => {
                self.child = None;
                false
            }
            Ok(None) => true,
            Err(_) => false,
        }
    }

    /// Extract the CBOR payload from a SUIT envelope.
    ///
    /// All envelopes are encrypted to the device decryption key (slot 2).
    /// Signature is verified against the provisioning authority (factory signing
    /// key on first provision, key authority from HSM on subsequent ones).
    #[cfg(feature = "suit")]
    fn extract_payload(
        &self,
        envelope_bytes: &[u8],
        is_factory: bool,
    ) -> Result<(Vec<u8>, u64), HsmError> {
        use sumo_crypto::RustCryptoBackend;
        use sumo_onboard::decryptor::StreamingDecryptor;
        use sumo_onboard::validator::Validator;

        let crypto = RustCryptoBackend::new();

        // Select trust anchor: factory signing key for first provision,
        // key authority from HSM for subsequent ones.
        let trust_anchor = if is_factory {
            Self::factory_provisioning_authority()
        } else {
            self.get_public_key(KeyRole::KeyAuthority)
                .unwrap_or_else(|_| Self::factory_provisioning_authority())
        };

        let mut validator = Validator::new(&trust_anchor, None);
        if !is_factory {
            let current_sv = self.load_security_version()?;
            validator.set_min_sequence(current_sv);
        }

        let manifest = validator
            .validate_envelope(envelope_bytes, &crypto, 0)
            .map_err(|e| HsmError::EnvelopeInvalid(format!("{e:?}")))?;

        // Verify component ID is ["hsm", "keys"]
        if let Some(cid) = manifest.component_id(0) {
            if cid.len() != 2
                || cid[0].as_slice() != b"hsm"
                || cid[1].as_slice() != b"keys"
            {
                return Err(HsmError::EnvelopeInvalid(
                    "unexpected component_id (expected [\"hsm\", \"keys\"])".into(),
                ));
            }
        }

        let security_version = manifest.security_version(0).unwrap_or(0);

        // Anti-rollback check for re-provision
        if !is_factory {
            let current = self.load_security_version()?;
            if security_version <= current {
                return Err(HsmError::RollbackRejected {
                    current,
                    attempted: security_version,
                });
            }
        }

        // Decrypt with device key (slot 2) — always the same key
        let device_key = self.load_device_decrypt_key()?;

        let ciphertext = manifest
            .integrated_payload("#hsm-keys")
            .ok_or_else(|| {
                HsmError::EnvelopeInvalid("missing integrated payload #hsm-keys".into())
            })?;

        let mut decryptor = StreamingDecryptor::new(&manifest, 0, &device_key, &crypto)
            .map_err(|e| HsmError::DecryptionFailed(format!("{e:?}")))?;

        let mut plaintext = vec![0u8; ciphertext.len() + 256];
        let mut total = 0;
        let n = decryptor
            .update(ciphertext, &mut plaintext)
            .map_err(|e| HsmError::DecryptionFailed(format!("update: {e:?}")))?;
        total += n;
        let n = decryptor
            .finalize(&mut plaintext[total..])
            .map_err(|e| HsmError::DecryptionFailed(format!("finalize: {e:?}")))?;
        total += n;
        plaintext.truncate(total);

        // Decompress if zstd-compressed (detect magic bytes)
        let payload = if plaintext.len() >= 4 && &plaintext[..4] == &[0x28, 0xB5, 0x2F, 0xFD] {
            decompress_zstd(&plaintext)?
        } else {
            plaintext
        };

        Ok((payload, security_version))
    }

    /// Load the device decryption private key as a coset::CoseKey (ECDH).
    #[cfg(feature = "suit")]
    fn load_device_decrypt_key(&self) -> Result<coset::CoseKey, HsmError> {
        let priv_path = self.keys_dir().join("device-decrypt.priv");
        let pem = std::fs::read_to_string(&priv_path)
            .map_err(|e| HsmError::KeystoreError(format!("read device key: {e}")))?;
        let scalar = extract_ec_scalar_from_pem(&pem)?;

        let pub_path = self.keys_dir().join("device-decrypt.pub");
        let pub_pem = std::fs::read_to_string(&pub_path)
            .map_err(|e| HsmError::KeystoreError(format!("read device pubkey: {e}")))?;
        let (x, y) = extract_ec_public_from_pem(&pub_pem)?;

        let mut key = coset::CoseKeyBuilder::new_ec2_priv_key(
            coset::iana::EllipticCurve::P_256,
            x.to_vec(),
            y.to_vec(),
            scalar.to_vec(),
        )
        .build();
        key.alg = None;
        Ok(key)
    }

    /// Fallback for builds without SUIT support — just parse raw CBOR.
    #[cfg(not(feature = "suit"))]
    fn extract_payload(
        &self,
        envelope_bytes: &[u8],
        _is_factory: bool,
    ) -> Result<(Vec<u8>, u64), HsmError> {
        let ks = payload::decode(envelope_bytes)
            .map_err(|e| HsmError::PayloadInvalid(e))?;
        let sv = ks.security_version;
        Ok((envelope_bytes.to_vec(), sv))
    }
}

impl HsmProvider for SimHsm {
    fn is_provisioned(&self) -> Result<bool, HsmError> {
        Ok(self.manifest_path().exists())
    }

    fn provision(&mut self, suit_envelope: &[u8]) -> Result<(), HsmError> {
        let is_factory = !self.is_provisioned()?;

        // Extract and validate the CBOR payload from the SUIT envelope
        let (cbor_payload, _security_version) =
            self.extract_payload(suit_envelope, is_factory)?;

        // Parse the key material
        let keystore = payload::decode(&cbor_payload)
            .map_err(|e| HsmError::PayloadInvalid(e))?;

        tracing::info!(
            slots = keystore.slots.len(),
            identities = keystore.identities.len(),
            security_version = keystore.security_version,
            factory = is_factory,
            "provisioning HSM keystore"
        );

        // For re-provision: write to temp dir, then swap atomically
        if !is_factory {
            let tmp_dir = self.keystore_path.with_extension("tmp");
            let orig_path = self.keystore_path.clone();

            // Temporarily point at the temp dir for writing
            self.keystore_path = tmp_dir.clone();
            let result = self.write_keystore(&keystore);
            self.keystore_path = orig_path.clone();

            result?;

            // Atomic swap: rename old → .bak, new → current
            let bak = orig_path.with_extension("bak");
            let _ = std::fs::remove_dir_all(&bak);
            std::fs::rename(&orig_path, &bak)
                .map_err(|e| HsmError::KeystoreError(format!("backup old keystore: {e}")))?;
            std::fs::rename(&tmp_dir, &orig_path)
                .map_err(|e| HsmError::KeystoreError(format!("swap keystore: {e}")))?;
            let _ = std::fs::remove_dir_all(&bak);
        } else {
            self.write_keystore(&keystore)?;
        }

        tracing::info!("HSM keystore provisioned");
        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<KeyInfo>, HsmError> {
        if !self.is_provisioned()? {
            return Err(HsmError::NotProvisioned);
        }
        self.parse_manifest()
    }

    fn start_service(&mut self) -> Result<u16, HsmError> {
        if self.is_running() {
            return Err(HsmError::AlreadyRunning);
        }

        if !self.is_provisioned()? {
            return Err(HsmError::NotProvisioned);
        }

        tracing::info!(
            bin = %self.daemon_bin.display(),
            keystore = %self.keystore_path.display(),
            port = self.tcp_port,
            "starting vhsm-test-ssd"
        );

        // Test mode: bind 127.0.0.1, allow that source IP as a generic
        // test VM identity. Production uses a policy file via --policy.
        let listen = format!("127.0.0.1:{}", self.tcp_port);
        let child = Command::new(&self.daemon_bin)
            .arg("--keystore")
            .arg(&self.keystore_path)
            .arg("--listen")
            .arg(&listen)
            .arg("--allow-ip")
            .arg("127.0.0.1=test-vm")
            .spawn()
            .map_err(|e| HsmError::ProcessError(format!("spawn vhsm-test-ssd: {e}")))?;

        let pid = child.id();
        self.child = Some(child);

        // Brief wait + liveness check
        std::thread::sleep(std::time::Duration::from_millis(500));
        if !self.is_running() {
            return Err(HsmError::ProcessError(
                "vhsm-test-ssd exited immediately".into(),
            ));
        }

        tracing::info!(pid, port = self.tcp_port, "vhsm-test-ssd started");
        Ok(self.tcp_port)
    }

    fn stop_service(&mut self) -> Result<(), HsmError> {
        let Some(mut child) = self.child.take() else {
            return Err(HsmError::NotRunning);
        };

        let pid = child.id();
        tracing::info!(pid, "stopping vhsm-test-ssd");

        #[cfg(unix)]
        {
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
        }

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    tracing::info!(pid, "vhsm-test-ssd stopped");
                    return Ok(());
                }
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                _ => break,
            }
        }

        tracing::warn!(pid, "vhsm-test-ssd did not exit, sending SIGKILL");
        let _ = child.kill();
        let _ = child.wait();
        Ok(())
    }

    fn status(&self) -> Result<HsmStatus, HsmError> {
        let provisioned = self.manifest_path().exists();

        let (service_running, service_pid) = if let Some(child) = &self.child {
            let pid = child.id();
            let alive = unsafe { libc::kill(pid as i32, 0) == 0 };
            (alive, Some(pid))
        } else {
            (false, None)
        };

        Ok(HsmStatus {
            provisioned,
            service_running,
            service_pid,
            keystore_path: self.keystore_path.clone(),
            tcp_port: self.tcp_port,
        })
    }

    fn get_public_key(&self, role: KeyRole) -> Result<Vec<u8>, HsmError> {
        if !self.is_provisioned()? {
            return Err(HsmError::NotProvisioned);
        }
        let pub_path = self.keys_dir().join(format!("{}.pub", role.key_id()));
        if !pub_path.exists() {
            return Err(HsmError::KeystoreError(format!(
                "no public key for role {:?} at {}",
                role,
                pub_path.display()
            )));
        }
        let pem = std::fs::read_to_string(&pub_path)
            .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", pub_path.display())))?;
        let (x, y) = extract_ec_public_from_pem(&pem)?;

        // Signing verification keys need alg=ES256; ECDH keys have no algorithm.
        let alg = match role {
            KeyRole::SoftwareAuthority | KeyRole::EcuSigning | KeyRole::KeyAuthority => {
                Some(coset::iana::Algorithm::ES256)
            }
            KeyRole::DeviceDecryption => None,
        };
        Ok(build_public_cose_key_with_alg(&x, &y, alg))
    }

    fn get_private_key(&self, role: KeyRole) -> Result<Vec<u8>, HsmError> {
        if !self.is_provisioned()? {
            return Err(HsmError::NotProvisioned);
        }
        let priv_path = self.keys_dir().join(format!("{}.priv", role.key_id()));
        let pub_path = self.keys_dir().join(format!("{}.pub", role.key_id()));
        if !priv_path.exists() {
            return Err(HsmError::KeystoreError(format!(
                "no private key for role {:?} at {}",
                role,
                priv_path.display()
            )));
        }
        let priv_pem = std::fs::read_to_string(&priv_path)
            .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", priv_path.display())))?;
        let scalar = extract_ec_scalar_from_pem(&priv_pem)?;

        let pub_pem = std::fs::read_to_string(&pub_path)
            .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", pub_path.display())))?;
        let (x, y) = extract_ec_public_from_pem(&pub_pem)?;

        Ok(build_private_cose_key(&scalar, &x, &y))
    }

    fn provisioning_state(&self) -> Result<ProvisioningState, HsmError> {
        if self.manifest_path().exists() {
            Ok(ProvisioningState::Provisioned)
        } else {
            Ok(ProvisioningState::Unprovisioned)
        }
    }
}

impl Drop for SimHsm {
    fn drop(&mut self) {
        if self.is_running() {
            if let Err(e) = self.stop_service() {
                tracing::warn!("failed to stop vhsm-test-ssd on drop: {e}");
            }
        }
    }
}

// --- Zstd decompression ---

/// Decompress a zstd-compressed payload.
#[cfg(feature = "suit")]
fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>, HsmError> {
    use sumo_onboard::decompressor::StreamingDecompressor;

    let mut dec = StreamingDecompressor::new()
        .map_err(|e| HsmError::PayloadInvalid(format!("zstd init: {e:?}")))?;

    let mut sink = vec![0u8; 0]; // not used by update (it accumulates internally)
    dec.update(data, &mut sink)
        .map_err(|e| HsmError::PayloadInvalid(format!("zstd update: {e:?}")))?;

    dec.finalize_to_vec()
        .map_err(|e| HsmError::PayloadInvalid(format!("zstd finalize: {e:?}")))
}

// --- PEM decoding helpers ---

/// Extract the raw 32-byte EC-P256 scalar from a SEC1 PEM private key.
pub(crate) fn extract_ec_scalar_from_pem(pem: &str) -> Result<Vec<u8>, HsmError> {
    let der = decode_pem(pem, "EC PRIVATE KEY")?;

    // SEC1 ECPrivateKey: SEQUENCE { INTEGER(1), OCTET STRING(scalar), ... }
    // Skip: 0x30 len 0x02 0x01 0x01 0x04 0x20 → scalar at offset 7
    if der.len() < 39 || der[0] != 0x30 || der[5] != 0x04 || der[6] != 0x20 {
        return Err(HsmError::KeystoreError(
            "unexpected SEC1 ECPrivateKey format".into(),
        ));
    }
    Ok(der[7..39].to_vec())
}

/// Extract (x, y) coordinates from a SubjectPublicKeyInfo PEM public key.
/// Returns (32-byte x, 32-byte y).
pub(crate) fn extract_ec_public_from_pem(pem: &str) -> Result<(Vec<u8>, Vec<u8>), HsmError> {
    let der = decode_pem(pem, "PUBLIC KEY")?;

    // SPKI: SEQUENCE { SEQUENCE { OID, OID }, BIT STRING { 0x00, 0x04, x, y } }
    // The uncompressed point (0x04 || x || y) is at the end of the DER.
    // Find it by scanning for the BIT STRING content.
    if der.len() < 91 {
        return Err(HsmError::KeystoreError(
            "SPKI too short for EC P-256".into(),
        ));
    }

    // The uncompressed point starts at offset 26 (after AlgId + BIT STRING header + 0x00 pad)
    // 0x30 0x59 | 0x30 0x13 ... (19 bytes algid) | 0x03 0x42 0x00 0x04 x(32) y(32)
    let point_start = der.len() - 65;
    if der[point_start] != 0x04 {
        return Err(HsmError::KeystoreError(
            "expected uncompressed EC point (0x04 prefix)".into(),
        ));
    }

    let x = der[point_start + 1..point_start + 33].to_vec();
    let y = der[point_start + 33..point_start + 65].to_vec();
    Ok((x, y))
}

/// Decode a PEM block with the given label, returning raw DER bytes.
pub(crate) fn decode_pem(pem: &str, expected_label: &str) -> Result<Vec<u8>, HsmError> {
    let begin = format!("-----BEGIN {expected_label}-----");
    let end = format!("-----END {expected_label}-----");

    let start = pem
        .find(&begin)
        .ok_or_else(|| HsmError::KeystoreError(format!("missing PEM header: {begin}")))?;
    let after_header = start + begin.len();

    let end_pos = pem[after_header..]
        .find(&end)
        .ok_or_else(|| HsmError::KeystoreError(format!("missing PEM footer: {end}")))?;

    let b64: String = pem[after_header..after_header + end_pos]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    base64_decode(&b64)
        .map_err(|e| HsmError::KeystoreError(format!("base64 decode: {e}")))
}

/// Simple base64 decoder.
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    const DECODE: [u8; 128] = {
        let mut t = [0xFFu8; 128];
        let mut i = 0u8;
        while i < 26 {
            t[(b'A' + i) as usize] = i;
            t[(b'a' + i) as usize] = i + 26;
            i += 1;
        }
        let mut d = 0u8;
        while d < 10 {
            t[(b'0' + d) as usize] = d + 52;
            d += 1;
        }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    };

    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;

    for &b in bytes {
        if b == b'=' {
            break;
        }
        if b >= 128 || DECODE[b as usize] == 0xFF {
            return Err(format!("invalid base64 char: {}", b as char));
        }
        buf = (buf << 6) | DECODE[b as usize] as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

// --- PEM encoding helpers ---
//
// vhsm-test-ssd reads PEM files via OpenSSL. We convert raw key bytes
// from the CBOR payload into PEM format on disk.

/// Write an EC P-256 private key as PEM (SEC1 / RFC 5915).
///
/// The raw 32-byte scalar is wrapped in the ASN.1 ECPrivateKey structure
/// with the P-256 OID, then base64-encoded as PEM.
pub(crate) fn write_pem_ec_private(path: &Path, scalar: &[u8]) -> Result<(), HsmError> {
    if scalar.len() != 32 {
        return Err(HsmError::PayloadInvalid(format!(
            "EC private key must be 32 bytes, got {}",
            scalar.len()
        )));
    }

    // ASN.1 ECPrivateKey (SEC1):
    //   SEQUENCE {
    //     INTEGER 1 (version)
    //     OCTET STRING (32 bytes, private key)
    //     [0] OID 1.2.840.10045.3.1.7 (P-256)
    //   }
    let mut der = Vec::with_capacity(48 + 32);
    // SEQUENCE tag + length (will patch)
    der.push(0x30);
    der.push(0x00); // placeholder

    // version = 1
    der.extend_from_slice(&[0x02, 0x01, 0x01]);

    // privateKey OCTET STRING
    der.push(0x04);
    der.push(0x20); // 32 bytes
    der.extend_from_slice(scalar);

    // parameters [0] EXPLICIT OID
    der.extend_from_slice(&[
        0xA0, 0x0A, // context [0], length 10
        0x06, 0x08, // OID, length 8
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // P-256
    ]);

    // Patch sequence length
    let seq_len = der.len() - 2;
    der[1] = seq_len as u8;

    write_pem_file(path, "EC PRIVATE KEY", &der)
}

/// Write an EC P-256 public key as PEM (SubjectPublicKeyInfo).
pub(crate) fn write_pem_ec_public(path: &Path, uncompressed: &[u8]) -> Result<(), HsmError> {
    if uncompressed.len() != 65 || uncompressed[0] != 0x04 {
        return Err(HsmError::PayloadInvalid(format!(
            "EC public key must be 65 bytes (uncompressed), got {}",
            uncompressed.len()
        )));
    }

    // SubjectPublicKeyInfo:
    //   SEQUENCE {
    //     SEQUENCE {
    //       OID 1.2.840.10045.2.1 (ecPublicKey)
    //       OID 1.2.840.10045.3.1.7 (P-256)
    //     }
    //     BIT STRING (0x00 prefix + 65 bytes)
    //   }
    let mut der = Vec::with_capacity(91);
    der.push(0x30); // outer SEQUENCE
    der.push(0x59); // 89 bytes

    // AlgorithmIdentifier SEQUENCE
    der.extend_from_slice(&[
        0x30, 0x13, // SEQUENCE, 19 bytes
        0x06, 0x07, // OID, 7 bytes
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // ecPublicKey
        0x06, 0x08, // OID, 8 bytes
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // P-256
    ]);

    // BIT STRING
    der.push(0x03);
    der.push(0x42); // 66 bytes (1 padding byte + 65 key bytes)
    der.push(0x00); // no unused bits
    der.extend_from_slice(uncompressed);

    write_pem_file(path, "PUBLIC KEY", &der)
}

/// Write a DER-encoded X.509 certificate as PEM.
fn write_pem_certificate(path: &Path, der: &[u8]) -> Result<(), HsmError> {
    write_pem_file(path, "CERTIFICATE", der)
}

/// Base64-encode DER data and write as PEM with the given label.
fn write_pem_file(path: &Path, label: &str, der: &[u8]) -> Result<(), HsmError> {
    use std::fmt::Write as FmtWrite;

    let b64 = base64_encode(der);
    let mut pem = String::new();
    writeln!(pem, "-----BEGIN {label}-----").unwrap();
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    writeln!(pem, "-----END {label}-----").unwrap();

    std::fs::write(path, pem.as_bytes())
        .map_err(|e| HsmError::KeystoreError(format!("write {}: {e}", path.display())))
}

/// Build a COSE_Key (EC2, P-256, public only) as CBOR bytes.
fn build_public_cose_key_with_alg(
    x: &[u8],
    y: &[u8],
    alg: Option<coset::iana::Algorithm>,
) -> Vec<u8> {
    use coset::CborSerializable;
    let mut builder = coset::CoseKeyBuilder::new_ec2_pub_key(
        coset::iana::EllipticCurve::P_256,
        x.to_vec(),
        y.to_vec(),
    );
    if let Some(a) = alg {
        builder = builder.algorithm(a);
    }
    let mut key = builder.build();
    if alg.is_none() {
        key.alg = None;
    }
    key.to_vec().unwrap()
}

/// Build a COSE_Key (EC2, P-256, private) as CBOR bytes.
fn build_private_cose_key(d: &[u8], x: &[u8], y: &[u8]) -> Vec<u8> {
    use coset::CborSerializable;
    let mut key = coset::CoseKeyBuilder::new_ec2_priv_key(
        coset::iana::EllipticCurve::P_256,
        x.to_vec(),
        y.to_vec(),
        d.to_vec(),
    )
    .build();
    key.alg = None;
    key.to_vec().unwrap()
}

/// Simple base64 encoder (no external dep needed).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }

        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::*;

    fn sample_keystore() -> HsmKeystore {
        HsmKeystore {
            schema_version: SCHEMA_VERSION,
            security_version: 1,
            identities: vec![IdentityDef {
                identity_id: "bali-vm-1".into(),
                public_key: {
                    let mut pk = vec![0x04];
                    pk.extend_from_slice(&[0x11; 32]);
                    pk.extend_from_slice(&[0x22; 32]);
                    pk
                },
            }],
            slots: vec![
                KeySlotDef {
                    key_id: "mykey".into(),
                    key_type: KEY_TYPE_EC_P256,
                    private_key: Some(vec![0xAA; 32]),
                    public_key: Some({
                        let mut pk = vec![0x04];
                        pk.extend_from_slice(&[0xBB; 32]);
                        pk.extend_from_slice(&[0xCC; 32]);
                        pk
                    }),
                    certificate: Some(vec![0x30, 0x82, 0x01, 0x00, 0xAA, 0xBB]),
                    allowed_guests: Some(vec!["bali-vm-1".into()]),
                    allowed_ops: Some(vec![OP_SIGN, OP_VERIFY]),
                },
                KeySlotDef {
                    key_id: "storage-key".into(),
                    key_type: KEY_TYPE_AES_256,
                    private_key: Some(vec![0xDD; 32]),
                    public_key: None,
                    certificate: None,
                    allowed_guests: Some(vec!["bali-vm-1".into()]),
                    allowed_ops: Some(vec![OP_ENCRYPT, OP_DECRYPT]),
                },
            ],
        }
    }

    #[test]
    fn provision_from_cbor_writes_keystore() {
        let tmp = std::env::temp_dir().join("hsm-test-provision");
        let _ = std::fs::remove_dir_all(&tmp);

        let hsm = SimHsm::new(
            PathBuf::from("/dev/null"),
            tmp.clone(),
            5100,
        );

        let ks = sample_keystore();
        let _cbor = payload::encode(&ks).unwrap();

        // Factory provision with raw CBOR (no SUIT feature needed for this test)
        hsm.write_keystore(&ks).unwrap();

        // Verify manifest file
        let manifest = std::fs::read_to_string(tmp.join("manifest")).unwrap();
        assert!(manifest.contains("mykey EC-P256 keys/mykey.priv keys/mykey.cert"));
        assert!(manifest.contains("allowed_guests=bali-vm-1"));
        assert!(manifest.contains("allowed_ops=SIGN,VERIFY"));
        assert!(manifest.contains("storage-key AES-256 keys/storage-key.bin -"));
        assert!(manifest.contains("allowed_ops=ENCRYPT,DECRYPT"));

        // Verify identities file
        let identities = std::fs::read_to_string(tmp.join("identities")).unwrap();
        assert!(identities.contains("bali-vm-1 keys/bali-vm-1.pub"));

        // Verify key files exist
        assert!(tmp.join("keys/mykey.priv").exists());
        assert!(tmp.join("keys/mykey.pub").exists());
        assert!(tmp.join("keys/mykey.cert").exists());
        assert!(tmp.join("keys/storage-key.bin").exists());
        assert!(tmp.join("keys/bali-vm-1.pub").exists());

        // Verify PEM format
        let priv_pem = std::fs::read_to_string(tmp.join("keys/mykey.priv")).unwrap();
        assert!(priv_pem.starts_with("-----BEGIN EC PRIVATE KEY-----\n"));
        assert!(priv_pem.ends_with("-----END EC PRIVATE KEY-----\n"));

        let pub_pem = std::fs::read_to_string(tmp.join("keys/mykey.pub")).unwrap();
        assert!(pub_pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));

        // Verify AES key is raw bytes
        let aes_key = std::fs::read(tmp.join("keys/storage-key.bin")).unwrap();
        assert_eq!(aes_key.len(), 32);
        assert!(aes_key.iter().all(|&b| b == 0xDD));

        // Verify provision state
        let state = std::fs::read_to_string(tmp.join("provision_state")).unwrap();
        assert!(state.starts_with("1")); // security_version

        // Verify list_keys works
        let keys = hsm.list_keys().unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].key_id, "mykey");
        assert_eq!(keys[0].key_type, KeyType::EcP256);
        assert!(keys[0].has_certificate);
        assert_eq!(keys[1].key_id, "storage-key");
        assert_eq!(keys[1].key_type, KeyType::Aes256);
        assert!(!keys[1].has_certificate);

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn security_version_roundtrip() {
        let tmp = std::env::temp_dir().join("hsm-test-secver");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let hsm = SimHsm::new(
            PathBuf::from("/dev/null"),
            tmp.clone(),
            5100,
        );

        // No state file → version 0
        assert_eq!(hsm.load_security_version().unwrap(), 0);

        // Save and reload
        hsm.save_state(42).unwrap();
        assert_eq!(hsm.load_security_version().unwrap(), 42);

        let state = std::fs::read_to_string(tmp.join("provision_state")).unwrap();
        assert_eq!(state, "42");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn pem_ec_private_roundtrip() {
        let tmp = std::env::temp_dir().join("hsm-test-pem-priv");
        let scalar = vec![0x42u8; 32];
        write_pem_ec_private(&tmp, &scalar).unwrap();

        let pem = std::fs::read_to_string(&tmp).unwrap();
        let recovered = extract_ec_scalar_from_pem(&pem).unwrap();
        assert_eq!(recovered, scalar);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn pem_ec_public_roundtrip() {
        let tmp = std::env::temp_dir().join("hsm-test-pem-pub");
        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(&[0xAA; 32]); // x
        uncompressed.extend_from_slice(&[0xBB; 32]); // y
        write_pem_ec_public(&tmp, &uncompressed).unwrap();

        let pem = std::fs::read_to_string(&tmp).unwrap();
        let (x, y) = extract_ec_public_from_pem(&pem).unwrap();
        assert_eq!(x, vec![0xAA; 32]);
        assert_eq!(y, vec![0xBB; 32]);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn base64_roundtrip() {
        for input in &[b"hello world".as_slice(), &[0u8; 32], &[0xFF; 65]] {
            let encoded = base64_encode(input);
            let decoded = base64_decode(&encoded).unwrap();
            assert_eq!(&decoded, input);
        }
    }

    #[test]
    fn base64_encode_basic() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }
}
