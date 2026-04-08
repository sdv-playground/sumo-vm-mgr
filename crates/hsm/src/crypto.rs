/// HsmCryptoProvider implementation for LinuxSimHsm.
///
/// Performs crypto operations in software using RustCrypto crates.
/// Keys are read from the file-based keystore (PEM for EC-P256,
/// raw binary for AES-256). On production hardware, this would be
/// replaced by a QnxHsm implementation that routes to HSM firmware.
///
/// Key material never leaves this module — callers (vhsm-ssd) only
/// see operation results (signatures, ciphertexts, etc.).

use crate::linux::{decode_pem, extract_ec_scalar_from_pem, LinuxSimHsm};
use crate::{HsmCryptoProvider, HsmError, HsmProvider, KeyInfo, KeyType};

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use ecdsa::signature::Signer;
use ecdsa::signature::Verifier;
use hkdf::Hkdf;
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand::RngCore;
use sha2::Sha256;

impl HsmCryptoProvider for LinuxSimHsm {
    fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        let key_info = self.get_key_info(key_id)?;
        if key_info.key_type != KeyType::EcP256 {
            return Err(HsmError::CryptoError(format!(
                "sign requires EC-P256 key, got {}",
                key_info.key_type
            )));
        }

        let scalar = load_ec_private_scalar(self, key_id)?;
        let signing_key = SigningKey::from_bytes((&scalar[..]).into())
            .map_err(|e| HsmError::CryptoError(format!("invalid signing key: {e}")))?;

        let signature: ecdsa::der::Signature<p256::NistP256> = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> Result<bool, HsmError> {
        let key_info = self.get_key_info(key_id)?;
        if key_info.key_type != KeyType::EcP256 {
            return Err(HsmError::CryptoError(format!(
                "verify requires EC-P256 key, got {}",
                key_info.key_type
            )));
        }

        let verifying_key = load_ec_verifying_key(self, key_id)?;
        let sig = ecdsa::der::Signature::<p256::NistP256>::from_bytes(signature)
            .map_err(|e| HsmError::CryptoError(format!("invalid signature: {e}")))?;

        match verifying_key.verify(data, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, HsmError> {
        let key_info = self.get_key_info(key_id)?;
        if key_info.key_type != KeyType::Aes256 {
            return Err(HsmError::CryptoError(format!(
                "encrypt requires AES-256 key, got {}",
                key_info.key_type
            )));
        }

        let raw_key = load_aes_key(self, key_id)?;
        let cipher = Aes256Gcm::new_from_slice(&raw_key)
            .map_err(|e| HsmError::CryptoError(format!("invalid AES key: {e}")))?;

        let mut iv_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut iv_bytes);
        let nonce = Nonce::from_slice(&iv_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| HsmError::CryptoError(format!("AES-GCM encrypt: {e}")))?;

        // Return iv(12) || ciphertext || tag (tag is appended by aes-gcm)
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&iv_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        let key_info = self.get_key_info(key_id)?;
        if key_info.key_type != KeyType::Aes256 {
            return Err(HsmError::CryptoError(format!(
                "decrypt requires AES-256 key, got {}",
                key_info.key_type
            )));
        }

        if data.len() < 12 + 16 {
            return Err(HsmError::CryptoError(
                "ciphertext too short (need at least iv + tag)".into(),
            ));
        }

        let raw_key = load_aes_key(self, key_id)?;
        let cipher = Aes256Gcm::new_from_slice(&raw_key)
            .map_err(|e| HsmError::CryptoError(format!("invalid AES key: {e}")))?;

        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext_and_tag = &data[12..];

        cipher
            .decrypt(nonce, ciphertext_and_tag)
            .map_err(|e| HsmError::CryptoError(format!("AES-GCM decrypt: {e}")))
    }

    fn derive(&self, key_id: &str, context: &[u8], len: usize) -> Result<Vec<u8>, HsmError> {
        let key_info = self.get_key_info(key_id)?;
        if key_info.key_type != KeyType::Aes256 {
            return Err(HsmError::CryptoError(format!(
                "derive requires AES-256 key, got {}",
                key_info.key_type
            )));
        }

        let raw_key = load_aes_key(self, key_id)?;
        let hk = Hkdf::<Sha256>::new(None, &raw_key);
        let mut okm = vec![0u8; len];
        hk.expand(context, &mut okm)
            .map_err(|e| HsmError::CryptoError(format!("HKDF expand: {e}")))?;
        Ok(okm)
    }

    fn random(&self, len: usize) -> Result<Vec<u8>, HsmError> {
        if len > 1024 {
            return Err(HsmError::CryptoError(format!(
                "random request too large: {len} (max 1024)"
            )));
        }
        let mut buf = vec![0u8; len];
        OsRng.fill_bytes(&mut buf);
        Ok(buf)
    }

    fn get_certificate_der(&self, key_id: &str) -> Result<Vec<u8>, HsmError> {
        let key_info = self.get_key_info(key_id)?;
        if !key_info.has_certificate {
            return Err(HsmError::KeyNotFound(format!(
                "no certificate for key '{key_id}'"
            )));
        }

        let cert_path = self.keys_dir().join(format!("{key_id}.cert"));
        let pem = std::fs::read_to_string(&cert_path)
            .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", cert_path.display())))?;
        decode_pem(&pem, "CERTIFICATE")
    }

    fn get_public_key_der(&self, key_id: &str) -> Result<Vec<u8>, HsmError> {
        let key_info = self.get_key_info(key_id)?;
        if key_info.key_type != KeyType::EcP256 {
            return Err(HsmError::CryptoError(format!(
                "get_public_key_der requires EC-P256 key, got {}",
                key_info.key_type
            )));
        }

        let pub_path = self.keys_dir().join(format!("{key_id}.pub"));
        let pem = std::fs::read_to_string(&pub_path)
            .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", pub_path.display())))?;
        decode_pem(&pem, "PUBLIC KEY")
    }

    fn get_key_info(&self, key_id: &str) -> Result<KeyInfo, HsmError> {
        if !self.is_provisioned()? {
            return Err(HsmError::NotProvisioned);
        }
        let keys = self.parse_manifest()?;
        keys.into_iter()
            .find(|k| k.key_id == key_id)
            .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))
    }

}

// --- Internal key loading helpers ---

fn load_ec_private_scalar(hsm: &LinuxSimHsm, key_id: &str) -> Result<Vec<u8>, HsmError> {
    let priv_path = hsm.keys_dir().join(format!("{key_id}.priv"));
    let pem = std::fs::read_to_string(&priv_path)
        .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", priv_path.display())))?;
    extract_ec_scalar_from_pem(&pem)
}

fn load_ec_verifying_key(
    hsm: &LinuxSimHsm,
    key_id: &str,
) -> Result<VerifyingKey, HsmError> {
    let pub_path = hsm.keys_dir().join(format!("{key_id}.pub"));
    let pem = std::fs::read_to_string(&pub_path)
        .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", pub_path.display())))?;
    let der = decode_pem(&pem, "PUBLIC KEY")?;
    VerifyingKey::from_sec1_bytes(&der[der.len() - 65..])
        .map_err(|e| HsmError::CryptoError(format!("invalid verifying key: {e}")))
}

fn load_aes_key(hsm: &LinuxSimHsm, key_id: &str) -> Result<Vec<u8>, HsmError> {
    let path = hsm.keys_dir().join(format!("{key_id}.bin"));
    let key = std::fs::read(&path)
        .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", path.display())))?;
    if key.len() != 32 {
        return Err(HsmError::CryptoError(format!(
            "AES key must be 32 bytes, got {}",
            key.len()
        )));
    }
    Ok(key)
}
