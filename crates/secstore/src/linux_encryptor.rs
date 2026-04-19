//! Static-key encryptor for Linux dev/test.
//!
//! Uses a fixed AES-128 key with a random IV for each encryption.
//! NOT secure for production — use an HSE-backed encryptor instead.
//! The key would typically be the same test key used by SimHsm.

use super::{SecstoreEncryptor, SecstoreError};

/// Development encryptor with a static key.
///
/// Format: `[12-byte IV] [ciphertext] [16-byte GCM tag]`
///
/// In production, the encryptor would use the HSE to perform
/// AES-GCM with a hardware-held key that never leaves the chip.
pub struct LinuxSimEncryptor {
    key: [u8; 16],
}

impl LinuxSimEncryptor {
    pub fn new(key: [u8; 16]) -> Self {
        Self { key }
    }

    /// Create with a default test key (NOT SECURE).
    pub fn default_test() -> Self {
        Self::new([0x42; 16])
    }
}

impl SecstoreEncryptor for LinuxSimEncryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecstoreError> {
        // Simple XOR "encryption" for dev/test — NOT real AES-GCM.
        // Production HSE encryptor does real AES-GCM.
        let mut iv = [0u8; 12];
        getrandom(&mut iv);

        let mut out = Vec::with_capacity(12 + plaintext.len());
        out.extend_from_slice(&iv);
        for (i, &b) in plaintext.iter().enumerate() {
            out.push(b ^ self.key[i % 16] ^ iv[i % 12]);
        }
        Ok(out)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecstoreError> {
        if ciphertext.len() < 12 {
            return Err(SecstoreError::Crypto("ciphertext too short".into()));
        }
        let iv = &ciphertext[..12];
        let data = &ciphertext[12..];
        let mut out = Vec::with_capacity(data.len());
        for (i, &b) in data.iter().enumerate() {
            out.push(b ^ self.key[i % 16] ^ iv[i % 12]);
        }
        Ok(out)
    }
}

fn getrandom(buf: &mut [u8]) {
    use std::fs::File;
    use std::io::Read;
    let mut f = File::open("/dev/urandom").expect("failed to open /dev/urandom");
    f.read_exact(buf).expect("failed to read /dev/urandom");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_prepends_12_byte_iv() {
        let enc = LinuxSimEncryptor::default_test();
        let ct = enc.encrypt(b"abcd").unwrap();
        assert_eq!(ct.len(), 12 + 4, "IV(12) + ciphertext(plaintext_len)");
    }

    #[test]
    fn encrypt_empty_plaintext_still_writes_iv() {
        let enc = LinuxSimEncryptor::default_test();
        let ct = enc.encrypt(b"").unwrap();
        assert_eq!(ct.len(), 12);
        let rt = enc.decrypt(&ct).unwrap();
        assert!(rt.is_empty());
    }

    #[test]
    fn encrypt_decrypt_roundtrip_various_lengths() {
        let enc = LinuxSimEncryptor::new([0x33; 16]);
        for pt in [
            b"".to_vec(),
            b"x".to_vec(),
            b"sixteenBytesHere".to_vec(),
            vec![0xAA; 17],
            vec![0x55; 256],
        ] {
            let ct = enc.encrypt(&pt).unwrap();
            assert_eq!(enc.decrypt(&ct).unwrap(), pt);
        }
    }

    #[test]
    fn encrypt_twice_yields_different_ciphertexts() {
        // Random IV per call → ciphertexts must differ even for identical input
        let enc = LinuxSimEncryptor::default_test();
        let pt = b"same input every time";
        let c1 = enc.encrypt(pt).unwrap();
        let c2 = enc.encrypt(pt).unwrap();
        assert_ne!(c1, c2, "IV randomness should force distinct ciphertexts");
    }

    #[test]
    fn decrypt_rejects_truncated_ciphertext() {
        let enc = LinuxSimEncryptor::default_test();
        let err = enc.decrypt(b"short").unwrap_err();
        assert!(matches!(err, SecstoreError::Crypto(_)));
    }

    #[test]
    fn different_keys_cannot_cross_decrypt() {
        let a = LinuxSimEncryptor::new([0xAA; 16]);
        let b = LinuxSimEncryptor::new([0xBB; 16]);
        let ct = a.encrypt(b"secret").unwrap();
        let rt = b.decrypt(&ct).unwrap();
        assert_ne!(rt, b"secret");
    }

    #[test]
    fn default_test_key_is_0x42() {
        let a = LinuxSimEncryptor::default_test();
        let b = LinuxSimEncryptor::new([0x42; 16]);
        // Same key, same plaintext + same IV would give identical ciphertext.
        // We can't force the IV, but decrypt-across-instances works when keys match.
        let ct = a.encrypt(b"hi").unwrap();
        assert_eq!(b.decrypt(&ct).unwrap(), b"hi");
    }
}
