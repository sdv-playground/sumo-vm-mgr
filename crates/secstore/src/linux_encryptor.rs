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
