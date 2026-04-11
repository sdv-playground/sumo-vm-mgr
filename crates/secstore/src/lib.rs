//! Encrypted key metadata persistence with pluggable backends.
//!
//! Two trait axes:
//! - [`SecstoreEncryptor`]: who encrypts (HSE on production, static key for dev)
//! - [`SecstoreBackend`]: where blobs live (filesystem, NOR flash, etc.)
//!
//! The generic [`FileBackend`] + any encryptor works on any POSIX system.
//! Board-specific crates (e.g. `hse-s32g3`) provide hardware encryptors.
//!
//! # What's Stored
//!
//! Key *metadata* only — not key material. The actual keys live in the HSE
//! (or file-based keystore in dev). Metadata maps opaque vhsm handles to
//! their backing key identity, algorithm, permissions, and ownership.
//!
//! # Concurrency
//!
//! The store is single-writer (vhsm-ssd daemon). Writes are atomic
//! (write-to-temp + rename) to survive power loss.

mod file_backend;
mod linux_encryptor;

pub use file_backend::FileBackend;
pub use linux_encryptor::LinuxSimEncryptor;

/// Encrypts/decrypts metadata blobs before storage.
///
/// Production: implemented by the board HSE crate (AES-GCM with HSE-held key).
/// Development: [`LinuxSimEncryptor`] uses a static key.
pub trait SecstoreEncryptor: Send + Sync {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecstoreError>;
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecstoreError>;
}

/// Persistent blob storage backend.
///
/// Default: [`FileBackend`] (std::fs, works on any POSIX).
/// Board-specific: NOR flash with wear leveling, secure RRAM, etc.
pub trait SecstoreBackend: Send + Sync {
    /// Read a blob by key. Returns None if not found.
    fn read(&self, key: &str) -> Result<Option<Vec<u8>>, SecstoreError>;

    /// Write a blob atomically (must survive power loss).
    fn write(&self, key: &str, data: &[u8]) -> Result<(), SecstoreError>;

    /// Delete a blob.
    fn delete(&self, key: &str) -> Result<(), SecstoreError>;

    /// List all stored keys.
    fn list(&self) -> Result<Vec<String>, SecstoreError>;
}

/// Key metadata record — serialized to/from the store.
#[derive(Debug, Clone)]
pub struct KeyMetadata {
    pub vhsm_handle: u32,
    pub key_id: String,
    pub algorithm: u32,
    pub permitted_ops: u32,
    pub owner_cid: u32,
    pub persistent: bool,
    pub label: String,
}

/// Combined encrypted store: encryptor + backend.
pub struct Secstore<E: SecstoreEncryptor, B: SecstoreBackend> {
    encryptor: E,
    backend: B,
}

impl<E: SecstoreEncryptor, B: SecstoreBackend> Secstore<E, B> {
    pub fn new(encryptor: E, backend: B) -> Self {
        Self { encryptor, backend }
    }

    /// Store key metadata (encrypt then write).
    pub fn store(&self, meta: &KeyMetadata) -> Result<(), SecstoreError> {
        let plaintext = serialize_metadata(meta);
        let ciphertext = self.encryptor.encrypt(&plaintext)?;
        let key = format!("handle_{:08x}", meta.vhsm_handle);
        self.backend.write(&key, &ciphertext)
    }

    /// Load all stored key metadata (read then decrypt).
    pub fn load_all(&self) -> Result<Vec<KeyMetadata>, SecstoreError> {
        let keys = self.backend.list()?;
        let mut result = Vec::new();
        for key in keys {
            if let Some(ciphertext) = self.backend.read(&key)? {
                let plaintext = self.encryptor.decrypt(&ciphertext)?;
                if let Some(meta) = deserialize_metadata(&plaintext) {
                    result.push(meta);
                }
            }
        }
        Ok(result)
    }

    /// Delete key metadata.
    pub fn delete(&self, vhsm_handle: u32) -> Result<(), SecstoreError> {
        let key = format!("handle_{:08x}", vhsm_handle);
        self.backend.delete(&key)
    }
}

#[derive(Debug)]
pub enum SecstoreError {
    Io(std::io::Error),
    Crypto(String),
    Format(String),
}

impl std::fmt::Display for SecstoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecstoreError::Io(e) => write!(f, "secstore I/O: {e}"),
            SecstoreError::Crypto(e) => write!(f, "secstore crypto: {e}"),
            SecstoreError::Format(e) => write!(f, "secstore format: {e}"),
        }
    }
}

impl std::error::Error for SecstoreError {}

impl From<std::io::Error> for SecstoreError {
    fn from(e: std::io::Error) -> Self {
        SecstoreError::Io(e)
    }
}

// Simple binary serialization (no serde dependency)
fn serialize_metadata(meta: &KeyMetadata) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&meta.vhsm_handle.to_le_bytes());
    buf.extend_from_slice(&meta.algorithm.to_le_bytes());
    buf.extend_from_slice(&meta.permitted_ops.to_le_bytes());
    buf.extend_from_slice(&meta.owner_cid.to_le_bytes());
    buf.push(meta.persistent as u8);
    // Length-prefixed strings
    let key_id = meta.key_id.as_bytes();
    buf.extend_from_slice(&(key_id.len() as u16).to_le_bytes());
    buf.extend_from_slice(key_id);
    let label = meta.label.as_bytes();
    buf.extend_from_slice(&(label.len() as u16).to_le_bytes());
    buf.extend_from_slice(label);
    buf
}

fn deserialize_metadata(data: &[u8]) -> Option<KeyMetadata> {
    if data.len() < 17 {
        return None;
    }
    let vhsm_handle = u32::from_le_bytes(data[0..4].try_into().ok()?);
    let algorithm = u32::from_le_bytes(data[4..8].try_into().ok()?);
    let permitted_ops = u32::from_le_bytes(data[8..12].try_into().ok()?);
    let owner_cid = u32::from_le_bytes(data[12..16].try_into().ok()?);
    let persistent = data[16] != 0;

    let mut pos = 17;
    let key_id_len = u16::from_le_bytes(data.get(pos..pos + 2)?.try_into().ok()?) as usize;
    pos += 2;
    let key_id = std::str::from_utf8(data.get(pos..pos + key_id_len)?).ok()?.to_string();
    pos += key_id_len;
    let label_len = u16::from_le_bytes(data.get(pos..pos + 2)?.try_into().ok()?) as usize;
    pos += 2;
    let label = std::str::from_utf8(data.get(pos..pos + label_len)?).ok()?.to_string();

    Some(KeyMetadata {
        vhsm_handle,
        key_id,
        algorithm,
        permitted_ops,
        owner_cid,
        persistent,
        label,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_roundtrip() {
        let meta = KeyMetadata {
            vhsm_handle: 0x0042,
            key_id: "ecu-signing".into(),
            algorithm: 0x0021,
            permitted_ops: 0x0330,
            owner_cid: 3,
            persistent: true,
            label: "ECU signing key".into(),
        };
        let bytes = serialize_metadata(&meta);
        let back = deserialize_metadata(&bytes).unwrap();
        assert_eq!(back.vhsm_handle, 0x0042);
        assert_eq!(back.key_id, "ecu-signing");
        assert_eq!(back.algorithm, 0x0021);
        assert_eq!(back.permitted_ops, 0x0330);
        assert_eq!(back.owner_cid, 3);
        assert!(back.persistent);
        assert_eq!(back.label, "ECU signing key");
    }

    #[test]
    fn store_and_load_roundtrip() {
        let dir = std::env::temp_dir().join("secstore-test");
        let _ = std::fs::remove_dir_all(&dir);

        let store = Secstore::new(
            LinuxSimEncryptor::new([0xAB; 16]),
            FileBackend::new(&dir),
        );

        let meta = KeyMetadata {
            vhsm_handle: 0x0100,
            key_id: "test-key".into(),
            algorithm: 0x0002,
            permitted_ops: 0x03,
            owner_cid: 0,
            persistent: true,
            label: "test".into(),
        };

        store.store(&meta).unwrap();
        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].vhsm_handle, 0x0100);
        assert_eq!(loaded[0].key_id, "test-key");

        store.delete(0x0100).unwrap();
        let loaded = store.load_all().unwrap();
        assert!(loaded.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
