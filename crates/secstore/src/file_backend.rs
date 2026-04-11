//! Filesystem-based blob storage backend.
//!
//! Stores each blob as a file in a directory. Writes are atomic
//! (write to temp file + rename) to survive power loss.

use std::path::{Path, PathBuf};

use super::{SecstoreBackend, SecstoreError};

/// File-based backend — one file per blob in a directory.
pub struct FileBackend {
    dir: PathBuf,
}

impl FileBackend {
    pub fn new(dir: &Path) -> Self {
        Self { dir: dir.to_path_buf() }
    }
}

impl SecstoreBackend for FileBackend {
    fn read(&self, key: &str) -> Result<Option<Vec<u8>>, SecstoreError> {
        let path = self.dir.join(key);
        match std::fs::read(&path) {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(SecstoreError::Io(e)),
        }
    }

    fn write(&self, key: &str, data: &[u8]) -> Result<(), SecstoreError> {
        std::fs::create_dir_all(&self.dir)?;
        let path = self.dir.join(key);
        let tmp = self.dir.join(format!(".{key}.tmp"));
        std::fs::write(&tmp, data)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), SecstoreError> {
        let path = self.dir.join(key);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(SecstoreError::Io(e)),
        }
    }

    fn list(&self) -> Result<Vec<String>, SecstoreError> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(SecstoreError::Io(e)),
        };
        let mut keys = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with('.') {
                keys.push(name);
            }
        }
        Ok(keys)
    }
}
