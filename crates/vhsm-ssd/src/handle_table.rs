/// Handle table — maps opaque uint32 handles to internal key state.
///
/// Well-known handles (0x0001..0x00FF) are pre-populated from the keystore
/// and are not owned by any specific CID (owner_cid = 0).
///
/// Dynamic handles (>= 0x0100) are allocated by KEY_GENERATE and owned
/// by the creating guest's CID.

use crate::proto::*;

/// A single entry in the handle table.
#[derive(Debug, Clone)]
pub struct HandleEntry {
    pub handle: u32,
    /// Host-internal key identifier (never sent to guest).
    pub key_id: String,
    pub algorithm: u32,
    pub permitted_ops: u32,
    /// Vsock CID of the creator. 0 = well-known (shared).
    pub owner_cid: u32,
    pub persistent: bool,
    pub label: [u8; LABEL_LEN],
}

/// The handle table.
pub struct HandleTable {
    entries: Vec<HandleEntry>,
    next_dynamic: u32,
}

impl HandleTable {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_dynamic: HANDLE_DYNAMIC_BASE,
        }
    }

    /// Register a well-known handle (from keystore at startup).
    /// Returns false if handle is already registered.
    pub fn register_well_known(
        &mut self,
        handle: u32,
        key_id: &str,
        algorithm: u32,
        permitted_ops: u32,
    ) -> bool {
        if !handle_is_well_known(handle) || handle == HANDLE_INVALID {
            return false;
        }
        if self.entries.iter().any(|e| e.handle == handle) {
            return false;
        }

        let mut label = [0u8; LABEL_LEN];
        let bytes = key_id.as_bytes();
        let copy_len = bytes.len().min(LABEL_LEN - 1);
        label[..copy_len].copy_from_slice(&bytes[..copy_len]);

        self.entries.push(HandleEntry {
            handle,
            key_id: key_id.to_string(),
            algorithm,
            permitted_ops,
            owner_cid: 0,
            persistent: true,
            label,
        });
        true
    }

    /// Allocate a dynamic handle (from KEY_GENERATE).
    /// Returns None if the table is full.
    pub fn allocate(
        &mut self,
        key_id: &str,
        algorithm: u32,
        permitted_ops: u32,
        owner_cid: u32,
        persistent: bool,
        label: &[u8; LABEL_LEN],
    ) -> Option<u32> {
        if self.entries.len() >= MAX_HANDLES {
            return None;
        }

        let handle = self.next_dynamic;
        self.next_dynamic += 1;

        self.entries.push(HandleEntry {
            handle,
            key_id: key_id.to_string(),
            algorithm,
            permitted_ops,
            owner_cid,
            persistent,
            label: *label,
        });

        Some(handle)
    }

    /// Look up a handle. Returns None if not found.
    pub fn get(&self, handle: u32) -> Option<&HandleEntry> {
        self.entries.iter().find(|e| e.handle == handle)
    }

    /// Resolve a handle for a specific caller CID.
    /// Well-known handles (owner_cid=0) are accessible to any CID.
    /// Dynamic handles require matching owner_cid.
    pub fn resolve(&self, handle: u32, caller_cid: u32) -> Option<&HandleEntry> {
        let entry = self.get(handle)?;
        if entry.owner_cid == 0 || entry.owner_cid == caller_cid {
            Some(entry)
        } else {
            None
        }
    }

    /// Remove a handle. Returns true if found and removed.
    pub fn remove(&mut self, handle: u32) -> bool {
        if let Some(pos) = self.entries.iter().position(|e| e.handle == handle) {
            self.entries.swap_remove(pos);
            true
        } else {
            false
        }
    }

    /// Remove all dynamic handles owned by a CID (on VM disconnect/restart).
    pub fn remove_by_cid(&mut self, cid: u32) {
        self.entries
            .retain(|e| e.owner_cid == 0 || e.owner_cid != cid);
    }

    /// Number of handles currently in use.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_handles() {
        let mut table = HandleTable::new();
        assert!(table.register_well_known(
            HANDLE_JWT_SIGNING,
            "jwt-signing",
            ALG_ECC_P256,
            PERM_SIGN | PERM_VERIFY | PERM_GET_PUBKEY,
        ));

        // Duplicate rejected
        assert!(!table.register_well_known(
            HANDLE_JWT_SIGNING,
            "jwt-signing",
            ALG_ECC_P256,
            PERM_SIGN,
        ));

        // Accessible from any CID
        assert!(table.resolve(HANDLE_JWT_SIGNING, 3).is_some());
        assert!(table.resolve(HANDLE_JWT_SIGNING, 4).is_some());
    }

    #[test]
    fn dynamic_handles() {
        let mut table = HandleTable::new();
        let label = [0u8; LABEL_LEN];

        let h = table
            .allocate("temp-key", ALG_AES_256, PERM_ENCRYPT | PERM_DECRYPT, 3, false, &label)
            .unwrap();
        assert!(h >= HANDLE_DYNAMIC_BASE);

        // Owner can access
        assert!(table.resolve(h, 3).is_some());
        // Other CID cannot
        assert!(table.resolve(h, 4).is_none());

        // Cleanup by CID
        table.remove_by_cid(3);
        assert!(table.resolve(h, 3).is_none());
    }
}
