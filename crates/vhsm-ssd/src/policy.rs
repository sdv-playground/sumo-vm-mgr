/// CID-based policy engine for vHSM access control.
///
/// A policy maps vsock CIDs to permitted operation bitmasks.
/// In production, this is loaded from a CMAC-signed binary file.
/// In dev/test, an allow-all policy or unsigned file can be used.

use std::collections::HashMap;
use std::path::Path;

use crate::proto::*;

/// Per-CID policy entry.
#[derive(Debug, Clone)]
pub struct PolicyEntry {
    pub cid: u32,
    pub permitted_ops: u32,
}

/// The policy table.
pub struct Policy {
    entries: HashMap<u32, u32>, // CID -> permitted_ops bitmask
}

impl Policy {
    /// Create an empty policy (rejects everything).
    pub fn empty() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Create a dev/test policy that allows all operations for given CIDs.
    pub fn allow_all(cids: &[u32]) -> Self {
        let all_perms = PERM_ENCRYPT
            | PERM_DECRYPT
            | PERM_MAC_GEN
            | PERM_MAC_VFY
            | PERM_SIGN
            | PERM_VERIFY
            | PERM_GET_PUBKEY
            | PERM_GET_CERT
            | PERM_KEY_GENERATE;

        let mut entries = HashMap::new();
        for &cid in cids {
            entries.insert(cid, all_perms);
        }
        Self { entries }
    }

    /// Add or update a policy entry.
    pub fn add(&mut self, cid: u32, permitted_ops: u32) {
        self.entries.insert(cid, permitted_ops);
    }

    /// Check if a CID is permitted to perform an operation.
    /// Returns the CID's permission mask, or None if CID is not in policy.
    pub fn lookup(&self, cid: u32) -> Option<u32> {
        self.entries.get(&cid).copied()
    }

    /// Check a specific operation for a CID.
    pub fn check(&self, cid: u32, required_perm: u32) -> Result<(), StatusCode> {
        match self.lookup(cid) {
            Some(perms) if perms & required_perm != 0 => Ok(()),
            Some(_) => Err(StatusCode::PermissionDeny),
            None => Err(StatusCode::PolicyReject),
        }
    }

    /// Load policy from a binary file.
    ///
    /// Binary format:
    ///   [4] magic "VPOL" (0x56504F4C)
    ///   [4] version (uint32 LE)
    ///   [4] n_entries (uint32 LE)
    ///   [16] cmac (skipped in dev mode)
    ///   For each entry:
    ///     [4] identity_type (1=VSOCK_CID)
    ///     [4] identity_value
    ///     [4] permitted_ops
    pub fn load_from_file(path: &Path, verify_cmac: bool) -> Result<Self, String> {
        let data =
            std::fs::read(path).map_err(|e| format!("read policy file: {e}"))?;

        if data.len() < 28 {
            return Err("policy file too short".into());
        }

        // Check magic
        if &data[0..4] != b"VPOL" {
            return Err("bad policy magic".into());
        }

        let _version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let n_entries = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        // data[12..28] = CMAC (16 bytes)

        if verify_cmac {
            // TODO: verify CMAC using HSE key
            return Err("CMAC verification not yet implemented".into());
        }

        let entry_start = 28;
        let entry_size = 12; // 4 + 4 + 4
        let expected_len = entry_start + n_entries * entry_size;
        if data.len() < expected_len {
            return Err(format!(
                "policy file truncated: expected {expected_len} bytes, got {}",
                data.len()
            ));
        }

        let mut entries = HashMap::new();
        for i in 0..n_entries {
            let off = entry_start + i * entry_size;
            let identity_type =
                u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
            let identity_value = u32::from_le_bytes([
                data[off + 4],
                data[off + 5],
                data[off + 6],
                data[off + 7],
            ]);
            let permitted_ops = u32::from_le_bytes([
                data[off + 8],
                data[off + 9],
                data[off + 10],
                data[off + 11],
            ]);

            // Only support VSOCK_CID type (1) for now
            if identity_type == 1 {
                entries.insert(identity_value, permitted_ops);
            }
        }

        Ok(Self { entries })
    }

    pub fn num_entries(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_all_policy() {
        let policy = Policy::allow_all(&[3, 4]);
        assert!(policy.check(3, PERM_SIGN).is_ok());
        assert!(policy.check(4, PERM_ENCRYPT).is_ok());
        assert!(policy.check(5, PERM_SIGN).is_err()); // unknown CID
    }

    #[test]
    fn restricted_policy() {
        let mut policy = Policy::empty();
        policy.add(3, PERM_SIGN | PERM_VERIFY);
        policy.add(4, PERM_ENCRYPT | PERM_DECRYPT);

        assert!(policy.check(3, PERM_SIGN).is_ok());
        assert!(policy.check(3, PERM_ENCRYPT).is_err()); // not permitted
        assert!(policy.check(4, PERM_ENCRYPT).is_ok());
        assert!(policy.check(4, PERM_SIGN).is_err()); // not permitted
    }
}
