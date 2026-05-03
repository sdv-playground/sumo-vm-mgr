//! IP-based policy engine for vHSM access control.
//!
//! Each connecting source IP is mapped to a `vm_id` plus a permitted-ops
//! bitmask. The trust anchor is the orchestrator's exclusive control over
//! QEMU-launch-time MAC assignment, paired with dnsmasq static MAC→IP
//! leases on the private `vbr-vhsm` bridge — so the source IP a connection
//! arrives from is as unspoofable as a vsock CID was.
//!
//! Policy file format (flat text, one entry per line):
//!
//! ```text
//! # comment lines start with '#'
//! 192.168.99.10 vm1 encrypt decrypt mac_gen mac_vfy sign verify get_pubkey get_cert key_generate
//! 192.168.99.11 vm2 sign verify get_pubkey
//! ```
//!
//! For dev/test, `Policy::allow_all` builds a policy that gives all
//! permissions to a list of (ip, vm_id) pairs.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use crate::proto::*;

/// A single allow-list entry.
#[derive(Debug, Clone)]
pub struct AllowEntry {
    pub vm_id: String,
    pub permitted_ops: u32,
}

/// The IP allow-list.
pub struct Policy {
    by_ip: HashMap<IpAddr, AllowEntry>,
}

impl Policy {
    /// Empty policy — rejects every connection.
    pub fn empty() -> Self {
        Self {
            by_ip: HashMap::new(),
        }
    }

    /// Dev/test convenience: grant all permissions to each (ip, vm_id) pair.
    pub fn allow_all<I, S>(entries: I) -> Self
    where
        I: IntoIterator<Item = (IpAddr, S)>,
        S: Into<String>,
    {
        let all_perms = PERM_ENCRYPT
            | PERM_DECRYPT
            | PERM_MAC_GEN
            | PERM_MAC_VFY
            | PERM_SIGN
            | PERM_VERIFY
            | PERM_GET_PUBKEY
            | PERM_GET_CERT
            | PERM_KEY_GENERATE;

        let mut by_ip = HashMap::new();
        for (ip, vm_id) in entries {
            by_ip.insert(
                ip,
                AllowEntry {
                    vm_id: vm_id.into(),
                    permitted_ops: all_perms,
                },
            );
        }
        Self { by_ip }
    }

    /// Add or replace an entry.
    pub fn add(&mut self, ip: IpAddr, vm_id: &str, permitted_ops: u32) {
        self.by_ip.insert(
            ip,
            AllowEntry {
                vm_id: vm_id.to_string(),
                permitted_ops,
            },
        );
    }

    /// Look up the policy entry for a source IP.
    pub fn lookup(&self, ip: IpAddr) -> Option<&AllowEntry> {
        self.by_ip.get(&ip)
    }

    /// Look up + check that the entry has the required permission bit.
    /// Returns the entry on success, or a status code that the caller
    /// can return to the guest verbatim.
    pub fn check(&self, ip: IpAddr, required_perm: u32) -> Result<&AllowEntry, StatusCode> {
        match self.lookup(ip) {
            Some(entry) if entry.permitted_ops & required_perm != 0 => Ok(entry),
            Some(_) => Err(StatusCode::PermissionDeny),
            None => Err(StatusCode::PolicyReject),
        }
    }

    /// Load a policy from a flat-text file. See module docs for the format.
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("read policy file {}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("policy file {}: {e}", path.display()))
    }

    /// Parse a policy from a string buffer.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut by_ip = HashMap::new();
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut tokens = line.split_whitespace();
            let ip_tok = tokens.next().ok_or_else(|| {
                format!("line {}: missing IP", lineno + 1)
            })?;
            let vm_id = tokens.next().ok_or_else(|| {
                format!("line {}: missing vm_id after IP", lineno + 1)
            })?;
            let ip: IpAddr = ip_tok
                .parse()
                .map_err(|e| format!("line {}: bad IP '{ip_tok}': {e}", lineno + 1))?;

            let mut permitted_ops = 0u32;
            for perm_tok in tokens {
                let bit = parse_perm(perm_tok).ok_or_else(|| {
                    format!("line {}: unknown permission '{perm_tok}'", lineno + 1)
                })?;
                permitted_ops |= bit;
            }

            by_ip.insert(
                ip,
                AllowEntry {
                    vm_id: vm_id.to_string(),
                    permitted_ops,
                },
            );
        }
        Ok(Self { by_ip })
    }

    pub fn num_entries(&self) -> usize {
        self.by_ip.len()
    }
}

fn parse_perm(name: &str) -> Option<u32> {
    Some(match name {
        "encrypt" => PERM_ENCRYPT,
        "decrypt" => PERM_DECRYPT,
        "mac_gen" => PERM_MAC_GEN,
        "mac_vfy" => PERM_MAC_VFY,
        "sign" => PERM_SIGN,
        "verify" => PERM_VERIFY,
        "derive" => PERM_DERIVE,
        "delete" => PERM_DELETE,
        "get_pubkey" => PERM_GET_PUBKEY,
        "get_cert" => PERM_GET_CERT,
        "key_generate" => PERM_KEY_GENERATE,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn allow_all_policy() {
        let policy = Policy::allow_all([
            (ip("192.168.99.10"), "vm1"),
            (ip("192.168.99.11"), "vm2"),
        ]);
        let entry = policy.check(ip("192.168.99.10"), PERM_SIGN).unwrap();
        assert_eq!(entry.vm_id, "vm1");
        assert!(policy.check(ip("192.168.99.11"), PERM_ENCRYPT).is_ok());
        // Unknown IP rejected
        assert!(matches!(
            policy.check(ip("192.168.99.99"), PERM_SIGN),
            Err(StatusCode::PolicyReject)
        ));
    }

    #[test]
    fn restricted_policy() {
        let mut policy = Policy::empty();
        policy.add(ip("192.168.99.10"), "vm1", PERM_SIGN | PERM_VERIFY);
        policy.add(ip("192.168.99.11"), "vm2", PERM_ENCRYPT | PERM_DECRYPT);

        assert!(policy.check(ip("192.168.99.10"), PERM_SIGN).is_ok());
        assert!(matches!(
            policy.check(ip("192.168.99.10"), PERM_ENCRYPT),
            Err(StatusCode::PermissionDeny)
        ));
        assert!(policy.check(ip("192.168.99.11"), PERM_ENCRYPT).is_ok());
        assert!(matches!(
            policy.check(ip("192.168.99.11"), PERM_SIGN),
            Err(StatusCode::PermissionDeny)
        ));
    }

    #[test]
    fn parse_typical_file() {
        let text = "\
            # vhsm policy\n\
            192.168.99.10 vm1 encrypt decrypt mac_gen mac_vfy sign verify get_pubkey get_cert key_generate\n\
            \n\
            192.168.99.11 vm2 sign verify get_pubkey   # restricted\n\
        ";
        let policy = Policy::parse(text).unwrap();
        assert_eq!(policy.num_entries(), 2);

        let vm1 = policy.lookup(IpAddr::V4(Ipv4Addr::new(192, 168, 99, 10))).unwrap();
        assert_eq!(vm1.vm_id, "vm1");
        assert_eq!(vm1.permitted_ops & PERM_KEY_GENERATE, PERM_KEY_GENERATE);

        let vm2 = policy.lookup(IpAddr::V4(Ipv4Addr::new(192, 168, 99, 11))).unwrap();
        assert_eq!(vm2.vm_id, "vm2");
        assert_eq!(vm2.permitted_ops, PERM_SIGN | PERM_VERIFY | PERM_GET_PUBKEY);
    }

    #[test]
    fn parse_rejects_unknown_perm() {
        let err = Policy::parse("192.168.99.10 vm1 encrypt fly")
            .err()
            .unwrap();
        assert!(err.contains("unknown permission 'fly'"), "got: {err}");
    }

    #[test]
    fn parse_rejects_bad_ip() {
        let err = Policy::parse("not.an.ip vm1 sign").err().unwrap();
        assert!(err.contains("bad IP"), "got: {err}");
    }
}
