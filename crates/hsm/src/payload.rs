/// HSM key material payload — CBOR schema for SUIT envelope contents.
///
/// This defines the binary format carried inside a SUIT envelope with
/// component ID `["hsm", "keys"]`. The same schema is used by both the
/// Linux simulation backend and future QNX HSM firmware.
///
/// # Wire format (CBOR, integer keys)
///
/// ```text
/// HsmKeystore = {
///   0: uint,              ; schema_version (1)
///   1: uint,              ; security_version
///   2: [* Identity],      ; guest identities
///   3: [* KeySlot],       ; key slots
///   4: ?uint,             ; kek_slot_index
/// }
///
/// Identity = {
///   0: tstr,              ; identity_id
///   1: bstr,              ; public_key (EC-P256 uncompressed, 65 bytes)
/// }
///
/// KeySlot = {
///   0: tstr,              ; key_id
///   1: uint,              ; key_type (0 = EC-P256, 1 = AES-256)
///   2: bstr,              ; private_key
///   3: ?bstr,             ; public_key (EC-P256 only)
///   4: ?bstr,             ; certificate (X.509 DER)
///   5: ?[* tstr],         ; allowed_guests
///   6: ?[* uint],         ; allowed_ops
/// }
/// ```

use serde::{Deserialize, Serialize};

use crate::KeyType;

/// Current schema version. Bump when breaking changes are made.
pub const SCHEMA_VERSION: u64 = 1;

/// Well-known factory KEK — used to encrypt the first provisioning envelope.
///
/// This is NOT real security. The private key is published in the spec.
/// Its purpose is to ensure the same encrypt→decrypt code path is used
/// for both factory and re-provision, eliminating an `if encrypted` branch.
///
/// On re-provision, the real KEK (from slot 0) replaces this.
///
/// EC-P256 key with private scalar = 1 (public key = generator point G).
pub const FACTORY_KEK_SCALAR: [u8; 32] = {
    let mut s = [0u8; 32];
    s[31] = 1;
    s
};

/// Factory KEK public key (P-256 generator point G, uncompressed).
#[rustfmt::skip]
pub const FACTORY_KEK_PUBLIC: [u8; 65] = [
    0x04,
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
    0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
    0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
    0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
    0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5,
];

/// Top-level keystore payload inside the SUIT envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmKeystore {
    /// Schema version (must be 1).
    #[serde(rename = "0")]
    pub schema_version: u64,

    /// Security version — must exceed current value on re-provision.
    #[serde(rename = "1")]
    pub security_version: u64,

    /// Guest identities (for challenge-response registration).
    #[serde(rename = "2")]
    pub identities: Vec<IdentityDef>,

    /// Key slots.
    #[serde(rename = "3")]
    pub slots: Vec<KeySlotDef>,

    /// Index into `slots` for the bootstrap KEK (EC-P256).
    /// The KEK's public key is used to encrypt future provisioning envelopes.
    #[serde(rename = "4", default, skip_serializing_if = "Option::is_none")]
    pub kek_slot_index: Option<u64>,
}

/// Guest identity for challenge-response registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityDef {
    /// Guest identifier (e.g. "bali-vm-1").
    #[serde(rename = "0")]
    pub identity_id: String,

    /// EC-P256 public key (65 bytes, uncompressed: 0x04 || x || y).
    #[serde(rename = "1", with = "serde_bytes")]
    pub public_key: Vec<u8>,
}

/// A single key slot in the HSM keystore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySlotDef {
    /// Key identifier (e.g. "jwt-signing", "storage-key").
    #[serde(rename = "0")]
    pub key_id: String,

    /// Key type: 0 = EC-P256, 1 = AES-256.
    #[serde(rename = "1")]
    pub key_type: u64,

    /// Private key material.
    /// - EC-P256: 32-byte scalar (big-endian).
    /// - AES-256: 32 random bytes.
    #[serde(rename = "2", with = "serde_bytes")]
    pub private_key: Vec<u8>,

    /// Public key (EC-P256 only, 65 bytes uncompressed).
    #[serde(rename = "3", default, skip_serializing_if = "Option::is_none", with = "serde_bytes_opt")]
    pub public_key: Option<Vec<u8>>,

    /// X.509 certificate (DER-encoded).
    #[serde(rename = "4", default, skip_serializing_if = "Option::is_none", with = "serde_bytes_opt")]
    pub certificate: Option<Vec<u8>>,

    /// Guest identities allowed to use this key.
    #[serde(rename = "5", default, skip_serializing_if = "Option::is_none")]
    pub allowed_guests: Option<Vec<String>>,

    /// Allowed operations (indices into: sign, verify, encrypt, decrypt,
    /// derive, get_cert, get_pubkey).
    #[serde(rename = "6", default, skip_serializing_if = "Option::is_none")]
    pub allowed_ops: Option<Vec<u64>>,
}

/// Key type constants for the CBOR wire format.
pub const KEY_TYPE_EC_P256: u64 = 0;
pub const KEY_TYPE_AES_256: u64 = 1;

/// Operation indices for the `allowed_ops` field.
pub const OP_SIGN: u64 = 0;
pub const OP_VERIFY: u64 = 1;
pub const OP_ENCRYPT: u64 = 2;
pub const OP_DECRYPT: u64 = 3;
pub const OP_DERIVE: u64 = 4;
pub const OP_GET_CERT: u64 = 5;
pub const OP_GET_PUBKEY: u64 = 6;

impl KeySlotDef {
    /// Convert the wire-format key type to the crate's `KeyType` enum.
    pub fn parsed_key_type(&self) -> Option<KeyType> {
        match self.key_type {
            KEY_TYPE_EC_P256 => Some(KeyType::EcP256),
            KEY_TYPE_AES_256 => Some(KeyType::Aes256),
            _ => None,
        }
    }

    /// Convert `allowed_ops` indices to the vhsm-test-ssd op name strings.
    pub fn ops_as_strings(&self) -> Option<Vec<&'static str>> {
        self.allowed_ops.as_ref().map(|ops| {
            ops.iter()
                .filter_map(|op| match *op {
                    OP_SIGN => Some("SIGN"),
                    OP_VERIFY => Some("VERIFY"),
                    OP_ENCRYPT => Some("ENCRYPT"),
                    OP_DECRYPT => Some("DECRYPT"),
                    OP_DERIVE => Some("DERIVE"),
                    OP_GET_CERT => Some("GET_CERT"),
                    OP_GET_PUBKEY => Some("GET_PUBKEY"),
                    _ => None,
                })
                .collect()
        })
    }
}

/// Serialize an `HsmKeystore` to CBOR bytes.
pub fn encode(keystore: &HsmKeystore) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(keystore, &mut buf)
        .map_err(|e| format!("CBOR encode: {e}"))?;
    Ok(buf)
}

/// Deserialize an `HsmKeystore` from CBOR bytes.
pub fn decode(data: &[u8]) -> Result<HsmKeystore, String> {
    let ks: HsmKeystore = ciborium::from_reader(data)
        .map_err(|e| format!("CBOR decode: {e}"))?;
    if ks.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "unsupported schema version {} (expected {SCHEMA_VERSION})",
            ks.schema_version
        ));
    }
    Ok(ks)
}

/// Serde helper for `Option<Vec<u8>>` as CBOR bstr.
mod serde_bytes_opt {
    use serde::{self, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serde_bytes::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::Deserialize;
        let opt: Option<serde_bytes::ByteBuf> = Option::deserialize(deserializer)?;
        Ok(opt.map(|b| b.into_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_keystore(num_slots: usize) -> HsmKeystore {
        let mut slots = Vec::with_capacity(num_slots);

        // KEK slot (always first)
        slots.push(KeySlotDef {
            key_id: "kek".to_string(),
            key_type: KEY_TYPE_EC_P256,
            private_key: vec![0xAA; 32],
            public_key: Some({
                let mut pk = vec![0x04]; // uncompressed prefix
                pk.extend_from_slice(&[0xBB; 32]); // x
                pk.extend_from_slice(&[0xCC; 32]); // y
                pk
            }),
            certificate: None,
            allowed_guests: None,
            allowed_ops: None,
        });

        // Generate remaining slots
        for i in 1..num_slots {
            if i % 3 == 0 {
                // AES-256 key
                slots.push(KeySlotDef {
                    key_id: format!("aes-key-{i}"),
                    key_type: KEY_TYPE_AES_256,
                    private_key: vec![(i & 0xFF) as u8; 32],
                    public_key: None,
                    certificate: None,
                    allowed_guests: Some(vec!["bali-vm-1".into()]),
                    allowed_ops: Some(vec![OP_ENCRYPT, OP_DECRYPT]),
                });
            } else {
                // EC-P256 key
                slots.push(KeySlotDef {
                    key_id: format!("ec-key-{i}"),
                    key_type: KEY_TYPE_EC_P256,
                    private_key: vec![(i & 0xFF) as u8; 32],
                    public_key: Some({
                        let mut pk = vec![0x04];
                        pk.extend_from_slice(&vec![(i & 0xFF) as u8; 32]);
                        pk.extend_from_slice(&vec![((i + 1) & 0xFF) as u8; 32]);
                        pk
                    }),
                    certificate: if i % 5 == 0 {
                        Some(vec![0x30, 0x82, 0x01, 0x00]) // fake DER prefix
                    } else {
                        None
                    },
                    allowed_guests: Some(vec!["bali-vm-1".into()]),
                    allowed_ops: Some(vec![OP_SIGN, OP_VERIFY, OP_GET_PUBKEY]),
                });
            }
        }

        HsmKeystore {
            schema_version: SCHEMA_VERSION,
            security_version: 1,
            identities: vec![IdentityDef {
                identity_id: "bali-vm-1".to_string(),
                public_key: {
                    let mut pk = vec![0x04];
                    pk.extend_from_slice(&[0x11; 32]);
                    pk.extend_from_slice(&[0x22; 32]);
                    pk
                },
            }],
            slots,
            kek_slot_index: Some(0),
        }
    }

    #[test]
    fn roundtrip_small() {
        let ks = sample_keystore(5);
        let encoded = encode(&ks).unwrap();
        let decoded = decode(&encoded).unwrap();

        assert_eq!(decoded.schema_version, SCHEMA_VERSION);
        assert_eq!(decoded.security_version, 1);
        assert_eq!(decoded.slots.len(), 5);
        assert_eq!(decoded.identities.len(), 1);
        assert_eq!(decoded.kek_slot_index, Some(0));
        assert_eq!(decoded.slots[0].key_id, "kek");
        assert_eq!(decoded.slots[0].private_key.len(), 32);
        assert_eq!(decoded.slots[0].public_key.as_ref().unwrap().len(), 65);
    }

    #[test]
    fn roundtrip_100_slots() {
        let ks = sample_keystore(100);
        let encoded = encode(&ks).unwrap();

        // ~15KB for 100 slots — verify it's reasonable
        assert!(encoded.len() < 50_000, "encoded size: {}", encoded.len());

        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.slots.len(), 100);

        // Spot check a few slots
        assert_eq!(decoded.slots[0].key_id, "kek");
        assert_eq!(decoded.slots[0].key_type, KEY_TYPE_EC_P256);
        assert_eq!(decoded.slots[3].key_id, "aes-key-3");
        assert_eq!(decoded.slots[3].key_type, KEY_TYPE_AES_256);
        assert!(decoded.slots[3].public_key.is_none());
    }

    #[test]
    fn bad_schema_version() {
        let mut ks = sample_keystore(1);
        ks.schema_version = 99;
        let encoded = encode(&ks).unwrap();
        let err = decode(&encoded).unwrap_err();
        assert!(err.contains("unsupported schema version"));
    }

    #[test]
    fn ops_as_strings() {
        let slot = KeySlotDef {
            key_id: "test".into(),
            key_type: KEY_TYPE_EC_P256,
            private_key: vec![0; 32],
            public_key: None,
            certificate: None,
            allowed_guests: None,
            allowed_ops: Some(vec![OP_SIGN, OP_VERIFY, OP_GET_PUBKEY]),
        };
        let ops = slot.ops_as_strings().unwrap();
        assert_eq!(ops, vec!["SIGN", "VERIFY", "GET_PUBKEY"]);
    }

    #[test]
    fn parsed_key_type() {
        let ec = KeySlotDef {
            key_id: "x".into(),
            key_type: KEY_TYPE_EC_P256,
            private_key: vec![],
            public_key: None,
            certificate: None,
            allowed_guests: None,
            allowed_ops: None,
        };
        assert_eq!(ec.parsed_key_type(), Some(KeyType::EcP256));

        let aes = KeySlotDef {
            key_id: "y".into(),
            key_type: KEY_TYPE_AES_256,
            private_key: vec![],
            public_key: None,
            certificate: None,
            allowed_guests: None,
            allowed_ops: None,
        };
        assert_eq!(aes.parsed_key_type(), Some(KeyType::Aes256));
    }
}
