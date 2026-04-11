/// vHSM wire protocol types (v2) — matches vhsm_proto.h exactly.
///
/// See specs/vhsm/protocol.md (VHSM-PROTO-002) for the full specification.

// ---- Magic and version --------------------------------------------------

pub const VHSM_MAGIC: [u8; 3] = [0x56, 0x48, 0x53]; // "VHS"
pub const VHSM_VERSION: u8 = 0x02;
pub const REQUEST_HEADER_SIZE: usize = 16;
pub const RESPONSE_HEADER_SIZE: usize = 20;

// ---- Limits -------------------------------------------------------------

pub const MAX_PAYLOAD: usize = 65536;
pub const MAX_RANDOM: usize = 1024;
pub const MAX_HANDLES: usize = 64;
pub const LABEL_LEN: usize = 32;

// ---- Transport ----------------------------------------------------------

pub const VHSM_PORT: u32 = 5100;

// ---- Operation codes (uint32) -------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Op {
    // Guest-facing: crypto
    GetRandom = 0x0001,

    // Guest-facing: key management
    KeyGenerate = 0x0010,

    // Host-only: key management
    KeyImport = 0x0011,
    KeyDerive = 0x0012,
    KeyDelete = 0x0013,

    // Guest-facing: symmetric crypto
    Encrypt = 0x0020,
    Decrypt = 0x0021,

    // Guest-facing: MAC
    MacGenerate = 0x0030,
    MacVerify = 0x0031,

    // Guest-facing: asymmetric crypto
    Sign = 0x0040,
    Verify = 0x0041,

    // Guest-facing: queries
    GetHandleInfo = 0x0050,
    GetPubkey = 0x0051,
    GetCert = 0x0052,
}

impl Op {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0x0001 => Some(Op::GetRandom),
            0x0010 => Some(Op::KeyGenerate),
            0x0011 => Some(Op::KeyImport),
            0x0012 => Some(Op::KeyDerive),
            0x0013 => Some(Op::KeyDelete),
            0x0020 => Some(Op::Encrypt),
            0x0021 => Some(Op::Decrypt),
            0x0030 => Some(Op::MacGenerate),
            0x0031 => Some(Op::MacVerify),
            0x0040 => Some(Op::Sign),
            0x0041 => Some(Op::Verify),
            0x0050 => Some(Op::GetHandleInfo),
            0x0051 => Some(Op::GetPubkey),
            0x0052 => Some(Op::GetCert),
            _ => None,
        }
    }

    /// True if this operation is host-only (rejected over vsock from guests).
    pub fn is_host_only(self) -> bool {
        matches!(self, Op::KeyImport | Op::KeyDerive | Op::KeyDelete)
    }

    /// Permission bit required for this operation, if applicable.
    pub fn required_perm(self) -> Option<u32> {
        match self {
            Op::Encrypt => Some(PERM_ENCRYPT),
            Op::Decrypt => Some(PERM_DECRYPT),
            Op::MacGenerate => Some(PERM_MAC_GEN),
            Op::MacVerify => Some(PERM_MAC_VFY),
            Op::Sign => Some(PERM_SIGN),
            Op::Verify => Some(PERM_VERIFY),
            Op::KeyDerive => Some(PERM_DERIVE),
            Op::KeyDelete => Some(PERM_DELETE),
            Op::GetPubkey => Some(PERM_GET_PUBKEY),
            Op::GetCert => Some(PERM_GET_CERT),
            Op::KeyGenerate => Some(PERM_KEY_GENERATE),
            Op::GetRandom | Op::GetHandleInfo | Op::KeyImport => None,
        }
    }
}

// ---- Status codes (uint32) ----------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum StatusCode {
    Ok = 0x00000000,
    InvalidHandle = 0x00000001,
    PermissionDeny = 0x00000002,
    PolicyReject = 0x00000003,
    HseError = 0x00000004,
    InvalidParam = 0x00000005,
    NoResource = 0x00000006,
    StorageError = 0x00000007,
    CryptoError = 0x00000008,
    Internal = 0x00000009,
}

// ---- Algorithm identifiers (uint32) -------------------------------------

pub const ALG_AES_128: u32 = 0x0001;
pub const ALG_AES_256: u32 = 0x0002;
pub const ALG_HMAC_SHA256: u32 = 0x0010;
pub const ALG_ED25519: u32 = 0x0020;
pub const ALG_ECC_P256: u32 = 0x0021;

// ---- Permission bitmask (uint32) ----------------------------------------

pub const PERM_ENCRYPT: u32 = 1 << 0;
pub const PERM_DECRYPT: u32 = 1 << 1;
pub const PERM_MAC_GEN: u32 = 1 << 2;
pub const PERM_MAC_VFY: u32 = 1 << 3;
pub const PERM_SIGN: u32 = 1 << 4;
pub const PERM_VERIFY: u32 = 1 << 5;
pub const PERM_DERIVE: u32 = 1 << 6; // host-only
pub const PERM_DELETE: u32 = 1 << 7; // host-only
pub const PERM_GET_PUBKEY: u32 = 1 << 8;
pub const PERM_GET_CERT: u32 = 1 << 9;
pub const PERM_KEY_GENERATE: u32 = 1 << 10;

// ---- Well-known handles -------------------------------------------------

pub const HANDLE_INVALID: u32 = 0x0000;
pub const HANDLE_KEK: u32 = 0x0001;
pub const HANDLE_SW_AUTHORITY: u32 = 0x0002;
pub const HANDLE_DEVICE_DECRYPT: u32 = 0x0003;
pub const HANDLE_ECU_SIGNING: u32 = 0x0004;
pub const HANDLE_JWT_SIGNING: u32 = 0x0005;
pub const HANDLE_STORAGE: u32 = 0x0006;
pub const HANDLE_DYNAMIC_BASE: u32 = 0x0100;

pub fn handle_is_well_known(h: u32) -> bool {
    h >= 0x0001 && h < HANDLE_DYNAMIC_BASE
}

// ---- Wire format structures ---------------------------------------------

/// Parsed request (after header decoding).
pub struct Request {
    pub op: u32,
    pub session_id: u32,
    pub payload: Vec<u8>,
}

/// Response to encode on the wire.
pub struct Response {
    pub op: u32,
    pub session_id: u32,
    pub status: u32,
    pub payload: Vec<u8>,
}

impl Response {
    pub fn ok(op: u32, session_id: u32, payload: Vec<u8>) -> Self {
        Self {
            op,
            session_id,
            status: StatusCode::Ok as u32,
            payload,
        }
    }

    pub fn err(op: u32, session_id: u32, status: StatusCode) -> Self {
        Self {
            op,
            session_id,
            status: status as u32,
            payload: Vec::new(),
        }
    }
}
