/// vHSM wire protocol types — matches vhsm_proto.h exactly.

pub const VHSM_MAGIC: [u8; 4] = *b"VHSM";
pub const VHSM_VERSION: u8 = 1;
pub const REQUEST_HEADER_SIZE: usize = 18;
pub const RESPONSE_HEADER_SIZE: usize = 20;
pub const MAX_KEY_ID: usize = 128;
pub const MAX_PAYLOAD: usize = 65536;
pub const MAX_RANDOM: usize = 1024;
pub const SESSION_TOKEN_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Op {
    Sign = 0x01,
    Verify = 0x02,
    Encrypt = 0x03,
    Decrypt = 0x04,
    Derive = 0x05,
    GetCert = 0x06,
    GetPubkey = 0x07,
    Random = 0x08,
    Register = 0x10,
    Status = 0x11,
    ProvisionIdentity = 0x12,
}

impl Op {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Op::Sign),
            0x02 => Some(Op::Verify),
            0x03 => Some(Op::Encrypt),
            0x04 => Some(Op::Decrypt),
            0x05 => Some(Op::Derive),
            0x06 => Some(Op::GetCert),
            0x07 => Some(Op::GetPubkey),
            0x08 => Some(Op::Random),
            0x10 => Some(Op::Register),
            0x11 => Some(Op::Status),
            0x12 => Some(Op::ProvisionIdentity),
            _ => None,
        }
    }

    /// ACL operation name (matches manifest format).
    pub fn acl_name(self) -> Option<&'static str> {
        match self {
            Op::Sign => Some("SIGN"),
            Op::Verify => Some("VERIFY"),
            Op::Encrypt => Some("ENCRYPT"),
            Op::Decrypt => Some("DECRYPT"),
            Op::Derive => Some("DERIVE"),
            Op::GetCert => Some("GET_CERT"),
            Op::GetPubkey => Some("GET_PUBKEY"),
            Op::Random | Op::Register | Op::Status | Op::ProvisionIdentity => None,
        }
    }
}

pub const FLAG_SESSION_TOKEN: u16 = 0x0001;
pub const FLAG_REGISTER_RESPONSE: u16 = 0x0002;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum StatusCode {
    Success = 0x00000000,
    AccessDenied = 0x00000001,
    KeyNotFound = 0x00000002,
    InvalidRequest = 0x00000004,
    NotRegistered = 0x00000007,
    CryptoError = 0x00000008,
    InternalError = 0xFFFFFFFF,
}

pub struct Request {
    pub op: u8,
    pub flags: u16,
    pub seq: u32,
    pub key_id: String,
    pub payload: Vec<u8>,
}

pub struct Response {
    pub op: u8,
    pub seq: u32,
    pub status: u32,
    pub result: Vec<u8>,
}

impl Response {
    pub fn ok(op: u8, seq: u32, result: Vec<u8>) -> Self {
        Self {
            op,
            seq,
            status: StatusCode::Success as u32,
            result,
        }
    }

    pub fn err(op: u8, seq: u32, status: StatusCode) -> Self {
        Self {
            op,
            seq,
            status: status as u32,
            result: Vec::new(),
        }
    }
}
