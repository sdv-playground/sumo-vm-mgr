/// Integration tests for vhsm-ssd.
///
/// Spins up a real server on TCP, connects as a client, and exercises
/// the full protocol: register, status, sign, verify, encrypt/decrypt,
/// derive, random, ACL enforcement.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hsm::linux::LinuxSimHsm;
use hsm::{HsmCryptoProvider, HsmProvider};

use vhsm_ssd::proto::*;
use vhsm_ssd::transport::TcpTransport;

static TEST_ID: AtomicU32 = AtomicU32::new(0);

// --- Test client helpers ---

fn write_request(
    w: &mut dyn Write,
    op: u8,
    flags: u16,
    seq: u32,
    key_id: &str,
    payload: &[u8],
) {
    let mut hdr = [0u8; REQUEST_HEADER_SIZE];
    hdr[0..4].copy_from_slice(&VHSM_MAGIC);
    hdr[4] = VHSM_VERSION;
    hdr[5] = op;
    hdr[6..8].copy_from_slice(&flags.to_le_bytes());
    hdr[8..12].copy_from_slice(&seq.to_le_bytes());
    hdr[12..14].copy_from_slice(&(key_id.len() as u16).to_le_bytes());
    hdr[14..18].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    w.write_all(&hdr).unwrap();
    if !key_id.is_empty() {
        w.write_all(key_id.as_bytes()).unwrap();
    }
    if !payload.is_empty() {
        w.write_all(payload).unwrap();
    }
    w.flush().unwrap();
}

fn read_response(r: &mut dyn Read) -> (u8, u32, u32, Vec<u8>) {
    let mut hdr = [0u8; RESPONSE_HEADER_SIZE];
    r.read_exact(&mut hdr).unwrap();
    assert_eq!(&hdr[0..4], &VHSM_MAGIC);
    assert_eq!(hdr[4], VHSM_VERSION);
    let op = hdr[5];
    let seq = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
    let status = u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]);
    let result_len = u32::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]) as usize;
    let mut result = vec![0u8; result_len];
    if result_len > 0 {
        r.read_exact(&mut result).unwrap();
    }
    (op, seq, status, result)
}

/// PROVISION_IDENTITY + REGISTER. Returns 32-byte session token.
fn provision_and_register(stream: &mut TcpStream, guest_id: &str) -> Vec<u8> {
    // Step 0: PROVISION_IDENTITY — get per-boot identity key from SSD
    let mut prov_payload = Vec::new();
    prov_payload.extend_from_slice(guest_id.as_bytes());
    prov_payload.push(0);
    write_request(stream, Op::ProvisionIdentity as u8, 0, 0, "", &prov_payload);
    let (_, _, status, scalar) = read_response(stream);
    assert_eq!(status, StatusCode::Success as u32, "provision_identity failed");
    assert_eq!(scalar.len(), 32, "expected 32-byte EC scalar");

    let signing_key =
        p256::ecdsa::SigningKey::from_bytes(scalar.as_slice().into()).unwrap();

    // Step 1: REGISTER phase 1 — get challenge
    let mut reg_payload = Vec::new();
    reg_payload.extend_from_slice(guest_id.as_bytes());
    reg_payload.push(0);
    reg_payload.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // sw_version
    reg_payload.extend_from_slice(&[0xAA; 32]); // nonce

    write_request(stream, Op::Register as u8, 0, 1, "", &reg_payload);
    let (op, seq, status, challenge) = read_response(stream);
    assert_eq!(op, Op::Register as u8);
    assert_eq!(seq, 1);
    assert_eq!(status, StatusCode::Success as u32, "register phase 1 failed");
    assert_eq!(challenge.len(), 64);

    // Step 2: REGISTER phase 2 — sign challenge
    let mut message = Vec::new();
    message.extend_from_slice(&challenge[0..32]);
    message.extend_from_slice(guest_id.as_bytes());
    message.extend_from_slice(&challenge[32..64]);

    let signature: ecdsa::der::Signature<p256::NistP256> = {
        use ecdsa::signature::Signer;
        signing_key.sign(&message)
    };

    write_request(
        stream,
        Op::Register as u8,
        FLAG_REGISTER_RESPONSE,
        2,
        "",
        &signature.to_bytes(),
    );
    let (_, _, status, token) = read_response(stream);
    assert_eq!(status, StatusCode::Success as u32, "register phase 2 failed");
    assert_eq!(token.len(), SESSION_TOKEN_LEN);
    token
}

fn with_token(token: &[u8], data: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(token.len() + data.len());
    p.extend_from_slice(token);
    p.extend_from_slice(data);
    p
}

// --- Keystore + server setup ---

struct TestFixture {
    port: u16,
    keystore_path: PathBuf,
    _handle: std::thread::JoinHandle<()>,
}

impl TestFixture {
    fn new() -> Self {
        let id = TEST_ID.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let keystore_path =
            std::env::temp_dir().join(format!("vhsm-ssd-test-{pid}-{id}"));

        Self::build_keystore(&keystore_path);

        let hsm = LinuxSimHsm::new(
            PathBuf::from("unused"),
            keystore_path.clone(),
            5555,
            Vec::new(),
        );
        let key_count = hsm.list_keys().map(|k| k.len() as u32).unwrap_or(0);
        let crypto: Arc<dyn HsmCryptoProvider> = Arc::new(hsm);

        let listener = TcpTransport::bind("127.0.0.1:0").unwrap();
        let port = listener.local_port();

        // Server thread: accept ONE connection, handle until EOF, then exit.
        let handle = std::thread::spawn(move || {
            let transport = vhsm_ssd::transport::Transport::Tcp(listener);
            let start_time = std::time::Instant::now();

            let mut conn = match transport.accept() {
                Ok(c) => c,
                Err(_) => return,
            };

            let mut sessions = vhsm_ssd::session::SessionManager::new(start_time);

            loop {
                let req = match vhsm_ssd::codec::read_request(conn.reader()) {
                    Ok(r) => r,
                    Err(_) => break,
                };
                let resp = vhsm_ssd::handler::handle_request(
                    &req,
                    &mut sessions,
                    &*crypto,
                    key_count,
                );
                if vhsm_ssd::codec::write_response(conn.writer(), &resp).is_err() {
                    break;
                }
            }
        });

        Self {
            port,
            keystore_path,
            _handle: handle,
        }
    }

    fn connect(&self) -> TcpStream {
        let s = TcpStream::connect(format!("127.0.0.1:{}", self.port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s
    }

    /// Provision identity + register as bali-vm-1, return session token.
    fn register(&self, stream: &mut TcpStream) -> Vec<u8> {
        provision_and_register(stream, "bali-vm-1")
    }

    fn build_keystore(path: &Path) {
        use hsm::payload::*;
        use p256::ecdsa::SigningKey;
        use rand::RngCore;

        let _ = std::fs::remove_dir_all(path);
        std::fs::create_dir_all(path).unwrap();

        // Generate "mykey" EC signing key
        let mykey = SigningKey::random(&mut rand::rngs::OsRng);
        let mykey_pub = mykey.verifying_key().to_encoded_point(false);

        // Fake certificate DER
        let fake_cert: Vec<u8> = [0x30, 0x82, 0x01, 0x00, 0x30, 0x81, 0xFC]
            .iter()
            .copied()
            .chain(std::iter::repeat(0xAA).take(252))
            .collect();

        let mut aes_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut aes_key);

        let mut restricted_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut restricted_key);

        let ks = HsmKeystore {
            schema_version: SCHEMA_VERSION,
            security_version: 1,
            identities: vec![],
            slots: vec![
                KeySlotDef {
                    key_id: "mykey".into(),
                    key_type: KEY_TYPE_EC_P256,
                    private_key: mykey.to_bytes().to_vec(),
                    public_key: Some(mykey_pub.as_bytes().to_vec()),
                    certificate: Some(fake_cert),
                    allowed_guests: Some(vec!["bali-vm-1".into()]),
                    allowed_ops: Some(vec![
                        OP_SIGN, OP_VERIFY, OP_GET_CERT, OP_GET_PUBKEY,
                    ]),
                },
                KeySlotDef {
                    key_id: "storage-key".into(),
                    key_type: KEY_TYPE_AES_256,
                    private_key: aes_key.to_vec(),
                    public_key: None,
                    certificate: None,
                    allowed_guests: Some(vec!["bali-vm-1".into()]),
                    allowed_ops: Some(vec![OP_ENCRYPT, OP_DECRYPT, OP_DERIVE]),
                },
                KeySlotDef {
                    key_id: "restricted-key".into(),
                    key_type: KEY_TYPE_AES_256,
                    private_key: restricted_key.to_vec(),
                    public_key: None,
                    certificate: None,
                    allowed_guests: Some(vec!["bali-vm-2".into()]),
                    allowed_ops: Some(vec![OP_ENCRYPT, OP_DECRYPT]),
                },
            ],
            kek_slot_index: None,
        };

        let hsm = LinuxSimHsm::new(
            PathBuf::from("unused"),
            path.to_path_buf(),
            5555,
            Vec::new(),
        );
        hsm.write_keystore(&ks).unwrap();
        std::fs::write(path.join("provision_state"), b"1\n").unwrap();
    }
}

impl Drop for TestFixture {
    fn drop(&mut self) {
        let _ = TcpStream::connect(format!("127.0.0.1:{}", self.port));
        let _ = std::fs::remove_dir_all(&self.keystore_path);
    }
}

// --- Tests ---

#[test]
fn status() {
    let fix = TestFixture::new();
    let mut s = fix.connect();

    write_request(&mut s, Op::Status as u8, 0, 1, "", &[]);
    let (op, seq, status, result) = read_response(&mut s);

    assert_eq!(op, Op::Status as u8);
    assert_eq!(seq, 1);
    assert_eq!(status, StatusCode::Success as u32);
    assert_eq!(result.len(), 8);
    let key_count = u32::from_le_bytes([result[4], result[5], result[6], result[7]]);
    assert_eq!(key_count, 3);
}

#[test]
fn register_and_sign_verify() {
    let fix = TestFixture::new();
    let mut s = fix.connect();
    let token = fix.register(&mut s);

    // SIGN
    let data = b"hello world";
    write_request(
        &mut s,
        Op::Sign as u8,
        FLAG_SESSION_TOKEN,
        3,
        "mykey",
        &with_token(&token, data),
    );
    let (_, _, status, sig) = read_response(&mut s);
    assert_eq!(status, StatusCode::Success as u32, "sign failed");
    assert!(sig.len() >= 64 && sig.len() <= 80, "bad sig len: {}", sig.len());

    // VERIFY
    let mut vp = Vec::new();
    vp.extend_from_slice(&token);
    vp.extend_from_slice(&(sig.len() as u32).to_le_bytes());
    vp.extend_from_slice(&sig);
    vp.extend_from_slice(data);
    write_request(&mut s, Op::Verify as u8, FLAG_SESSION_TOKEN, 4, "mykey", &vp);
    let (_, _, status, _) = read_response(&mut s);
    assert_eq!(status, StatusCode::Success as u32, "verify failed");
}

#[test]
fn verify_rejects_bad_signature() {
    let fix = TestFixture::new();
    let mut s = fix.connect();
    let token = fix.register(&mut s);

    // Construct a syntactically valid but wrong DER signature
    let mut bad = vec![0x30, 0x44, 0x02, 0x20];
    bad.extend_from_slice(&[0xFF; 32]);
    bad.extend_from_slice(&[0x02, 0x20]);
    bad.extend_from_slice(&[0xFF; 32]);

    let mut p = Vec::new();
    p.extend_from_slice(&token);
    p.extend_from_slice(&(bad.len() as u32).to_le_bytes());
    p.extend_from_slice(&bad);
    p.extend_from_slice(b"data");
    write_request(&mut s, Op::Verify as u8, FLAG_SESSION_TOKEN, 3, "mykey", &p);
    let (_, _, status, _) = read_response(&mut s);
    assert_eq!(status, StatusCode::CryptoError as u32);
}

#[test]
fn encrypt_decrypt_roundtrip() {
    let fix = TestFixture::new();
    let mut s = fix.connect();
    let token = fix.register(&mut s);

    let plaintext = b"secret AES-GCM data";

    // ENCRYPT
    write_request(
        &mut s,
        Op::Encrypt as u8,
        FLAG_SESSION_TOKEN,
        3,
        "storage-key",
        &with_token(&token, plaintext),
    );
    let (_, _, status, ct) = read_response(&mut s);
    assert_eq!(status, StatusCode::Success as u32, "encrypt failed");
    assert!(ct.len() >= 12 + plaintext.len() + 16);

    // DECRYPT
    write_request(
        &mut s,
        Op::Decrypt as u8,
        FLAG_SESSION_TOKEN,
        4,
        "storage-key",
        &with_token(&token, &ct),
    );
    let (_, _, status, pt) = read_response(&mut s);
    assert_eq!(status, StatusCode::Success as u32, "decrypt failed");
    assert_eq!(pt, plaintext);
}

#[test]
fn random_bytes() {
    let fix = TestFixture::new();
    let mut s = fix.connect();
    let token = fix.register(&mut s);

    let count: u32 = 32;
    write_request(
        &mut s,
        Op::Random as u8,
        FLAG_SESSION_TOKEN,
        3,
        "",
        &with_token(&token, &count.to_le_bytes()),
    );
    let (_, _, status, bytes) = read_response(&mut s);
    assert_eq!(status, StatusCode::Success as u32, "random failed");
    assert_eq!(bytes.len(), 32);
    assert!(bytes.iter().any(|&b| b != 0));
}

#[test]
fn hkdf_derive() {
    let fix = TestFixture::new();
    let mut s = fix.connect();
    let token = fix.register(&mut s);

    let ctx = b"test-context";
    write_request(
        &mut s,
        Op::Derive as u8,
        FLAG_SESSION_TOKEN,
        3,
        "storage-key",
        &with_token(&token, ctx),
    );
    let (_, _, status, d1) = read_response(&mut s);
    assert_eq!(status, StatusCode::Success as u32, "derive failed");
    assert_eq!(d1.len(), 32);

    // Same context → same result (deterministic)
    write_request(
        &mut s,
        Op::Derive as u8,
        FLAG_SESSION_TOKEN,
        4,
        "storage-key",
        &with_token(&token, ctx),
    );
    let (_, _, _, d2) = read_response(&mut s);
    assert_eq!(d1, d2, "HKDF should be deterministic");
}

#[test]
fn get_pubkey() {
    let fix = TestFixture::new();
    let mut s = fix.connect();
    let token = fix.register(&mut s);

    write_request(
        &mut s,
        Op::GetPubkey as u8,
        FLAG_SESSION_TOKEN,
        3,
        "mykey",
        &with_token(&token, &[]),
    );
    let (_, _, status, pk) = read_response(&mut s);
    assert_eq!(status, StatusCode::Success as u32, "get_pubkey failed");
    assert_eq!(pk.len(), 91, "expected 91-byte SPKI DER");
}

#[test]
fn get_cert() {
    let fix = TestFixture::new();
    let mut s = fix.connect();
    let token = fix.register(&mut s);

    write_request(
        &mut s,
        Op::GetCert as u8,
        FLAG_SESSION_TOKEN,
        3,
        "mykey",
        &with_token(&token, &[]),
    );
    let (_, _, status, cert) = read_response(&mut s);
    assert_eq!(status, StatusCode::Success as u32, "get_cert failed");
    assert!(!cert.is_empty());
}

#[test]
fn acl_denies_wrong_guest() {
    let fix = TestFixture::new();
    let mut s = fix.connect();
    let token = fix.register(&mut s); // registered as bali-vm-1

    // restricted-key only allows bali-vm-2
    write_request(
        &mut s,
        Op::Encrypt as u8,
        FLAG_SESSION_TOKEN,
        3,
        "restricted-key",
        &with_token(&token, b"test"),
    );
    let (_, _, status, _) = read_response(&mut s);
    assert_eq!(status, StatusCode::AccessDenied as u32);
}

#[test]
fn acl_denies_wrong_op() {
    let fix = TestFixture::new();
    let mut s = fix.connect();
    let token = fix.register(&mut s);

    // mykey only allows SIGN,VERIFY,GET_CERT,GET_PUBKEY — not ENCRYPT
    write_request(
        &mut s,
        Op::Encrypt as u8,
        FLAG_SESSION_TOKEN,
        3,
        "mykey",
        &with_token(&token, b"test"),
    );
    let (_, _, status, _) = read_response(&mut s);
    assert_eq!(status, StatusCode::AccessDenied as u32);
}

#[test]
fn key_not_found() {
    let fix = TestFixture::new();
    let mut s = fix.connect();
    let token = fix.register(&mut s);

    write_request(
        &mut s,
        Op::Sign as u8,
        FLAG_SESSION_TOKEN,
        3,
        "no-such-key",
        &with_token(&token, b"data"),
    );
    let (_, _, status, _) = read_response(&mut s);
    assert_eq!(status, StatusCode::KeyNotFound as u32);
}

#[test]
fn not_registered_rejected() {
    let fix = TestFixture::new();
    let mut s = fix.connect();

    // No session token flag → rejected
    write_request(&mut s, Op::Sign as u8, 0, 1, "mykey", b"test");
    let (_, _, status, _) = read_response(&mut s);
    assert_eq!(status, StatusCode::NotRegistered as u32);
}
