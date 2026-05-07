/// Integration tests for vhsm-ssd (v2).
///
/// Tests the handler dispatch chain directly: build keystore, init handle
/// table + policy, call handle_request(), verify responses.
/// No network transport needed — tests the full protocol logic in-process.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use hsm::sim::SimHsm;
use hsm::HsmCryptoProvider;

use vhsm_ssd::handle_table::HandleTable;
use vhsm_ssd::handler::{self, CallerId};
use vhsm_ssd::policy::Policy;
use vhsm_ssd::proto::*;

static TEST_ID: AtomicU32 = AtomicU32::new(0);

/// Simulated callers for tests.
const TEST_VM: &str = "vm1";
const OTHER_VM: &str = "vm2";
const TEST_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 99, 10));
const OTHER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 99, 11));
const UNKNOWN_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 99, 99));

fn caller(ip: IpAddr, vm_id: &str) -> CallerId {
    CallerId {
        peer_ip: ip,
        vm_id: vm_id.to_string(),
    }
}

// --- Keystore + fixture setup ---

struct TestFixture {
    crypto: Arc<dyn HsmCryptoProvider>,
    handle_table: HandleTable,
    policy: Policy,
    keystore_path: PathBuf,
}

impl TestFixture {
    fn new() -> Self {
        let id = TEST_ID.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let keystore_path =
            std::env::temp_dir().join(format!("vhsm-ssd-test-v2-{pid}-{id}"));

        Self::build_keystore(&keystore_path);

        let hsm = SimHsm::new(
            PathBuf::from("unused"),
            keystore_path.clone(),
            5100,
        );
        let crypto: Arc<dyn HsmCryptoProvider> = Arc::new(hsm);

        // Init handle table with well-known handles
        let mut handle_table = HandleTable::new();
        handle_table.register_well_known(
            HANDLE_ECU_SIGNING,
            "mykey",
            ALG_ECC_P256,
            PERM_SIGN | PERM_VERIFY | PERM_GET_PUBKEY | PERM_GET_CERT,
        );
        handle_table.register_well_known(
            HANDLE_STORAGE,
            "storage-key",
            ALG_AES_256,
            PERM_ENCRYPT | PERM_DECRYPT,
        );
        // restricted-key: only accessible via handle owned by OTHER_VM
        let label = [0u8; LABEL_LEN];
        handle_table.allocate(
            "restricted-key",
            ALG_AES_256,
            PERM_ENCRYPT | PERM_DECRYPT,
            OTHER_VM,
            false,
            &label,
        );

        // Allow-all policy for TEST_VM, restricted for OTHER_VM
        let mut policy = Policy::empty();
        policy.add(
            TEST_IP,
            TEST_VM,
            PERM_SIGN | PERM_VERIFY | PERM_ENCRYPT | PERM_DECRYPT
                | PERM_GET_PUBKEY | PERM_GET_CERT | PERM_KEY_GENERATE,
        );
        policy.add(OTHER_IP, OTHER_VM, PERM_ENCRYPT | PERM_DECRYPT);

        Self {
            crypto,
            handle_table,
            policy,
            keystore_path,
        }
    }

    fn request(&mut self, caller: &CallerId, op: Op, payload: Vec<u8>) -> Response {
        let req = Request {
            op: op as u32,
            session_id: 1,
            payload,
        };
        handler::handle_request(&req, caller, &mut self.handle_table, &self.policy, &*self.crypto)
    }

    /// Helper: build payload with handle prefix + data.
    fn with_handle(handle: u32, data: &[u8]) -> Vec<u8> {
        let mut p = Vec::with_capacity(4 + data.len());
        p.extend_from_slice(&handle.to_le_bytes());
        p.extend_from_slice(data);
        p
    }

    fn build_keystore(path: &Path) {
        use hsm::payload::*;
        use p256::ecdsa::SigningKey;
        use rand::RngCore;

        let _ = std::fs::remove_dir_all(path);
        std::fs::create_dir_all(path).unwrap();

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
                    private_key: Some(mykey.to_bytes().to_vec()),
                    public_key: Some(mykey_pub.as_bytes().to_vec()),
                    certificate: Some(fake_cert),
                    allowed_guests: None,
                    allowed_ops: None,
                },
                KeySlotDef {
                    key_id: "storage-key".into(),
                    key_type: KEY_TYPE_AES_256,
                    private_key: Some(aes_key.to_vec()),
                    public_key: None,
                    certificate: None,
                    allowed_guests: None,
                    allowed_ops: None,
                },
                KeySlotDef {
                    key_id: "restricted-key".into(),
                    key_type: KEY_TYPE_AES_256,
                    private_key: Some(restricted_key.to_vec()),
                    public_key: None,
                    certificate: None,
                    allowed_guests: None,
                    allowed_ops: None,
                },
            ],
        };

        let hsm = SimHsm::new(
            PathBuf::from("unused"),
            path.to_path_buf(),
            5100,
        );
        hsm.write_keystore(&ks).unwrap();
        std::fs::write(path.join("provision_state"), b"1\n").unwrap();
    }
}

impl Drop for TestFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.keystore_path);
    }
}

// --- Tests ---

#[test]
fn random_bytes() {
    let mut fix = TestFixture::new();

    let count: u32 = 32;
    let resp = fix.request(&caller(TEST_IP, TEST_VM), Op::GetRandom, count.to_le_bytes().to_vec());

    assert_eq!(resp.status, StatusCode::Ok as u32, "random failed");
    assert_eq!(resp.payload.len(), 32);
    assert!(resp.payload.iter().any(|&b| b != 0));
}

#[test]
fn sign_and_verify() {
    let mut fix = TestFixture::new();

    // SIGN
    let data = b"hello world";
    let resp = fix.request(
        &caller(TEST_IP, TEST_VM),
        Op::Sign,
        TestFixture::with_handle(HANDLE_ECU_SIGNING, data),
    );
    assert_eq!(resp.status, StatusCode::Ok as u32, "sign failed");
    let sig = resp.payload;
    assert!(sig.len() >= 64 && sig.len() <= 80, "bad sig len: {}", sig.len());

    // VERIFY: handle(4) + sig_len(4) + sig + hash_len(4) + hash
    let mut vp = Vec::new();
    vp.extend_from_slice(&HANDLE_ECU_SIGNING.to_le_bytes());
    vp.extend_from_slice(&(sig.len() as u32).to_le_bytes());
    vp.extend_from_slice(&sig);
    vp.extend_from_slice(&(data.len() as u32).to_le_bytes());
    vp.extend_from_slice(data);

    let req = Request {
        op: Op::Verify as u32,
        session_id: 2,
        payload: vp,
    };
    let resp = handler::handle_request(
        &req, &caller(TEST_IP, TEST_VM), &mut fix.handle_table, &fix.policy, &*fix.crypto,
    );
    assert_eq!(resp.status, StatusCode::Ok as u32, "verify failed");
}

#[test]
fn verify_rejects_bad_signature() {
    let mut fix = TestFixture::new();

    // Construct a syntactically valid but wrong DER signature
    let mut bad = vec![0x30, 0x44, 0x02, 0x20];
    bad.extend_from_slice(&[0xFF; 32]);
    bad.extend_from_slice(&[0x02, 0x20]);
    bad.extend_from_slice(&[0xFF; 32]);

    let mut p = Vec::new();
    p.extend_from_slice(&HANDLE_ECU_SIGNING.to_le_bytes());
    p.extend_from_slice(&(bad.len() as u32).to_le_bytes());
    p.extend_from_slice(&bad);
    p.extend_from_slice(&(4u32).to_le_bytes());
    p.extend_from_slice(b"data");

    let req = Request {
        op: Op::Verify as u32,
        session_id: 1,
        payload: p,
    };
    let resp = handler::handle_request(
        &req, &caller(TEST_IP, TEST_VM), &mut fix.handle_table, &fix.policy, &*fix.crypto,
    );
    assert_eq!(resp.status, StatusCode::CryptoError as u32);
}

#[test]
fn encrypt_decrypt_roundtrip() {
    let mut fix = TestFixture::new();

    let plaintext = b"secret AES-GCM data";

    // ENCRYPT
    let resp = fix.request(
        &caller(TEST_IP, TEST_VM),
        Op::Encrypt,
        TestFixture::with_handle(HANDLE_STORAGE, plaintext),
    );
    assert_eq!(resp.status, StatusCode::Ok as u32, "encrypt failed");
    let ct = resp.payload;
    assert!(ct.len() >= 12 + plaintext.len() + 16);

    // DECRYPT
    let resp = fix.request(
        &caller(TEST_IP, TEST_VM),
        Op::Decrypt,
        TestFixture::with_handle(HANDLE_STORAGE, &ct),
    );
    assert_eq!(resp.status, StatusCode::Ok as u32, "decrypt failed");
    assert_eq!(resp.payload, plaintext);
}

#[test]
fn get_pubkey() {
    let mut fix = TestFixture::new();

    let resp = fix.request(
        &caller(TEST_IP, TEST_VM),
        Op::GetPubkey,
        HANDLE_ECU_SIGNING.to_le_bytes().to_vec(),
    );
    assert_eq!(resp.status, StatusCode::Ok as u32, "get_pubkey failed");
    // Response: pubkey_len(4) + pubkey
    assert!(resp.payload.len() >= 4);
    let pk_len = u32::from_le_bytes([
        resp.payload[0], resp.payload[1], resp.payload[2], resp.payload[3],
    ]) as usize;
    assert_eq!(pk_len, 91, "expected 91-byte SPKI DER");
    assert_eq!(resp.payload.len(), 4 + pk_len);
}

#[test]
fn get_cert() {
    let mut fix = TestFixture::new();

    let resp = fix.request(
        &caller(TEST_IP, TEST_VM),
        Op::GetCert,
        HANDLE_ECU_SIGNING.to_le_bytes().to_vec(),
    );
    assert_eq!(resp.status, StatusCode::Ok as u32, "get_cert failed");
    assert!(resp.payload.len() >= 4);
    let c_len = u32::from_le_bytes([
        resp.payload[0], resp.payload[1], resp.payload[2], resp.payload[3],
    ]) as usize;
    assert!(c_len > 0);
}

#[test]
fn get_handle_info() {
    let mut fix = TestFixture::new();

    let resp = fix.request(
        &caller(TEST_IP, TEST_VM),
        Op::GetHandleInfo,
        HANDLE_ECU_SIGNING.to_le_bytes().to_vec(),
    );
    assert_eq!(resp.status, StatusCode::Ok as u32, "handle_info failed");
    assert_eq!(resp.payload.len(), 48);
    let handle = u32::from_le_bytes([
        resp.payload[0], resp.payload[1], resp.payload[2], resp.payload[3],
    ]);
    let alg = u32::from_le_bytes([
        resp.payload[4], resp.payload[5], resp.payload[6], resp.payload[7],
    ]);
    assert_eq!(handle, HANDLE_ECU_SIGNING);
    assert_eq!(alg, ALG_ECC_P256);
}

#[test]
fn invalid_handle_rejected() {
    let mut fix = TestFixture::new();

    // Use a handle that doesn't exist
    let resp = fix.request(
        &caller(TEST_IP, TEST_VM),
        Op::Sign,
        TestFixture::with_handle(0xDEAD, b"data"),
    );
    assert_eq!(resp.status, StatusCode::InvalidHandle as u32);
}

#[test]
fn dynamic_handle_ownership() {
    let mut fix = TestFixture::new();

    // Dynamic handle created by OTHER_VM is not accessible by TEST_VM
    let dynamic_handle = HANDLE_DYNAMIC_BASE; // first dynamic handle allocated in fixture
    let resp = fix.request(
        &caller(TEST_IP, TEST_VM),
        Op::Encrypt,
        TestFixture::with_handle(dynamic_handle, b"test"),
    );
    assert_eq!(resp.status, StatusCode::InvalidHandle as u32,
        "TEST_VM should not access OTHER_VM's dynamic handle");

    // OTHER_VM can access its own handle
    let resp = fix.request(
        &caller(OTHER_IP, OTHER_VM),
        Op::Encrypt,
        TestFixture::with_handle(dynamic_handle, b"test"),
    );
    assert_eq!(resp.status, StatusCode::Ok as u32,
        "OTHER_VM should access its own handle");
}

#[test]
fn well_known_handles_shared() {
    let mut fix = TestFixture::new();

    // Both VMs can access well-known handles (if policy allows the op)
    let resp = fix.request(
        &caller(TEST_IP, TEST_VM),
        Op::Encrypt,
        TestFixture::with_handle(HANDLE_STORAGE, b"test"),
    );
    assert_eq!(resp.status, StatusCode::Ok as u32);

    let resp = fix.request(
        &caller(OTHER_IP, OTHER_VM),
        Op::Encrypt,
        TestFixture::with_handle(HANDLE_STORAGE, b"test"),
    );
    assert_eq!(resp.status, StatusCode::Ok as u32);
}

#[test]
fn policy_rejects_unknown_ip() {
    let mut fix = TestFixture::new();

    // UNKNOWN_IP is not in the policy
    let resp = fix.request(
        &caller(UNKNOWN_IP, "stranger"),
        Op::Sign,
        TestFixture::with_handle(HANDLE_ECU_SIGNING, b"data"),
    );
    assert_eq!(resp.status, StatusCode::PolicyReject as u32);
}

#[test]
fn policy_denies_unpermitted_op() {
    let mut fix = TestFixture::new();

    // OTHER_VM only has ENCRYPT|DECRYPT — not SIGN
    let resp = fix.request(
        &caller(OTHER_IP, OTHER_VM),
        Op::Sign,
        TestFixture::with_handle(HANDLE_ECU_SIGNING, b"data"),
    );
    assert_eq!(resp.status, StatusCode::PermissionDeny as u32);
}

#[test]
fn handle_permission_denies_wrong_op() {
    let mut fix = TestFixture::new();

    // HANDLE_ECU_SIGNING has SIGN|VERIFY|GET_PUBKEY|GET_CERT — not ENCRYPT
    let resp = fix.request(
        &caller(TEST_IP, TEST_VM),
        Op::Encrypt,
        TestFixture::with_handle(HANDLE_ECU_SIGNING, b"test"),
    );
    assert_eq!(resp.status, StatusCode::PermissionDeny as u32);
}

#[test]
fn host_only_ops_rejected() {
    let mut fix = TestFixture::new();

    let req = Request {
        op: Op::KeyImport as u32,
        session_id: 1,
        payload: vec![],
    };
    let resp = handler::handle_request(
        &req, &caller(TEST_IP, TEST_VM), &mut fix.handle_table, &fix.policy, &*fix.crypto,
    );
    assert_eq!(resp.status, StatusCode::PolicyReject as u32);
}

#[test]
fn unknown_op_rejected() {
    let mut fix = TestFixture::new();

    let req = Request {
        op: 0xFFFF,
        session_id: 1,
        payload: vec![],
    };
    let resp = handler::handle_request(
        &req, &caller(TEST_IP, TEST_VM), &mut fix.handle_table, &fix.policy, &*fix.crypto,
    );
    assert_eq!(resp.status, StatusCode::InvalidParam as u32);
}
