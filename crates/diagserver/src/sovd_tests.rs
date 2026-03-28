use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use nv_store::block::MemBlockDevice;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::*;

use crate::ota;
use crate::sovd::router::create_router;
use crate::sovd::security::TestSecurityProvider;
use crate::sovd::state::{AppState, ModeStore, UploadStore};
use crate::manifest_provider::ManifestProvider;
use crate::suit_provider::SuitProvider;

// --- Test SUIT helpers ---

use sumo_crypto::{CryptoBackend, RustCryptoBackend};
use sumo_offboard::keygen;
use sumo_offboard::ImageManifestBuilder;

struct TestKeys {
    signing_key: sumo_offboard::CoseKey,
    trust_anchor: Vec<u8>,
}

fn generate_test_keys() -> TestKeys {
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let trust_anchor = signing_key.public_key_bytes();
    TestKeys {
        signing_key,
        trust_anchor,
    }
}

fn make_test_suit_envelope(
    keys: &TestKeys,
    component: &str,
    seq: u64,
    image: &[u8],
) -> Vec<u8> {
    let crypto = RustCryptoBackend::new();
    let digest = crypto.sha256(image);

    ImageManifestBuilder::new()
        .component_id(vec![component.to_string()])
        .sequence_number(seq)
        .payload_digest(&digest, image.len() as u64)
        .integrated_payload("#firmware".to_string(), image.to_vec())
        .build(&keys.signing_key)
        .unwrap()
}

fn test_provider(keys: &TestKeys) -> Arc<dyn crate::manifest_provider::ManifestProvider> {
    Arc::new(SuitProvider::new(keys.trust_anchor.clone()))
}

fn test_state(
    nv: Arc<Mutex<NvStore<MemBlockDevice>>>,
    uploads: Arc<Mutex<UploadStore>>,
    keys: &TestKeys,
) -> AppState<MemBlockDevice> {
    AppState {
        nv,
        uploads,
        manifest_provider: test_provider(keys),
        modes: Arc::new(Mutex::new(ModeStore::new())),
        security_provider: Arc::new(TestSecurityProvider),
    }
}

// --- App constructors ---

fn make_app() -> axum::Router {
    let keys = generate_test_keys();
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    let mut state = NvBootState::default();
    nv.write_boot_state(&mut state).unwrap();
    let nv = Arc::new(Mutex::new(nv));
    create_router(test_state(nv, Arc::new(Mutex::new(UploadStore::new())), &keys))
}

fn make_app_with_nv() -> (axum::Router, Arc<Mutex<NvStore<MemBlockDevice>>>) {
    let keys = generate_test_keys();
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    let mut state = NvBootState::default();
    nv.write_boot_state(&mut state).unwrap();
    let nv = Arc::new(Mutex::new(nv));
    let app_state = test_state(nv.clone(), Arc::new(Mutex::new(UploadStore::new())), &keys);
    (create_router(app_state), nv)
}

fn make_app_with_keys() -> (AppState<MemBlockDevice>, TestKeys) {
    let keys = generate_test_keys();
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    let mut boot = NvBootState::default();
    nv.write_boot_state(&mut boot).unwrap();
    let nv = Arc::new(Mutex::new(nv));
    let uploads = Arc::new(Mutex::new(UploadStore::new()));
    let state = test_state(nv, uploads, &keys);
    (state, keys)
}

/// Put component into programming+unlocked state for flash tests.
async fn unlock_for_flash(state: &AppState<MemBlockDevice>, component: &str) {
    // Switch to programming
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::put(&format!("/vehicle/v1/components/{component}/modes/session"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"value":"programming"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Request seed
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::put(&format!("/vehicle/v1/components/{component}/modes/security"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"value":"level1_requestseed"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let seed_str = body["seed"]["Request_Seed"].as_str().unwrap();

    // Parse seed and compute key (XOR 0xFF)
    let seed_bytes: Vec<u8> = seed_str
        .split_whitespace()
        .map(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
        .collect();
    let key_bytes: Vec<u8> = seed_bytes.iter().map(|b| b ^ 0xFF).collect();
    let key_hex: String = key_bytes.iter().map(|b| format!("{b:02x}")).collect();

    // Send key
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::put(&format!("/vehicle/v1/components/{component}/modes/security"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"value": "level1", "key": key_hex}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// --- HTTP helpers ---

async fn get(app: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn post(app: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(Request::post(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn put_json(app: axum::Router, uri: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(
            Request::put(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn delete(app: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(Request::delete(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    (status, json)
}

// ============================================================
// Health
// ============================================================

#[tokio::test]
async fn health_check() {
    let (status, json) = get(make_app(), "/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "ok");
    assert_eq!(json["components"], 3);
}

// ============================================================
// Components
// ============================================================

#[tokio::test]
async fn list_components_returns_three() {
    let (status, json) = get(make_app(), "/vehicle/v1/components").await;
    assert_eq!(status, StatusCode::OK);
    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    assert_eq!(items[0]["id"], "hyp");
    assert_eq!(items[1]["id"], "os1");
    assert_eq!(items[2]["id"], "os2");
}

#[tokio::test]
async fn get_component_os1() {
    let (status, json) = get(make_app(), "/vehicle/v1/components/os1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["id"], "os1");
    assert_eq!(json["name"], "OS1");
    assert!(json["capabilities"]["read_data"].as_bool().unwrap());
    assert!(!json["capabilities"]["io_control"].as_bool().unwrap());
}

#[tokio::test]
async fn get_component_not_found() {
    let (status, json) = get(make_app(), "/vehicle/v1/components/fake").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["error"], "not_found");
}

// ============================================================
// Data / Parameters
// ============================================================

#[tokio::test]
async fn list_parameters_has_standard_dids() {
    let (status, json) = get(make_app(), "/vehicle/v1/components/os1/data").await;
    assert_eq!(status, StatusCode::OK);
    let items = json["items"].as_array().unwrap();
    assert!(items.len() >= 21);
    let ids: Vec<&str> = items.iter().map(|i| i["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&"fw_version"));
    assert!(ids.contains(&"active_bank"));
    assert!(ids.contains(&"committed"));
    assert!(ids.contains(&"vin"));
}

#[tokio::test]
async fn read_dynamic_did_active_bank() {
    let (status, json) = get(make_app(), "/vehicle/v1/components/os1/data/active_bank").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["value"], "A");
    assert_eq!(json["did"], "FD00");
}

#[tokio::test]
async fn read_dynamic_did_committed() {
    let (status, json) = get(make_app(), "/vehicle/v1/components/os1/data/committed").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["value"], true);
}

#[tokio::test]
async fn read_dynamic_did_boot_count() {
    let (status, json) = get(make_app(), "/vehicle/v1/components/os1/data/boot_count").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["value"], 0);
}

#[tokio::test]
async fn read_factory_did_after_provision() {
    let (app, nv) = make_app_with_nv();
    {
        let mut nv = nv.lock().unwrap();
        let mut factory = NvFactory::default();
        let serial = b"SN12345";
        factory.serial_number[..serial.len()].copy_from_slice(serial);
        let vin = b"WVWZZZ3CZWE123456";
        factory.vin[..vin.len()].copy_from_slice(vin);
        nv.write_factory(&mut factory).unwrap();
    }
    let (status, json) = get(app, "/vehicle/v1/components/os1/data/serial_number").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["value"], "SN12345");
}

#[tokio::test]
async fn read_parameter_by_hex_did() {
    let (app, nv) = make_app_with_nv();
    {
        let mut nv = nv.lock().unwrap();
        let mut factory = NvFactory::default();
        factory.vin[..3].copy_from_slice(b"VIN");
        nv.write_factory(&mut factory).unwrap();
    }
    // F190 is VIN
    let (status, json) = get(app, "/vehicle/v1/components/os1/data/F190").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["id"], "vin");
    assert_eq!(json["did"], "F190");
}

#[tokio::test]
async fn read_parameter_not_found() {
    let (status, json) = get(make_app(), "/vehicle/v1/components/os1/data/nonexistent").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["error"], "not_found");
}

#[tokio::test]
async fn write_runtime_did() {
    let keys = generate_test_keys();
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    let mut state = NvBootState::default();
    nv.write_boot_state(&mut state).unwrap();
    let nv = Arc::new(Mutex::new(nv));
    let mk_state = || test_state(nv.clone(), Arc::new(Mutex::new(UploadStore::new())), &keys);

    let (status, json) = put_json(
        create_router(mk_state()),
        "/vehicle/v1/components/os1/data/FD10",
        serde_json::json!({"value": "hello"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["success"].as_bool().unwrap());

    // Read it back
    let (status, json) = get(
        create_router(mk_state()),
        "/vehicle/v1/components/os1/data/FD10",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["value"], "hello");
}

#[tokio::test]
async fn write_readonly_did_forbidden() {
    let (status, json) = put_json(
        make_app(),
        "/vehicle/v1/components/os1/data/fw_version",
        serde_json::json!({"value": "nope"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(json["error"], "forbidden");
}

#[tokio::test]
async fn list_parameters_includes_runtime_dids() {
    let keys = generate_test_keys();
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    let mut state = NvBootState::default();
    nv.write_boot_state(&mut state).unwrap();
    // Write a runtime DID
    crate::did::write_did(&mut nv, BankSet::Os1, 0xFD10, b"val").unwrap();

    let nv = Arc::new(Mutex::new(nv));
    let provider = test_provider(&keys);

    let (status, json) = get(
        create_router(test_state(nv.clone(), Arc::new(Mutex::new(UploadStore::new())), &keys)),
        "/vehicle/v1/components/os1/data",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let items = json["items"].as_array().unwrap();
    let ids: Vec<&str> = items.iter().map(|i| i["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&"runtime_FD10"));
}

// ============================================================
// Bank set isolation
// ============================================================

#[tokio::test]
async fn different_bank_sets_are_independent() {
    let keys = generate_test_keys();
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    let mut state = NvBootState::default();
    nv.write_boot_state(&mut state).unwrap();
    crate::did::write_did(&mut nv, BankSet::Os1, 0xFD10, b"os1val").unwrap();

    let nv = Arc::new(Mutex::new(nv));
    let mk_state = || test_state(nv.clone(), Arc::new(Mutex::new(UploadStore::new())), &keys);

    // os1 should have the DID
    let (status, json) = get(
        create_router(mk_state()),
        "/vehicle/v1/components/os1/data/FD10",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["value"], "os1val");

    // os2 should not
    let (status, _) = get(
        create_router(mk_state()),
        "/vehicle/v1/components/os2/data/FD10",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ============================================================
// Faults
// ============================================================

#[tokio::test]
async fn faults_empty_initially() {
    let (status, json) = get(make_app(), "/vehicle/v1/components/os1/faults").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["total_count"], 0);
    assert!(json["items"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn faults_and_clear() {
    let keys = generate_test_keys();
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    let mut state = NvBootState::default();
    nv.write_boot_state(&mut state).unwrap();
    // Write a DTC directly
    let bs = nv.read_boot_state().unwrap();
    let active = bs.banks[BankSet::Os1 as usize].active_bank;
    let mut runtime = nv.read_runtime(BankSet::Os1, active).unwrap_or_default();
    runtime.dtc_count = 1;
    runtime.dtcs[0] = DtcEntry {
        dtc_number: 0x00A301,
        status: 0x01,
    };
    nv.write_runtime(BankSet::Os1, active, &mut runtime).unwrap();

    let nv = Arc::new(Mutex::new(nv));
    let mk_state = || test_state(nv.clone(), Arc::new(Mutex::new(UploadStore::new())), &keys);

    let (status, json) = get(
        create_router(mk_state()),
        "/vehicle/v1/components/os1/faults",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["total_count"], 1);
    assert_eq!(json["items"][0]["dtc_code"], "00A301");
    assert!(json["items"][0]["active"].as_bool().unwrap());

    // Clear
    let (status, json) = delete(
        create_router(mk_state()),
        "/vehicle/v1/components/os1/faults",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["cleared_count"], 1);

    // Verify cleared
    let (status, json) = get(
        create_router(mk_state()),
        "/vehicle/v1/components/os1/faults",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["total_count"], 0);
}

// ============================================================
// Flash / Activation
// ============================================================

#[tokio::test]
async fn activation_state_committed() {
    let (status, json) = get(
        make_app(),
        "/vehicle/v1/components/os1/flash/activation",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["state"], "committed");
    assert!(json["supports_rollback"].as_bool().unwrap());
}

#[tokio::test]
async fn commit_when_already_committed_is_conflict() {
    let (status, json) = post(
        make_app(),
        "/vehicle/v1/components/os1/flash/commit",
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(json["error"], "conflict");
}

#[tokio::test]
async fn rollback_when_committed_is_conflict() {
    let (status, json) = post(
        make_app(),
        "/vehicle/v1/components/os1/flash/rollback",
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(json["error"], "conflict");
}

#[tokio::test]
async fn full_ota_commit_via_sovd() {
    let keys = generate_test_keys();
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    let mut boot_state = NvBootState::default();
    nv.write_boot_state(&mut boot_state).unwrap();

    // Install OTA via library (puts os1 in trial mode)
    let image = b"test-image-data";
    let mut meta = ota::ImageMeta::default();
    meta.fw_version[..5].copy_from_slice(b"2.0.0");
    meta.fw_secver = 1;
    meta.fw_seq = 1;
    ota::install(&mut nv, BankSet::Os1, image, &meta).unwrap();

    let nv = Arc::new(Mutex::new(nv));
    let mk_state = || test_state(nv.clone(), Arc::new(Mutex::new(UploadStore::new())), &keys);

    // Check activation shows trial
    let (status, json) = get(
        create_router(mk_state()),
        "/vehicle/v1/components/os1/flash/activation",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["state"], "trial");
    assert_eq!(json["active_version"].as_str().unwrap(), "2.0.0");

    // Commit via SOVD endpoint
    let (status, json) = post(
        create_router(mk_state()),
        "/vehicle/v1/components/os1/flash/commit",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["success"].as_bool().unwrap());

    // Verify committed
    let (status, json) = get(
        create_router(mk_state()),
        "/vehicle/v1/components/os1/flash/activation",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["state"], "committed");
}

#[tokio::test]
async fn full_ota_rollback_via_sovd() {
    let keys = generate_test_keys();
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    let mut boot_state = NvBootState::default();
    nv.write_boot_state(&mut boot_state).unwrap();

    // Install OTA
    let image = b"test-image-data";
    let mut meta = ota::ImageMeta::default();
    meta.fw_version[..5].copy_from_slice(b"2.0.0");
    meta.fw_secver = 1;
    meta.fw_seq = 1;
    ota::install(&mut nv, BankSet::Os1, image, &meta).unwrap();

    let nv = Arc::new(Mutex::new(nv));
    let mk_state = || test_state(nv.clone(), Arc::new(Mutex::new(UploadStore::new())), &keys);

    // Active bank should now be B
    let (_, json) = get(
        create_router(mk_state()),
        "/vehicle/v1/components/os1/data/active_bank",
    )
    .await;
    assert_eq!(json["value"], "B");

    // Rollback via SOVD
    let (status, json) = post(
        create_router(mk_state()),
        "/vehicle/v1/components/os1/flash/rollback",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["message"].as_str().unwrap().contains("bank A"));

    // Active bank should be back to A
    let (_, json) = get(
        create_router(mk_state()),
        "/vehicle/v1/components/os1/data/active_bank",
    )
    .await;
    assert_eq!(json["value"], "A");
}

// ============================================================
// FW Meta through SOVD
// ============================================================

#[tokio::test]
async fn read_fw_version_after_install() {
    let keys = generate_test_keys();
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    let mut boot_state = NvBootState::default();
    nv.write_boot_state(&mut boot_state).unwrap();

    let image = b"img";
    let mut meta = ota::ImageMeta::default();
    meta.fw_version[..5].copy_from_slice(b"3.1.0");
    meta.fw_secver = 1;
    meta.fw_seq = 1;
    ota::install(&mut nv, BankSet::Os1, image, &meta).unwrap();

    let nv = Arc::new(Mutex::new(nv));
    let provider = test_provider(&keys);

    let (status, json) = get(
        create_router(test_state(nv.clone(), Arc::new(Mutex::new(UploadStore::new())), &keys)),
        "/vehicle/v1/components/os1/data/fw_version",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["value"], "3.1.0");
}

// ============================================================
// CORS
// ============================================================

#[tokio::test]
async fn cors_headers_present() {
    let app = make_app();
    let resp = app
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert!(resp.headers().get("access-control-allow-origin").is_some());
}

// ============================================================
// Flash file upload/transfer (SUIT envelopes)
// ============================================================

#[tokio::test]
async fn flash_upload_suit_envelope() {
    let (state, keys) = make_app_with_keys();
    unlock_for_flash(&state, "os1").await;
    let image = vec![0xAA; 1024];
    let envelope = make_test_suit_envelope(&keys, "os1", 2, &image);

    // Upload
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/vehicle/v1/components/os1/files")
                .header("content-type", "application/octet-stream")
                .body(Body::from(envelope))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(body["file_id"].as_str().is_some());
}

#[tokio::test]
async fn flash_full_suit_flow() {
    let (state, keys) = make_app_with_keys();
    unlock_for_flash(&state, "os1").await;
    let image = vec![0xBB; 2048];
    let envelope = make_test_suit_envelope(&keys, "os1", 2, &image);

    // 1. Upload
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/vehicle/v1/components/os1/files")
                .header("content-type", "application/octet-stream")
                .body(Body::from(envelope))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let upload_id = body["file_id"].as_str().unwrap().to_string();

    // 2. Verify
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::post(&format!(
                "/vehicle/v1/components/os1/files/{upload_id}/verify"
            ))
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["state"], "verified");
    assert!(body["image_sha256"].as_str().unwrap().len() == 64);
    assert_eq!(body["image_size"], 2048);

    // 3. Start transfer
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/vehicle/v1/components/os1/flash/transfer")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"file_id": upload_id}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["state"], "completed");
    let transfer_id = body["transfer_id"].as_str().unwrap().to_string();

    // 4. Progress
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::get(&format!(
                "/vehicle/v1/components/os1/flash/transfer/{transfer_id}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["percent"], 100);

    // 5. Check activation state — should be "trial"
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::get("/vehicle/v1/components/os1/flash/activation")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["state"], "trial");

    // 6. Commit
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/vehicle/v1/components/os1/flash/commit")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 7. Verify committed
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::get("/vehicle/v1/components/os1/flash/activation")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["state"], "committed");
}

#[tokio::test]
async fn flash_upload_bad_envelope() {
    let (state, _keys) = make_app_with_keys();
    unlock_for_flash(&state, "os1").await;
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/vehicle/v1/components/os1/files")
                .header("content-type", "application/octet-stream")
                .body(Body::from(vec![0xFF; 100]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn flash_upload_wrong_component_rejected() {
    let (state, keys) = make_app_with_keys();
    unlock_for_flash(&state, "os1").await;
    let image = vec![0xCC; 512];
    // Envelope says "os2" but we upload to "os1"
    let envelope = make_test_suit_envelope(&keys, "os2", 1, &image);

    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/vehicle/v1/components/os1/files")
                .header("content-type", "application/octet-stream")
                .body(Body::from(envelope))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ============================================================
// SUIT provider unit tests
// ============================================================

#[test]
fn suit_provider_validates_good_envelope() {
    let keys = generate_test_keys();
    let provider = SuitProvider::new(keys.trust_anchor.clone());
    let image = vec![0xDD; 4096];
    let envelope = make_test_suit_envelope(&keys, "os1", 5, &image);

    let result = provider.validate(&envelope, 0).unwrap();
    assert_eq!(result.bank_set, BankSet::Os1);
    assert_eq!(result.image_meta.fw_seq, 5);
    assert_eq!(result.image_meta.fw_secver, 5);
    assert_eq!(result.image_data, image);
}

#[test]
fn suit_provider_rejects_wrong_key() {
    let keys = generate_test_keys();
    let other_keys = generate_test_keys(); // different key pair
    let provider = SuitProvider::new(other_keys.trust_anchor.clone());
    let image = vec![0xEE; 256];
    let envelope = make_test_suit_envelope(&keys, "os1", 1, &image);

    let result = provider.validate(&envelope, 0);
    assert!(result.is_err());
}

#[test]
fn suit_provider_rejects_rollback() {
    let keys = generate_test_keys();
    let provider = SuitProvider::new(keys.trust_anchor.clone());
    let image = vec![0xFF; 256];
    let envelope = make_test_suit_envelope(&keys, "os1", 3, &image);

    // min_security_ver=5 should reject seq=3
    let result = provider.validate(&envelope, 5);
    assert!(result.is_err());
}

#[test]
fn suit_provider_maps_component_to_bank_set() {
    let keys = generate_test_keys();
    let provider = SuitProvider::new(keys.trust_anchor.clone());

    for (comp, expected) in [
        ("hyp", BankSet::Hypervisor),
        ("os1", BankSet::Os1),
        ("os2", BankSet::Os2),
    ] {
        let image = vec![0x42; 128];
        let envelope = make_test_suit_envelope(&keys, comp, 1, &image);
        let result = provider.validate(&envelope, 0).unwrap();
        assert_eq!(result.bank_set, expected);
    }
}

// ============================================================
// Session / Security modes
// ============================================================

#[tokio::test]
async fn session_default_initially() {
    let (status, json) = get(make_app(), "/vehicle/v1/components/os1/modes/session").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["id"], "session");
    assert_eq!(json["value"], "default");
}

#[tokio::test]
async fn session_switch_to_programming() {
    let (state, _keys) = make_app_with_keys();
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::put("/vehicle/v1/components/os1/modes/session")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"value":"programming"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["value"], "programming");

    // Verify GET reflects the change
    let (status, json) = get(
        create_router(state.clone()),
        "/vehicle/v1/components/os1/modes/session",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["value"], "programming");
}

#[tokio::test]
async fn security_locked_initially() {
    let (status, json) = get(make_app(), "/vehicle/v1/components/os1/modes/security").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["id"], "security");
    assert_eq!(json["value"], "locked");
}

#[tokio::test]
async fn security_seed_key_flow() {
    let (state, _keys) = make_app_with_keys();

    // Switch to programming first
    let app = create_router(state.clone());
    app.oneshot(
        Request::put("/vehicle/v1/components/os1/modes/session")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"value":"programming"}"#))
            .unwrap(),
    )
    .await
    .unwrap();

    // Request seed
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::put("/vehicle/v1/components/os1/modes/security")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"value":"level1_requestseed"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(body["seed"]["Request_Seed"].as_str().is_some());

    // Parse seed, compute key (XOR 0xFF)
    let seed_str = body["seed"]["Request_Seed"].as_str().unwrap();
    let seed_bytes: Vec<u8> = seed_str
        .split_whitespace()
        .map(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
        .collect();
    let key_hex: String = seed_bytes.iter().map(|b| format!("{:02x}", b ^ 0xFF)).collect();

    // Send key
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::put("/vehicle/v1/components/os1/modes/security")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"value": "level1", "key": key_hex}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["value"], "level1");

    // GET should show unlocked
    let (status, json) = get(
        create_router(state.clone()),
        "/vehicle/v1/components/os1/modes/security",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["value"], "level1");
}

#[tokio::test]
async fn security_wrong_key_rejected() {
    let (state, _keys) = make_app_with_keys();

    // Programming session
    let app = create_router(state.clone());
    app.oneshot(
        Request::put("/vehicle/v1/components/os1/modes/session")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"value":"programming"}"#))
            .unwrap(),
    )
    .await
    .unwrap();

    // Request seed
    let app = create_router(state.clone());
    app.oneshot(
        Request::put("/vehicle/v1/components/os1/modes/security")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"value":"level1_requestseed"}"#))
            .unwrap(),
    )
    .await
    .unwrap();

    // Send wrong key
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::put("/vehicle/v1/components/os1/modes/security")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"value":"level1","key":"deadbeef"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn session_change_resets_security() {
    let (state, _keys) = make_app_with_keys();
    unlock_for_flash(&state, "os1").await;

    // Verify unlocked
    let (_, json) = get(
        create_router(state.clone()),
        "/vehicle/v1/components/os1/modes/security",
    )
    .await;
    assert_eq!(json["value"], "level1");

    // Switch session back to default
    let app = create_router(state.clone());
    app.oneshot(
        Request::put("/vehicle/v1/components/os1/modes/session")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"value":"default"}"#))
            .unwrap(),
    )
    .await
    .unwrap();

    // Security should be locked again
    let (_, json) = get(
        create_router(state.clone()),
        "/vehicle/v1/components/os1/modes/security",
    )
    .await;
    assert_eq!(json["value"], "locked");
}

// ============================================================
// Flash gating
// ============================================================

#[tokio::test]
async fn flash_upload_rejected_in_default_session() {
    let (state, keys) = make_app_with_keys();
    let image = vec![0xAA; 256];
    let envelope = make_test_suit_envelope(&keys, "os1", 1, &image);

    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/vehicle/v1/components/os1/files")
                .header("content-type", "application/octet-stream")
                .body(Body::from(envelope))
                .unwrap(),
        )
        .await
        .unwrap();
    // 409 — programming session required
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn flash_upload_rejected_when_locked() {
    let (state, keys) = make_app_with_keys();

    // Switch to programming but don't unlock
    let app = create_router(state.clone());
    app.oneshot(
        Request::put("/vehicle/v1/components/os1/modes/session")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"value":"programming"}"#))
            .unwrap(),
    )
    .await
    .unwrap();

    let image = vec![0xAA; 256];
    let envelope = make_test_suit_envelope(&keys, "os1", 1, &image);

    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/vehicle/v1/components/os1/files")
                .header("content-type", "application/octet-stream")
                .body(Body::from(envelope))
                .unwrap(),
        )
        .await
        .unwrap();
    // 403 — security unlock required
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn capabilities_show_sessions_and_security() {
    let (status, json) = get(make_app(), "/vehicle/v1/components/os1").await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["capabilities"]["sessions"].as_bool().unwrap());
    assert!(json["capabilities"]["security"].as_bool().unwrap());
}
