/// Integration tests for VmBackend via sovd-api.
///
/// These test the full HTTP flow through sovd-api's router, ensuring
/// our DiagnosticBackend implementation works correctly with the
/// standard SOVD REST API.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use nv_store::block::MemBlockDevice;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::*;

use sovd_core::DiagnosticBackend;

use crate::backend::VmBackend;
use crate::manifest_provider::ManifestProvider;
use crate::ota;
use crate::sovd::security::TestSecurityProvider;
use crate::suit_provider::SuitProvider;

use sumo_crypto::{CryptoBackend, RustCryptoBackend};
use sumo_offboard::keygen;
use sumo_offboard::ImageManifestBuilder;

// --- Test helpers ---

struct TestKeys {
    signing_key: sumo_offboard::CoseKey,
    trust_anchor: Vec<u8>,
}

fn generate_test_keys() -> TestKeys {
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let trust_anchor = signing_key.public_key_bytes();
    TestKeys { signing_key, trust_anchor }
}

fn make_test_suit_envelope(keys: &TestKeys, component: &str, seq: u64, image: &[u8]) -> Vec<u8> {
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

fn make_router() -> (axum::Router, Arc<Mutex<NvStore<MemBlockDevice>>>, TestKeys) {
    let keys = generate_test_keys();
    let manifest_provider: Arc<dyn ManifestProvider> =
        Arc::new(SuitProvider::new(keys.trust_anchor.clone()));
    let security_provider = Arc::new(TestSecurityProvider);

    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    let mut boot_state = NvBootState::default();
    nv.write_boot_state(&mut boot_state).unwrap();
    let nv = Arc::new(Mutex::new(nv));

    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    for (id, set) in [("hyp", BankSet::Hypervisor), ("os1", BankSet::Os1), ("os2", BankSet::Os2)] {
        backends.insert(
            id.to_string(),
            Arc::new(VmBackend::new(set, nv.clone(), manifest_provider.clone(), security_provider.clone())),
        );
    }

    let state = sovd_api::AppState::new(backends);
    let router = sovd_api::create_router(state);
    (router, nv, keys)
}

async fn get(router: &axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let resp = router
        .clone()
        .oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn put_json(router: &axum::Router, uri: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let resp = router
        .clone()
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
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn post_bytes(router: &axum::Router, uri: &str, data: Vec<u8>) -> (StatusCode, serde_json::Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::post(uri)
                .header("content-type", "application/octet-stream")
                .body(Body::from(data))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn post_json(router: &axum::Router, uri: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::post(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn post_empty(router: &axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let resp = router
        .clone()
        .oneshot(Request::post(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn delete(router: &axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let resp = router
        .clone()
        .oneshot(Request::delete(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// Unlock a component: switch to programming + seed/key flow.
async fn unlock_for_flash(router: &axum::Router, component: &str) {
    put_json(router, &format!("/vehicle/v1/components/{component}/modes/session"),
        serde_json::json!({"value": "programming"})).await;

    let (_, seed_resp) = put_json(router,
        &format!("/vehicle/v1/components/{component}/modes/security"),
        serde_json::json!({"value": "level1_requestseed"})).await;

    // Parse "0xf4 0x7b 0x82 0x92" format from Request_Seed
    let seed_str = seed_resp["seed"]["Request_Seed"].as_str().unwrap();
    let seed_bytes: Vec<u8> = seed_str
        .split_whitespace()
        .map(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
        .collect();
    let key_hex: String = seed_bytes.iter().map(|b| format!("{:02x}", b ^ 0xFF)).collect();

    put_json(router, &format!("/vehicle/v1/components/{component}/modes/security"),
        serde_json::json!({"value": "level1", "key": key_hex})).await;
}

// ============================================================
// Health & Components
// ============================================================

#[tokio::test]
async fn health_check() {
    let (router, _, _) = make_router();
    let resp = router
        .clone()
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn list_components() {
    let (router, _, _) = make_router();
    let (status, json) = get(&router, "/vehicle/v1/components").await;
    assert_eq!(status, StatusCode::OK);
    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
}

#[tokio::test]
async fn get_component_os1() {
    let (router, _, _) = make_router();
    let (status, json) = get(&router, "/vehicle/v1/components/os1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["id"], "os1");
    assert!(json["capabilities"]["sessions"].as_bool().unwrap());
    assert!(json["capabilities"]["security"].as_bool().unwrap());
    assert!(json["capabilities"]["software_update"].as_bool().unwrap());
}

// ============================================================
// Data / Parameters
// ============================================================

#[tokio::test]
async fn list_parameters() {
    let (router, _, _) = make_router();
    let (status, json) = get(&router, "/vehicle/v1/components/os1/data").await;
    assert_eq!(status, StatusCode::OK);
    let items = json["items"].as_array().unwrap();
    assert!(items.len() >= 21);
}

#[tokio::test]
async fn read_active_bank() {
    let (router, _, _) = make_router();
    let (status, json) = get(&router, "/vehicle/v1/components/os1/data/active_bank").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["value"], "A");
}

#[tokio::test]
async fn read_committed() {
    let (router, _, _) = make_router();
    let (status, json) = get(&router, "/vehicle/v1/components/os1/data/committed").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["value"], true);
}

// ============================================================
// Session / Security
// ============================================================

#[tokio::test]
async fn session_default_initially() {
    let (router, _, _) = make_router();
    let (status, json) = get(&router, "/vehicle/v1/components/os1/modes/session").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["value"], "default");
}

#[tokio::test]
async fn session_switch_to_programming() {
    let (router, _, _) = make_router();
    let (status, json) = put_json(&router, "/vehicle/v1/components/os1/modes/session",
        serde_json::json!({"value": "programming"})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["value"], "programming");
}

#[tokio::test]
async fn security_locked_initially() {
    let (router, _, _) = make_router();
    let (status, json) = get(&router, "/vehicle/v1/components/os1/modes/security").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["value"], "locked");
}

#[tokio::test]
async fn security_seed_key_unlock() {
    let (router, _, _) = make_router();
    // Programming session first
    put_json(&router, "/vehicle/v1/components/os1/modes/session",
        serde_json::json!({"value": "programming"})).await;

    // Request seed
    let (status, json) = put_json(&router, "/vehicle/v1/components/os1/modes/security",
        serde_json::json!({"value": "level1_requestseed"})).await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["seed"].is_object());

    // Parse "0xf4 0x7b 0x82 0x92" format
    let seed_str = json["seed"]["Request_Seed"].as_str().unwrap();
    let seed_bytes: Vec<u8> = seed_str
        .split_whitespace()
        .map(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
        .collect();
    let key_hex: String = seed_bytes.iter().map(|b| format!("{:02x}", b ^ 0xFF)).collect();

    // Send key
    let (status, json) = put_json(&router, "/vehicle/v1/components/os1/modes/security",
        serde_json::json!({"value": "level1", "key": key_hex})).await;
    assert_eq!(status, StatusCode::OK);
    // Unlocked — value should be "level1"
    assert!(json["value"].as_str().unwrap().contains("level"));
}

#[tokio::test]
async fn session_change_resets_security() {
    let (router, _, _) = make_router();
    unlock_for_flash(&router, "os1").await;

    // Switch back to default
    put_json(&router, "/vehicle/v1/components/os1/modes/session",
        serde_json::json!({"value": "default"})).await;

    // Security should be locked
    let (_, json) = get(&router, "/vehicle/v1/components/os1/modes/security").await;
    assert_eq!(json["value"], "locked");
}

// ============================================================
// Flash gating
// ============================================================

#[tokio::test]
async fn flash_rejected_in_default_session() {
    let (router, _, keys) = make_router();
    let envelope = make_test_suit_envelope(&keys, "os1", 1, &[0xAA; 256]);
    let (status, _) = post_bytes(&router, "/vehicle/v1/components/os1/files", envelope).await;
    // Should be rejected — not in programming session
    assert_ne!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn flash_rejected_when_locked() {
    let (router, _, keys) = make_router();
    // Programming but no security unlock
    put_json(&router, "/vehicle/v1/components/os1/modes/session",
        serde_json::json!({"value": "programming"})).await;

    let envelope = make_test_suit_envelope(&keys, "os1", 1, &[0xAA; 256]);
    let (status, _) = post_bytes(&router, "/vehicle/v1/components/os1/files", envelope).await;
    assert_ne!(status, StatusCode::CREATED);
}

// ============================================================
// Flash full flow
// ============================================================

#[tokio::test]
async fn flash_full_suit_flow() {
    let (router, _, keys) = make_router();
    unlock_for_flash(&router, "os1").await;

    let image = vec![0xBB; 2048];
    let envelope = make_test_suit_envelope(&keys, "os1", 2, &image);

    // 1. Upload
    let (status, json) = post_bytes(&router, "/vehicle/v1/components/os1/files", envelope).await;
    assert_eq!(status, StatusCode::CREATED);
    let file_id = json["file_id"].as_str().unwrap().to_string();

    // 2. Verify
    let (status, json) = post_empty(&router,
        &format!("/vehicle/v1/components/os1/files/{file_id}/verify")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["valid"].as_bool().unwrap());

    // 3. Start transfer
    let (status, _json) = post_json(&router, "/vehicle/v1/components/os1/flash/transfer",
        serde_json::json!({"file_id": file_id})).await;
    assert!(status == StatusCode::OK || status == StatusCode::ACCEPTED);

    // 4. Check activation — should be trial (activated)
    let (status, json) = get(&router, "/vehicle/v1/components/os1/flash/activation").await;
    assert_eq!(status, StatusCode::OK);
    // Trial state — sovd-api serializes FlashState::Activated
    assert!(json["state"].as_str().unwrap() != "committed");

    // 5. Commit
    let (status, _) = post_empty(&router, "/vehicle/v1/components/os1/flash/commit").await;
    assert_eq!(status, StatusCode::OK);

    // 6. Verify committed
    let (status, json) = get(&router, "/vehicle/v1/components/os1/flash/activation").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["state"], "committed");
}

// ============================================================
// Faults
// ============================================================

#[tokio::test]
async fn faults_empty_initially() {
    let (router, _, _) = make_router();
    let (status, json) = get(&router, "/vehicle/v1/components/os1/faults").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["total_count"], 0);
}

#[tokio::test]
async fn faults_and_clear() {
    let (router, nv, _) = make_router();
    // Write a DTC directly
    {
        let mut nv = nv.lock().unwrap();
        let bs = nv.read_boot_state().unwrap();
        let active = bs.banks[BankSet::Os1 as usize].active_bank;
        let mut runtime = nv.read_runtime(BankSet::Os1, active).unwrap_or_default();
        runtime.dtc_count = 1;
        runtime.dtcs[0] = DtcEntry { dtc_number: 0x00A301, status: 0x01 };
        nv.write_runtime(BankSet::Os1, active, &mut runtime).unwrap();
    }

    let (status, json) = get(&router, "/vehicle/v1/components/os1/faults").await;
    assert_eq!(status, StatusCode::OK);
    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);

    // Clear
    let (status, json) = delete(&router, "/vehicle/v1/components/os1/faults").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["cleared_count"], 1);
}

// ============================================================
// OTA via direct API (commit/rollback without flash upload)
// ============================================================

#[tokio::test]
async fn ota_commit_via_sovd() {
    let (router, nv, _) = make_router();

    // Install OTA directly via library
    {
        let mut nv = nv.lock().unwrap();
        let mut meta = ota::ImageMeta::default();
        meta.fw_version[..5].copy_from_slice(b"2.0.0");
        meta.fw_secver = 1;
        meta.fw_seq = 1;
        ota::install(&mut *nv, BankSet::Os1, b"test", &meta).unwrap();
    }

    let (_, json) = get(&router, "/vehicle/v1/components/os1/flash/activation").await;
    // Trial state — sovd-api serializes FlashState::Activated
    assert!(json["state"].as_str().unwrap() != "committed");

    let (status, _) = post_empty(&router, "/vehicle/v1/components/os1/flash/commit").await;
    assert_eq!(status, StatusCode::OK);

    let (_, json) = get(&router, "/vehicle/v1/components/os1/flash/activation").await;
    assert_eq!(json["state"], "committed");
}

#[tokio::test]
async fn ota_rollback_via_sovd() {
    let (router, nv, _) = make_router();

    {
        let mut nv = nv.lock().unwrap();
        let mut meta = ota::ImageMeta::default();
        meta.fw_version[..5].copy_from_slice(b"2.0.0");
        meta.fw_secver = 1;
        meta.fw_seq = 1;
        ota::install(&mut *nv, BankSet::Os1, b"test", &meta).unwrap();
    }

    let (status, _) = post_empty(&router, "/vehicle/v1/components/os1/flash/rollback").await;
    assert_eq!(status, StatusCode::OK);

    let (_, json) = get(&router, "/vehicle/v1/components/os1/data/active_bank").await;
    assert_eq!(json["value"], "A");
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
    assert_eq!(result.image_data, image);
}

#[test]
fn suit_provider_rejects_wrong_key() {
    let keys = generate_test_keys();
    let other_keys = generate_test_keys();
    let provider = SuitProvider::new(other_keys.trust_anchor.clone());
    let image = vec![0xEE; 256];
    let envelope = make_test_suit_envelope(&keys, "os1", 1, &image);
    assert!(provider.validate(&envelope, 0).is_err());
}

#[test]
fn suit_provider_rejects_rollback() {
    let keys = generate_test_keys();
    let provider = SuitProvider::new(keys.trust_anchor.clone());
    let image = vec![0xFF; 256];
    let envelope = make_test_suit_envelope(&keys, "os1", 3, &image);
    assert!(provider.validate(&envelope, 5).is_err());
}
