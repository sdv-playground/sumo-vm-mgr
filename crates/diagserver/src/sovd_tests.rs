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
use crate::sovd::state::{AppState, UploadStore};

fn make_app() -> axum::Router {
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    let mut state = NvBootState::default();
    nv.write_boot_state(&mut state).unwrap();
    let app_state = AppState {
        nv: Arc::new(Mutex::new(nv)),
        uploads: Arc::new(Mutex::new(UploadStore::new())),
    };
    create_router(app_state)
}

fn make_app_with_nv() -> (axum::Router, Arc<Mutex<NvStore<MemBlockDevice>>>) {
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    let mut state = NvBootState::default();
    nv.write_boot_state(&mut state).unwrap();
    let nv = Arc::new(Mutex::new(nv));
    let app_state = AppState { nv: nv.clone(), uploads: Arc::new(Mutex::new(UploadStore::new())) };
    (create_router(app_state), nv)
}

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
    let (_, nv) = make_app_with_nv();
    let (status, json) = put_json(
        create_router(AppState { nv: nv.clone(), uploads: Arc::new(Mutex::new(UploadStore::new())) }),
        "/vehicle/v1/components/os1/data/FD10",
        serde_json::json!({"value": "hello"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["success"].as_bool().unwrap());

    // Read it back
    let (status, json) = get(
        create_router(AppState { nv: nv.clone(), uploads: Arc::new(Mutex::new(UploadStore::new())) }),
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
    let (_, nv) = make_app_with_nv();
    // Write a runtime DID
    {
        let mut nv = nv.lock().unwrap();
        crate::did::write_did(&mut *nv, BankSet::Os1, 0xFD10, b"val").unwrap();
    }
    let (status, json) = get(
        create_router(AppState { nv: nv.clone(), uploads: Arc::new(Mutex::new(UploadStore::new())) }),
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
    let (_, nv) = make_app_with_nv();
    {
        let mut nv = nv.lock().unwrap();
        crate::did::write_did(&mut *nv, BankSet::Os1, 0xFD10, b"os1val").unwrap();
    }
    // os1 should have the DID
    let (status, json) = get(
        create_router(AppState { nv: nv.clone(), uploads: Arc::new(Mutex::new(UploadStore::new())) }),
        "/vehicle/v1/components/os1/data/FD10",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["value"], "os1val");

    // os2 should not
    let (status, _) = get(
        create_router(AppState { nv: nv.clone(), uploads: Arc::new(Mutex::new(UploadStore::new())) }),
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
    let (_, nv) = make_app_with_nv();
    // Write a DTC directly
    {
        let mut nv = nv.lock().unwrap();
        let bs = nv.read_boot_state().unwrap();
        let active = bs.banks[BankSet::Os1 as usize].active_bank;
        let mut runtime = nv.read_runtime(BankSet::Os1, active).unwrap_or_default();
        runtime.dtc_count = 1;
        runtime.dtcs[0] = DtcEntry {
            dtc_number: 0x00A301,
            status: 0x01,
        };
        nv.write_runtime(BankSet::Os1, active, &mut runtime).unwrap();
    }

    let (status, json) = get(
        create_router(AppState { nv: nv.clone(), uploads: Arc::new(Mutex::new(UploadStore::new())) }),
        "/vehicle/v1/components/os1/faults",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["total_count"], 1);
    assert_eq!(json["items"][0]["dtc_code"], "00A301");
    assert!(json["items"][0]["active"].as_bool().unwrap());

    // Clear
    let (status, json) = delete(
        create_router(AppState { nv: nv.clone(), uploads: Arc::new(Mutex::new(UploadStore::new())) }),
        "/vehicle/v1/components/os1/faults",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["cleared_count"], 1);

    // Verify cleared
    let (status, json) = get(
        create_router(AppState { nv: nv.clone(), uploads: Arc::new(Mutex::new(UploadStore::new())) }),
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
    let (_, nv) = make_app_with_nv();

    // Install OTA via library (puts os1 in trial mode)
    {
        let mut nv = nv.lock().unwrap();
        let image = b"test-image-data";
        let mut meta = ota::ImageMeta::default();
        meta.fw_version[..5].copy_from_slice(b"2.0.0");
        meta.fw_secver = 1;
        meta.fw_seq = 1;
        ota::install(&mut *nv, BankSet::Os1, image, &meta).unwrap();
    }

    // Check activation shows trial
    let (status, json) = get(
        create_router(AppState { nv: nv.clone(), uploads: Arc::new(Mutex::new(UploadStore::new())) }),
        "/vehicle/v1/components/os1/flash/activation",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["state"], "trial");
    assert_eq!(json["active_version"].as_str().unwrap(), "2.0.0");

    // Commit via SOVD endpoint
    let (status, json) = post(
        create_router(AppState { nv: nv.clone(), uploads: Arc::new(Mutex::new(UploadStore::new())) }),
        "/vehicle/v1/components/os1/flash/commit",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["success"].as_bool().unwrap());

    // Verify committed
    let (status, json) = get(
        create_router(AppState { nv: nv.clone(), uploads: Arc::new(Mutex::new(UploadStore::new())) }),
        "/vehicle/v1/components/os1/flash/activation",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["state"], "committed");
}

#[tokio::test]
async fn full_ota_rollback_via_sovd() {
    let (_, nv) = make_app_with_nv();

    // Install OTA
    {
        let mut nv = nv.lock().unwrap();
        let image = b"test-image-data";
        let mut meta = ota::ImageMeta::default();
        meta.fw_version[..5].copy_from_slice(b"2.0.0");
        meta.fw_secver = 1;
        meta.fw_seq = 1;
        ota::install(&mut *nv, BankSet::Os1, image, &meta).unwrap();
    }

    // Active bank should now be B
    let (_, json) = get(
        create_router(AppState { nv: nv.clone(), uploads: Arc::new(Mutex::new(UploadStore::new())) }),
        "/vehicle/v1/components/os1/data/active_bank",
    )
    .await;
    assert_eq!(json["value"], "B");

    // Rollback via SOVD
    let (status, json) = post(
        create_router(AppState { nv: nv.clone(), uploads: Arc::new(Mutex::new(UploadStore::new())) }),
        "/vehicle/v1/components/os1/flash/rollback",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["message"].as_str().unwrap().contains("bank A"));

    // Active bank should be back to A
    let (_, json) = get(
        create_router(AppState { nv: nv.clone(), uploads: Arc::new(Mutex::new(UploadStore::new())) }),
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
    let (_, nv) = make_app_with_nv();
    {
        let mut nv = nv.lock().unwrap();
        let image = b"img";
        let mut meta = ota::ImageMeta::default();
        meta.fw_version[..5].copy_from_slice(b"3.1.0");
        meta.fw_secver = 1;
        meta.fw_seq = 1;
        ota::install(&mut *nv, BankSet::Os1, image, &meta).unwrap();
    }

    let (status, json) = get(
        create_router(AppState { nv: nv.clone(), uploads: Arc::new(Mutex::new(UploadStore::new())) }),
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
// Flash file upload/transfer
// ============================================================

use crate::manifest::{FirmwareBundle, FirmwareManifest};

fn make_test_bundle(component: &str, version: &str) -> Vec<u8> {
    let yaml = format!(
        r#"
component_id: ["{component}"]
sequence_number: 2
version: "{version}"
spare_part_number: "SP-TEST"
ecu_sw_number: "SW-TEST"
system_name: "TEST-{component}"
"#
    );
    let manifest = FirmwareManifest::from_yaml(&yaml).unwrap();
    let image = vec![0xAA; 1024]; // 1KB test image
    FirmwareBundle::pack(&manifest, &image)
}

#[tokio::test]
async fn flash_upload_and_status() {
    let (app, nv) = make_app_with_nv();
    let bundle = make_test_bundle("os1", "2.0.0");

    // Upload
    let resp = app
        .oneshot(
            Request::post("/vehicle/v1/components/os1/files")
                .header("content-type", "application/octet-stream")
                .body(Body::from(bundle))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["state"], "uploaded");
    let upload_id = body["upload_id"].as_str().unwrap().to_string();

    // Status
    let (status, _) = get(
        create_router(AppState { nv: nv.clone(), uploads: Arc::new(Mutex::new(UploadStore::new())) }),
        &format!("/vehicle/v1/components/os1/files/{upload_id}"),
    )
    .await;
    // This uses a fresh router so it won't have the upload — expect 404
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn flash_full_flow() {
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    let mut boot_state = NvBootState::default();
    nv.write_boot_state(&mut boot_state).unwrap();
    let nv = Arc::new(Mutex::new(nv));
    let uploads = Arc::new(Mutex::new(UploadStore::new()));
    let state = AppState {
        nv: nv.clone(),
        uploads: uploads.clone(),
    };

    let bundle = make_test_bundle("os1", "2.0.0");

    // 1. Upload
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/vehicle/v1/components/os1/files")
                .header("content-type", "application/octet-stream")
                .body(Body::from(bundle))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let upload_id = body["upload_id"].as_str().unwrap().to_string();

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
    assert_eq!(body["active_version"], "2.0.0");

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
async fn flash_upload_bad_bundle() {
    let app = make_app();
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
