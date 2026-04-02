/// HTTP API for VM lifecycle control.
///
/// Routes:
///   GET  /vms                → list all VMs + status
///   POST /vms/{name}/start   → start a VM
///   POST /vms/{name}/stop    → stop a VM
///   POST /vms/{name}/restart → stop + start
///   GET  /vms/{name}/health  → health status

use std::sync::Arc;
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
};
use serde::Serialize;
use tokio::sync::Mutex;

use crate::health::HealthStatus;
use crate::manager::{ManagerError, VmManager};

type SharedManager = Arc<Mutex<VmManager>>;

pub fn router(manager: SharedManager) -> Router {
    Router::new()
        .route("/vms", get(list_vms))
        .route("/vms/{name}/start", post(start_vm))
        .route("/vms/{name}/stop", post(stop_vm))
        .route("/vms/{name}/restart", post(restart_vm))
        .route("/vms/{name}/health", get(health_vm))
        .with_state(manager)
}

#[derive(Serialize)]
struct VmInfoResponse {
    name: String,
    status: HealthStatus,
    pid: Option<u32>,
    backend: String,
}

async fn list_vms(State(mgr): State<SharedManager>) -> Json<Vec<VmInfoResponse>> {
    let mut mgr = mgr.lock().await;
    let vms = mgr.list().into_iter().map(|v| VmInfoResponse {
        name: v.name,
        status: v.status,
        pid: v.pid,
        backend: format!("{:?}", v.backend).to_lowercase(),
    }).collect();
    Json(vms)
}

async fn start_vm(
    State(mgr): State<SharedManager>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    // Run the blocking runner operation in a blocking task
    let mut mgr = mgr.lock().await;
    match mgr.start_vm(&name) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))),
        Err(e) => error_response(e),
    }
}

async fn stop_vm(
    State(mgr): State<SharedManager>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let mut mgr = mgr.lock().await;
    match mgr.stop_vm(&name) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))),
        Err(e) => error_response(e),
    }
}

async fn restart_vm(
    State(mgr): State<SharedManager>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let mut mgr = mgr.lock().await;
    match mgr.restart_vm(&name) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))),
        Err(e) => error_response(e),
    }
}

async fn health_vm(
    State(mgr): State<SharedManager>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let mut mgr = mgr.lock().await;
    match mgr.health(&name) {
        Ok(status) => (StatusCode::OK, Json(serde_json::json!({"status": status}))),
        Err(e) => error_response(e),
    }
}

fn error_response(e: ManagerError) -> (StatusCode, Json<serde_json::Value>) {
    let (code, msg) = match &e {
        ManagerError::NotFound(_) => (StatusCode::NOT_FOUND, e.to_string()),
        ManagerError::AlreadyRunning(_) => (StatusCode::CONFLICT, e.to_string()),
        ManagerError::NotRunning(_) => (StatusCode::CONFLICT, e.to_string()),
        ManagerError::Runner(_) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    (code, Json(serde_json::json!({"error": msg})))
}
