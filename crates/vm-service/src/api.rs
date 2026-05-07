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
use crate::manager::{self, ManagerError, VmManager};

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
    // Phase 1: signal shutdown (fast, under lock)
    let stop_handle = {
        let mut mgr = mgr.lock().await;
        match mgr.initiate_stop(&name) {
            Ok(sh) => sh,
            Err(e) => return error_response(e),
        }
    };
    // Lock is released here — health/list remain responsive

    // Phase 2: wait for process to exit (blocking, NO lock held)
    if let Some(pid) = stop_handle.pid {
        let timeout = stop_handle.timeout_secs;
        tokio::task::spawn_blocking(move || {
            manager::wait_for_exit(pid, timeout);
        }).await.ok();
    }

    // Phase 3: force-kill if needed + cleanup (fast, under lock)
    {
        let mut mgr = mgr.lock().await;
        mgr.finalize_stop(&name);
    }

    (StatusCode::OK, Json(serde_json::json!({"ok": true})))
}

async fn restart_vm(
    State(mgr): State<SharedManager>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    // Stop phase (same 3-phase pattern as stop_vm)
    let stop_handle = {
        let mut mgr = mgr.lock().await;
        match mgr.initiate_stop(&name) {
            Ok(sh) => Some(sh),
            Err(ManagerError::NotRunning(_)) => None,
            Err(e) => return error_response(e),
        }
    };

    if let Some(sh) = stop_handle {
        if let Some(pid) = sh.pid {
            let timeout = sh.timeout_secs;
            tokio::task::spawn_blocking(move || {
                manager::wait_for_exit(pid, timeout);
            }).await.ok();
        }
        let mut mgr = mgr.lock().await;
        mgr.finalize_stop(&name);
    }

    // Start phase (may block on devb-loopback wait)
    let mgr_clone = mgr.clone();
    let name_clone = name.clone();
    let result = tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Handle::current();
        let mut mgr = rt.block_on(mgr_clone.lock());
        mgr.start_vm(&name_clone)
    }).await;

    match result {
        Ok(Ok(())) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))),
        Ok(Err(e)) => error_response(e),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "start task panicked"}))),
    }
}

async fn health_vm(
    State(mgr): State<SharedManager>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let mut mgr = mgr.lock().await;
    match mgr.health_detail(&name) {
        Ok(detail) => (StatusCode::OK, Json(serde_json::json!({
            "status": detail.status,
            "guest_state": detail.guest_state,
            "hb_seq": detail.hb_seq,
        }))),
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
