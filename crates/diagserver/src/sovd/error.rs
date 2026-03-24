use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::ota::OtaError;

pub enum ApiError {
    NotFound(String),
    BadRequest(String),
    Conflict(String),
    Forbidden(String),
    Internal(String),
}

impl From<OtaError> for ApiError {
    fn from(e: OtaError) -> Self {
        match e {
            OtaError::InTrial
            | OtaError::AlreadyCommitted
            | OtaError::NotInTrial
            | OtaError::SecurityVersionTooLow { .. } => ApiError::Conflict(e.to_string()),
            OtaError::NoBootState | OtaError::NvError(_) | OtaError::VerifyFailed { .. } => {
                ApiError::Internal(e.to_string())
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_type, message) = match self {
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", msg),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg),
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, "internal", msg),
        };

        let body = json!({ "error": error_type, "message": message });
        (status, axum::Json(body)).into_response()
    }
}
