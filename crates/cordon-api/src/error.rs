//! API error handling — maps CordonError to HTTP status codes
#![allow(missing_docs)]

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use cordon_core::CordonError;
use crate::types::ApiError;

/// Axum-compatible error wrapper
pub struct ApiErrorResponse {
    pub status: StatusCode,
    pub body: ApiError,
}

impl IntoResponse for ApiErrorResponse {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

impl From<CordonError> for ApiErrorResponse {
    fn from(err: CordonError) -> Self {
        let (status, code) = match &err {
            CordonError::AuthFailed(_) => (StatusCode::UNAUTHORIZED, "auth_failed"),
            CordonError::RateLimitExceeded { .. } => (StatusCode::TOO_MANY_REQUESTS, "rate_limit_exceeded"),
            CordonError::ValidationFailed(_) => (StatusCode::BAD_REQUEST, "validation_failed"),
            CordonError::ModelNotFound { .. } => (StatusCode::NOT_FOUND, "model_not_found"),
            CordonError::ModelIntegrityViolation { .. } => (StatusCode::SERVICE_UNAVAILABLE, "integrity_violation"),
            CordonError::AttestationInvalid(_) => (StatusCode::SERVICE_UNAVAILABLE, "attestation_invalid"),
            CordonError::Quarantined => (StatusCode::SERVICE_UNAVAILABLE, "quarantined"),
            CordonError::Locked => (StatusCode::SERVICE_UNAVAILABLE, "locked"),
            CordonError::Zeroized => (StatusCode::SERVICE_UNAVAILABLE, "zeroized"),
            CordonError::ContentPolicyViolation { .. } => (StatusCode::UNPROCESSABLE_ENTITY, "content_policy_violation"),
            CordonError::CovertChannelDetected { .. } => (StatusCode::UNPROCESSABLE_ENTITY, "covert_channel_detected"),
            CordonError::AuditWriteFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, "audit_write_failed"),
            CordonError::AdminRejected(_) => (StatusCode::FORBIDDEN, "admin_rejected"),
            CordonError::Timeout { .. } => (StatusCode::GATEWAY_TIMEOUT, "timeout"),
            CordonError::InferenceFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, "inference_failed"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };

        ApiErrorResponse {
            status,
            body: ApiError::new(code, err.to_string()),
        }
    }
}

/// Helper to convert Results into Axum responses
pub fn map_err(err: CordonError) -> ApiErrorResponse {
    ApiErrorResponse::from(err)
}
