//! Mapping from [`CordonError`] to HTTP responses.
//!
//! Error bodies carry a stable machine-readable code and a message written for
//! the caller. Internal detail — filesystem paths, upstream diagnostics, key
//! material identifiers — is logged at the node and replaced with a generic
//! message on the wire, so an error response never becomes a reconnaissance
//! tool.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use cordon_core::CordonError;

use crate::types::ApiError;

/// An error ready to be returned from a handler.
pub struct ApiErrorResponse {
    /// HTTP status.
    pub status: StatusCode,
    /// Response body.
    pub body: ApiError,
}

impl IntoResponse for ApiErrorResponse {
    fn into_response(self) -> Response {
        let mut response = (self.status, Json(self.body)).into_response();
        // Signal backpressure explicitly rather than leaving the client to guess
        // how long to wait.
        if self.status == StatusCode::SERVICE_UNAVAILABLE
            || self.status == StatusCode::TOO_MANY_REQUESTS
        {
            response
                .headers_mut()
                .insert("retry-after", axum::http::HeaderValue::from_static("5"));
        }
        response
    }
}

impl From<CordonError> for ApiErrorResponse {
    fn from(err: CordonError) -> Self {
        let (status, code, public_message) = classify(&err);

        // Anything not safe to disclose is still recorded here, so operators
        // lose no diagnostic power.
        if status.is_server_error() {
            tracing::error!(code, "Request failed: {}", err);
        }

        ApiErrorResponse {
            status,
            body: ApiError::new(code, public_message),
        }
    }
}

/// Decide the status, code, and caller-facing message for an error.
///
/// Client-fault errors describe precisely what was wrong, because the caller can
/// act on that. Node-fault errors are generalised: an internal failure's detail
/// is for the operator's logs, not for whoever provoked it.
fn classify(err: &CordonError) -> (StatusCode, &'static str, String) {
    use CordonError::*;

    match err {
        AuthFailed(msg) => (StatusCode::UNAUTHORIZED, "auth_failed", msg.clone()),

        RateLimitExceeded { .. } => (
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_exceeded",
            "rate limit exceeded for this client".to_string(),
        ),

        ValidationFailed(msg) => (StatusCode::BAD_REQUEST, "validation_failed", msg.clone()),

        RequestTooLarge(msg) => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_too_large",
            msg.clone(),
        ),

        ModelNotFound { bundle_id } => (
            StatusCode::NOT_FOUND,
            "model_not_found",
            format!("no model named '{}' is available", bundle_id),
        ),

        ModelIntegrityViolation { .. } => (
            StatusCode::SERVICE_UNAVAILABLE,
            "integrity_violation",
            "the requested model failed its integrity check and is not being served".to_string(),
        ),

        AttestationInvalid(msg) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "attestation_invalid",
            msg.clone(),
        ),

        Quarantined => (
            StatusCode::SERVICE_UNAVAILABLE,
            "quarantined",
            "the node is quarantined and is not serving inference".to_string(),
        ),

        Locked => (
            StatusCode::SERVICE_UNAVAILABLE,
            "locked",
            "the node is locked and requires operator recovery".to_string(),
        ),

        Zeroized => (
            StatusCode::SERVICE_UNAVAILABLE,
            "zeroized",
            "the node's key material has been zeroized and it must be re-provisioned".to_string(),
        ),

        ContentPolicyViolation { rule_id } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "content_policy_violation",
            format!(
                "the response was withheld by content policy rule '{}'",
                rule_id
            ),
        ),

        CovertChannelDetected { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "covert_channel_detected",
            "the response was withheld after covert-channel analysis".to_string(),
        ),

        AdminRejected(msg) => (StatusCode::FORBIDDEN, "admin_rejected", msg.clone()),

        Overloaded { max_concurrent } => (
            StatusCode::SERVICE_UNAVAILABLE,
            "overloaded",
            format!(
                "the node is serving its maximum of {} concurrent requests",
                max_concurrent
            ),
        ),

        Timeout { seconds } => (
            StatusCode::GATEWAY_TIMEOUT,
            "timeout",
            format!("the request exceeded its {}s deadline", seconds),
        ),

        RuntimeUnavailable(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_unavailable",
            "the model runtime is not available".to_string(),
        ),

        ModelDownloadFailed(msg) => (
            StatusCode::BAD_GATEWAY,
            "model_download_failed",
            msg.clone(),
        ),

        ModeForbidden { mode, reason } => (
            StatusCode::FORBIDDEN,
            "mode_forbidden",
            format!("not permitted in {} mode: {}", mode, reason),
        ),

        // The remainder are node faults. The caller gets a request identifier
        // and nothing else; the detail is in the node's log.
        InferenceFailed(_) => (
            StatusCode::BAD_GATEWAY,
            "inference_failed",
            "the model runtime did not return a usable response".to_string(),
        ),

        AuditWriteFailed(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "audit_write_failed",
            "the request was refused because it could not be recorded in the audit log".to_string(),
        ),

        KeyError(_) | ConfigError(_) | OutputFilterError(_) | Internal(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "an internal error occurred; see the node's logs".to_string(),
        ),
    }
}

/// Convert a [`CordonError`] into a handler-ready response.
pub fn map_err(err: CordonError) -> ApiErrorResponse {
    ApiErrorResponse::from(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_faults_carry_actionable_detail() {
        let r = map_err(CordonError::ValidationFailed(
            "max_tokens must be > 0".into(),
        ));
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        assert!(r.body.message.contains("max_tokens"));
    }

    /// Internal failures must not describe the node's internals to whoever
    /// triggered them.
    #[test]
    fn internal_faults_are_generalised() {
        let r = map_err(CordonError::Internal(
            "cannot open /var/lib/cordon/secret.key: permission denied".into(),
        ));
        assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!r.body.message.contains("/var/lib/cordon"));
        assert!(!r.body.message.contains("secret.key"));
    }

    #[test]
    fn runtime_failures_do_not_disclose_the_upstream() {
        let r = map_err(CordonError::InferenceFailed(
            "cannot reach the model runtime at http://127.0.0.1:51234: refused".into(),
        ));
        assert!(!r.body.message.contains("51234"));
        assert!(!r.body.message.contains("127.0.0.1"));

        let r = map_err(CordonError::RuntimeUnavailable(
            "llama-server binary not found at /opt/llama/llama-server".into(),
        ));
        assert!(!r.body.message.contains("/opt/llama"));
    }

    #[test]
    fn key_errors_never_leak() {
        let r = map_err(CordonError::KeyError(
            "invalid CMK: bad hex at byte 4".into(),
        ));
        assert!(!r.body.message.contains("CMK"));
        assert_eq!(r.body.error, "internal_error");
    }

    #[test]
    fn overload_and_rate_limit_signal_retry() {
        for err in [
            CordonError::Overloaded { max_concurrent: 32 },
            CordonError::RateLimitExceeded {
                client_id: "c".into(),
            },
        ] {
            let response = map_err(err).into_response();
            assert!(response.headers().contains_key("retry-after"));
        }
    }

    #[test]
    fn status_codes_match_semantics() {
        let cases: Vec<(CordonError, StatusCode)> = vec![
            (
                CordonError::AuthFailed("x".into()),
                StatusCode::UNAUTHORIZED,
            ),
            (
                CordonError::AdminRejected("x".into()),
                StatusCode::FORBIDDEN,
            ),
            (
                CordonError::ModelNotFound {
                    bundle_id: "m".into(),
                },
                StatusCode::NOT_FOUND,
            ),
            (
                CordonError::RequestTooLarge("x".into()),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                CordonError::ContentPolicyViolation {
                    rule_id: "r".into(),
                },
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (CordonError::Quarantined, StatusCode::SERVICE_UNAVAILABLE),
            (
                CordonError::Timeout { seconds: 30 },
                StatusCode::GATEWAY_TIMEOUT,
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(map_err(err).status, expected);
        }
    }
}
