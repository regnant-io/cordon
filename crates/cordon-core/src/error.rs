//! Core error types

use thiserror::Error;

/// Result type for Cordon core operations
pub type CordonResult<T> = Result<T, CordonError>;

/// Cordon core errors
#[derive(Debug, Error)]
pub enum CordonError {
    /// Request rejected — authentication failed
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    /// Request rejected — rate limit exceeded
    #[error("Rate limit exceeded for client {client_id}")]
    RateLimitExceeded {
        /// Client that exceeded limit
        client_id: String,
    },

    /// Request rejected — input validation failed
    #[error("Request validation failed: {0}")]
    ValidationFailed(String),

    /// Inference engine error
    #[error("Inference error: {0}")]
    InferenceFailed(String),

    /// Model not found or not loaded
    #[error("Model not found: {bundle_id}")]
    ModelNotFound {
        /// Bundle ID requested
        bundle_id: String,
    },

    /// Model integrity check failed
    #[error("Model integrity violation for bundle {bundle_id}")]
    ModelIntegrityViolation {
        /// Bundle ID with violation
        bundle_id: String,
    },

    /// Attestation failed or expired
    #[error("Attestation invalid: {0}")]
    AttestationInvalid(String),

    /// Node is in quarantine mode
    #[error("Node is in quarantine mode — no inference permitted")]
    Quarantined,

    /// Node is locked
    #[error("Node is locked — operator recovery required")]
    Locked,

    /// Node has been zeroized — must re-provision
    #[error("Node has been zeroized — full re-provisioning required")]
    Zeroized,

    /// Content policy violation
    #[error("Content policy violation: rule {rule_id} triggered")]
    ContentPolicyViolation {
        /// Rule that triggered
        rule_id: String,
    },

    /// Covert channel detected
    #[error("Covert channel detected: anomaly score {score:.3}")]
    CovertChannelDetected {
        /// Anomaly score
        score: f32,
    },

    /// Output filter error
    #[error("Output filter error: {0}")]
    OutputFilterError(String),

    /// Audit log write failed (fatal)
    #[error("FATAL: Audit log write failed: {0} — request rejected per log-before-process policy")]
    AuditWriteFailed(String),

    /// Administrative command rejected
    #[error("Admin command rejected: {0}")]
    AdminRejected(String),

    /// Key material error
    #[error("Key error: {0}")]
    KeyError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Request timeout
    #[error("Request timed out after {seconds}s")]
    Timeout {
        /// Timeout in seconds
        seconds: u64,
    },

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<cordon_crypto::CryptoError> for CordonError {
    fn from(e: cordon_crypto::CryptoError) -> Self {
        CordonError::KeyError(e.to_string())
    }
}

impl From<cordon_audit::AuditError> for CordonError {
    fn from(e: cordon_audit::AuditError) -> Self {
        CordonError::AuditWriteFailed(e.to_string())
    }
}

impl From<anyhow::Error> for CordonError {
    fn from(e: anyhow::Error) -> Self {
        CordonError::Internal(e.to_string())
    }
}
