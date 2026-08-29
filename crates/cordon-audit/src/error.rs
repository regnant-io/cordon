//! Audit log error types

use thiserror::Error;

/// Result type for audit operations
pub type AuditResult<T> = Result<T, AuditError>;

/// Errors from audit log operations
#[derive(Debug, Error)]
pub enum AuditError {
    /// Write failure — treated as fatal (log-before-process semantics)
    #[error("Audit log write failed: {0}")]
    WriteFailed(String),

    /// Chain integrity violation
    #[error("Chain integrity violation at entry {entry_id}: {reason}")]
    ChainViolation {
        /// Entry ID where violation was found
        entry_id: String,
        /// Description of the violation
        reason: String,
    },

    /// Signature verification failed
    #[error("Signature invalid at entry {entry_id}")]
    SignatureInvalid {
        /// Entry ID where signature failed
        entry_id: String,
    },

    /// Genesis entry mismatch
    #[error("Genesis entry hash mismatch — log may have been replaced")]
    GenesisMismatch,

    /// Log file not found or inaccessible
    #[error("Log not accessible: {0}")]
    LogNotAccessible(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Export error
    #[error("Export error: {0}")]
    ExportError(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(String),

    /// Crypto error
    #[error("Crypto error: {0}")]
    CryptoError(String),
}

impl From<std::io::Error> for AuditError {
    fn from(e: std::io::Error) -> Self {
        AuditError::IoError(e.to_string())
    }
}

impl From<serde_json::Error> for AuditError {
    fn from(e: serde_json::Error) -> Self {
        AuditError::SerializationError(e.to_string())
    }
}

impl From<cordon_crypto::CryptoError> for AuditError {
    fn from(e: cordon_crypto::CryptoError) -> Self {
        AuditError::CryptoError(e.to_string())
    }
}
