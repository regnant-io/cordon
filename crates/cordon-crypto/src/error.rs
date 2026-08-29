//! Cryptographic error types

use thiserror::Error;

/// Result type for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Errors from cryptographic operations
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed (authentication tag mismatch or corrupt data)
    #[error("Decryption failed — data may be tampered")]
    DecryptionFailed,

    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    KdfFailed(String),

    /// Signature verification failed
    #[error("Signature verification failed")]
    SignatureInvalid,

    /// Signing operation failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Key material is invalid or corrupt
    #[error("Invalid key material: {0}")]
    InvalidKey(String),

    /// Attestation verification failed
    #[error("Attestation verification failed: {0}")]
    AttestationFailed(String),

    /// Nonce/replay check failed
    #[error("Nonce mismatch — possible replay attack")]
    NonceMismatch,

    /// PCR value mismatch
    #[error("PCR value mismatch at index {index}: expected {expected}, got {actual}")]
    PcrMismatch {
        /// PCR register index
        index: u8,
        /// Expected value
        expected: String,
        /// Actual value
        actual: String,
    },

    /// MRENCLAVE mismatch
    #[error("MRENCLAVE mismatch: expected {expected}, got {actual}")]
    EnclaveMeasurementMismatch {
        /// Expected measurement
        expected: String,
        /// Actual measurement
        actual: String,
    },

    /// RNG failure
    #[error("Random number generation failed: {0}")]
    RngFailed(String),

    /// Base64 decode error
    #[error("Base64 decode error: {0}")]
    Base64Error(String),

    /// Hex decode error
    #[error("Hex decode error: {0}")]
    HexError(String),

    /// Generic internal error
    #[error("Internal crypto error: {0}")]
    Internal(String),
}

impl From<base64::DecodeError> for CryptoError {
    fn from(e: base64::DecodeError) -> Self {
        CryptoError::Base64Error(e.to_string())
    }
}

impl From<hex::FromHexError> for CryptoError {
    fn from(e: hex::FromHexError) -> Self {
        CryptoError::HexError(e.to_string())
    }
}
