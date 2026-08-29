//! Cordon Cryptographic Primitives
//!
//! All security-critical cryptographic operations for Cordon v2.0.
//! Implements: AES-256-GCM, HKDF-SHA256, Ed25519, X25519, key hierarchy,
//! memory zeroization, and constant-time comparison.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Forbid unwrap/expect in production crypto code; allow them in unit tests.
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]

pub mod attestation;
pub mod error;
pub mod hierarchy;
pub mod kdf;
pub mod signing;
pub mod symmetric;
pub mod zeroize_ext;

pub use attestation::{
    compute_combined_hash, AttestationReport, CombinedAttestation, ExpectedMeasurements, TeeQuote,
    TeeType, TpmPcrSet, TpmQuote,
};
pub use error::{CryptoError, CryptoResult};
pub use hierarchy::{AdminKey, BundleKey, KeyHierarchy, LogKey, MasterKey, SessionKey};
pub use kdf::{ct_eq, derive_key, DomainSeparation};
pub use signing::{sign_bytes, verify_bytes, Signature, SigningKey, VerifyingKey};
pub use symmetric::{
    decrypt_blob, decrypt_shard, encrypt_blob, encrypt_shard, AesGcmKey, EncryptedBlob,
};
pub use zeroize_ext::{SecretBytes, SecretVec};
