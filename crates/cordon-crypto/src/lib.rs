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

pub mod error;
pub mod hierarchy;
pub mod symmetric;
pub mod signing;
pub mod kdf;
pub mod zeroize_ext;
pub mod attestation;

pub use error::{CryptoError, CryptoResult};
pub use hierarchy::{KeyHierarchy, MasterKey, BundleKey, SessionKey, LogKey, AdminKey};
pub use symmetric::{AesGcmKey, EncryptedBlob, decrypt_blob, encrypt_blob, encrypt_shard, decrypt_shard};
pub use signing::{SigningKey, VerifyingKey, Signature, sign_bytes, verify_bytes};
pub use kdf::{derive_key, DomainSeparation, ct_eq};
pub use zeroize_ext::{SecretBytes, SecretVec};
pub use attestation::{
    AttestationReport, TpmQuote, TeeQuote, CombinedAttestation,
    TpmPcrSet, ExpectedMeasurements, TeeType, compute_combined_hash,
};
