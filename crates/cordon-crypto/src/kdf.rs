//! Key Derivation Functions
//!
//! Implements HKDF-SHA256 with domain separation strings.
//! Every derived key has a unique purpose encoded in its derivation path.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{CryptoError, CryptoResult};

/// Domain separation strings for key derivation.
/// Each string encodes the purpose of the derived key.
/// Cross-purpose key use is architecturally prevented.
pub struct DomainSeparation;

impl DomainSeparation {
    /// Bundle encryption key
    pub const BUNDLE_KEY: &'static str = "CORDON_BUNDLE_KEY_v1";
    /// Per-shard encryption key
    pub const SHARD_KEY: &'static str = "CORDON_SHARD_KEY_v1";
    /// Session authentication key
    pub const SESSION_KEY: &'static str = "CORDON_SESSION_KEY_v1";
    /// Audit log signing key
    pub const LOG_KEY: &'static str = "CORDON_LOG_KEY_v1";
    /// Administrative command authorization key
    pub const ADMIN_KEY: &'static str = "CORDON_ADMIN_KEY_v1";
    /// Enclave sealing key
    pub const SEAL_KEY: &'static str = "CORDON_SEAL_KEY_v1";
    /// Update authorization key
    pub const UPDATE_KEY: &'static str = "CORDON_UPDATE_KEY_v1";
    /// Enclave response-signing key (signs inference responses + attestation reports)
    pub const ENCLAVE_KEY: &'static str = "CORDON_ENCLAVE_KEY_v1";
}

/// Derive a key using HKDF-SHA256.
///
/// # Arguments
/// * `ikm` - Input key material (the parent key)
/// * `info` - Domain separation info string (encodes purpose + identifiers)
/// * `output_len` - Desired output length in bytes
///
/// # Security
/// The `info` string must be unique per (purpose, deployment, client) tuple.
/// Keys derived with different `info` strings are cryptographically independent.
pub fn derive_key(ikm: &[u8], info: &str, output_len: usize) -> CryptoResult<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = vec![0u8; output_len];
    hk.expand(info.as_bytes(), &mut okm)
        .map_err(|e| CryptoError::KdfFailed(e.to_string()))?;
    Ok(okm)
}

/// Derive a 32-byte (256-bit) key — the standard output for AES-256 and Ed25519 seeds
pub fn derive_32_byte_key(ikm: &[u8], info: &str) -> CryptoResult<[u8; 32]> {
    let bytes = derive_key(ikm, info, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Build the HKDF info string for a bundle key.
/// Format: "CORDON_BUNDLE_KEY_v1:{bundle_id}:{client_id}"
pub fn bundle_key_info(bundle_id: &str, client_id: &str) -> String {
    format!(
        "{}:{}:{}",
        DomainSeparation::BUNDLE_KEY,
        bundle_id,
        client_id
    )
}

/// Build the HKDF info string for a shard key.
pub fn shard_key_info(shard_index: u32) -> String {
    format!("{}:{}", DomainSeparation::SHARD_KEY, shard_index)
}

/// Build the HKDF info string for a session key.
pub fn session_key_info(deployment_id: &str, client_id: &str) -> String {
    format!(
        "{}:{}:{}",
        DomainSeparation::SESSION_KEY,
        deployment_id,
        client_id
    )
}

/// Build the HKDF info string for a log signing key.
pub fn log_key_info(deployment_id: &str, client_id: &str) -> String {
    format!(
        "{}:{}:{}",
        DomainSeparation::LOG_KEY,
        deployment_id,
        client_id
    )
}

/// Build the HKDF info string for an admin authorization key.
pub fn admin_key_info(deployment_id: &str, client_id: &str) -> String {
    format!(
        "{}:{}:{}",
        DomainSeparation::ADMIN_KEY,
        deployment_id,
        client_id
    )
}

/// Build the HKDF info string for the enclave response-signing key.
pub fn enclave_key_info(deployment_id: &str, client_id: &str) -> String {
    format!(
        "{}:{}:{}",
        DomainSeparation::ENCLAVE_KEY,
        deployment_id,
        client_id
    )
}

/// Constant-time comparison of two byte slices.
/// Returns true only if slices are equal length AND equal content.
/// Prevents timing side-channels in key/token comparisons.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Securely erase a mutable byte vector.
pub fn secure_zero(buf: &mut Vec<u8>) {
    buf.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let ikm = b"test_master_key_32_bytes_padding!";
        let info = "CORDON_BUNDLE_KEY_v1:bundle-123:client-456";
        let k1 = derive_key(ikm, info, 32).unwrap();
        let k2 = derive_key(ikm, info, 32).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_key_domain_separation() {
        let ikm = b"test_master_key_32_bytes_padding!";
        let k_bundle = derive_key(ikm, &bundle_key_info("b1", "c1"), 32).unwrap();
        let k_log = derive_key(ikm, &log_key_info("d1", "c1"), 32).unwrap();
        // Keys for different purposes must be different
        assert_ne!(k_bundle, k_log);
    }

    #[test]
    fn test_ct_eq() {
        assert!(ct_eq(b"hello", b"hello"));
        assert!(!ct_eq(b"hello", b"world"));
        assert!(!ct_eq(b"hello", b"hell"));
    }
}
