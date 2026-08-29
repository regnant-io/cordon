//! Symmetric encryption — AES-256-GCM
//!
//! All weight shards and sensitive data at rest are encrypted with AES-256-GCM.
//! Each encryption uses a fresh random nonce. Authenticated encryption ensures
//! any tampering with ciphertext is detected during decryption.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::error::{CryptoError, CryptoResult};

/// AES-256-GCM key (32 bytes, zeroized on drop)
#[derive(ZeroizeOnDrop)]
pub struct AesGcmKey {
    key: [u8; 32],
}

impl AesGcmKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { key: bytes }
    }

    /// Create from a slice (must be exactly 32 bytes)
    pub fn from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != 32 {
            return Err(CryptoError::InvalidKey(format!(
                "AES-256 key must be 32 bytes, got {}",
                slice.len()
            )));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(slice);
        Ok(Self { key })
    }

    /// Get a reference to the raw key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

/// Encrypted blob: ciphertext + 12-byte nonce + 16-byte GCM tag (included in ciphertext)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    /// Base64-encoded 12-byte nonce
    pub nonce_b64: String,
    /// Base64-encoded ciphertext (includes 16-byte GCM authentication tag)
    pub ciphertext_b64: String,
    /// SHA-256 of the original plaintext (hex), for integrity verification
    pub plaintext_sha256: String,
    /// SHA-256 of the ciphertext bytes (hex)
    pub ciphertext_sha256: String,
}

/// Encrypt plaintext with AES-256-GCM using a fresh random nonce.
///
/// Returns an `EncryptedBlob` containing the ciphertext, nonce, and
/// integrity hashes of both plaintext and ciphertext.
pub fn encrypt_blob(key: &AesGcmKey, plaintext: &[u8]) -> CryptoResult<EncryptedBlob> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use sha2::{Digest, Sha256};

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let plaintext_sha256 = hex::encode(Sha256::digest(plaintext));
    let ciphertext_sha256 = hex::encode(Sha256::digest(&ciphertext));

    Ok(EncryptedBlob {
        nonce_b64: B64.encode(nonce.as_slice()),
        ciphertext_b64: B64.encode(&ciphertext),
        plaintext_sha256,
        ciphertext_sha256,
    })
}

/// Decrypt an `EncryptedBlob` with AES-256-GCM.
///
/// Verifies ciphertext hash before decryption, then verifies plaintext
/// hash after decryption. Both checks must pass.
pub fn decrypt_blob(key: &AesGcmKey, blob: &EncryptedBlob) -> CryptoResult<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use sha2::{Digest, Sha256};

    let nonce_bytes = B64
        .decode(&blob.nonce_b64)
        .map_err(|e| CryptoError::Base64Error(e.to_string()))?;
    let ciphertext = B64
        .decode(&blob.ciphertext_b64)
        .map_err(|e| CryptoError::Base64Error(e.to_string()))?;

    // Verify ciphertext hash before attempting decryption
    let ct_hash = hex::encode(Sha256::digest(&ciphertext));
    if ct_hash != blob.ciphertext_sha256 {
        return Err(CryptoError::DecryptionFailed);
    }

    if nonce_bytes.len() != 12 {
        return Err(CryptoError::InvalidKey("Invalid nonce length".into()));
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.key));
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|_| CryptoError::DecryptionFailed)?;

    // Verify plaintext hash after decryption
    let pt_hash = hex::encode(Sha256::digest(&plaintext));
    if pt_hash != blob.plaintext_sha256 {
        return Err(CryptoError::DecryptionFailed);
    }

    Ok(plaintext)
}

/// Encrypt raw bytes with a given key and nonce (for streaming/shard use)
pub fn encrypt_shard(key: &AesGcmKey, plaintext: &[u8], nonce: &[u8; 12]) -> CryptoResult<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.key));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))
}

/// Decrypt raw bytes with a given key and nonce (for streaming/shard use)
pub fn decrypt_shard(
    key: &AesGcmKey,
    ciphertext: &[u8],
    nonce: &[u8; 12],
) -> CryptoResult<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.key));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> AesGcmKey {
        AesGcmKey::from_bytes([0x42u8; 32])
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = b"Hello, Cordon! This is a test payload for AES-256-GCM.";
        let blob = encrypt_blob(&key, plaintext).unwrap();
        let decrypted = decrypt_blob(&key, &blob).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_tamper_detection() {
        let key = test_key();
        let plaintext = b"Sensitive data that must not be tampered with.";
        let mut blob = encrypt_blob(&key, plaintext).unwrap();
        // Corrupt the ciphertext
        blob.ciphertext_sha256 = "0".repeat(64);
        let result = decrypt_blob(&key, &blob);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = test_key();
        let key2 = AesGcmKey::from_bytes([0x99u8; 32]);
        let plaintext = b"Data encrypted with key1";
        let blob = encrypt_blob(&key1, plaintext).unwrap();
        let result = decrypt_blob(&key2, &blob);
        assert!(result.is_err());
    }
}
