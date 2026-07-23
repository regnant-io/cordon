//! Ed25519 Digital Signatures
//!
//! Used for: audit log signing, response signing, admin command authorization,
//! manifest signing, and attestation report signing.

use ed25519_dalek::{
    ed25519::signature::Signer as _,
    Signature as DalekSignature, SigningKey as DalekSigningKey,
    VerifyingKey as DalekVerifyingKey, Verifier as _,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::error::{CryptoError, CryptoResult};

/// Ed25519 signing (private) key — zeroized on drop
#[derive(ZeroizeOnDrop)]
pub struct SigningKey {
    inner: DalekSigningKey,
}

/// Ed25519 verifying (public) key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyingKey {
    #[serde(with = "hex_bytes_32")]
    bytes: [u8; 32],
}

/// Ed25519 signature (64 bytes)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    #[serde(with = "hex_bytes_64")]
    bytes: [u8; 64],
}

impl SigningKey {
    /// Generate a new random Ed25519 signing key
    pub fn generate() -> Self {
        let inner = DalekSigningKey::generate(&mut OsRng);
        Self { inner }
    }

    /// Restore from 32-byte seed (e.g., derived via HKDF)
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let inner = DalekSigningKey::from_bytes(seed);
        Self { inner }
    }

    /// Get the corresponding verifying key
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            bytes: self.inner.verifying_key().to_bytes(),
        }
    }

    /// Sign a message
    pub fn sign(&self, msg: &[u8]) -> Signature {
        let sig = self.inner.sign(msg);
        Signature { bytes: sig.to_bytes() }
    }
}

impl VerifyingKey {
    /// Restore from 32 raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> CryptoResult<Self> {
        // Validate the bytes form a valid point
        DalekVerifyingKey::from_bytes(&bytes)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        Ok(Self { bytes })
    }

    /// Restore from hex string
    pub fn from_hex(s: &str) -> CryptoResult<Self> {
        let bytes = hex::decode(s).map_err(CryptoError::from)?;
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey("Ed25519 public key must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Self::from_bytes(arr)
    }

    /// Get bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// Get hex representation
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Verify a signature
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> CryptoResult<()> {
        let vk = DalekVerifyingKey::from_bytes(&self.bytes)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let dalek_sig = DalekSignature::from_bytes(&sig.bytes);
        vk.verify(msg, &dalek_sig)
            .map_err(|_| CryptoError::SignatureInvalid)
    }
}

impl Signature {
    /// Get bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        self.bytes
    }

    /// Get hex representation
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Restore from hex string
    pub fn from_hex(s: &str) -> CryptoResult<Self> {
        let bytes = hex::decode(s).map_err(CryptoError::from)?;
        if bytes.len() != 64 {
            return Err(CryptoError::InvalidKey("Ed25519 signature must be 64 bytes".into()));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Self { bytes: arr })
    }
}

/// Sign a message with a signing key
pub fn sign_bytes(key: &SigningKey, msg: &[u8]) -> Signature {
    key.sign(msg)
}

/// Verify a message signature with a verifying key
pub fn verify_bytes(vk: &VerifyingKey, msg: &[u8], sig: &Signature) -> CryptoResult<()> {
    vk.verify(msg, sig)
}

// Serde helpers for fixed-size byte arrays
mod hex_bytes_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

mod hex_bytes_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("expected 64 bytes"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();
        let msg = b"test message for signing";
        let sig = sign_bytes(&sk, msg);
        assert!(verify_bytes(&vk, msg, &sig).is_ok());
    }

    #[test]
    fn test_wrong_message_fails() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();
        let sig = sign_bytes(&sk, b"original");
        assert!(verify_bytes(&vk, b"tampered", &sig).is_err());
    }

    #[test]
    fn test_from_seed_deterministic() {
        let seed = [0x33u8; 32];
        let sk1 = SigningKey::from_seed(&seed);
        let sk2 = SigningKey::from_seed(&seed);
        let msg = b"determinism test";
        let sig1 = sign_bytes(&sk1, msg);
        let sig2 = sign_bytes(&sk2, msg);
        // Ed25519 with deterministic nonce (RFC 8032) → same sig
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }
}
