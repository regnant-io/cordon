//! Key Hierarchy
//!
//! Implements the CMK → derived key hierarchy from the Cordon spec §6.2.
//! Every key has exactly one purpose. Cross-purpose key use is prevented
//! by domain separation in HKDF derivation paths.

use zeroize::ZeroizeOnDrop;

use crate::{
    error::{CryptoError, CryptoResult},
    kdf::{
        admin_key_info, bundle_key_info, derive_32_byte_key, enclave_key_info, log_key_info,
        session_key_info, shard_key_info,
    },
    signing::SigningKey,
    symmetric::AesGcmKey,
};

/// Client Master Key — the root of the entire key hierarchy.
/// This key is held by the client, never transmitted to Cordon.
/// All other keys are derived from this via HKDF-SHA256.
///
/// `Clone` is intentionally supported so the node can retain the CMK in
/// enclave memory and derive per-bundle keys on demand; every copy is
/// zeroized on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: [u8; 32],
}

impl MasterKey {
    /// Create from raw 32 bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Create from a hex string (for provisioning tools)
    pub fn from_hex(s: &str) -> CryptoResult<Self> {
        let bytes = hex::decode(s).map_err(CryptoError::from)?;
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey(
                "Master key must be exactly 32 bytes".into(),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self { bytes: arr })
    }

    /// Get hex representation of the master key
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Derive the bundle encryption key for a specific model bundle + client
    pub fn derive_bundle_key(&self, bundle_id: &str, client_id: &str) -> CryptoResult<BundleKey> {
        let info = bundle_key_info(bundle_id, client_id);
        let bytes = derive_32_byte_key(&self.bytes, &info)?;
        Ok(BundleKey { bytes })
    }

    /// Derive the session authentication key for a deployment + client
    pub fn derive_session_key(
        &self,
        deployment_id: &str,
        client_id: &str,
    ) -> CryptoResult<SessionKey> {
        let info = session_key_info(deployment_id, client_id);
        let bytes = derive_32_byte_key(&self.bytes, &info)?;
        Ok(SessionKey { bytes })
    }

    /// Derive the audit log signing key for a deployment + client
    pub fn derive_log_key(&self, deployment_id: &str, client_id: &str) -> CryptoResult<LogKey> {
        let info = log_key_info(deployment_id, client_id);
        let bytes = derive_32_byte_key(&self.bytes, &info)?;
        // Ed25519 seed from the derived bytes
        Ok(LogKey {
            signing_key: SigningKey::from_seed(&bytes),
        })
    }

    /// Derive the audit log signing key as an owned `SigningKey`
    /// (convenience for the audit log, which takes the key by value).
    pub fn derive_log_signing_key(
        &self,
        deployment_id: &str,
        client_id: &str,
    ) -> CryptoResult<SigningKey> {
        let info = log_key_info(deployment_id, client_id);
        let bytes = derive_32_byte_key(&self.bytes, &info)?;
        Ok(SigningKey::from_seed(&bytes))
    }

    /// Derive the enclave response-signing key (Ed25519).
    ///
    /// Signs inference responses and attestation reports. Because it is
    /// derived deterministically from the CMK, a client holding the CMK can
    /// derive the matching verifying key and check response signatures
    /// offline — no need to trust a key the node hands over.
    pub fn derive_enclave_key(
        &self,
        deployment_id: &str,
        client_id: &str,
    ) -> CryptoResult<SigningKey> {
        let info = enclave_key_info(deployment_id, client_id);
        let bytes = derive_32_byte_key(&self.bytes, &info)?;
        Ok(SigningKey::from_seed(&bytes))
    }

    /// Derive the admin authorization key for a deployment + client
    pub fn derive_admin_key(&self, deployment_id: &str, client_id: &str) -> CryptoResult<AdminKey> {
        let info = admin_key_info(deployment_id, client_id);
        let bytes = derive_32_byte_key(&self.bytes, &info)?;
        Ok(AdminKey {
            signing_key: SigningKey::from_seed(&bytes),
        })
    }
}

/// Bundle Key — encrypts a specific model bundle's weight shards.
/// Derived per (bundle_id, client_id). Released to enclave only after attestation.
#[derive(ZeroizeOnDrop)]
pub struct BundleKey {
    bytes: [u8; 32],
}

impl BundleKey {
    /// Derive a per-shard encryption key
    pub fn derive_shard_key(&self, shard_index: u32) -> CryptoResult<AesGcmKey> {
        let info = shard_key_info(shard_index);
        let bytes = derive_32_byte_key(&self.bytes, &info)?;
        Ok(AesGcmKey::from_bytes(bytes))
    }

    /// Get raw bytes (for transport inside attested channel)
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Restore from bytes (inside enclave, after receiving from client)
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }
}

/// Session Key — authenticates the enclave-to-client TLS channel.
/// Rotated on schedule or on demand.
#[derive(ZeroizeOnDrop)]
pub struct SessionKey {
    bytes: [u8; 32],
}

impl SessionKey {
    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// Log Signing Key — signs all audit log entries.
/// The corresponding verifying key is held by the client for log verification.
pub struct LogKey {
    signing_key: SigningKey,
}

impl LogKey {
    /// Get the underlying signing key
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Get the verifying key (safe to share with client)
    pub fn verifying_key(&self) -> crate::signing::VerifyingKey {
        self.signing_key.verifying_key()
    }
}

/// Admin Authorization Key — signs administrative commands.
/// Cordon verifies admin command signatures before execution.
pub struct AdminKey {
    signing_key: SigningKey,
}

impl AdminKey {
    /// Get the underlying signing key
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Get the verifying key (provisioned into Cordon at deployment time)
    pub fn verifying_key(&self) -> crate::signing::VerifyingKey {
        self.signing_key.verifying_key()
    }
}

/// Key Hierarchy — manages the complete derived key set for a deployment
pub struct KeyHierarchy {
    master: MasterKey,
    deployment_id: String,
    client_id: String,
}

impl KeyHierarchy {
    /// Create a new key hierarchy
    pub fn new(master: MasterKey, deployment_id: String, client_id: String) -> Self {
        Self {
            master,
            deployment_id,
            client_id,
        }
    }

    /// Derive all keys needed for a deployment
    pub fn derive_all(&self, bundle_id: &str) -> CryptoResult<DerivedKeys> {
        Ok(DerivedKeys {
            bundle_key: self.master.derive_bundle_key(bundle_id, &self.client_id)?,
            session_key: self
                .master
                .derive_session_key(&self.deployment_id, &self.client_id)?,
            log_key: self
                .master
                .derive_log_key(&self.deployment_id, &self.client_id)?,
            admin_key: self
                .master
                .derive_admin_key(&self.deployment_id, &self.client_id)?,
        })
    }
}

/// Set of all derived keys for a deployment
pub struct DerivedKeys {
    /// Model weight encryption key
    pub bundle_key: BundleKey,
    /// Session authentication key
    pub session_key: SessionKey,
    /// Audit log signing key
    pub log_key: LogKey,
    /// Administrative authorization key
    pub admin_key: AdminKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cmk() -> MasterKey {
        MasterKey::from_bytes([0xABu8; 32])
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let cmk = test_cmk();
        let k1 = cmk.derive_bundle_key("bundle-1", "client-a").unwrap();
        let k2 = test_cmk()
            .derive_bundle_key("bundle-1", "client-a")
            .unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn test_different_bundles_different_keys() {
        let cmk = test_cmk();
        let k1 = cmk.derive_bundle_key("bundle-1", "client-a").unwrap();
        let k2 = test_cmk()
            .derive_bundle_key("bundle-2", "client-a")
            .unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn test_different_purposes_different_keys() {
        let cmk = test_cmk();
        let bundle_key = cmk.derive_bundle_key("bundle-1", "client-a").unwrap();
        let session_key = test_cmk()
            .derive_session_key("deploy-1", "client-a")
            .unwrap();
        assert_ne!(bundle_key.as_bytes(), session_key.as_bytes());
    }

    #[test]
    fn test_shard_key_derivation() {
        let cmk = test_cmk();
        let bundle_key = cmk.derive_bundle_key("bundle-1", "client-a").unwrap();
        let shard_0 = bundle_key.derive_shard_key(0).unwrap();
        let shard_1 = bundle_key.derive_shard_key(1).unwrap();
        assert_ne!(shard_0.as_bytes(), shard_1.as_bytes());
    }
}
