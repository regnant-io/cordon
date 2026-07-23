//! Secure Model Store — Layer 3, §6
//!
//! Manages encrypted model bundles. Weights are stored AES-256-GCM encrypted.
//! Decryption happens only inside the TEE using keys provisioned after attestation.
//! Continuous integrity monitoring samples ciphertext hashes every 15 minutes.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::{interval, Duration};

use zeroize::Zeroize;

use cordon_crypto::{
    BundleKey,
    signing::{VerifyingKey, Signature},
};
use crate::error::{CordonError, CordonResult};

/// Shard descriptor in the model manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardDescriptor {
    /// Relative path to the encrypted shard file
    pub path: String,
    /// SHA-256 of the plaintext (verified after decryption)
    pub plaintext_sha256: String,
    /// SHA-256 of the ciphertext (verified before decryption)
    pub ciphertext_sha256: String,
    /// Base64-encoded 12-byte IV
    pub iv_base64: String,
    /// Shard size in bytes
    pub size_bytes: u64,
    /// Layer index
    pub layer_index: u32,
}

/// Hardware requirements in the manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareRequirements {
    /// Minimum GPU VRAM in GB
    pub min_gpu_vram_gb: u32,
    /// Minimum RAM in GB
    pub min_ram_gb: u32,
    /// ECC memory required
    pub ecc_memory_required: bool,
}

/// TEE requirements in the manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeRequirements {
    /// Minimum SGX ISV SVN
    pub sgx_isv_svn_min: Option<u16>,
    /// Minimum SEV-SNP API version
    pub sev_snp_api_min: Option<String>,
}

/// Minimum requirements for running this bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinimumRequirements {
    /// Minimum Cordon version
    pub cordon_version: String,
    /// TEE requirements
    pub tee: TeeRequirements,
    /// Hardware requirements
    pub hardware: HardwareRequirements,
}

/// Model bundle manifest — plaintext metadata about an encrypted bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    /// Unique bundle ID
    pub bundle_id: String,
    /// Human-readable model name
    pub model_name: String,
    /// Model version
    pub model_version: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Encryption info
    pub encryption_algorithm: String,
    /// Key derivation algorithm
    pub key_derivation: String,
    /// Client key ID used for this bundle
    pub client_key_id: String,
    /// Shard descriptors
    pub shards: Vec<ShardDescriptor>,
    /// SHA-256 of all shards concatenated in order
    pub total_plaintext_sha256: String,
    /// Minimum requirements
    pub minimum_requirements: MinimumRequirements,
    /// SHA-256 of the output policy (plaintext)
    pub policy_hash: String,
    /// Vendor Ed25519 signature (hex)
    pub vendor_signature: String,
    /// Client approval Ed25519 signature (hex)
    pub client_approval_signature: String,
}

impl BundleManifest {
    /// Compute the canonical bytes for signing (everything except the signatures)
    pub fn signable_bytes(&self) -> CordonResult<Vec<u8>> {
        let mut m = self.clone();
        m.vendor_signature = String::new();
        m.client_approval_signature = String::new();
        serde_json::to_vec(&m)
            .map_err(|e| CordonError::Internal(e.to_string()))
    }

    /// Verify the vendor signature
    pub fn verify_vendor_signature(&self, vendor_vk: &VerifyingKey) -> CordonResult<()> {
        let bytes = self.signable_bytes()?;
        let sig = Signature::from_hex(&self.vendor_signature)
            .map_err(|e| CordonError::Internal(e.to_string()))?;
        vendor_vk.verify(&bytes, &sig)
            .map_err(|_| CordonError::Internal("Vendor signature invalid on bundle manifest".into()))
    }

    /// Verify the client approval signature
    pub fn verify_client_signature(&self, client_vk: &VerifyingKey) -> CordonResult<()> {
        let bytes = self.signable_bytes()?;
        let sig = Signature::from_hex(&self.client_approval_signature)
            .map_err(|e| CordonError::Internal(e.to_string()))?;
        client_vk.verify(&bytes, &sig)
            .map_err(|_| CordonError::Internal("Client approval signature invalid on bundle manifest".into()))
    }

    /// SHA-256 of the serialized manifest (for PCR[13] extension)
    pub fn manifest_hash(&self) -> CordonResult<String> {
        let bytes = serde_json::to_vec(self)
            .map_err(|e| CordonError::Internal(e.to_string()))?;
        Ok(hex::encode(Sha256::digest(&bytes)))
    }
}

/// State of a loaded bundle
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleStatus {
    /// Bundle is present but not yet decrypted/loaded
    Encrypted,
    /// Bundle is decrypted and ready for inference
    Ready,
    /// Bundle failed integrity check
    Tampered,
    /// Bundle is being loaded
    Loading,
}

/// A tracked bundle entry in the store
struct BundleEntry {
    manifest: BundleManifest,
    bundle_dir: PathBuf,
    status: BundleStatus,
    last_integrity_check: Option<DateTime<Utc>>,
    integrity_check_passed: bool,
}

/// Secure model store
pub struct ModelStore {
    store_dir: PathBuf,
    bundles: Arc<RwLock<HashMap<String, BundleEntry>>>,
    /// Optional vendor verifying key (for manifest signature verification)
    vendor_vk: Option<VerifyingKey>,
}

impl ModelStore {
    /// Create a new model store
    pub fn new(store_dir: PathBuf, vendor_vk: Option<VerifyingKey>) -> CordonResult<Self> {
        std::fs::create_dir_all(&store_dir)
            .map_err(|e| CordonError::Internal(format!("Cannot create model store: {}", e)))?;
        let store = Self {
            store_dir,
            bundles: Arc::new(RwLock::new(HashMap::new())),
            vendor_vk,
        };
        store.scan_existing_bundles()?;
        Ok(store)
    }

    /// Scan store directory for existing bundles
    fn scan_existing_bundles(&self) -> CordonResult<()> {
        let entries = std::fs::read_dir(&self.store_dir)
            .map_err(|e| CordonError::Internal(e.to_string()))?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let manifest_path = path.join("manifest.json");
                if manifest_path.exists() {
                    match self.load_manifest_from_dir(&path) {
                        Ok(manifest) => {
                            let bundle_id = manifest.bundle_id.clone();
                            tracing::info!("Found bundle {} at {:?}", bundle_id, path);
                            self.bundles.write().insert(bundle_id, BundleEntry {
                                manifest,
                                bundle_dir: path,
                                status: BundleStatus::Encrypted,
                                last_integrity_check: None,
                                integrity_check_passed: false,
                            });
                        }
                        Err(e) => {
                            tracing::warn!("Cannot load manifest from {:?}: {}", path, e);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Load a manifest from a bundle directory
    fn load_manifest_from_dir(&self, dir: &Path) -> CordonResult<BundleManifest> {
        let manifest_path = dir.join("manifest.json");
        let content = std::fs::read_to_string(&manifest_path)
            .map_err(|e| CordonError::Internal(format!("Cannot read manifest: {}", e)))?;
        let manifest: BundleManifest = serde_json::from_str(&content)
            .map_err(|e| CordonError::Internal(format!("Invalid manifest JSON: {}", e)))?;
        Ok(manifest)
    }

    /// Register a new bundle (after receiving and verifying it)
    pub fn register_bundle(
        &self,
        manifest: BundleManifest,
        bundle_dir: PathBuf,
        client_vk: Option<&VerifyingKey>,
    ) -> CordonResult<()> {
        // Verify vendor signature if we have the key
        if let Some(vk) = &self.vendor_vk {
            manifest.verify_vendor_signature(vk)?;
        }
        // Verify client approval signature if provided
        if let Some(vk) = client_vk {
            manifest.verify_client_signature(vk)?;
        }

        let bundle_id = manifest.bundle_id.clone();
        self.bundles.write().insert(bundle_id.clone(), BundleEntry {
            manifest,
            bundle_dir,
            status: BundleStatus::Encrypted,
            last_integrity_check: None,
            integrity_check_passed: false,
        });
        tracing::info!("Bundle {} registered in model store", bundle_id);
        Ok(())
    }

    /// Get a manifest by bundle ID
    pub fn get_manifest(&self, bundle_id: &str) -> CordonResult<BundleManifest> {
        self.bundles.read()
            .get(bundle_id)
            .map(|e| e.manifest.clone())
            .ok_or_else(|| CordonError::ModelNotFound { bundle_id: bundle_id.to_string() })
    }

    /// Whether a bundle with this id is registered in the store.
    pub fn is_registered(&self, bundle_id: &str) -> bool {
        self.bundles.read().contains_key(bundle_id)
    }

    /// List all bundle IDs and their status
    pub fn list_bundles(&self) -> Vec<(String, BundleStatus)> {
        self.bundles.read()
            .iter()
            .map(|(id, e)| (id.clone(), e.status.clone()))
            .collect()
    }

    /// Run integrity check on a bundle — samples ciphertext hashes against manifest
    pub fn run_integrity_check(&self, bundle_id: &str) -> CordonResult<bool> {
        let bundles = self.bundles.read();
        let entry = bundles.get(bundle_id)
            .ok_or_else(|| CordonError::ModelNotFound { bundle_id: bundle_id.to_string() })?;

        let manifest = &entry.manifest;
        let bundle_dir = &entry.bundle_dir;

        // Sample 5–10% of shards (at least 1)
        let total_shards = manifest.shards.len();
        let sample_count = ((total_shards as f64 * 0.1).ceil() as usize).max(1);

        // Deterministic sampling: take evenly spaced shards
        let step = total_shards / sample_count;
        let indices: Vec<usize> = (0..sample_count).map(|i| i * step).collect();

        for idx in indices {
            if let Some(shard) = manifest.shards.get(idx) {
                let shard_path = bundle_dir.join(&shard.path);
                if !shard_path.exists() {
                    tracing::error!("Shard {} missing: {:?}", shard.path, shard_path);
                    return Ok(false);
                }

                let shard_bytes = std::fs::read(&shard_path)
                    .map_err(|e| CordonError::Internal(format!("Cannot read shard: {}", e)))?;

                let computed_hash = hex::encode(Sha256::digest(&shard_bytes));
                if computed_hash != shard.ciphertext_sha256 {
                    tracing::error!(
                        "Shard {} ciphertext hash MISMATCH: expected {}, got {}",
                        shard.path, shard.ciphertext_sha256, computed_hash
                    );
                    return Ok(false);
                }
            }
        }

        // Verify manifest signatures still valid
        if let Some(vk) = &self.vendor_vk {
            manifest.verify_vendor_signature(vk)
                .map_err(|e| {
                    tracing::error!("Manifest vendor signature invalid during integrity check: {}", e);
                    e
                })?;
        }

        drop(bundles);

        // Update last check time
        if let Some(entry) = self.bundles.write().get_mut(bundle_id) {
            entry.last_integrity_check = Some(Utc::now());
            entry.integrity_check_passed = true;
        }

        tracing::debug!("Integrity check passed for bundle {}", bundle_id);
        Ok(true)
    }

    /// Decrypt a specific shard (inside TEE — plaintext weights only exist here)
    pub fn decrypt_shard(
        &self,
        bundle_id: &str,
        shard_index: usize,
        bundle_key: &BundleKey,
    ) -> CordonResult<Vec<u8>> {
        use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
        use cordon_crypto::symmetric::decrypt_shard;

        let bundles = self.bundles.read();
        let entry = bundles.get(bundle_id)
            .ok_or_else(|| CordonError::ModelNotFound { bundle_id: bundle_id.to_string() })?;

        let shard_desc = entry.manifest.shards.get(shard_index)
            .ok_or_else(|| CordonError::Internal(format!("Shard index {} out of range", shard_index)))?;

        let shard_path = entry.bundle_dir.join(&shard_desc.path);
        let ciphertext = std::fs::read(&shard_path)
            .map_err(|e| CordonError::Internal(format!("Cannot read shard file: {}", e)))?;

        // Verify ciphertext hash before decryption
        let ct_hash = hex::encode(Sha256::digest(&ciphertext));
        if ct_hash != shard_desc.ciphertext_sha256 {
            return Err(CordonError::ModelIntegrityViolation {
                bundle_id: bundle_id.to_string(),
            });
        }

        // Derive per-shard key
        let shard_key = bundle_key.derive_shard_key(shard_index as u32)
            .map_err(|e| CordonError::KeyError(e.to_string()))?;

        // Decode IV
        let iv_bytes = B64.decode(&shard_desc.iv_base64)
            .map_err(|e| CordonError::Internal(format!("Invalid IV: {}", e)))?;
        if iv_bytes.len() != 12 {
            return Err(CordonError::Internal("Shard IV must be 12 bytes".into()));
        }
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_bytes);

        // Decrypt
        let plaintext = decrypt_shard(&shard_key, &ciphertext, &iv)
            .map_err(|_| CordonError::ModelIntegrityViolation { bundle_id: bundle_id.to_string() })?;

        // Verify plaintext hash
        let pt_hash = hex::encode(Sha256::digest(&plaintext));
        if pt_hash != shard_desc.plaintext_sha256 {
            return Err(CordonError::ModelIntegrityViolation {
                bundle_id: bundle_id.to_string(),
            });
        }

        Ok(plaintext)
    }

    /// Gate a model for serving (§6.5). A bundle may be served only if it is
    /// registered, passes a fresh integrity check, and — when a `bundle_key`
    /// is available — can actually be decrypted (proving the enclave holds the
    /// correct key). Plaintext produced by the decryption proof is zeroized
    /// immediately and never leaves this function.
    ///
    /// If the store is empty (no bundles provisioned) the model is allowed
    /// through as a development convenience. Once any bundle exists, unknown
    /// models are rejected unless `allow_unregistered` is set.
    pub fn ensure_servable(
        &self,
        bundle_id: &str,
        bundle_key: Option<&BundleKey>,
        allow_unregistered: bool,
    ) -> CordonResult<()> {
        let (store_empty, registered) = {
            let bundles = self.bundles.read();
            (bundles.is_empty(), bundles.contains_key(bundle_id))
        };

        if !registered {
            if store_empty || allow_unregistered {
                return Ok(());
            }
            return Err(CordonError::ModelNotFound { bundle_id: bundle_id.to_string() });
        }

        // Integrity check (samples ciphertext hashes + manifest signature).
        if !self.run_integrity_check(bundle_id)? {
            return Err(CordonError::ModelIntegrityViolation { bundle_id: bundle_id.to_string() });
        }

        // Key-possession proof: decrypt shard 0 and discard the plaintext.
        if let Some(bk) = bundle_key {
            let has_shards = self.bundles.read()
                .get(bundle_id)
                .map(|e| !e.manifest.shards.is_empty())
                .unwrap_or(false);
            if has_shards {
                let mut plaintext = self.decrypt_shard(bundle_id, 0, bk)?;
                plaintext.zeroize();
            }
        }

        // Mark ready.
        if let Some(entry) = self.bundles.write().get_mut(bundle_id) {
            entry.status = BundleStatus::Ready;
        }
        Ok(())
    }

    /// Decrypt every shard of a bundle in order, verify the full-plaintext
    /// hash, and return the reconstructed weights in a zeroizing buffer.
    ///
    /// This is the real in-enclave decryption path used before loading a model.
    /// Per-shard ciphertext and plaintext hashes are checked by `decrypt_shard`;
    /// the concatenated result is checked against `total_plaintext_sha256`.
    pub fn materialize_plaintext(
        &self,
        bundle_id: &str,
        bundle_key: &BundleKey,
    ) -> CordonResult<cordon_crypto::zeroize_ext::SecretVec> {
        let (shard_count, total_size, expected_total) = {
            let bundles = self.bundles.read();
            let entry = bundles.get(bundle_id)
                .ok_or_else(|| CordonError::ModelNotFound { bundle_id: bundle_id.to_string() })?;
            let total: u64 = entry.manifest.shards.iter().map(|s| s.size_bytes).sum();
            (entry.manifest.shards.len(), total as usize, entry.manifest.total_plaintext_sha256.clone())
        };

        let mut out = cordon_crypto::zeroize_ext::SecretVec::with_capacity(total_size);
        let mut hasher = Sha256::new();
        for idx in 0..shard_count {
            let mut pt = self.decrypt_shard(bundle_id, idx, bundle_key)?;
            hasher.update(&pt);
            out.extend_from_slice(&pt);
            pt.zeroize();
        }

        let total = hex::encode(hasher.finalize());
        if !expected_total.is_empty() && total != expected_total {
            return Err(CordonError::ModelIntegrityViolation { bundle_id: bundle_id.to_string() });
        }

        tracing::info!("Materialized {} plaintext bytes for bundle {} ({} shards)", out.len(), bundle_id, shard_count);
        Ok(out)
    }

    /// Remove a bundle from the store
    pub fn remove_bundle(&self, bundle_id: &str) -> CordonResult<()> {
        let mut bundles = self.bundles.write();
        if bundles.remove(bundle_id).is_none() {
            return Err(CordonError::ModelNotFound { bundle_id: bundle_id.to_string() });
        }
        tracing::info!("Bundle {} removed from model store", bundle_id);
        Ok(())
    }

    /// Start the background integrity monitor
    pub fn start_integrity_monitor(
        self: Arc<Self>,
        interval_minutes: u64,
        halt_on_tamper: Arc<std::sync::atomic::AtomicBool>,
    ) {
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(interval_minutes * 60));
            ticker.tick().await; // Skip first immediate tick
            loop {
                ticker.tick().await;
                let bundle_ids: Vec<String> = self.bundles.read().keys().cloned().collect();
                for bundle_id in bundle_ids {
                    match self.run_integrity_check(&bundle_id) {
                        Ok(true) => {
                            tracing::debug!("Integrity check passed: {}", bundle_id);
                        }
                        Ok(false) => {
                            tracing::error!(
                                "INTEGRITY VIOLATION detected for bundle {}",
                                bundle_id
                            );
                            halt_on_tamper.store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                        Err(e) => {
                            tracing::error!("Integrity check error for {}: {}", bundle_id, e);
                        }
                    }
                }
            }
        });
    }
}
