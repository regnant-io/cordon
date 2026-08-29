//! Encrypted model store (Layer 3).
//!
//! A bundle is a directory holding a plaintext `manifest.json` and one or more
//! AES-256-GCM encrypted weight shards. Shard keys are derived from the Client
//! Master Key, so an operator without the CMK holds ciphertext and nothing else.
//!
//! # Serving path
//!
//! 1. **Gate.** [`ModelStore::ensure_servable`] admits a bundle only if it is
//!    registered and its most recent integrity check is both recent and passing.
//!    The check itself never runs on the request path — it is a cached verdict,
//!    refreshed in the background and on demand off the async runtime.
//! 2. **Stage.** [`ModelStore::stage_plaintext`] decrypts the bundle shard by
//!    shard, streaming to a mode-0600 file rather than reconstructing the whole
//!    model in memory, and verifies the full-plaintext digest as it goes.
//! 3. **Load and erase.** The runtime is started against the staged file with
//!    memory mapping disabled, so it reads the weights fully into its own
//!    address space. [`StagedModel`] then deletes the file, and does so again on
//!    drop. Plaintext weights exist on disk only for the duration of the load.
//!
//! This is disk-backed staging, not enclave-resident decryption. It bounds the
//! window in which plaintext weights are readable; it does not eliminate it. A
//! deployment that needs the stronger property should stage onto a memory-backed
//! filesystem — see `model_store.staging_dir`.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use zeroize::Zeroize;

use crate::error::{CordonError, CordonResult};
use cordon_crypto::{
    signing::{Signature, VerifyingKey},
    BundleKey,
};

/// Read buffer for streaming hashes and decryption.
const IO_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// Shard descriptor in the model manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardDescriptor {
    /// Path to the encrypted shard, relative to the bundle directory.
    pub path: String,
    /// SHA-256 of the plaintext, verified after decryption.
    pub plaintext_sha256: String,
    /// SHA-256 of the ciphertext, verified before decryption.
    pub ciphertext_sha256: String,
    /// Base64-encoded 12-byte nonce.
    pub iv_base64: String,
    /// Plaintext size in bytes.
    pub size_bytes: u64,
    /// Ordering index. Shards are concatenated in this order.
    pub layer_index: u32,
}

/// Hardware requirements declared by a bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareRequirements {
    /// Minimum GPU VRAM in GB.
    pub min_gpu_vram_gb: u32,
    /// Minimum system RAM in GB.
    pub min_ram_gb: u32,
    /// Whether ECC memory is required.
    pub ecc_memory_required: bool,
}

/// TEE requirements declared by a bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeRequirements {
    /// Minimum SGX ISV SVN.
    pub sgx_isv_svn_min: Option<u16>,
    /// Minimum SEV-SNP API version.
    pub sev_snp_api_min: Option<String>,
}

/// Minimum requirements for running a bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinimumRequirements {
    /// Minimum Cordon version.
    pub cordon_version: String,
    /// TEE requirements.
    pub tee: TeeRequirements,
    /// Hardware requirements.
    pub hardware: HardwareRequirements,
}

/// Plaintext metadata describing an encrypted bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    /// Unique bundle ID.
    pub bundle_id: String,
    /// Human-readable model name.
    pub model_name: String,
    /// Model version.
    pub model_version: String,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Encryption algorithm. Must be `AES-256-GCM`.
    pub encryption_algorithm: String,
    /// Key derivation algorithm. Must be `HKDF-SHA256`.
    pub key_derivation: String,
    /// Client key ID the bundle was encrypted for.
    pub client_key_id: String,
    /// Shard descriptors, in concatenation order.
    pub shards: Vec<ShardDescriptor>,
    /// SHA-256 of all plaintext shards concatenated in order.
    pub total_plaintext_sha256: String,
    /// Minimum requirements.
    pub minimum_requirements: MinimumRequirements,
    /// SHA-256 of the output policy.
    pub policy_hash: String,
    /// Vendor Ed25519 signature (hex). Empty when unsigned.
    pub vendor_signature: String,
    /// Client approval Ed25519 signature (hex). Empty when unsigned.
    pub client_approval_signature: String,
}

/// The encryption algorithm a bundle must declare.
pub const REQUIRED_ENCRYPTION_ALGORITHM: &str = "AES-256-GCM";
/// The key-derivation algorithm a bundle must declare.
pub const REQUIRED_KEY_DERIVATION: &str = "HKDF-SHA256";

impl BundleManifest {
    /// Canonical bytes for signing: the manifest with both signature fields
    /// cleared, serialised deterministically.
    pub fn signable_bytes(&self) -> CordonResult<Vec<u8>> {
        let mut m = self.clone();
        m.vendor_signature = String::new();
        m.client_approval_signature = String::new();
        serde_json::to_vec(&m).map_err(|e| CordonError::Internal(e.to_string()))
    }

    /// Verify the vendor signature.
    pub fn verify_vendor_signature(&self, vendor_vk: &VerifyingKey) -> CordonResult<()> {
        let bytes = self.signable_bytes()?;
        let sig = Signature::from_hex(&self.vendor_signature)
            .map_err(|_| CordonError::ValidationFailed("malformed vendor signature".into()))?;
        vendor_vk.verify(&bytes, &sig).map_err(|_| {
            CordonError::ValidationFailed("vendor signature invalid on bundle manifest".into())
        })
    }

    /// Verify the client approval signature.
    pub fn verify_client_signature(&self, client_vk: &VerifyingKey) -> CordonResult<()> {
        let bytes = self.signable_bytes()?;
        let sig = Signature::from_hex(&self.client_approval_signature).map_err(|_| {
            CordonError::ValidationFailed("malformed client approval signature".into())
        })?;
        client_vk.verify(&bytes, &sig).map_err(|_| {
            CordonError::ValidationFailed(
                "client approval signature invalid on bundle manifest".into(),
            )
        })
    }

    /// SHA-256 of the serialised manifest, used to extend the model PCR.
    pub fn manifest_hash(&self) -> CordonResult<String> {
        let bytes = serde_json::to_vec(self).map_err(|e| CordonError::Internal(e.to_string()))?;
        Ok(hex::encode(Sha256::digest(&bytes)))
    }

    /// Reject a manifest that does not describe a genuinely encrypted bundle.
    ///
    /// A manifest claiming `encryption_algorithm = "NONE"`, or carrying an
    /// all-zero nonce, or whose ciphertext digest equals its plaintext digest,
    /// describes plaintext weights wearing a bundle's clothing. Admitting one
    /// would let the store report a model as protected when it is not.
    pub fn validate_structure(&self) -> CordonResult<()> {
        if self.bundle_id.trim().is_empty() {
            return Err(CordonError::ValidationFailed(
                "bundle_id must not be empty".into(),
            ));
        }
        if !self
            .encryption_algorithm
            .eq_ignore_ascii_case(REQUIRED_ENCRYPTION_ALGORITHM)
        {
            return Err(CordonError::ValidationFailed(format!(
                "bundle '{}' declares encryption_algorithm '{}'; Cordon serves only \
                 {} bundles. Re-encrypt it with `cordon-provision encrypt`.",
                self.bundle_id, self.encryption_algorithm, REQUIRED_ENCRYPTION_ALGORITHM
            )));
        }
        if !self
            .key_derivation
            .eq_ignore_ascii_case(REQUIRED_KEY_DERIVATION)
        {
            return Err(CordonError::ValidationFailed(format!(
                "bundle '{}' declares key_derivation '{}'; expected {}",
                self.bundle_id, self.key_derivation, REQUIRED_KEY_DERIVATION
            )));
        }
        if self.shards.is_empty() {
            return Err(CordonError::ValidationFailed(format!(
                "bundle '{}' declares no shards",
                self.bundle_id
            )));
        }

        for (idx, shard) in self.shards.iter().enumerate() {
            validate_relative_path(&shard.path, &self.bundle_id)?;
            validate_digest(&shard.plaintext_sha256, &format!("shard {} plaintext", idx))?;
            validate_digest(
                &shard.ciphertext_sha256,
                &format!("shard {} ciphertext", idx),
            )?;

            if shard
                .plaintext_sha256
                .eq_ignore_ascii_case(&shard.ciphertext_sha256)
            {
                return Err(CordonError::ValidationFailed(format!(
                    "bundle '{}' shard {} has identical plaintext and ciphertext \
                     digests — the shard is not encrypted",
                    self.bundle_id, idx
                )));
            }

            let iv = decode_iv(&shard.iv_base64).map_err(|e| {
                CordonError::ValidationFailed(format!(
                    "bundle '{}' shard {}: {}",
                    self.bundle_id, idx, e
                ))
            })?;
            if iv.iter().all(|b| *b == 0) {
                return Err(CordonError::ValidationFailed(format!(
                    "bundle '{}' shard {} uses an all-zero nonce. Nonce reuse under \
                     AES-GCM is catastrophic; re-encrypt the bundle.",
                    self.bundle_id, idx
                )));
            }
        }

        // Nonce reuse across shards under related keys is not automatically a
        // break, but it signals a provisioning tool that is not generating
        // nonces, which is worth refusing outright.
        let mut seen = std::collections::HashSet::new();
        for (idx, shard) in self.shards.iter().enumerate() {
            if !seen.insert(shard.iv_base64.clone()) {
                return Err(CordonError::ValidationFailed(format!(
                    "bundle '{}' reuses a nonce at shard {}",
                    self.bundle_id, idx
                )));
            }
        }

        validate_digest(&self.total_plaintext_sha256, "total_plaintext_sha256")?;
        Ok(())
    }
}

fn validate_digest(value: &str, what: &str) -> CordonResult<()> {
    if value.len() != 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CordonError::ValidationFailed(format!(
            "{} is not a SHA-256 hex digest",
            what
        )));
    }
    Ok(())
}

/// Reject shard paths that could escape the bundle directory.
fn validate_relative_path(path: &str, bundle_id: &str) -> CordonResult<()> {
    let p = Path::new(path);
    if p.is_absolute() {
        return Err(CordonError::ValidationFailed(format!(
            "bundle '{}' names an absolute shard path '{}'",
            bundle_id, path
        )));
    }
    for component in p.components() {
        match component {
            std::path::Component::Normal(_) => {}
            _ => {
                return Err(CordonError::ValidationFailed(format!(
                    "bundle '{}' shard path '{}' escapes the bundle directory",
                    bundle_id, path
                )));
            }
        }
    }
    Ok(())
}

fn decode_iv(iv_base64: &str) -> Result<[u8; 12], String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let bytes = B64
        .decode(iv_base64)
        .map_err(|e| format!("invalid base64 nonce: {}", e))?;
    if bytes.len() != 12 {
        return Err(format!("nonce must be 12 bytes, got {}", bytes.len()));
    }
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&bytes);
    Ok(iv)
}

/// State of a bundle in the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    /// Present and encrypted; not staged.
    Encrypted,
    /// Staged and being served.
    Ready,
    /// Failed an integrity check. Not servable.
    Tampered,
    /// Currently being staged.
    Staging,
}

/// The outcome of the most recent integrity check on a bundle.
#[derive(Debug, Clone, Copy)]
struct IntegrityVerdict {
    checked_at: DateTime<Utc>,
    passed: bool,
}

struct BundleEntry {
    manifest: BundleManifest,
    bundle_dir: PathBuf,
    status: BundleStatus,
    verdict: Option<IntegrityVerdict>,
}

/// A summary of one bundle, for the models endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct BundleSummary {
    /// Bundle identifier.
    pub bundle_id: String,
    /// Human-readable model name.
    pub model_name: String,
    /// Model version.
    pub model_version: String,
    /// Current status.
    pub status: BundleStatus,
    /// Total plaintext size across all shards.
    pub size_bytes: u64,
    /// When the bundle last passed or failed an integrity check.
    pub last_integrity_check: Option<DateTime<Utc>>,
    /// Whether that check passed.
    pub integrity_ok: bool,
}

/// The encrypted model store.
pub struct ModelStore {
    store_dir: PathBuf,
    bundles: Arc<RwLock<HashMap<String, BundleEntry>>>,
    vendor_vk: Option<VerifyingKey>,
    /// How long an integrity verdict remains usable on the serving path.
    verdict_ttl: ChronoDuration,
    /// Serialises integrity checks so a burst of requests hashing the same
    /// bundle does not multiply the I/O.
    check_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl ModelStore {
    /// Open a store rooted at `store_dir`, scanning it for existing bundles.
    pub fn new(store_dir: PathBuf, vendor_vk: Option<VerifyingKey>) -> CordonResult<Self> {
        Self::with_verdict_ttl(store_dir, vendor_vk, 15)
    }

    /// Open a store with an explicit integrity-verdict lifetime, in minutes.
    pub fn with_verdict_ttl(
        store_dir: PathBuf,
        vendor_vk: Option<VerifyingKey>,
        verdict_ttl_minutes: i64,
    ) -> CordonResult<Self> {
        std::fs::create_dir_all(&store_dir)
            .map_err(|e| CordonError::Internal(format!("cannot create model store: {}", e)))?;
        let store = Self {
            store_dir,
            bundles: Arc::new(RwLock::new(HashMap::new())),
            vendor_vk,
            verdict_ttl: ChronoDuration::minutes(verdict_ttl_minutes.max(1)),
            check_locks: Arc::new(Mutex::new(HashMap::new())),
        };
        store.scan_existing_bundles()?;
        Ok(store)
    }

    /// Scan the store directory for bundle subdirectories.
    ///
    /// A directory whose manifest is malformed, unencrypted, or otherwise
    /// invalid is skipped with a loud warning rather than admitted: half-valid
    /// bundles are how unencrypted weights end up being served.
    fn scan_existing_bundles(&self) -> CordonResult<()> {
        let entries =
            std::fs::read_dir(&self.store_dir).map_err(|e| CordonError::Internal(e.to_string()))?;

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() || !path.join("manifest.json").exists() {
                continue;
            }
            match load_manifest_from_dir(&path) {
                Ok(manifest) => match manifest.validate_structure() {
                    Ok(()) => {
                        let bundle_id = manifest.bundle_id.clone();
                        tracing::info!(bundle_id = %bundle_id, path = %path.display(), "Bundle found");
                        self.bundles.write().insert(
                            bundle_id,
                            BundleEntry {
                                manifest,
                                bundle_dir: path,
                                status: BundleStatus::Encrypted,
                                verdict: None,
                            },
                        );
                    }
                    Err(e) => tracing::error!(
                        path = %path.display(),
                        "Refusing bundle: {}. It will not be served.",
                        e
                    ),
                },
                Err(e) => tracing::warn!(path = %path.display(), "Cannot read manifest: {}", e),
            }
        }
        Ok(())
    }

    /// Register a bundle, validating its structure and any signatures first.
    pub fn register_bundle(
        &self,
        manifest: BundleManifest,
        bundle_dir: PathBuf,
        client_vk: Option<&VerifyingKey>,
    ) -> CordonResult<()> {
        manifest.validate_structure()?;

        if let Some(vk) = &self.vendor_vk {
            manifest.verify_vendor_signature(vk)?;
        }
        if let Some(vk) = client_vk {
            manifest.verify_client_signature(vk)?;
        }

        let bundle_id = manifest.bundle_id.clone();
        self.bundles.write().insert(
            bundle_id.clone(),
            BundleEntry {
                manifest,
                bundle_dir,
                status: BundleStatus::Encrypted,
                verdict: None,
            },
        );
        tracing::info!(bundle_id = %bundle_id, "Bundle registered");
        Ok(())
    }

    /// The manifest for a bundle.
    pub fn get_manifest(&self, bundle_id: &str) -> CordonResult<BundleManifest> {
        self.bundles
            .read()
            .get(bundle_id)
            .map(|e| e.manifest.clone())
            .ok_or_else(|| CordonError::ModelNotFound {
                bundle_id: bundle_id.to_string(),
            })
    }

    /// Whether a bundle is registered.
    pub fn is_registered(&self, bundle_id: &str) -> bool {
        self.bundles.read().contains_key(bundle_id)
    }

    /// Whether the store holds no bundles.
    pub fn is_empty(&self) -> bool {
        self.bundles.read().is_empty()
    }

    /// Summaries of every registered bundle.
    pub fn list_bundles(&self) -> Vec<BundleSummary> {
        let mut out: Vec<BundleSummary> = self
            .bundles
            .read()
            .values()
            .map(|e| BundleSummary {
                bundle_id: e.manifest.bundle_id.clone(),
                model_name: e.manifest.model_name.clone(),
                model_version: e.manifest.model_version.clone(),
                status: e.status,
                size_bytes: e.manifest.shards.iter().map(|s| s.size_bytes).sum(),
                last_integrity_check: e.verdict.map(|v| v.checked_at),
                integrity_ok: e.verdict.map(|v| v.passed).unwrap_or(false),
            })
            .collect();
        out.sort_by(|a, b| a.bundle_id.cmp(&b.bundle_id));
        out
    }

    /// Admit a bundle for serving, using the cached integrity verdict.
    ///
    /// This runs on every request, so it performs no cryptography and no I/O:
    /// it consults the verdict established at registration, at staging, and by
    /// the background monitor. A stale or failing verdict is refused, which
    /// means a monitor that has stopped running takes the node out of service
    /// rather than leaving it serving unverified weights.
    pub fn ensure_servable(&self, bundle_id: &str, allow_unregistered: bool) -> CordonResult<()> {
        let bundles = self.bundles.read();

        let Some(entry) = bundles.get(bundle_id) else {
            // An empty store is a node with no bundles provisioned at all, which
            // is the normal state when the runtime serves a plain model file.
            if bundles.is_empty() || allow_unregistered {
                return Ok(());
            }
            return Err(CordonError::ModelNotFound {
                bundle_id: bundle_id.to_string(),
            });
        };

        if entry.status == BundleStatus::Tampered {
            return Err(CordonError::ModelIntegrityViolation {
                bundle_id: bundle_id.to_string(),
            });
        }

        match entry.verdict {
            Some(v) if v.passed && Utc::now() - v.checked_at < self.verdict_ttl => Ok(()),
            Some(v) if !v.passed => Err(CordonError::ModelIntegrityViolation {
                bundle_id: bundle_id.to_string(),
            }),
            _ => Err(CordonError::ModelIntegrityViolation {
                bundle_id: format!(
                    "{} (integrity verdict is stale or absent — the integrity monitor \
                     has not confirmed this bundle recently)",
                    bundle_id
                ),
            }),
        }
    }

    /// Verify a bundle's ciphertext against its manifest and record the verdict.
    ///
    /// Shards are hashed by streaming, so a multi-gigabyte bundle is checked in
    /// constant memory. Blocking; call it from `spawn_blocking` or a background
    /// task, never directly from an async request path.
    pub fn run_integrity_check(&self, bundle_id: &str) -> CordonResult<bool> {
        let lock = {
            let mut locks = self.check_locks.lock();
            locks
                .entry(bundle_id.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        let _guard = lock.lock();

        let (manifest, bundle_dir) = {
            let bundles = self.bundles.read();
            let entry = bundles
                .get(bundle_id)
                .ok_or_else(|| CordonError::ModelNotFound {
                    bundle_id: bundle_id.to_string(),
                })?;
            (entry.manifest.clone(), entry.bundle_dir.clone())
        };

        let passed = self.check_shards(&manifest, &bundle_dir)?;
        self.record_verdict(bundle_id, passed);
        if passed {
            tracing::debug!(bundle_id, "Integrity check passed");
        } else {
            tracing::error!(
                bundle_id,
                "INTEGRITY VIOLATION — bundle withdrawn from service"
            );
        }
        Ok(passed)
    }

    fn check_shards(&self, manifest: &BundleManifest, bundle_dir: &Path) -> CordonResult<bool> {
        for shard in &manifest.shards {
            let shard_path = bundle_dir.join(&shard.path);
            if !shard_path.exists() {
                tracing::error!(shard = %shard.path, "Shard missing");
                return Ok(false);
            }
            let computed = hash_file_streaming(&shard_path)?;
            if !cordon_crypto::kdf::ct_eq(computed.as_bytes(), shard.ciphertext_sha256.as_bytes()) {
                tracing::error!(
                    shard = %shard.path,
                    expected = %shard.ciphertext_sha256,
                    actual = %computed,
                    "Shard ciphertext digest mismatch"
                );
                return Ok(false);
            }
        }

        if let Some(vk) = &self.vendor_vk {
            if manifest.verify_vendor_signature(vk).is_err() {
                tracing::error!(bundle_id = %manifest.bundle_id, "Vendor signature no longer valid");
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn record_verdict(&self, bundle_id: &str, passed: bool) {
        if let Some(entry) = self.bundles.write().get_mut(bundle_id) {
            entry.verdict = Some(IntegrityVerdict {
                checked_at: Utc::now(),
                passed,
            });
            if !passed {
                entry.status = BundleStatus::Tampered;
            }
        }
    }

    /// Decrypt one shard, verifying both digests. Used by the provisioning
    /// verifier; the serving path streams instead via [`Self::stage_plaintext`].
    pub fn decrypt_shard(
        &self,
        bundle_id: &str,
        shard_index: usize,
        bundle_key: &BundleKey,
    ) -> CordonResult<Vec<u8>> {
        use cordon_crypto::symmetric::decrypt_shard;

        let (shard_desc, shard_path) = {
            let bundles = self.bundles.read();
            let entry = bundles
                .get(bundle_id)
                .ok_or_else(|| CordonError::ModelNotFound {
                    bundle_id: bundle_id.to_string(),
                })?;
            let shard = entry
                .manifest
                .shards
                .get(shard_index)
                .ok_or_else(|| {
                    CordonError::Internal(format!("shard index {} out of range", shard_index))
                })?
                .clone();
            let path = entry.bundle_dir.join(&shard.path);
            (shard, path)
        };

        let ciphertext = std::fs::read(&shard_path)
            .map_err(|e| CordonError::Internal(format!("cannot read shard: {}", e)))?;

        let ct_hash = hex::encode(Sha256::digest(&ciphertext));
        if !cordon_crypto::kdf::ct_eq(ct_hash.as_bytes(), shard_desc.ciphertext_sha256.as_bytes()) {
            return Err(CordonError::ModelIntegrityViolation {
                bundle_id: bundle_id.to_string(),
            });
        }

        let shard_key = bundle_key
            .derive_shard_key(shard_index as u32)
            .map_err(|e| CordonError::KeyError(e.to_string()))?;
        let iv = decode_iv(&shard_desc.iv_base64).map_err(CordonError::ValidationFailed)?;

        let plaintext = decrypt_shard(&shard_key, &ciphertext, &iv).map_err(|_| {
            CordonError::ModelIntegrityViolation {
                bundle_id: bundle_id.to_string(),
            }
        })?;

        let pt_hash = hex::encode(Sha256::digest(&plaintext));
        if !cordon_crypto::kdf::ct_eq(pt_hash.as_bytes(), shard_desc.plaintext_sha256.as_bytes()) {
            return Err(CordonError::ModelIntegrityViolation {
                bundle_id: bundle_id.to_string(),
            });
        }

        Ok(plaintext)
    }

    /// Decrypt an entire bundle into a restricted-permission file the runtime
    /// can load, verifying every shard digest and the full-plaintext digest.
    ///
    /// Shards are written as they are decrypted, so peak memory is one shard
    /// rather than the whole model. Blocking; call from `spawn_blocking`.
    pub fn stage_plaintext(
        &self,
        bundle_id: &str,
        bundle_key: &BundleKey,
        staging_dir: &Path,
    ) -> CordonResult<StagedModel> {
        use cordon_crypto::symmetric::decrypt_shard;

        let (manifest, bundle_dir) = {
            let bundles = self.bundles.read();
            let entry = bundles
                .get(bundle_id)
                .ok_or_else(|| CordonError::ModelNotFound {
                    bundle_id: bundle_id.to_string(),
                })?;
            (entry.manifest.clone(), entry.bundle_dir.clone())
        };

        if let Some(entry) = self.bundles.write().get_mut(bundle_id) {
            entry.status = BundleStatus::Staging;
        }

        std::fs::create_dir_all(staging_dir).map_err(|e| {
            CordonError::Internal(format!("cannot create staging directory: {}", e))
        })?;

        let staged_path = staging_dir.join(format!("{}.staged", bundle_id));
        let file = create_private_file(&staged_path)?;
        let mut writer = BufWriter::with_capacity(IO_BUFFER_BYTES, file);
        let mut total_hasher = Sha256::new();

        let mut shards: Vec<(usize, &ShardDescriptor)> =
            manifest.shards.iter().enumerate().collect();
        shards.sort_by_key(|(_, s)| s.layer_index);

        for (index, shard) in shards {
            let shard_path = bundle_dir.join(&shard.path);
            let ciphertext = std::fs::read(&shard_path).map_err(|e| {
                CordonError::Internal(format!("cannot read shard {}: {}", shard.path, e))
            })?;

            let ct_hash = hex::encode(Sha256::digest(&ciphertext));
            if !cordon_crypto::kdf::ct_eq(ct_hash.as_bytes(), shard.ciphertext_sha256.as_bytes()) {
                return Err(CordonError::ModelIntegrityViolation {
                    bundle_id: bundle_id.to_string(),
                });
            }

            let shard_key = bundle_key
                .derive_shard_key(index as u32)
                .map_err(|e| CordonError::KeyError(e.to_string()))?;
            let iv = decode_iv(&shard.iv_base64).map_err(CordonError::ValidationFailed)?;

            let mut plaintext = decrypt_shard(&shard_key, &ciphertext, &iv).map_err(|_| {
                CordonError::ModelIntegrityViolation {
                    bundle_id: bundle_id.to_string(),
                }
            })?;

            let pt_hash = hex::encode(Sha256::digest(&plaintext));
            if !cordon_crypto::kdf::ct_eq(pt_hash.as_bytes(), shard.plaintext_sha256.as_bytes()) {
                plaintext.zeroize();
                return Err(CordonError::ModelIntegrityViolation {
                    bundle_id: bundle_id.to_string(),
                });
            }

            total_hasher.update(&plaintext);
            let write_result = writer.write_all(&plaintext);
            plaintext.zeroize();
            write_result.map_err(|e| {
                CordonError::Internal(format!("cannot write staged weights: {}", e))
            })?;
        }

        writer
            .flush()
            .map_err(|e| CordonError::Internal(format!("cannot flush staged weights: {}", e)))?;
        drop(writer);

        let total = hex::encode(total_hasher.finalize());
        if !cordon_crypto::kdf::ct_eq(total.as_bytes(), manifest.total_plaintext_sha256.as_bytes())
        {
            let _ = std::fs::remove_file(&staged_path);
            return Err(CordonError::ModelIntegrityViolation {
                bundle_id: bundle_id.to_string(),
            });
        }

        self.record_verdict(bundle_id, true);
        if let Some(entry) = self.bundles.write().get_mut(bundle_id) {
            entry.status = BundleStatus::Ready;
        }

        let size = std::fs::metadata(&staged_path)
            .map(|m| m.len())
            .unwrap_or(0);
        tracing::info!(
            bundle_id,
            bytes = size,
            path = %staged_path.display(),
            "Bundle decrypted to staging; the file is erased once the runtime has loaded it"
        );

        Ok(StagedModel {
            path: staged_path,
            size_bytes: size,
        })
    }

    /// Remove a bundle from the store.
    pub fn remove_bundle(&self, bundle_id: &str) -> CordonResult<()> {
        if self.bundles.write().remove(bundle_id).is_none() {
            return Err(CordonError::ModelNotFound {
                bundle_id: bundle_id.to_string(),
            });
        }
        self.check_locks.lock().remove(bundle_id);
        tracing::info!(bundle_id, "Bundle removed from the model store");
        Ok(())
    }

    /// Every registered bundle ID.
    pub fn bundle_ids(&self) -> Vec<String> {
        self.bundles.read().keys().cloned().collect()
    }

    /// The store's root directory.
    pub fn store_dir(&self) -> &Path {
        &self.store_dir
    }
}

/// A decrypted model file on disk, deleted when this value is dropped.
///
/// Call [`StagedModel::erase`] as soon as the runtime has finished reading the
/// file, rather than relying on drop, so the plaintext window is as short as it
/// can be.
#[derive(Debug)]
pub struct StagedModel {
    path: PathBuf,
    size_bytes: u64,
}

impl StagedModel {
    /// Path to the decrypted file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Size of the decrypted file in bytes.
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Delete the staged file now. Idempotent.
    pub fn erase(&self) {
        if self.path.exists() {
            match std::fs::remove_file(&self.path) {
                Ok(()) => tracing::info!(
                    path = %self.path.display(),
                    "Staged plaintext weights erased"
                ),
                Err(e) => tracing::error!(
                    path = %self.path.display(),
                    "Could not erase staged plaintext weights: {}. Remove the file manually.",
                    e
                ),
            }
        }
    }
}

impl Drop for StagedModel {
    fn drop(&mut self) {
        self.erase();
    }
}

/// Create a file readable and writable only by the current user.
fn create_private_file(path: &Path) -> CordonResult<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let file = options
        .open(path)
        .map_err(|e| CordonError::Internal(format!("cannot create {}: {}", path.display(), e)))?;

    // Windows has no mode bits; the file inherits the directory ACL. Staging
    // directories are created under the node's data directory, which the
    // deployment guide requires be restricted to the service account.
    #[cfg(not(unix))]
    {
        tracing::debug!(
            path = %path.display(),
            "Staged file permissions follow the parent directory ACL on this platform"
        );
    }

    Ok(file)
}

/// SHA-256 a file in constant memory.
fn hash_file_streaming(path: &Path) -> CordonResult<String> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| CordonError::Internal(format!("cannot open {}: {}", path.display(), e)))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; IO_BUFFER_BYTES];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| CordonError::Internal(format!("cannot read {}: {}", path.display(), e)))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn load_manifest_from_dir(dir: &Path) -> CordonResult<BundleManifest> {
    let manifest_path = dir.join("manifest.json");
    let content = std::fs::read_to_string(&manifest_path)
        .map_err(|e| CordonError::Internal(format!("cannot read manifest: {}", e)))?;
    serde_json::from_str(&content)
        .map_err(|e| CordonError::Internal(format!("invalid manifest JSON: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn shard(path: &str, iv: [u8; 12], pt: &str, ct: &str) -> ShardDescriptor {
        ShardDescriptor {
            path: path.into(),
            plaintext_sha256: pt.into(),
            ciphertext_sha256: ct.into(),
            iv_base64: base64::engine::general_purpose::STANDARD.encode(iv),
            size_bytes: 1024,
            layer_index: 0,
        }
    }

    fn manifest() -> BundleManifest {
        BundleManifest {
            bundle_id: "test-bundle".into(),
            model_name: "Test".into(),
            model_version: "1.0".into(),
            created_at: Utc::now(),
            encryption_algorithm: REQUIRED_ENCRYPTION_ALGORITHM.into(),
            key_derivation: REQUIRED_KEY_DERIVATION.into(),
            client_key_id: "client".into(),
            shards: vec![shard(
                "shard-0.enc",
                [7u8; 12],
                &"a".repeat(64),
                &"b".repeat(64),
            )],
            total_plaintext_sha256: "a".repeat(64),
            minimum_requirements: MinimumRequirements {
                cordon_version: "2.0".into(),
                tee: TeeRequirements {
                    sgx_isv_svn_min: None,
                    sev_snp_api_min: None,
                },
                hardware: HardwareRequirements {
                    min_gpu_vram_gb: 0,
                    min_ram_gb: 1,
                    ecc_memory_required: false,
                },
            },
            policy_hash: "c".repeat(64),
            vendor_signature: String::new(),
            client_approval_signature: String::new(),
        }
    }

    #[test]
    fn accepts_a_well_formed_manifest() {
        manifest().validate_structure().unwrap();
    }

    #[test]
    fn rejects_unencrypted_bundles() {
        let mut m = manifest();
        m.encryption_algorithm = "NONE".into();
        let err = m.validate_structure().unwrap_err().to_string();
        assert!(err.contains("AES-256-GCM"), "unexpected error: {}", err);
    }

    #[test]
    fn rejects_identical_plaintext_and_ciphertext_digests() {
        let mut m = manifest();
        m.shards[0].ciphertext_sha256 = m.shards[0].plaintext_sha256.clone();
        let err = m.validate_structure().unwrap_err().to_string();
        assert!(err.contains("not encrypted"), "unexpected error: {}", err);
    }

    #[test]
    fn rejects_all_zero_nonce() {
        let mut m = manifest();
        m.shards[0] = shard("s.enc", [0u8; 12], &"a".repeat(64), &"b".repeat(64));
        let err = m.validate_structure().unwrap_err().to_string();
        assert!(err.contains("all-zero nonce"), "unexpected error: {}", err);
    }

    #[test]
    fn rejects_nonce_reuse_across_shards() {
        let mut m = manifest();
        let mut second = shard("s1.enc", [7u8; 12], &"d".repeat(64), &"e".repeat(64));
        second.layer_index = 1;
        m.shards.push(second);
        let err = m.validate_structure().unwrap_err().to_string();
        assert!(err.contains("reuses a nonce"), "unexpected error: {}", err);
    }

    #[test]
    fn rejects_shard_path_traversal() {
        for bad in ["../../etc/passwd", "/etc/passwd", "sub/../../escape"] {
            let mut m = manifest();
            m.shards[0].path = bad.into();
            assert!(
                m.validate_structure().is_err(),
                "path '{}' should be rejected",
                bad
            );
        }
    }

    #[test]
    fn rejects_malformed_digests() {
        let mut m = manifest();
        m.shards[0].plaintext_sha256 = "short".into();
        assert!(m.validate_structure().is_err());

        let mut m = manifest();
        m.total_plaintext_sha256 = "z".repeat(64);
        assert!(m.validate_structure().is_err());
    }

    #[test]
    fn rejects_empty_shard_list() {
        let mut m = manifest();
        m.shards.clear();
        assert!(m.validate_structure().is_err());
    }

    #[test]
    fn empty_store_admits_any_model() {
        let dir = tempfile::tempdir().unwrap();
        let store = ModelStore::new(dir.path().into(), None).unwrap();
        assert!(store.ensure_servable("anything", false).is_ok());
    }

    #[test]
    fn populated_store_refuses_unknown_models() {
        let dir = tempfile::tempdir().unwrap();
        let store = ModelStore::new(dir.path().into(), None).unwrap();
        store
            .register_bundle(manifest(), dir.path().join("test-bundle"), None)
            .unwrap();
        assert!(matches!(
            store.ensure_servable("some-other-model", false),
            Err(CordonError::ModelNotFound { .. })
        ));
        assert!(store.ensure_servable("some-other-model", true).is_ok());
    }

    #[test]
    fn a_bundle_without_a_verdict_is_not_servable() {
        let dir = tempfile::tempdir().unwrap();
        let store = ModelStore::new(dir.path().into(), None).unwrap();
        store
            .register_bundle(manifest(), dir.path().join("test-bundle"), None)
            .unwrap();
        // Registered but never integrity-checked: fail closed.
        assert!(matches!(
            store.ensure_servable("test-bundle", false),
            Err(CordonError::ModelIntegrityViolation { .. })
        ));
    }

    #[test]
    fn a_fresh_passing_verdict_admits_the_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let store = ModelStore::new(dir.path().into(), None).unwrap();
        store
            .register_bundle(manifest(), dir.path().join("test-bundle"), None)
            .unwrap();
        store.record_verdict("test-bundle", true);
        assert!(store.ensure_servable("test-bundle", false).is_ok());
    }

    #[test]
    fn a_stale_verdict_takes_the_bundle_out_of_service() {
        let dir = tempfile::tempdir().unwrap();
        let store = ModelStore::with_verdict_ttl(dir.path().into(), None, 1).unwrap();
        store
            .register_bundle(manifest(), dir.path().join("test-bundle"), None)
            .unwrap();
        if let Some(entry) = store.bundles.write().get_mut("test-bundle") {
            entry.verdict = Some(IntegrityVerdict {
                checked_at: Utc::now() - ChronoDuration::hours(2),
                passed: true,
            });
        }
        assert!(store.ensure_servable("test-bundle", false).is_err());
    }

    #[test]
    fn a_failing_verdict_marks_the_bundle_tampered() {
        let dir = tempfile::tempdir().unwrap();
        let store = ModelStore::new(dir.path().into(), None).unwrap();
        store
            .register_bundle(manifest(), dir.path().join("test-bundle"), None)
            .unwrap();
        store.record_verdict("test-bundle", false);
        assert!(store.ensure_servable("test-bundle", false).is_err());
        assert_eq!(store.list_bundles()[0].status, BundleStatus::Tampered);
    }

    #[test]
    fn scan_skips_invalid_bundles() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_dir = dir.path().join("bad-bundle");
        std::fs::create_dir_all(&bundle_dir).unwrap();
        let mut m = manifest();
        m.bundle_id = "bad-bundle".into();
        m.encryption_algorithm = "NONE".into();
        std::fs::write(
            bundle_dir.join("manifest.json"),
            serde_json::to_vec_pretty(&m).unwrap(),
        )
        .unwrap();

        let store = ModelStore::new(dir.path().into(), None).unwrap();
        assert!(
            store.is_empty(),
            "an unencrypted bundle must not be admitted"
        );
    }

    #[test]
    fn staged_model_deletes_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("weights.staged");
        std::fs::write(&path, b"plaintext").unwrap();
        {
            let _staged = StagedModel {
                path: path.clone(),
                size_bytes: 9,
            };
            assert!(path.exists());
        }
        assert!(!path.exists(), "staged plaintext must be erased on drop");
    }

    #[test]
    fn streaming_hash_matches_one_shot_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob.bin");
        let data: Vec<u8> = (0..(IO_BUFFER_BYTES + 1024))
            .map(|i| (i % 251) as u8)
            .collect();
        std::fs::write(&path, &data).unwrap();
        assert_eq!(
            hash_file_streaming(&path).unwrap(),
            hex::encode(Sha256::digest(&data))
        );
    }
}
