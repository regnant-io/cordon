//! Sealing model weights into encrypted bundles, and checking them.
//!
//! This is the library behind `cordon bundle`, `cordon-provision` and the
//! desktop app's bundle page, so all three produce byte-for-byte the same
//! format and refuse the same things.
//!
//! Weights are split into fixed-size shards, each encrypted with AES-256-GCM
//! under its own key derived from the Client Master Key, and each given a fresh
//! random nonce. Sharding bounds memory during both sealing and loading: a
//! multi-gigabyte model is processed one shard at a time.
//!
//! A bundle directory is written in an order that keeps a half-finished one
//! from ever looking complete: shards first, `manifest.json` last. The model
//! store only admits directories with a manifest, and a seal that fails or is
//! cancelled removes the directory it created.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine;
use chrono::Utc;
use sha2::{Digest, Sha256};

use cordon_crypto::{
    hierarchy::MasterKey,
    symmetric::{decrypt_shard, encrypt_shard},
};

use crate::error::{CordonError, CordonResult};
pub use crate::model_store::is_safe_bundle_id;
use crate::model_store::{
    BundleManifest, HardwareRequirements, MinimumRequirements, ShardDescriptor, TeeRequirements,
    REQUIRED_ENCRYPTION_ALGORITHM, REQUIRED_KEY_DERIVATION,
};

/// Plaintext bytes per shard. Large enough that per-shard overhead is
/// negligible, small enough that a shard fits comfortably in memory.
pub const DEFAULT_SHARD_SIZE: usize = 256 * 1024 * 1024;

/// Weight file extensions recognised as model payloads.
pub const WEIGHT_EXTENSIONS: &[&str] = &["gguf", "safetensors", "bin", "pt", "pth"];

/// Bytes read from a weight file at a time, so progress moves within a shard.
const READ_CHUNK: usize = 8 * 1024 * 1024;

/// What to seal and how.
pub struct SealRequest<'a> {
    /// A weight file, or a directory of them.
    pub weights: &'a Path,
    /// The Client Master Key the bundle is sealed under.
    pub master: &'a MasterKey,
    /// The key-derivation principal. The serving node must use the same one.
    pub principal: &'a str,
    /// Bundle ID. Generated when absent. It feeds key derivation.
    pub bundle_id: Option<String>,
    /// Human-readable model name.
    pub model_name: &'a str,
    /// Model version.
    pub model_version: &'a str,
    /// Directory to write the bundle into. Must not exist, or be empty.
    pub output: &'a Path,
    /// Plaintext bytes per shard.
    pub shard_size: usize,
}

/// Progress reported while sealing or verifying.
#[derive(Debug, Clone)]
pub enum BundleEvent {
    /// Work has started.
    Started {
        /// The bundle's ID.
        bundle_id: String,
        /// Bytes that will be processed in total.
        total_bytes: u64,
        /// Number of weight files (sealing) or shards (verifying).
        items: usize,
    },
    /// Bytes processed so far.
    Progress {
        /// Bytes processed.
        done_bytes: u64,
        /// Bytes in total.
        total_bytes: u64,
    },
    /// One shard is finished.
    Shard {
        /// Shard index.
        index: u32,
        /// Shard file name, relative to the bundle.
        path: String,
        /// Plaintext bytes in the shard.
        plaintext_bytes: u64,
        /// Ciphertext bytes on disk.
        ciphertext_bytes: u64,
        /// Outcome, for verification. Always `None` while sealing.
        problem: Option<String>,
    },
}

/// The outcome of [`verify`].
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct VerifyReport {
    /// The bundle's ID.
    pub bundle_id: String,
    /// Shards in the manifest.
    pub shards: usize,
    /// Whether a key was supplied, so the shards were also decrypted.
    pub decrypted: bool,
    /// One line per shard that failed, and one for the whole-model digest.
    pub failures: Vec<String>,
}

impl VerifyReport {
    /// Whether every check passed.
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Seal weights into a new bundle directory.
///
/// Blocking and CPU-heavy; run it on a blocking thread. Setting `cancel`
/// stops it at the next read, and the partial bundle is removed.
pub fn seal(
    request: &SealRequest<'_>,
    cancel: &AtomicBool,
    mut on_event: impl FnMut(BundleEvent),
) -> CordonResult<BundleManifest> {
    if request.shard_size == 0 {
        return Err(invalid("shard size must be greater than zero"));
    }
    let principal = request.principal.trim();
    if principal.is_empty() {
        return Err(invalid("the key principal must not be empty"));
    }
    let model_name = request.model_name.trim();
    if model_name.is_empty() {
        return Err(invalid("the model name must not be empty"));
    }

    let files = collect_weight_files(request.weights)?;
    if files.is_empty() {
        return Err(invalid(&format!(
            "no weight files found in {}. Expected one of: {}",
            request.weights.display(),
            WEIGHT_EXTENSIONS.join(", ")
        )));
    }
    let total_bytes: u64 = files
        .iter()
        .map(|f| std::fs::metadata(f).map(|m| m.len()).unwrap_or(0))
        .sum();

    let output = request.output;
    let created = prepare_output(output)?;
    let result = seal_into(
        request,
        principal,
        model_name,
        &files,
        total_bytes,
        cancel,
        &mut on_event,
    );
    if result.is_err() && created {
        let _ = std::fs::remove_dir_all(output);
    }
    result
}

fn seal_into(
    request: &SealRequest<'_>,
    principal: &str,
    model_name: &str,
    files: &[PathBuf],
    total_bytes: u64,
    cancel: &AtomicBool,
    on_event: &mut impl FnMut(BundleEvent),
) -> CordonResult<BundleManifest> {
    let bundle_id = request
        .bundle_id
        .clone()
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    if !is_safe_bundle_id(&bundle_id) {
        return Err(invalid(
            "a bundle ID may contain only letters, digits, '.', '-' and '_'",
        ));
    }

    let bundle_key = request
        .master
        .derive_bundle_key(&bundle_id, principal)
        .map_err(|e| CordonError::KeyError(e.to_string()))?;

    let shards_dir = request.output.join("shards");
    std::fs::create_dir_all(&shards_dir).map_err(|e| io("create", &shards_dir, e))?;

    on_event(BundleEvent::Started {
        bundle_id: bundle_id.clone(),
        total_bytes,
        items: files.len(),
    });

    let shard_size = request.shard_size;
    let mut shards: Vec<ShardDescriptor> = Vec::new();
    let mut total_hasher = Sha256::new();
    let mut shard_index: u32 = 0;
    let mut buffer = vec![0u8; shard_size];
    let mut done: u64 = 0;

    for path in files {
        let mut file = std::fs::File::open(path).map_err(|e| io("open", path, e))?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("weights");

        loop {
            // Fill the buffer completely before sealing a shard, so shard
            // boundaries depend on the byte stream rather than on how the
            // filesystem happened to return reads.
            let mut filled = 0;
            while filled < shard_size {
                if cancel.load(Ordering::Relaxed) {
                    return Err(CordonError::Internal("cancelled".into()));
                }
                let end = (filled + READ_CHUNK).min(shard_size);
                let n = file
                    .read(&mut buffer[filled..end])
                    .map_err(|e| io("read", path, e))?;
                if n == 0 {
                    break;
                }
                filled += n;
                done += n as u64;
                on_event(BundleEvent::Progress {
                    done_bytes: done,
                    total_bytes,
                });
            }
            if filled == 0 {
                break;
            }

            let plaintext = &buffer[..filled];
            total_hasher.update(plaintext);

            let shard_key = bundle_key
                .derive_shard_key(shard_index)
                .map_err(|e| CordonError::KeyError(e.to_string()))?;

            // A fresh nonce per shard. Reusing one under AES-GCM would be
            // catastrophic, so it is drawn from the OS CSPRNG each time.
            let mut nonce = [0u8; 12];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut nonce);

            let ciphertext = encrypt_shard(&shard_key, plaintext, &nonce)
                .map_err(|e| CordonError::Internal(format!("encryption failed: {}", e)))?;

            let shard_name = format!("{:05}-{}.enc", shard_index, sanitize(name));
            let shard_path = shards_dir.join(&shard_name);
            std::fs::write(&shard_path, &ciphertext).map_err(|e| io("write", &shard_path, e))?;

            let relative = format!("shards/{}", shard_name);
            shards.push(ShardDescriptor {
                path: relative.clone(),
                plaintext_sha256: hex::encode(Sha256::digest(plaintext)),
                ciphertext_sha256: hex::encode(Sha256::digest(&ciphertext)),
                iv_base64: base64::engine::general_purpose::STANDARD.encode(nonce),
                // The plaintext length, which is what a loader needs to size its
                // buffer. The ciphertext is 16 bytes longer for the GCM tag.
                size_bytes: filled as u64,
                layer_index: shard_index,
            });
            on_event(BundleEvent::Shard {
                index: shard_index,
                path: relative,
                plaintext_bytes: filled as u64,
                ciphertext_bytes: ciphertext.len() as u64,
                problem: None,
            });

            shard_index += 1;
            if filled < shard_size {
                break;
            }
        }
    }

    let manifest = BundleManifest {
        bundle_id,
        model_name: model_name.to_string(),
        model_version: request.model_version.trim().to_string(),
        created_at: Utc::now(),
        encryption_algorithm: REQUIRED_ENCRYPTION_ALGORITHM.to_string(),
        key_derivation: REQUIRED_KEY_DERIVATION.to_string(),
        client_key_id: principal.to_string(),
        total_plaintext_sha256: hex::encode(total_hasher.finalize()),
        shards,
        minimum_requirements: MinimumRequirements {
            cordon_version: env!("CARGO_PKG_VERSION").to_string(),
            tee: TeeRequirements {
                sgx_isv_svn_min: None,
                sev_snp_api_min: None,
            },
            hardware: HardwareRequirements {
                min_gpu_vram_gb: 0,
                min_ram_gb: 4,
                ecc_memory_required: false,
            },
        },
        policy_hash: hex::encode(Sha256::digest(b"cordon-default-policy-v1")),
        // Signatures are applied by the vendor and the approving client with
        // their own keys. An unsigned bundle is accepted only by a node that has
        // no verifying key configured for them.
        vendor_signature: String::new(),
        client_approval_signature: String::new(),
    };

    // Refuse to emit a manifest the node would reject: catching it here saves
    // an operator from discovering it at serve time.
    manifest.validate_structure()?;

    let manifest_path = request.output.join("manifest.json");
    let tmp = request.output.join("manifest.json.tmp");
    let bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| CordonError::Internal(format!("cannot serialise the manifest: {}", e)))?;
    write_synced(&tmp, &bytes)?;
    std::fs::rename(&tmp, &manifest_path).map_err(|e| io("write", &manifest_path, e))?;

    Ok(manifest)
}

/// Check a bundle's ciphertext against its manifest and, given a key, decrypt
/// every shard and check the plaintext too.
///
/// Returns a report rather than failing on the first bad shard, so a damaged
/// bundle is described in full. Errors are reserved for a bundle that cannot
/// be read at all.
pub fn verify(
    bundle_dir: &Path,
    key: Option<(&MasterKey, &str)>,
    cancel: &AtomicBool,
    mut on_event: impl FnMut(BundleEvent),
) -> CordonResult<VerifyReport> {
    let manifest = read_manifest(bundle_dir)?;
    manifest.validate_structure()?;

    let bundle_key = match key {
        Some((master, principal)) => Some(
            master
                .derive_bundle_key(&manifest.bundle_id, principal)
                .map_err(|e| CordonError::KeyError(e.to_string()))?,
        ),
        None => None,
    };

    let total_bytes: u64 = manifest.shards.iter().map(|s| s.size_bytes).sum();
    let mut report = VerifyReport {
        bundle_id: manifest.bundle_id.clone(),
        shards: manifest.shards.len(),
        decrypted: bundle_key.is_some(),
        failures: Vec::new(),
    };
    on_event(BundleEvent::Started {
        bundle_id: manifest.bundle_id.clone(),
        total_bytes,
        items: manifest.shards.len(),
    });

    let mut total_hasher = Sha256::new();
    let mut done: u64 = 0;

    for (index, shard) in manifest.shards.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return Err(CordonError::Internal("cancelled".into()));
        }
        let problem = match check_shard(bundle_dir, index as u32, shard, bundle_key.as_ref()) {
            Ok(Some(plaintext)) => {
                total_hasher.update(&plaintext);
                None
            }
            Ok(None) => None,
            Err(problem) => Some(problem),
        };
        if let Some(problem) = &problem {
            report
                .failures
                .push(format!("shard {} ({}): {}", index, shard.path, problem));
        }
        done += shard.size_bytes;
        on_event(BundleEvent::Shard {
            index: index as u32,
            path: shard.path.clone(),
            plaintext_bytes: shard.size_bytes,
            ciphertext_bytes: shard.size_bytes + 16,
            problem,
        });
        on_event(BundleEvent::Progress {
            done_bytes: done,
            total_bytes,
        });
    }

    if report.decrypted && report.failures.is_empty() {
        let total = hex::encode(total_hasher.finalize());
        if total != manifest.total_plaintext_sha256 {
            report
                .failures
                .push("the whole-model digest does not match the manifest".into());
        }
    }
    Ok(report)
}

/// Check one shard. With a key, returns its plaintext for the running digest.
fn check_shard(
    bundle_dir: &Path,
    index: u32,
    shard: &ShardDescriptor,
    bundle_key: Option<&cordon_crypto::BundleKey>,
) -> Result<Option<Vec<u8>>, String> {
    let path = bundle_dir.join(&shard.path);
    let ciphertext = std::fs::read(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => "missing".to_string(),
        _ => format!("unreadable: {}", e),
    })?;
    if hex::encode(Sha256::digest(&ciphertext)) != shard.ciphertext_sha256 {
        return Err("ciphertext does not match the manifest".into());
    }
    let Some(bundle_key) = bundle_key else {
        return Ok(None);
    };
    let shard_key = bundle_key
        .derive_shard_key(index)
        .map_err(|e| e.to_string())?;
    let nonce = decode_nonce(&shard.iv_base64)?;
    let plaintext = decrypt_shard(&shard_key, &ciphertext, &nonce)
        .map_err(|_| "cannot be decrypted: wrong key or principal, or tampered".to_string())?;
    if hex::encode(Sha256::digest(&plaintext)) != shard.plaintext_sha256 {
        return Err("plaintext does not match the manifest".into());
    }
    Ok(Some(plaintext))
}

/// Read `manifest.json` from a bundle directory.
pub fn read_manifest(bundle_dir: &Path) -> CordonResult<BundleManifest> {
    let path = bundle_dir.join("manifest.json");
    let contents = std::fs::read_to_string(&path).map_err(|e| io("read", &path, e))?;
    serde_json::from_str(&contents).map_err(|e| {
        CordonError::ValidationFailed(format!(
            "{} is not a bundle manifest: {}",
            path.display(),
            e
        ))
    })
}

/// Collect weight files, sorted, so a bundle built twice from the same inputs
/// shards them the same way.
pub fn collect_weight_files(source: &Path) -> CordonResult<Vec<PathBuf>> {
    if source.is_file() {
        return Ok(vec![source.to_path_buf()]);
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(source)
        .map_err(|e| io("read", source, e))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| WEIGHT_EXTENSIONS.contains(&e.to_lowercase().as_str()))
                    .unwrap_or(false)
        })
        .collect();
    files.sort();
    Ok(files)
}

/// A readable bundle ID for a model: its name as a slug plus a random suffix,
/// so two bundles of the same model never collide.
///
/// The ID is what a node's configuration names the model by, so something an
/// operator can recognise in `runtime.model_path` beats a bare UUID.
pub fn suggest_bundle_id(model_name: &str) -> String {
    let mut slug = String::new();
    for c in model_name.trim().chars() {
        if c.is_ascii_alphanumeric() || c == '.' {
            slug.push(c.to_ascii_lowercase());
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug: String = slug
        .trim_matches(|c| c == '-' || c == '.')
        .chars()
        .take(48)
        .collect();
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    if slug.is_empty() {
        format!("bundle-{}", suffix)
    } else {
        format!("{}-{}", slug.trim_end_matches(['-', '.']), suffix)
    }
}

/// A model name for a weight file or directory: the file stem, or the
/// directory name.
pub fn model_name_from_path(path: &Path) -> String {
    let stem = if path.is_dir() {
        path.file_name()
    } else {
        path.file_stem()
    };
    stem.map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "model".to_string())
}

/// Reduce a filename to characters that are safe in a path and a manifest.
pub fn sanitize(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "shard".to_string()
    } else {
        cleaned
    }
}

/// Decode a shard nonce from the manifest.
pub fn decode_nonce(iv_base64: &str) -> Result<[u8; 12], String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(iv_base64)
        .map_err(|_| "the nonce is not valid base64".to_string())?;
    bytes
        .try_into()
        .map_err(|b: Vec<u8>| format!("the nonce must be 12 bytes, not {}", b.len()))
}

/// Create the output directory, refusing one that already holds something.
/// Returns whether it was created here, and so may be removed on failure.
fn prepare_output(output: &Path) -> CordonResult<bool> {
    match std::fs::read_dir(output) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Err(invalid(&format!(
                    "{} already exists and is not empty; choose a new folder",
                    output.display()
                )));
            }
            Ok(false)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(output).map_err(|e| io("create", output, e))?;
            Ok(true)
        }
        Err(e) => Err(io("read", output, e)),
    }
}

fn write_synced(path: &Path, bytes: &[u8]) -> CordonResult<()> {
    use std::io::Write;
    let mut file = std::fs::File::create(path).map_err(|e| io("create", path, e))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| io("write", path, e))
}

fn invalid(message: &str) -> CordonError {
    CordonError::ValidationFailed(message.to_string())
}

fn io(verb: &str, path: &Path, e: std::io::Error) -> CordonError {
    CordonError::Internal(format!("cannot {} {}: {}", verb, path.display(), e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealed(dir: &Path, payload: &[u8], shard_size: usize) -> (BundleManifest, MasterKey) {
        let weights = dir.join("model.gguf");
        std::fs::write(&weights, payload).unwrap();
        let master = MasterKey::from_hex(&"33".repeat(32)).unwrap();
        let manifest = seal(
            &SealRequest {
                weights: &weights,
                master: &master,
                principal: "operator",
                bundle_id: Some("test-bundle".into()),
                model_name: "Test Model",
                model_version: "1.0",
                output: &dir.join("bundle"),
                shard_size,
            },
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap();
        (manifest, master)
    }

    /// A sealed bundle satisfies the node's validator and decrypts back to the
    /// original bytes; the wrong principal cannot read it.
    #[test]
    fn a_sealed_bundle_is_valid_and_decrypts() {
        let dir = tempfile::tempdir().unwrap();
        let payload: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        let (manifest, master) = sealed(dir.path(), &payload, 1024);

        manifest.validate_structure().unwrap();
        assert_eq!(manifest.shards.len(), 3, "3000 bytes at 1024/shard");
        assert_eq!(
            manifest.total_plaintext_sha256,
            hex::encode(Sha256::digest(&payload))
        );

        let mut nonces: Vec<&str> = manifest
            .shards
            .iter()
            .map(|s| s.iv_base64.as_str())
            .collect();
        nonces.sort_unstable();
        nonces.dedup();
        assert_eq!(
            nonces.len(),
            manifest.shards.len(),
            "nonces must not repeat"
        );

        let bundle = dir.path().join("bundle");
        let never = AtomicBool::new(false);
        let good = verify(&bundle, Some((&master, "operator")), &never, |_| {}).unwrap();
        assert!(good.passed(), "{:?}", good.failures);
        assert!(good.decrypted);

        let wrong = verify(&bundle, Some((&master, "someone-else")), &never, |_| {}).unwrap();
        assert_eq!(wrong.failures.len(), 3);
    }

    #[test]
    fn tampering_is_reported_per_shard() {
        let dir = tempfile::tempdir().unwrap();
        let payload = vec![7u8; 2500];
        let (manifest, _) = sealed(dir.path(), &payload, 1024);
        let bundle = dir.path().join("bundle");
        let victim = bundle.join(&manifest.shards[1].path);
        let mut bytes = std::fs::read(&victim).unwrap();
        bytes[0] ^= 0xff;
        std::fs::write(&victim, bytes).unwrap();

        let report = verify(&bundle, None, &AtomicBool::new(false), |_| {}).unwrap();
        assert_eq!(report.failures.len(), 1);
        assert!(report.failures[0].starts_with("shard 1"));
    }

    #[test]
    fn a_cancelled_seal_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let weights = dir.path().join("model.gguf");
        std::fs::write(&weights, vec![1u8; 4096]).unwrap();
        let master = MasterKey::from_hex(&"44".repeat(32)).unwrap();
        let output = dir.path().join("bundle");
        let result = seal(
            &SealRequest {
                weights: &weights,
                master: &master,
                principal: "operator",
                bundle_id: None,
                model_name: "M",
                model_version: "1",
                output: &output,
                shard_size: 1024,
            },
            &AtomicBool::new(true),
            |_| {},
        );
        assert!(result.is_err());
        assert!(!output.exists());
    }

    #[test]
    fn an_occupied_output_folder_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("bundle");
        std::fs::create_dir_all(&output).unwrap();
        std::fs::write(output.join("keep.txt"), "mine").unwrap();
        assert!(prepare_output(&output).is_err());
        assert_eq!(
            std::fs::read_to_string(output.join("keep.txt")).unwrap(),
            "mine"
        );
    }

    #[test]
    fn bundle_ids_cannot_escape_a_directory() {
        assert!(is_safe_bundle_id("smollm2-360m_v1.2"));
        assert!(!is_safe_bundle_id("../etc"));
        assert!(!is_safe_bundle_id("a/b"));
        assert!(!is_safe_bundle_id(".."));
        assert!(!is_safe_bundle_id(""));
    }

    #[test]
    fn suggested_ids_are_readable_and_safe() {
        let id = suggest_bundle_id("SmolLM2 360M Instruct (Q8_0)");
        assert!(id.starts_with("smollm2-360m-instruct-q8-0-"), "{}", id);
        assert!(is_safe_bundle_id(&id));
        assert!(suggest_bundle_id("../..").starts_with("bundle-"));
        assert_ne!(suggest_bundle_id("x"), suggest_bundle_id("x"));
    }

    #[test]
    fn filenames_are_reduced_to_safe_characters() {
        assert_eq!(sanitize("model.gguf"), "model.gguf");
        assert_eq!(sanitize("../../etc/passwd"), ".._.._etc_passwd");
        assert_eq!(sanitize(""), "shard");
        assert_eq!(sanitize(&"x".repeat(200)).len(), 64);
    }

    #[test]
    fn nonces_must_be_twelve_bytes() {
        let good = base64::engine::general_purpose::STANDARD.encode([1u8; 12]);
        assert!(decode_nonce(&good).is_ok());
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 8]);
        assert!(decode_nonce(&short).is_err());
        assert!(decode_nonce("not base64!!").is_err());
    }
}
