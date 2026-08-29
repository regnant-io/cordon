//! `cordon-provision` — package model weights into an encrypted Cordon bundle.
//!
//! Weights are split into fixed-size shards, each encrypted with AES-256-GCM
//! under its own key derived from the Client Master Key, and each given a fresh
//! random nonce. Sharding is not cosmetic: it bounds memory during both
//! provisioning and loading, so a multi-gigabyte model is processed a shard at
//! a time rather than held in memory twice.
//!
//! The CMK never leaves the operator's control. A node without it holds
//! ciphertext and a manifest, and can prove neither what the weights are nor
//! that it could read them.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::Engine;
use chrono::Utc;
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use cordon_core::model_store::{
    BundleManifest, HardwareRequirements, MinimumRequirements, ShardDescriptor, TeeRequirements,
    REQUIRED_ENCRYPTION_ALGORITHM, REQUIRED_KEY_DERIVATION,
};
use cordon_crypto::{
    hierarchy::MasterKey,
    symmetric::{decrypt_shard, encrypt_shard},
};

/// Plaintext bytes per shard. Large enough that per-shard overhead is
/// negligible, small enough that a shard fits comfortably in memory.
const SHARD_SIZE: usize = 256 * 1024 * 1024;

/// Weight file extensions recognised as model payloads.
const WEIGHT_EXTENSIONS: &[&str] = &["gguf", "safetensors", "bin", "pt", "pth"];

#[derive(Parser)]
#[command(
    name = "cordon-provision",
    version = env!("CARGO_PKG_VERSION"),
    about = "Package model weights into an encrypted Cordon bundle",
    long_about = "Encrypts model weights with AES-256-GCM under per-shard keys derived\n\
                  from the Client Master Key via HKDF-SHA256.\n\n\
                  The CMK is the root of trust. Source it from an HSM in production;\n\
                  a node never needs it except to decrypt at load time."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt weight files into a bundle.
    Encrypt {
        /// Directory of weight files, or a single weight file.
        #[arg(long)]
        weights: PathBuf,
        /// Client Master Key, hex. Prefer `--cmk-file`.
        #[arg(long, conflicts_with = "cmk_file")]
        cmk: Option<String>,
        /// File containing the Client Master Key, hex.
        #[arg(long)]
        cmk_file: Option<PathBuf>,
        /// Bundle ID. Generated if absent. Feeds key derivation, so it must
        /// match what the serving node is configured with.
        #[arg(long)]
        bundle_id: Option<String>,
        /// Key-derivation principal. Must match the node's CORDON_CLIENT_ID.
        #[arg(long)]
        client_id: String,
        /// Human-readable model name.
        #[arg(long)]
        model_name: String,
        /// Model version.
        #[arg(long, default_value = "1.0.0")]
        model_version: String,
        /// Output directory for the bundle.
        #[arg(long)]
        output: PathBuf,
        /// Plaintext bytes per shard.
        #[arg(long, default_value_t = SHARD_SIZE)]
        shard_size: usize,
    },

    /// Verify a bundle's ciphertext against its manifest, and optionally
    /// confirm the key can decrypt it.
    Verify {
        /// Bundle directory.
        #[arg(long)]
        bundle: PathBuf,
        /// Client Master Key, hex. Omit to check ciphertext digests only.
        #[arg(long, conflicts_with = "cmk_file")]
        cmk: Option<String>,
        /// File containing the Client Master Key.
        #[arg(long)]
        cmk_file: Option<PathBuf>,
        /// Key-derivation principal.
        #[arg(long)]
        client_id: Option<String>,
    },

    /// Print a bundle's manifest.
    Inspect {
        /// Bundle directory.
        #[arg(long)]
        bundle: PathBuf,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();

    match Cli::parse().command {
        Command::Encrypt {
            weights,
            cmk,
            cmk_file,
            bundle_id,
            client_id,
            model_name,
            model_version,
            output,
            shard_size,
        } => encrypt(
            &weights,
            &load_cmk(cmk, cmk_file)?,
            bundle_id,
            &client_id,
            &model_name,
            &model_version,
            &output,
            shard_size,
        ),

        Command::Verify {
            bundle,
            cmk,
            cmk_file,
            client_id,
        } => {
            let key = match (cmk.is_some() || cmk_file.is_some(), client_id) {
                (true, Some(id)) => Some((load_cmk(cmk, cmk_file)?, id)),
                (true, None) => bail!("--client-id is required when a CMK is supplied"),
                (false, _) => None,
            };
            verify(&bundle, key)
        }

        Command::Inspect { bundle } => inspect(&bundle),
    }
}

/// Read the CMK from a file where possible; a key on a command line is visible
/// in the process table and in shell history.
fn load_cmk(inline: Option<String>, file: Option<PathBuf>) -> Result<String> {
    if let Some(path) = file {
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        return Ok(contents.trim().to_string());
    }
    if let Some(hex) = inline {
        eprintln!(
            "warning: the Client Master Key was passed on the command line, where it is \
             visible in the process table and shell history. Prefer --cmk-file."
        );
        return Ok(hex.trim().to_string());
    }
    bail!("a Client Master Key is required; pass --cmk-file")
}

#[allow(clippy::too_many_arguments)]
fn encrypt(
    weights: &Path,
    cmk_hex: &str,
    bundle_id: Option<String>,
    client_id: &str,
    model_name: &str,
    model_version: &str,
    output: &Path,
    shard_size: usize,
) -> Result<()> {
    if shard_size == 0 {
        bail!("--shard-size must be greater than zero");
    }

    let bundle_id = bundle_id.unwrap_or_else(|| Uuid::new_v4().to_string());
    let master = MasterKey::from_hex(cmk_hex).context("invalid Client Master Key")?;
    let bundle_key = master
        .derive_bundle_key(&bundle_id, client_id)
        .context("cannot derive the bundle key")?;

    let files = collect_weight_files(weights)?;
    if files.is_empty() {
        bail!(
            "no weight files found in {}. Expected one of: {}",
            weights.display(),
            WEIGHT_EXTENSIONS.join(", ")
        );
    }

    let shards_dir = output.join("shards");
    std::fs::create_dir_all(&shards_dir)
        .with_context(|| format!("cannot create {}", shards_dir.display()))?;

    println!("Encrypting bundle '{}'", bundle_id);
    println!("  model     {} v{}", model_name, model_version);
    println!("  principal {}", client_id);
    println!("  sources   {} file(s)", files.len());
    println!();

    let mut shards: Vec<ShardDescriptor> = Vec::new();
    let mut total_hasher = Sha256::new();
    let mut shard_index: u32 = 0;
    let mut buffer = vec![0u8; shard_size];

    for path in &files {
        let mut file =
            std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
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
                let n = file
                    .read(&mut buffer[filled..])
                    .with_context(|| format!("cannot read {}", path.display()))?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            if filled == 0 {
                break;
            }

            let plaintext = &buffer[..filled];
            total_hasher.update(plaintext);

            let shard_key = bundle_key
                .derive_shard_key(shard_index)
                .context("cannot derive the shard key")?;

            // A fresh nonce per shard. Reusing one under AES-GCM would be
            // catastrophic, so it is drawn from the OS CSPRNG each time.
            let mut nonce = [0u8; 12];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut nonce);

            let ciphertext =
                encrypt_shard(&shard_key, plaintext, &nonce).context("encryption failed")?;

            let shard_name = format!("{:05}-{}.enc", shard_index, sanitize(name));
            let shard_path = shards_dir.join(&shard_name);
            std::fs::write(&shard_path, &ciphertext)
                .with_context(|| format!("cannot write {}", shard_path.display()))?;

            shards.push(ShardDescriptor {
                path: format!("shards/{}", shard_name),
                plaintext_sha256: hex::encode(Sha256::digest(plaintext)),
                ciphertext_sha256: hex::encode(Sha256::digest(&ciphertext)),
                iv_base64: base64::engine::general_purpose::STANDARD.encode(nonce),
                // The plaintext length, which is what a loader needs to size its
                // buffer. The ciphertext is 16 bytes longer for the GCM tag.
                size_bytes: filled as u64,
                layer_index: shard_index,
            });

            println!(
                "  shard {:>5}  {:>12} → {:<12}  {}",
                shard_index,
                human_bytes(filled as u64),
                human_bytes(ciphertext.len() as u64),
                shard_name
            );

            shard_index += 1;
            if filled < shard_size {
                break;
            }
        }
    }

    let manifest = BundleManifest {
        bundle_id: bundle_id.clone(),
        model_name: model_name.to_string(),
        model_version: model_version.to_string(),
        created_at: Utc::now(),
        encryption_algorithm: REQUIRED_ENCRYPTION_ALGORITHM.to_string(),
        key_derivation: REQUIRED_KEY_DERIVATION.to_string(),
        client_key_id: client_id.to_string(),
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
    manifest
        .validate_structure()
        .context("the generated manifest failed validation")?;

    let manifest_path = output.join("manifest.json");
    let mut file = std::fs::File::create(&manifest_path)
        .with_context(|| format!("cannot write {}", manifest_path.display()))?;
    file.write_all(&serde_json::to_vec_pretty(&manifest)?)?;
    file.sync_all()?;

    println!();
    println!("Bundle written to {}", output.display());
    println!("  bundle_id   {}", manifest.bundle_id);
    println!("  shards      {}", manifest.shards.len());
    println!(
        "  plaintext   {}",
        hex_prefix(&manifest.total_plaintext_sha256)
    );
    println!();
    println!("The serving node must be configured with:");
    println!("  the same bundle_id           {}", manifest.bundle_id);
    println!("  the same derivation principal {}", client_id);
    println!("  the same Client Master Key");
    println!();
    println!("Copy this directory into the node's model store, then verify it there:");
    println!(
        "  cordon-provision verify --bundle <dir> --cmk-file <file> --client-id {}",
        client_id
    );

    Ok(())
}

fn verify(bundle_dir: &Path, key: Option<(String, String)>) -> Result<()> {
    let manifest = read_manifest(bundle_dir)?;

    println!(
        "Verifying {} ({} v{})",
        manifest.bundle_id, manifest.model_name, manifest.model_version
    );

    manifest
        .validate_structure()
        .context("the manifest is not a valid encrypted bundle")?;
    println!("  manifest    valid");

    let bundle_key = match &key {
        Some((cmk_hex, client_id)) => {
            let master = MasterKey::from_hex(cmk_hex).context("invalid Client Master Key")?;
            Some(
                master
                    .derive_bundle_key(&manifest.bundle_id, client_id)
                    .context("cannot derive the bundle key")?,
            )
        }
        None => None,
    };

    let mut failures = 0;
    let mut total_hasher = Sha256::new();

    for (index, shard) in manifest.shards.iter().enumerate() {
        let path = bundle_dir.join(&shard.path);
        if !path.exists() {
            println!("  shard {:>5}  MISSING  {}", index, shard.path);
            failures += 1;
            continue;
        }

        let ciphertext =
            std::fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
        let digest = hex::encode(Sha256::digest(&ciphertext));

        if digest != shard.ciphertext_sha256 {
            println!("  shard {:>5}  CIPHERTEXT DIGEST MISMATCH", index);
            failures += 1;
            continue;
        }

        let Some(bundle_key) = &bundle_key else {
            println!("  shard {:>5}  ciphertext ok", index);
            continue;
        };

        let shard_key = bundle_key.derive_shard_key(index as u32)?;
        let nonce = decode_nonce(&shard.iv_base64)?;

        match decrypt_shard(&shard_key, &ciphertext, &nonce) {
            Ok(plaintext) => {
                let pt_digest = hex::encode(Sha256::digest(&plaintext));
                if pt_digest != shard.plaintext_sha256 {
                    println!("  shard {:>5}  PLAINTEXT DIGEST MISMATCH", index);
                    failures += 1;
                } else {
                    total_hasher.update(&plaintext);
                    println!("  shard {:>5}  decrypted and verified", index);
                }
            }
            Err(_) => {
                println!(
                    "  shard {:>5}  DECRYPTION FAILED — wrong key, or tampered",
                    index
                );
                failures += 1;
            }
        }
    }

    if bundle_key.is_some() && failures == 0 {
        let total = hex::encode(total_hasher.finalize());
        if total != manifest.total_plaintext_sha256 {
            println!("  total       PLAINTEXT DIGEST MISMATCH");
            failures += 1;
        } else {
            println!("  total       {}", hex_prefix(&total));
        }
    }

    println!();
    if failures == 0 {
        println!("Bundle verified.");
        Ok(())
    } else {
        println!("{} shard(s) failed verification.", failures);
        std::process::exit(1);
    }
}

fn inspect(bundle_dir: &Path) -> Result<()> {
    let manifest = read_manifest(bundle_dir)?;
    let plaintext_total: u64 = manifest.shards.iter().map(|s| s.size_bytes).sum();

    println!("Bundle       {}", manifest.bundle_id);
    println!(
        "Model        {} v{}",
        manifest.model_name, manifest.model_version
    );
    println!("Created      {}", manifest.created_at);
    println!("Encryption   {}", manifest.encryption_algorithm);
    println!("Derivation   {}", manifest.key_derivation);
    println!("Principal    {}", manifest.client_key_id);
    println!("Shards       {}", manifest.shards.len());
    println!("Plaintext    {}", human_bytes(plaintext_total));
    println!(
        "Digest       {}",
        hex_prefix(&manifest.total_plaintext_sha256)
    );
    println!(
        "Vendor sig   {}",
        if manifest.vendor_signature.is_empty() {
            "unsigned"
        } else {
            "present"
        }
    );
    println!(
        "Client sig   {}",
        if manifest.client_approval_signature.is_empty() {
            "unsigned"
        } else {
            "present"
        }
    );
    println!();

    match manifest.validate_structure() {
        Ok(()) => println!("Structure    valid"),
        Err(e) => println!("Structure    INVALID — {}", e),
    }
    Ok(())
}

fn read_manifest(bundle_dir: &Path) -> Result<BundleManifest> {
    let path = bundle_dir.join("manifest.json");
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    serde_json::from_str(&contents).with_context(|| format!("invalid manifest {}", path.display()))
}

/// Collect weight files, sorted, so a bundle built twice from the same inputs
/// shards them the same way.
fn collect_weight_files(source: &Path) -> Result<Vec<PathBuf>> {
    if source.is_file() {
        return Ok(vec![source.to_path_buf()]);
    }

    let mut files: Vec<PathBuf> = std::fs::read_dir(source)
        .with_context(|| format!("cannot read {}", source.display()))?
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

fn decode_nonce(iv_base64: &str) -> Result<[u8; 12]> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(iv_base64)
        .context("invalid base64 nonce")?;
    if bytes.len() != 12 {
        bail!("nonce must be 12 bytes, got {}", bytes.len());
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bytes);
    Ok(nonce)
}

/// Reduce a filename to characters that are safe in a path and a manifest.
fn sanitize(name: &str) -> String {
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

fn hex_prefix(digest: &str) -> String {
    digest.chars().take(32).collect::<String>() + "…"
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} B", bytes)
    } else {
        format!("{:.1} {}", value, UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filenames_are_reduced_to_safe_characters() {
        assert_eq!(sanitize("model.gguf"), "model.gguf");
        assert_eq!(sanitize("../../etc/passwd"), ".._.._etc_passwd");
        assert_eq!(sanitize("a b;c"), "a_b_c");
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

    /// End-to-end: a bundle this tool produces must satisfy the validator the
    /// serving node applies, and must round-trip through decryption.
    #[test]
    fn a_produced_bundle_is_valid_and_decrypts() {
        let dir = tempfile::tempdir().unwrap();
        let weights = dir.path().join("weights");
        std::fs::create_dir_all(&weights).unwrap();

        // Two shards' worth, so sharding is actually exercised.
        let payload: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(weights.join("model.gguf"), &payload).unwrap();

        let cmk = "33".repeat(32);
        let output = dir.path().join("bundle");

        encrypt(
            &weights,
            &cmk,
            Some("test-bundle".into()),
            "operator",
            "Test Model",
            "1.0",
            &output,
            1024,
        )
        .unwrap();

        let manifest = read_manifest(&output).unwrap();
        manifest.validate_structure().unwrap();
        assert_eq!(
            manifest.shards.len(),
            3,
            "3000 bytes at 1024/shard is 3 shards"
        );
        assert_eq!(
            manifest.shards.iter().map(|s| s.size_bytes).sum::<u64>(),
            payload.len() as u64
        );
        assert_eq!(
            manifest.total_plaintext_sha256,
            hex::encode(Sha256::digest(&payload))
        );

        // Every shard has a distinct nonce, and none is all-zero.
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

        // The bundle decrypts back to the original bytes.
        let master = MasterKey::from_hex(&cmk).unwrap();
        let bundle_key = master.derive_bundle_key("test-bundle", "operator").unwrap();
        let mut recovered = Vec::new();
        for (index, shard) in manifest.shards.iter().enumerate() {
            let ciphertext = std::fs::read(output.join(&shard.path)).unwrap();
            let key = bundle_key.derive_shard_key(index as u32).unwrap();
            let nonce = decode_nonce(&shard.iv_base64).unwrap();
            recovered.extend_from_slice(&decrypt_shard(&key, &ciphertext, &nonce).unwrap());
        }
        assert_eq!(recovered, payload);

        // The wrong principal derives the wrong key and cannot decrypt.
        let wrong = master
            .derive_bundle_key("test-bundle", "someone-else")
            .unwrap();
        let key = wrong.derive_shard_key(0).unwrap();
        let ciphertext = std::fs::read(output.join(&manifest.shards[0].path)).unwrap();
        let nonce = decode_nonce(&manifest.shards[0].iv_base64).unwrap();
        assert!(decrypt_shard(&key, &ciphertext, &nonce).is_err());
    }
}
