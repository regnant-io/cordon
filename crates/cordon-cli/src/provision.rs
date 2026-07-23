//! cordon-provision — Encrypt and provision model bundles for Cordon
//!
//! Usage:
//!   cordon-provision encrypt --weights <dir> --cmk <hex> --bundle-id <id>
//!                             --client-id <id> --output <dir>
//!   cordon-provision verify  --bundle <dir> --cmk <hex> --client-id <id>

use std::path::PathBuf;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use base64::Engine;

use cordon_crypto::{
    hierarchy::MasterKey,
    symmetric::encrypt_shard,
};
use cordon_core::model_store::{BundleManifest, ShardDescriptor, MinimumRequirements, TeeRequirements, HardwareRequirements};

#[derive(Parser)]
#[command(
    name = "cordon-provision",
    about = "Encrypt and provision model weight bundles for Cordon",
    long_about = "Encrypts model weights with AES-256-GCM using per-shard keys\n\
        derived from the Client Master Key via HKDF-SHA256.\n\
        The CMK should be provided from an HSM in production.",
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt model weights into a Cordon bundle
    Encrypt {
        /// Directory containing weight files (*.safetensors, *.bin, etc.)
        #[arg(long)]
        weights: PathBuf,

        /// CMK hex (32 bytes)
        #[arg(long)]
        cmk: String,

        /// Bundle ID (generated if not specified)
        #[arg(long)]
        bundle_id: Option<String>,

        /// Client ID
        #[arg(long)]
        client_id: String,

        /// Model name
        #[arg(long)]
        model_name: String,

        /// Model version
        #[arg(long, default_value = "1.0.0")]
        model_version: String,

        /// Output directory for encrypted bundle
        #[arg(long)]
        output: PathBuf,
    },

    /// Verify an encrypted bundle against expected hashes
    Verify {
        /// Bundle directory
        #[arg(long)]
        bundle: PathBuf,

        /// CMK hex
        #[arg(long)]
        cmk: String,

        /// Client ID
        #[arg(long)]
        client_id: String,
    },

    /// Display bundle manifest information
    Inspect {
        /// Bundle directory
        #[arg(long)]
        bundle: PathBuf,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            weights,
            cmk,
            bundle_id,
            client_id,
            model_name,
            model_version,
            output,
        } => encrypt_bundle(weights, cmk, bundle_id, client_id, model_name, model_version, output),

        Commands::Verify { bundle, cmk, client_id } => {
            verify_bundle(bundle, cmk, client_id)
        }

        Commands::Inspect { bundle } => inspect_bundle(bundle),
    }
}

fn encrypt_bundle(
    weights_dir: PathBuf,
    cmk_hex: String,
    bundle_id: Option<String>,
    client_id: String,
    model_name: String,
    model_version: String,
    output_dir: PathBuf,
) -> Result<()> {
    let bundle_id = bundle_id.unwrap_or_else(|| Uuid::new_v4().to_string());

    println!("Encrypting model bundle '{}'", model_name);
    println!("Bundle ID: {}", bundle_id);

    // Derive bundle key
    let master = MasterKey::from_hex(&cmk_hex).context("Invalid CMK")?;
    let bundle_key = master.derive_bundle_key(&bundle_id, &client_id)
        .context("Bundle key derivation failed")?;

    // Find weight files
    let weight_files: Vec<PathBuf> = std::fs::read_dir(&weights_dir)
        .context("Cannot read weights directory")?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            matches!(ext, "safetensors" | "bin" | "pt" | "pth" | "gguf")
        })
        .collect();

    if weight_files.is_empty() {
        // For testing: create a dummy weight file
        println!("No weight files found — creating test payload for demonstration");
        let test_file = weights_dir.join("test_weights.bin");
        std::fs::create_dir_all(&weights_dir)?;
        std::fs::write(&test_file, b"CORDON_TEST_WEIGHTS_v2".repeat(100))?;
        return encrypt_bundle(
            weights_dir, cmk_hex, Some(bundle_id), client_id,
            model_name, model_version, output_dir
        );
    }

    // Create output directories
    let weights_out = output_dir.join("weights");
    std::fs::create_dir_all(&weights_out).context("Cannot create weights output dir")?;

    let mut shards = Vec::new();
    let mut all_plaintext = Vec::new();

    println!("Encrypting {} weight file(s)...", weight_files.len());

    for (idx, weight_path) in weight_files.iter().enumerate() {
        let filename = weight_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("shard");

        print!("  [{}/{}] {:?}... ", idx + 1, weight_files.len(), filename);

        let plaintext = std::fs::read(&weight_path)
            .context(format!("Cannot read weight file {:?}", weight_path))?;

        let plaintext_hash = hex::encode(Sha256::digest(&plaintext));
        all_plaintext.extend_from_slice(&plaintext);

        // Derive per-shard key
        let shard_key = bundle_key.derive_shard_key(idx as u32)
            .context("Shard key derivation failed")?;

        // Generate random IV
        let mut iv = [0u8; 12];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut iv);

        // Encrypt
        let ciphertext = encrypt_shard(&shard_key, &plaintext, &iv)
            .context("Encryption failed")?;

        let ciphertext_hash = hex::encode(Sha256::digest(&ciphertext));

        // Write encrypted shard
        let enc_filename = format!("{}.enc", filename);
        let enc_path = weights_out.join(&enc_filename);
        std::fs::write(&enc_path, &ciphertext)
            .context(format!("Cannot write encrypted shard {:?}", enc_path))?;

        let iv_b64 = base64::engine::general_purpose::STANDARD.encode(&iv);

        shards.push(ShardDescriptor {
            path: format!("weights/{}", enc_filename),
            plaintext_sha256: plaintext_hash,
            ciphertext_sha256: ciphertext_hash,
            iv_base64: iv_b64,
            size_bytes: ciphertext.len() as u64,
            layer_index: idx as u32,
        });

        println!("✓ ({} bytes → {} bytes encrypted)", plaintext.len(), ciphertext.len());
    }

    let total_plaintext_hash = hex::encode(Sha256::digest(&all_plaintext));

    // Build manifest
    let manifest = BundleManifest {
        bundle_id: bundle_id.clone(),
        model_name: model_name.clone(),
        model_version: model_version.clone(),
        created_at: Utc::now(),
        encryption_algorithm: "AES-256-GCM".to_string(),
        key_derivation: "HKDF-SHA256".to_string(),
        client_key_id: client_id.clone(),
        shards,
        total_plaintext_sha256: total_plaintext_hash,
        minimum_requirements: MinimumRequirements {
            cordon_version: "2.0.0".to_string(),
            tee: TeeRequirements {
                sgx_isv_svn_min: Some(3),
                sev_snp_api_min: Some("1.51".to_string()),
            },
            hardware: HardwareRequirements {
                min_gpu_vram_gb: 0,
                min_ram_gb: 16,
                ecc_memory_required: true,
            },
        },
        policy_hash: hex::encode(Sha256::digest(b"default-policy")),
        vendor_signature: "UNSIGNED".to_string(),
        client_approval_signature: "UNSIGNED".to_string(),
    };

    // Write manifest
    let manifest_path = output_dir.join("manifest.json");
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .context("Manifest serialization failed")?;
    std::fs::write(&manifest_path, &manifest_json)
        .context("Cannot write manifest")?;

    println!();
    println!("Bundle encrypted successfully:");
    println!("  Output:    {:?}", output_dir);
    println!("  Bundle ID: {}", bundle_id);
    println!("  Shards:    {}", manifest.shards.len());
    println!("  Manifest:  {:?}", manifest_path);
    println!();
    println!("Next steps:");
    println!("  1. Sign manifest with vendor key:  cordon-provision sign-vendor ...");
    println!("  2. Sign manifest with client key:  cordon-provision sign-client ...");
    println!("  3. Copy bundle to Cordon node:    {:?}", output_dir);

    Ok(())
}

fn verify_bundle(bundle_dir: PathBuf, cmk_hex: String, client_id: String) -> Result<()> {
    let manifest_path = bundle_dir.join("manifest.json");
    let content = std::fs::read_to_string(&manifest_path)
        .context("Cannot read manifest")?;
    let manifest: BundleManifest = serde_json::from_str(&content)
        .context("Invalid manifest")?;

    println!("Verifying bundle: {}", manifest.bundle_id);
    println!("Model: {} v{}", manifest.model_name, manifest.model_version);
    println!();

    let master = MasterKey::from_hex(&cmk_hex).context("Invalid CMK")?;
    let _bundle_key = master.derive_bundle_key(&manifest.bundle_id, &client_id)?;

    let mut all_passed = true;
    for (idx, shard) in manifest.shards.iter().enumerate() {
        let shard_path = bundle_dir.join(&shard.path);
        print!("  Shard {:3}: {:?}... ", idx, shard.path);

        if !shard_path.exists() {
            println!("✗ MISSING");
            all_passed = false;
            continue;
        }

        let ciphertext = std::fs::read(&shard_path)?;
        let ct_hash = hex::encode(Sha256::digest(&ciphertext));

        if ct_hash != shard.ciphertext_sha256 {
            println!("✗ CIPHERTEXT HASH MISMATCH");
            all_passed = false;
        } else {
            println!("✓");
        }
    }

    println!();
    if all_passed {
        println!("✓ Bundle verified — all ciphertext hashes match");
    } else {
        println!("✗ Bundle FAILED verification — possible tampering");
        std::process::exit(1);
    }

    Ok(())
}

fn inspect_bundle(bundle_dir: PathBuf) -> Result<()> {
    let manifest_path = bundle_dir.join("manifest.json");
    let content = std::fs::read_to_string(&manifest_path)
        .context("Cannot read manifest")?;
    let manifest: BundleManifest = serde_json::from_str(&content)
        .context("Invalid manifest")?;

    println!("Bundle Manifest");
    println!("═══════════════");
    println!("Bundle ID:   {}", manifest.bundle_id);
    println!("Model:       {} v{}", manifest.model_name, manifest.model_version);
    println!("Created:     {}", manifest.created_at);
    println!("Encryption:  {}", manifest.encryption_algorithm);
    println!("KDF:         {}", manifest.key_derivation);
    println!("Shards:      {}", manifest.shards.len());
    println!("Total hash:  {}", &manifest.total_plaintext_sha256[..32]);
    println!("Policy hash: {}", &manifest.policy_hash[..32]);
    println!("Vendor sig:  {}", if manifest.vendor_signature == "UNSIGNED" { "NOT SIGNED" } else { "SIGNED" });
    println!("Client sig:  {}", if manifest.client_approval_signature == "UNSIGNED" { "NOT SIGNED" } else { "SIGNED" });
    println!();
    println!("Minimum requirements:");
    println!("  Cordon: >= {}", manifest.minimum_requirements.cordon_version);
    println!("  RAM:     >= {} GB", manifest.minimum_requirements.hardware.min_ram_gb);
    println!("  ECC:     {}", manifest.minimum_requirements.hardware.ecc_memory_required);

    Ok(())
}

