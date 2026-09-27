//! `cordon-provision`, also `cordon bundle`: seal model weights into an
//! encrypted Cordon bundle, and check one.
//!
//! Weights are split into shards, each encrypted with AES-256-GCM under its own
//! key derived from the Client Master Key. The CMK never leaves the operator's
//! control: a node without it holds ciphertext and a manifest, and can prove
//! neither what the weights are nor that it could read them.
//!
//! ```text
//! cordon bundle seal   --weights model.gguf --cmk-file cmk.hex
//! cordon bundle verify --bundle model.bundle --cmk-file cmk.hex
//! cordon bundle inspect --bundle model.bundle
//! ```
//!
//! The work itself is [`cordon_core::bundle`], which the desktop app uses too.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};

use cordon_core::bundle::{self, BundleEvent, SealRequest, DEFAULT_SHARD_SIZE};
use cordon_crypto::hierarchy::MasterKey;

#[allow(dead_code)]
#[derive(Parser)]
#[command(
    name = "cordon-provision",
    version = env!("CARGO_PKG_VERSION"),
    about = "Seal model weights into an encrypted Cordon bundle",
    long_about = "Encrypts model weights with AES-256-GCM under per-shard keys derived\n\
                  from the Client Master Key via HKDF-SHA256.\n\n\
                  The CMK is the root of trust. Source it from an HSM in production;\n\
                  a node never needs it except to decrypt at load time."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Bundle commands.
#[derive(Subcommand)]
pub enum Command {
    /// Seal weight files into a bundle.
    ///
    /// Only the weights and the key are required. The model name defaults to
    /// the file name, the bundle is written next to the current directory as
    /// `<name>.bundle`, and the principal is `operator`, which is what a node
    /// uses unless configured otherwise.
    #[command(visible_alias = "encrypt")]
    Seal {
        /// A weight file, or a directory of weight files.
        #[arg(long, value_name = "PATH")]
        weights: PathBuf,
        /// File containing the Client Master Key, hex.
        #[arg(long, value_name = "FILE", conflicts_with = "cmk")]
        cmk_file: Option<PathBuf>,
        /// Client Master Key, hex. Visible in the process table; prefer
        /// `--cmk-file`.
        #[arg(long, hide = true)]
        cmk: Option<String>,
        /// Key-derivation principal. Must match the node's `key_principal`.
        #[arg(long, default_value = "operator")]
        client_id: String,
        /// Human-readable model name. Defaults to the file name.
        #[arg(long)]
        model_name: Option<String>,
        /// Model version.
        #[arg(long, default_value = "1.0.0")]
        model_version: String,
        /// Bundle ID. It feeds key derivation, and a node names the model by
        /// it. Defaults to the model name plus a random suffix.
        #[arg(long)]
        bundle_id: Option<String>,
        /// Output directory. Defaults to `<bundle-id>.bundle`.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Plaintext bytes per shard.
        #[arg(long, default_value_t = DEFAULT_SHARD_SIZE, hide = true)]
        shard_size: usize,
    },

    /// Check a bundle's ciphertext against its manifest and, given the key,
    /// decrypt every shard and check the plaintext too.
    Verify {
        /// Bundle directory.
        #[arg(long)]
        bundle: PathBuf,
        /// File containing the Client Master Key. Omit to check ciphertext
        /// digests only.
        #[arg(long, conflicts_with = "cmk")]
        cmk_file: Option<PathBuf>,
        /// Client Master Key, hex.
        #[arg(long, hide = true)]
        cmk: Option<String>,
        /// Key-derivation principal.
        #[arg(long, default_value = "operator")]
        client_id: String,
    },

    /// Print a bundle's manifest.
    Inspect {
        /// Bundle directory.
        #[arg(long)]
        bundle: PathBuf,
    },
}

#[allow(dead_code)]
fn main() -> Result<()> {
    run(Cli::parse().command)
}

/// Run one bundle command. Shared by `cordon-provision` and `cordon bundle`.
pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Seal {
            weights,
            cmk_file,
            cmk,
            client_id,
            model_name,
            model_version,
            bundle_id,
            output,
            shard_size,
        } => {
            let master = load_cmk(cmk, cmk_file)?
                .context("a Client Master Key is required; pass --cmk-file")?;
            let model_name = model_name.unwrap_or_else(|| bundle::model_name_from_path(&weights));
            let bundle_id = bundle_id.unwrap_or_else(|| bundle::suggest_bundle_id(&model_name));
            let output = output.unwrap_or_else(|| PathBuf::from(format!("{}.bundle", bundle_id)));
            seal(&SealRequest {
                weights: &weights,
                master: &master,
                principal: &client_id,
                bundle_id: Some(bundle_id),
                model_name: &model_name,
                model_version: &model_version,
                output: &output,
                shard_size,
            })
        }
        Command::Verify {
            bundle,
            cmk_file,
            cmk,
            client_id,
        } => verify(&bundle, load_cmk(cmk, cmk_file)?, &client_id),
        Command::Inspect { bundle } => inspect(&bundle),
    }
}

/// Read the CMK from a file where possible; a key on a command line is visible
/// in the process table and in shell history.
fn load_cmk(inline: Option<String>, file: Option<PathBuf>) -> Result<Option<MasterKey>> {
    let hex = match (file, inline) {
        (Some(path), _) => std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?,
        (None, Some(hex)) => {
            eprintln!(
                "warning: the Client Master Key was passed on the command line, where it is \
                 visible in the process table and shell history. Prefer --cmk-file."
            );
            hex
        }
        (None, None) => return Ok(None),
    };
    MasterKey::from_hex(hex.trim())
        .map(Some)
        .context("invalid Client Master Key")
}

fn progress_bar() -> ProgressBar {
    let bar = ProgressBar::new(0);
    bar.set_style(
        ProgressStyle::with_template(
            "  {bar:34.cyan/blue} {bytes:>10}/{total_bytes:<10} {bytes_per_sec:>11}  eta {eta}",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("━━╸"),
    );
    bar
}

fn seal(request: &SealRequest<'_>) -> Result<()> {
    println!("Sealing {}", request.weights.display());
    println!(
        "  model      {} v{}",
        request.model_name, request.model_version
    );
    println!("  principal  {}", request.principal);
    println!();

    let bar = progress_bar();
    let manifest = bundle::seal(request, &AtomicBool::new(false), |event| match event {
        BundleEvent::Started { total_bytes, .. } => bar.set_length(total_bytes),
        BundleEvent::Progress { done_bytes, .. } => bar.set_position(done_bytes),
        BundleEvent::Shard { .. } => {}
    });
    bar.finish_and_clear();
    let manifest = manifest?;

    println!("Bundle written to {}", request.output.display());
    println!("  bundle_id  {}", manifest.bundle_id);
    println!("  shards     {}", manifest.shards.len());
    println!(
        "  digest     {}",
        hex_prefix(&manifest.total_plaintext_sha256)
    );
    println!();
    println!("To serve it, copy the folder into the node's model store");
    println!("(model_store.path), and set:");
    println!();
    println!("  cmk_path           = \"<the same key file>\"");
    println!("  key_principal      = \"{}\"", request.principal);
    println!("  [runtime]");
    println!("  model_path         = \"{}\"", manifest.bundle_id);
    Ok(())
}

fn verify(bundle_dir: &Path, master: Option<MasterKey>, principal: &str) -> Result<()> {
    let manifest = bundle::read_manifest(bundle_dir)?;
    println!(
        "Verifying {} ({} v{})",
        manifest.bundle_id, manifest.model_name, manifest.model_version
    );
    if master.is_none() {
        println!("  no key given: checking ciphertext only");
    }

    let bar = progress_bar();
    let report = bundle::verify(
        bundle_dir,
        master.as_ref().map(|m| (m, principal)),
        &AtomicBool::new(false),
        |event| match event {
            BundleEvent::Started { total_bytes, .. } => bar.set_length(total_bytes),
            BundleEvent::Progress { done_bytes, .. } => bar.set_position(done_bytes),
            BundleEvent::Shard { .. } => {}
        },
    );
    bar.finish_and_clear();
    let report = report?;

    if report.passed() {
        println!(
            "Bundle verified: {} shard(s){}.",
            report.shards,
            if report.decrypted {
                ", decrypted and matched"
            } else {
                ", ciphertext matched"
            }
        );
        return Ok(());
    }
    for failure in &report.failures {
        println!("  {}", failure);
    }
    bail!("{} check(s) failed", report.failures.len())
}

fn inspect(bundle_dir: &Path) -> Result<()> {
    let manifest = bundle::read_manifest(bundle_dir)?;
    let plaintext_total: u64 = manifest.shards.iter().map(|s| s.size_bytes).sum();
    let signed = |sig: &str| {
        if sig.is_empty() {
            "unsigned"
        } else {
            "present"
        }
    };

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
    println!("Vendor sig   {}", signed(&manifest.vendor_signature));
    println!(
        "Client sig   {}",
        signed(&manifest.client_approval_signature)
    );
    println!();
    match manifest.validate_structure() {
        Ok(()) => println!("Structure    valid"),
        Err(e) => println!("Structure    INVALID: {}", e),
    }
    Ok(())
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
