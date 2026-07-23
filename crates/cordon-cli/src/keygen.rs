//! cordon-keygen — Generate Cordon Client Master Key and derived keys
//!
//! Usage:
//!   cordon-keygen generate [--output <dir>]
//!   cordon-keygen derive --cmk <hex> --bundle-id <id> --client-id <id>
//!   cordon-keygen show-public --cmk <hex> --deployment-id <id> --client-id <id>

use std::path::PathBuf;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use cordon_crypto::hierarchy::MasterKey;

#[derive(Parser)]
#[command(
    name = "cordon-keygen",
    about = "Cordon key generation and derivation tool",
    long_about = "Generates the Client Master Key (CMK) and derives all child keys.\n\
        The CMK must be stored in a FIPS 140-2 Level 3+ HSM in production.\n\
        Never store the CMK in a file in production environments.",
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Client Master Key
    Generate {
        /// Output directory for key material
        #[arg(short, long, default_value = "./cordon-keys")]
        output: PathBuf,

        /// Deployment ID (used in key derivation)
        #[arg(long)]
        deployment_id: String,

        /// Client ID
        #[arg(long)]
        client_id: String,

        /// Model bundle ID (for deriving bundle key)
        #[arg(long)]
        bundle_id: Option<String>,
    },

    /// Derive a specific child key from a CMK
    Derive {
        /// CMK in hex (32 bytes / 64 hex chars)
        #[arg(long)]
        cmk: String,

        /// Deployment ID
        #[arg(long)]
        deployment_id: String,

        /// Client ID
        #[arg(long)]
        client_id: String,

        /// Bundle ID (required for bundle/shard key derivation)
        #[arg(long)]
        bundle_id: Option<String>,

        /// Key type to derive
        #[arg(long, default_value = "all")]
        key_type: String,
    },

    /// Show public keys derived from a CMK (safe to share with Cordon node)
    ShowPublic {
        /// CMK in hex
        #[arg(long)]
        cmk: String,

        /// Deployment ID
        #[arg(long)]
        deployment_id: String,

        /// Client ID
        #[arg(long)]
        client_id: String,
    },

    /// Sign an administrative command with K_admin (for /v1/admin/* endpoints).
    /// Prints the signature hex to paste into the request's `admin_signature`.
    AdminSign {
        /// CMK in hex
        #[arg(long)]
        cmk: String,

        /// Deployment ID
        #[arg(long)]
        deployment_id: String,

        /// Client ID (the key-derivation principal; must match CORDON_CLIENT_ID on the node)
        #[arg(long)]
        client_id: String,

        /// Admin action: teardown | recover | quarantine
        #[arg(long)]
        action: String,

        /// Command parameters (usually the reason string; must match the request body)
        #[arg(long, default_value = "")]
        params: String,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate {
            output,
            deployment_id,
            client_id,
            bundle_id,
        } => generate_keys(output, deployment_id, client_id, bundle_id),

        Commands::Derive {
            cmk,
            deployment_id,
            client_id,
            bundle_id,
            key_type,
        } => derive_keys(cmk, deployment_id, client_id, bundle_id, key_type),

        Commands::ShowPublic {
            cmk,
            deployment_id,
            client_id,
        } => show_public_keys(cmk, deployment_id, client_id),

        Commands::AdminSign {
            cmk,
            deployment_id,
            client_id,
            action,
            params,
        } => admin_sign(cmk, deployment_id, client_id, action, params),
    }
}

fn admin_sign(
    cmk_hex: String,
    deployment_id: String,
    client_id: String,
    action: String,
    params: String,
) -> Result<()> {
    let master = MasterKey::from_hex(&cmk_hex).context("Invalid CMK hex")?;
    let admin_key = master.derive_admin_key(&deployment_id, &client_id)
        .context("Admin key derivation failed")?;
    // Canonical string MUST match CordonNode::authorize_admin.
    let canonical = format!("CORDON_ADMIN:{}:{}", action, params);
    let sig = admin_key.signing_key().sign(canonical.as_bytes());
    println!("action:      {}", action);
    println!("params:      {}", params);
    println!("signed_msg:  {}", canonical);
    println!("admin_signature: {}", sig.to_hex());
    println!();
    println!("POST body example:");
    println!("  {{\"admin_signature\": \"{}\", \"reason\": \"{}\"}}", sig.to_hex(), params);
    Ok(())
}

fn generate_keys(
    output: PathBuf,
    deployment_id: String,
    client_id: String,
    bundle_id: Option<String>,
) -> Result<()> {
    use rand::RngCore;

    eprintln!("⚠️  WARNING: In production, generate the CMK inside an HSM.");
    eprintln!("             Never store CMK in a file in production.");
    eprintln!();

    // Generate 32 bytes of random key material
    let mut cmk_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut cmk_bytes);

    let master = MasterKey::from_bytes(cmk_bytes);
    let cmk_hex = master.to_hex();

    std::fs::create_dir_all(&output).context("Cannot create output directory")?;

    // Write CMK
    let cmk_path = output.join("cmk.hex");
    std::fs::write(&cmk_path, &cmk_hex)
        .context("Cannot write CMK")?;
    set_restrictive_permissions(&cmk_path)?;

    println!("Generated CMK: {}", cmk_hex);
    println!("Saved to: {:?}", cmk_path);
    println!("Permission: 0600 (owner read-only)");
    println!();

    // Derive and show public keys
    println!("Derived public verification keys:");
    println!("══════════════════════════════════");

    let log_key = master.derive_log_key(&deployment_id, &client_id)
        .context("Log key derivation failed")?;
    let log_vk = log_key.verifying_key();
    println!("Log verification key (K_log_pub):   {}", log_vk.to_hex());
    std::fs::write(output.join("log_verifying_key.hex"), log_vk.to_hex())
        .context("Cannot write log key")?;

    let admin_key = master.derive_admin_key(&deployment_id, &client_id)
        .context("Admin key derivation failed")?;
    let admin_vk = admin_key.verifying_key();
    println!("Admin verification key (K_admin_pub): {}", admin_vk.to_hex());
    std::fs::write(output.join("admin_verifying_key.hex"), admin_vk.to_hex())
        .context("Cannot write admin key")?;

    if let Some(bid) = &bundle_id {
        let _bundle_key = master.derive_bundle_key(bid, &client_id)
            .context("Bundle key derivation failed")?;
        println!("Bundle key (K_bundle, SECRET):      {} bytes derived", 32);
        println!("  (Store in HSM; release to enclave only after attestation)");
    }

    println!();
    println!("Next steps:");
    println!("  1. Store CMK in FIPS 140-2 Level 3+ HSM");
    println!("  2. Provision log_verifying_key.hex to Cordon node");
    println!("  3. Provision admin_verifying_key.hex to Cordon node");
    println!("  4. Delete {:?} after HSM import", cmk_path);

    Ok(())
}

fn derive_keys(
    cmk_hex: String,
    deployment_id: String,
    client_id: String,
    bundle_id: Option<String>,
    key_type: String,
) -> Result<()> {
    let master = MasterKey::from_hex(&cmk_hex).context("Invalid CMK hex")?;

    match key_type.as_str() {
        "bundle" | "all" => {
            if let Some(bid) = &bundle_id {
                let k = master.derive_bundle_key(bid, &client_id)?;
                println!("Bundle key (K_bundle): {}", hex::encode(k.as_bytes()));
            } else if key_type == "bundle" {
                anyhow::bail!("--bundle-id required for bundle key derivation");
            }
        }
        _ => {}
    }

    match key_type.as_str() {
        "session" | "all" => {
            let k = master.derive_session_key(&deployment_id, &client_id)?;
            println!("Session key (K_session): {}", hex::encode(k.as_bytes()));
        }
        _ => {}
    }

    match key_type.as_str() {
        "log" | "all" => {
            let k = master.derive_log_key(&deployment_id, &client_id)?;
            println!("Log signing key (K_log pub):  {}", k.verifying_key().to_hex());
        }
        _ => {}
    }

    match key_type.as_str() {
        "admin" | "all" => {
            let k = master.derive_admin_key(&deployment_id, &client_id)?;
            println!("Admin signing key (K_admin pub): {}", k.verifying_key().to_hex());
        }
        _ => {}
    }

    Ok(())
}

fn show_public_keys(
    cmk_hex: String,
    deployment_id: String,
    client_id: String,
) -> Result<()> {
    let master = MasterKey::from_hex(&cmk_hex).context("Invalid CMK hex")?;

    let log_key = master.derive_log_key(&deployment_id, &client_id)?;
    let admin_key = master.derive_admin_key(&deployment_id, &client_id)?;

    println!("Public keys (safe to provision to Cordon node):");
    println!("K_log_pub:   {}", log_key.verifying_key().to_hex());
    println!("K_admin_pub: {}", admin_key.verifying_key().to_hex());
    println!();
    println!("Provision these to the Cordon node via the deployment manifest.");

    Ok(())
}

#[cfg(unix)]
fn set_restrictive_permissions(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .context("Cannot set file permissions")?;
    Ok(())
}

#[cfg(not(unix))]
fn set_restrictive_permissions(_path: &std::path::Path) -> Result<()> {
    Ok(()) // Best-effort on non-Unix
}
