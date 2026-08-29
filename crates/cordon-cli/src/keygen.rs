//! `cordon-keygen` — generate the Client Master Key and derive its children.
//!
//! The CMK is the root of trust for a deployment. Everything else — the audit
//! log signing key, the admin authorization key, the response signing key, and
//! every bundle key — is HKDF-derived from it. A client holding the CMK derives
//! the same public halves and can therefore verify a node's signatures without
//! trusting the node.
//!
//! ```text
//! cordon-keygen generate    --deployment-id <id> --client-id <id> [--output <dir>]
//! cordon-keygen public      --cmk-file <path> --deployment-id <id> --client-id <id>
//! cordon-keygen derive      --cmk-file <path> --deployment-id <id> --client-id <id> --key-type <type>
//! cordon-keygen admin-sign  --cmk-file <path> --deployment-id <id> --client-id <id>
//!                           --action <action> --params <params>
//! ```
//!
//! # Handling the key
//!
//! In production the CMK belongs in an HSM. A file is acceptable only on a
//! memory-backed filesystem, which the node reads through `CORDON_CMK_FILE`.
//!
//! Secret material is never printed unless you ask for it explicitly. A key
//! echoed to a terminal ends up in scrollback, in shell history when it is
//! pasted back, and in CI logs when a pipeline runs one of these commands.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use cordon_crypto::hierarchy::MasterKey;

#[derive(Parser)]
#[command(
    name = "cordon-keygen",
    version = env!("CARGO_PKG_VERSION"),
    about = "Generate and derive Cordon key material",
    long_about = "Generates the Client Master Key and derives every child key.\n\n\
        The CMK belongs in a FIPS 140-2 Level 3 or higher HSM in production. A\n\
        key on disk is acceptable only on a memory-backed filesystem; a key on a\n\
        command line is visible in the process table and in shell history."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// How to obtain the Client Master Key. Shared by every command that needs one.
#[derive(clap::Args)]
struct CmkSource {
    /// File containing the Client Master Key, hex. Preferred.
    #[arg(long, conflicts_with = "cmk")]
    cmk_file: Option<PathBuf>,

    /// The Client Master Key itself, hex. Visible in the process table.
    #[arg(long)]
    cmk: Option<String>,
}

impl CmkSource {
    fn load(&self) -> Result<MasterKey> {
        let hex = match (&self.cmk_file, &self.cmk) {
            (Some(path), _) => std::fs::read_to_string(path)
                .with_context(|| format!("cannot read {}", path.display()))?,
            (None, Some(hex)) => {
                eprintln!(
                    "warning: the Client Master Key was passed on the command line, where \
                     it is visible in the process table and shell history. Prefer --cmk-file."
                );
                hex.clone()
            }
            (None, None) => bail!("a Client Master Key is required; pass --cmk-file"),
        };
        MasterKey::from_hex(hex.trim()).context("invalid Client Master Key")
    }
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new Client Master Key and write its public halves.
    Generate {
        /// Directory to write key material into.
        #[arg(short, long, default_value = "./cordon-keys")]
        output: PathBuf,

        /// Deployment ID. Feeds every derivation, so it must match the node's.
        #[arg(long)]
        deployment_id: String,

        /// Key-derivation principal. Must match the node's CORDON_CLIENT_ID.
        #[arg(long)]
        client_id: String,

        /// Also print the Client Master Key to stdout.
        ///
        /// Off by default: a key on a terminal survives in scrollback and in CI
        /// logs. The key is always written to the output directory regardless.
        #[arg(long)]
        print_cmk: bool,
    },

    /// Show the public keys a node can be provisioned with, and a client uses
    /// to verify what that node produces.
    Public {
        #[command(flatten)]
        cmk: CmkSource,

        /// Deployment ID.
        #[arg(long)]
        deployment_id: String,

        /// Key-derivation principal.
        #[arg(long)]
        client_id: String,
    },

    /// Derive a specific child key.
    Derive {
        #[command(flatten)]
        cmk: CmkSource,

        /// Deployment ID.
        #[arg(long)]
        deployment_id: String,

        /// Key-derivation principal.
        #[arg(long)]
        client_id: String,

        /// Bundle ID, required for `bundle`.
        #[arg(long)]
        bundle_id: Option<String>,

        /// One of: log, admin, enclave, session, bundle.
        #[arg(long)]
        key_type: String,

        /// Print secret key material rather than only its public half.
        ///
        /// `session` and `bundle` are symmetric and have no public half, so
        /// they cannot be shown without this.
        #[arg(long)]
        reveal_secret: bool,
    },

    /// Sign an administrative command with the admin key.
    ///
    /// Prints the signature to paste into the request's `admin_signature`. The
    /// signature covers the action and its parameters together, so it cannot be
    /// replayed against a different command.
    AdminSign {
        #[command(flatten)]
        cmk: CmkSource,

        /// Deployment ID.
        #[arg(long)]
        deployment_id: String,

        /// Key-derivation principal. Must match the node's CORDON_CLIENT_ID.
        #[arg(long)]
        client_id: String,

        /// One of: teardown, recover, quarantine, suspend-client,
        /// provision-model.
        #[arg(long)]
        action: String,

        /// Command parameters. Must match the request body exactly — for most
        /// commands this is the `reason` string.
        #[arg(long, default_value = "")]
        params: String,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Generate {
            output,
            deployment_id,
            client_id,
            print_cmk,
        } => generate(&output, &deployment_id, &client_id, print_cmk),

        Command::Public {
            cmk,
            deployment_id,
            client_id,
        } => public(&cmk.load()?, &deployment_id, &client_id),

        Command::Derive {
            cmk,
            deployment_id,
            client_id,
            bundle_id,
            key_type,
            reveal_secret,
        } => derive(
            &cmk.load()?,
            &deployment_id,
            &client_id,
            bundle_id.as_deref(),
            &key_type,
            reveal_secret,
        ),

        Command::AdminSign {
            cmk,
            deployment_id,
            client_id,
            action,
            params,
        } => admin_sign(&cmk.load()?, &deployment_id, &client_id, &action, &params),
    }
}

fn generate(output: &Path, deployment_id: &str, client_id: &str, print_cmk: bool) -> Result<()> {
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let master = MasterKey::from_bytes(bytes);

    std::fs::create_dir_all(output)
        .with_context(|| format!("cannot create {}", output.display()))?;

    let cmk_path = output.join("cmk.hex");
    write_secret(&cmk_path, &master.to_hex())?;

    let log = master.derive_log_signing_key(deployment_id, client_id)?;
    let admin = master.derive_admin_key(deployment_id, client_id)?;
    let enclave = master.derive_enclave_key(deployment_id, client_id)?;

    let public_keys = [
        ("log_verifying_key.hex", log.verifying_key().to_hex()),
        ("admin_verifying_key.hex", admin.verifying_key().to_hex()),
        (
            "enclave_verifying_key.hex",
            enclave.verifying_key().to_hex(),
        ),
    ];
    for (name, value) in &public_keys {
        std::fs::write(output.join(name), value)
            .with_context(|| format!("cannot write {}", name))?;
    }

    println!("Client Master Key written to {}", cmk_path.display());
    if cfg!(unix) {
        println!("  mode 0600, owner only");
    }
    if print_cmk {
        println!("  value  {}", master.to_hex());
    } else {
        println!("  (pass --print-cmk to display it)");
    }
    println!();
    println!("Derivation inputs — these must match the node exactly:");
    println!("  deployment_id  {}", deployment_id);
    println!("  client_id      {}", client_id);
    println!();
    println!("Public keys (safe to publish):");
    println!("  K_log      {}", log.verifying_key().to_hex());
    println!("    verifies the audit log, with `cordon-verify-log`");
    println!("  K_admin    {}", admin.verifying_key().to_hex());
    println!("    the node checks admin commands against this");
    println!("  K_enclave  {}", enclave.verifying_key().to_hex());
    println!("    verifies inference responses and attestation reports");
    println!();
    println!("Next:");
    println!("  1. Import the CMK into an HSM, or place it on a tmpfs the node reads");
    println!("     through CORDON_CMK_FILE.");
    println!(
        "  2. Delete {} once it is stored safely.",
        cmk_path.display()
    );
    println!("  3. Keep the public keys — they are what let you verify this node");
    println!("     without trusting it.");

    Ok(())
}

fn public(master: &MasterKey, deployment_id: &str, client_id: &str) -> Result<()> {
    let log = master.derive_log_signing_key(deployment_id, client_id)?;
    let admin = master.derive_admin_key(deployment_id, client_id)?;
    let enclave = master.derive_enclave_key(deployment_id, client_id)?;

    println!("K_log      {}", log.verifying_key().to_hex());
    println!("K_admin    {}", admin.verifying_key().to_hex());
    println!("K_enclave  {}", enclave.verifying_key().to_hex());
    Ok(())
}

fn derive(
    master: &MasterKey,
    deployment_id: &str,
    client_id: &str,
    bundle_id: Option<&str>,
    key_type: &str,
    reveal_secret: bool,
) -> Result<()> {
    match key_type {
        "log" => {
            let key = master.derive_log_signing_key(deployment_id, client_id)?;
            println!("K_log public   {}", key.verifying_key().to_hex());
        }
        "admin" => {
            let key = master.derive_admin_key(deployment_id, client_id)?;
            println!("K_admin public {}", key.verifying_key().to_hex());
        }
        "enclave" => {
            let key = master.derive_enclave_key(deployment_id, client_id)?;
            println!("K_enclave public {}", key.verifying_key().to_hex());
        }
        "session" => {
            if !reveal_secret {
                bail!(
                    "K_session is symmetric and has no public half. Pass --reveal-secret \
                     to print it, understanding that it will appear in your terminal \
                     scrollback."
                );
            }
            let key = master.derive_session_key(deployment_id, client_id)?;
            println!("K_session {}", hex::encode(key.as_bytes()));
        }
        "bundle" => {
            let Some(bundle_id) = bundle_id else {
                bail!("--bundle-id is required for bundle key derivation");
            };
            if !reveal_secret {
                bail!(
                    "K_bundle is symmetric and has no public half. Pass --reveal-secret \
                     to print it, understanding that anyone who sees it can decrypt \
                     bundle '{}'.",
                    bundle_id
                );
            }
            let key = master.derive_bundle_key(bundle_id, client_id)?;
            println!("K_bundle {}", hex::encode(key.as_bytes()));
        }
        other => bail!(
            "unknown key type '{}'. One of: log, admin, enclave, session, bundle",
            other
        ),
    }
    Ok(())
}

fn admin_sign(
    master: &MasterKey,
    deployment_id: &str,
    client_id: &str,
    action: &str,
    params: &str,
) -> Result<()> {
    let admin = master
        .derive_admin_key(deployment_id, client_id)
        .context("cannot derive the admin key")?;

    // This string must match `CordonNode::admin_canonical` exactly. A mismatch
    // produces a signature the node rejects, which is the safe failure, but it
    // is also a confusing one — so the signed message is printed for comparison.
    let canonical = format!("CORDON_ADMIN:{}:{}", action, params);
    let signature = admin.signing_key().sign(canonical.as_bytes());

    println!("signed message   {}", canonical);
    println!("admin_signature  {}", signature.to_hex());
    println!();
    println!("Request body:");
    println!(
        r#"  {{"admin_signature": "{}", "reason": "{}"}}"#,
        signature.to_hex(),
        params
    );
    println!();
    println!(
        "This signature authorizes '{}' with exactly these parameters.",
        action
    );
    println!("It cannot be reused for another action, or for different parameters.");

    Ok(())
}

/// Write a secret readable only by its owner.
fn write_secret(path: &Path, contents: &str) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;

    use std::io::Write;
    let result = file
        .write_all(contents.as_bytes())
        .and_then(|_| file.sync_all())
        .with_context(|| format!("cannot write {}", path.display()));

    if result.is_err() {
        // Never leave a partially written key behind.
        let _ = std::fs::remove_file(path);
    }
    result?;

    #[cfg(not(unix))]
    eprintln!(
        "note: {} inherits its directory's permissions on this platform. Confirm \
         only the intended account can read it.",
        path.display()
    );

    Ok(())
}
