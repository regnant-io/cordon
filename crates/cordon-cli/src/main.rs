//! `cordon` — the node server and operator command line.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::{fmt, EnvFilter};

use cordon_api::{
    server::ApiServer,
    tls::{TlsConfig, TlsMode},
};
use cordon_core::{
    config::{CordonConfig, DeploymentMode, RuntimeBackend},
    hub,
    node::CordonNode,
    runtime::discover_llama_server,
};

mod doctor;
mod pull;

#[derive(Parser)]
#[command(
    name = "cordon",
    version = env!("CARGO_PKG_VERSION"),
    about = "Cordon — a confidential inference control plane",
    long_about = "Cordon fronts a local model runtime with identity, policy, rate limiting,\n\
                  output filtering, tamper-evident auditing, and signed responses.\n\n\
                  Getting started:\n  \
                    cordon doctor                       check this machine\n  \
                    cordon pull <owner/repo>            fetch a GGUF model\n  \
                    cordon run <model>                  serve it"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fetch a model from the Hugging Face Hub.
    ///
    /// Accepts `owner/repo`, `owner/repo:Q4_K_M` to pick a quantisation, and
    /// `owner/repo@revision` to pin a commit. Downloads resume if interrupted,
    /// and the content digest the Hub publishes is verified before the file is
    /// admitted.
    Pull {
        /// Model reference, e.g. `HuggingFaceTB/SmolLM2-360M-Instruct-GGUF:Q4_K_M`.
        model: String,
        /// Directory to store models in.
        #[arg(long, default_value = "./data/models")]
        model_dir: PathBuf,
    },

    /// Serve a model that has already been pulled.
    ///
    /// A shorthand for `serve` with the supervised runtime pointed at a local
    /// model. Development defaults: no TLS, loopback, console enabled.
    Run {
        /// Model ID from `cordon models`, or a path to a GGUF file.
        model: String,
        /// Address to bind the API to.
        #[arg(long, default_value = "127.0.0.1:8477")]
        bind: String,
        /// Directory holding pulled models.
        #[arg(long, default_value = "./data/models")]
        model_dir: PathBuf,
        /// Directory for audit logs and bundles.
        #[arg(long, default_value = "./data")]
        data_dir: PathBuf,
        /// Layers to offload to the GPU.
        #[arg(long, default_value_t = 0)]
        gpu_layers: u32,
        /// Context window size.
        #[arg(long, default_value_t = 4096)]
        ctx_size: u32,
        /// Do not start the operator console.
        #[arg(long)]
        no_ui: bool,
        /// Console port.
        #[arg(long, default_value_t = 8478)]
        ui_port: u16,
    },

    /// List models available locally.
    Models {
        /// Directory holding pulled models.
        #[arg(long, default_value = "./data/models")]
        model_dir: PathBuf,
    },

    /// Remove a local model.
    Remove {
        /// Model ID from `cordon models`.
        model: String,
        /// Directory holding pulled models.
        #[arg(long, default_value = "./data/models")]
        model_dir: PathBuf,
    },

    /// Start a node from a configuration file.
    Serve {
        /// Configuration file.
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,
        /// Address to bind the API to.
        #[arg(short, long, default_value = "0.0.0.0:8443")]
        bind: String,
        /// Node ID. Generated if absent.
        #[arg(long)]
        node_id: Option<String>,
        /// Deployment ID. Feeds every derived key, so it must be stable.
        #[arg(long)]
        deployment_id: Option<String>,
        /// Directory for audit logs and bundles.
        #[arg(short, long, default_value = "/var/lib/cordon")]
        data_dir: PathBuf,
        /// TLS certificate.
        #[arg(long)]
        tls_cert: Option<PathBuf>,
        /// TLS private key.
        #[arg(long)]
        tls_key: Option<PathBuf>,
        /// Disable TLS. Development only; refused outside Light mode.
        #[arg(long)]
        no_tls: bool,
    },

    /// Check that this machine can run Cordon.
    Doctor {
        /// Configuration file to check, if any.
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,
        /// Directory holding pulled models.
        #[arg(long, default_value = "./data/models")]
        model_dir: PathBuf,
    },

    /// Query a running node's status.
    Status {
        /// API endpoint.
        #[arg(short, long, default_value = "http://127.0.0.1:8477")]
        api: String,
        /// Client ID sent on a plaintext development listener.
        #[arg(long, default_value = "cli-operator")]
        client_id: String,
    },

    /// Request and verify an attestation report.
    Attest {
        /// API endpoint.
        #[arg(short, long, default_value = "http://127.0.0.1:8477")]
        api: String,
        /// Client ID sent on a plaintext development listener.
        #[arg(long, default_value = "cli-operator")]
        client_id: String,
        /// Print the node's current measurements as a `[attestation.expected]`
        /// block, ready to paste into a configuration file.
        #[arg(long)]
        pin: bool,
    },

    /// Print a default configuration for a deployment mode.
    DefaultConfig {
        /// One of: light, island, vault, sovereign_cloud, dark.
        #[arg(short, long, default_value = "light")]
        mode: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Pull { model, model_dir } => pull::pull(&model, &model_dir).await,
        Command::Models { model_dir } => pull::list(&model_dir),
        Command::Remove { model, model_dir } => pull::remove(&model, &model_dir),
        Command::Doctor { config, model_dir } => doctor::run(config.as_deref(), &model_dir).await,
        Command::Status { api, client_id } => status(&api, &client_id).await,
        Command::Attest {
            api,
            client_id,
            pin,
        } => attest(&api, &client_id, pin).await,
        Command::DefaultConfig { mode } => print_default_config(&mode),

        Command::Run {
            model,
            bind,
            model_dir,
            data_dir,
            gpu_layers,
            ctx_size,
            no_ui,
            ui_port,
        } => {
            let config = build_run_config(
                &model, &model_dir, &data_dir, gpu_layers, ctx_size, !no_ui, ui_port,
            )?;
            init_logging(&config.log_level, false);
            serve_with(config, &bind, None).await
        }

        Command::Serve {
            config,
            bind,
            node_id,
            deployment_id,
            data_dir,
            tls_cert,
            tls_key,
            no_tls,
        } => {
            let mut cfg = match &config {
                Some(path) => CordonConfig::from_file(path)
                    .with_context(|| format!("cannot load {}", path.display()))?,
                None => CordonConfig::default_light(
                    node_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                    deployment_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                ),
            };
            cfg.audit.log_path = data_dir.join("audit");
            cfg.model_store.path = data_dir.join("bundles");

            init_logging(&cfg.log_level, true);

            if no_tls && cfg.mode != DeploymentMode::Light {
                bail!(
                    "--no-tls is refused in {} mode. Client identity would come from a \
                     header any caller can set, which defeats every guarantee this mode \
                     claims.",
                    cfg.mode
                );
            }

            let tls = if no_tls {
                None
            } else {
                Some(TlsConfig {
                    cert_path: tls_cert.unwrap_or_else(|| data_dir.join("tls/server.crt")),
                    key_path: tls_key.unwrap_or_else(|| data_dir.join("tls/server.key")),
                    client_ca_path: cfg.network.client_ca_path.clone(),
                    mode: if cfg.network.require_mtls {
                        TlsMode::Mutual
                    } else {
                        TlsMode::ServerOnly
                    },
                })
            };

            serve_with(cfg, &bind, tls).await
        }
    }
}

/// Build the configuration `cordon run` uses: Light mode, supervised runtime,
/// loopback console.
fn build_run_config(
    model: &str,
    model_dir: &std::path::Path,
    data_dir: &std::path::Path,
    gpu_layers: u32,
    ctx_size: u32,
    ui: bool,
    ui_port: u16,
) -> Result<CordonConfig> {
    // A path to an existing file wins; otherwise the argument names a pulled
    // model.
    let model_path = if std::path::Path::new(model).is_file() {
        PathBuf::from(model)
    } else {
        match hub::find_local_model(model_dir, model)? {
            Some(found) => found.path,
            None => {
                let available = hub::list_local_models(model_dir)?;
                if available.is_empty() {
                    bail!(
                        "no model named '{}', and no models have been pulled yet.\n\
                         Fetch one first:\n\n    \
                         cordon pull HuggingFaceTB/SmolLM2-360M-Instruct-GGUF\n",
                        model
                    );
                }
                bail!(
                    "no model named '{}'. Available:\n{}",
                    model,
                    available
                        .iter()
                        .map(|m| format!("    {}", m.id))
                        .collect::<Vec<_>>()
                        .join("\n")
                );
            }
        }
    };

    if discover_llama_server(None).is_none() {
        bail!(
            "no llama-server binary found on this machine.\n\n\
             Cordon supervises llama.cpp so the runtime is bound to loopback with its \
             own web UI unreachable. Install llama.cpp, then set CORDON_LLAMA_SERVER \
             or add it to PATH.\n\n\
             Run `cordon doctor` for a full check."
        );
    }

    let mut config = CordonConfig::default_light(
        format!("cordon-{}", uuid::Uuid::new_v4().simple()),
        // A stable deployment ID keeps derived keys and the audit chain
        // consistent across restarts of the same data directory.
        stable_deployment_id(data_dir)?,
    );

    config.audit.log_path = data_dir.join("audit");
    config.model_store.path = data_dir.join("bundles");
    config.runtime.backend = RuntimeBackend::Supervised;
    config.runtime.model_path = Some(model_path);
    config.runtime.model_dir = model_dir.to_path_buf();
    config.runtime.gpu_layers = gpu_layers;
    config.runtime.context_size = ctx_size;
    config.ui.enabled = ui;
    config.ui.port = ui_port;

    config.validate()?;
    Ok(config)
}

/// Read, or create, a deployment ID stored alongside the data directory.
fn stable_deployment_id(data_dir: &std::path::Path) -> Result<String> {
    let path = data_dir.join("deployment-id");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("cannot create {}", data_dir.display()))?;
    let id = uuid::Uuid::new_v4().to_string();
    std::fs::write(&path, &id).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(id)
}

/// Build the node, start it, and serve until interrupted.
async fn serve_with(config: CordonConfig, bind: &str, tls: Option<TlsConfig>) -> Result<()> {
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        node_id = %config.node_id,
        mode = %config.mode,
        "Cordon starting"
    );

    std::fs::create_dir_all(&config.audit.log_path)
        .context("cannot create the audit log directory")?;
    std::fs::create_dir_all(&config.model_store.path)
        .context("cannot create the model store directory")?;

    let addr: SocketAddr = bind.parse().context("invalid bind address")?;
    let ui_enabled = config.ui.enabled;
    let ui_port = config.ui.port;

    // Building the node starts the model runtime, which can take a while for a
    // large model on a cold cache.
    let node = Arc::new(
        CordonNode::build(config)
            .await
            .context("cannot start the node")?,
    );

    node.start_background_services();
    node.go_operational().context("cannot go operational")?;

    println!();
    println!("  Cordon is serving on http://{}", addr);
    if ui_enabled {
        println!("  Operator console at http://127.0.0.1:{}", ui_port);
    }
    println!("  Runtime: {}", node.inference.backend_name());
    println!("  Keys:    {}", node.key_provenance().as_str());
    println!();
    println!("  Press Ctrl-C to stop.");
    println!();

    ApiServer::new(node, addr, tls).run(shutdown_signal()).await
}

/// Resolve when the process is asked to stop.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("Shutdown signal received");
}

/// Initialise logging. `structured` selects JSON output for a service manager;
/// interactive commands get human-readable lines.
fn init_logging(default_level: &str, structured: bool) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    if structured {
        fmt()
            .with_env_filter(filter)
            .with_target(true)
            .json()
            .init();
    } else {
        fmt()
            .with_env_filter(filter)
            .with_target(false)
            .compact()
            .init();
    }
}

async fn status(api: &str, client_id: &str) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let response = client
        .get(format!("{}/v1/health/detailed", api.trim_end_matches('/')))
        .header("x-client-id", client_id)
        .send()
        .await
        .with_context(|| format!("cannot reach a Cordon node at {}", api))?;

    if !response.status().is_success() {
        bail!("the node returned HTTP {}", response.status());
    }
    let body: serde_json::Value = response.json().await.context("malformed response")?;

    let get = |path: &str| -> String {
        body.pointer(path)
            .map(|v| match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .unwrap_or_else(|| "—".into())
    };

    println!("Cordon node");
    println!("  Status        {}", get("/status"));
    println!("  Runtime       {}", get("/inference/runtime"));
    println!(
        "  In flight     {} / {}",
        get("/inference/active_requests"),
        get("/inference/max_concurrent")
    );
    println!("  Measurements  {}", get("/enclave/measurement_source"));
    println!("  Key material  {}", get("/enclave/key_provenance"));
    println!("  Audit entries {}", get("/audit/entries_total"));
    println!("  Chain         {}", get("/audit/chain_valid"));
    println!(
        "  Clients       {} enrolled",
        get("/security/enrolled_clients")
    );

    if body.pointer("/integrity/tamper_detected") == Some(&serde_json::Value::Bool(true)) {
        println!();
        println!("  TAMPER DETECTED — operator recovery required");
    }
    Ok(())
}

async fn attest(api: &str, client_id: &str, pin: bool) -> Result<()> {
    let nonce = uuid::Uuid::new_v4().to_string();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let response = client
        .post(format!(
            "{}/v1/attestation/verify",
            api.trim_end_matches('/')
        ))
        .header("x-client-id", client_id)
        .json(&serde_json::json!({ "nonce": nonce }))
        .send()
        .await
        .with_context(|| format!("cannot reach a Cordon node at {}", api))?;

    let body: serde_json::Value = response.json().await.context("malformed response")?;

    if pin {
        return print_pin_block(&body);
    }

    let verified = body["verified"].as_bool().unwrap_or(false);
    println!("Attestation");
    println!("  Verified      {}", verified);
    println!(
        "  Source        {}",
        body["measurement_source"].as_str().unwrap_or("—")
    );
    println!(
        "  Measurement   {}",
        body["mrenclave"].as_str().unwrap_or("—")
    );
    if let Some(reason) = body["reason"].as_str() {
        println!("  Reason        {}", reason);
        println!();
        println!("  If this node has no pinned measurements, capture them with:");
        println!("      cordon attest --pin >> /etc/cordon/cordon.toml");
    }
    Ok(())
}

/// Render the node's current measurements as a configuration block.
///
/// Pinning is what makes verification mean anything, so the workflow is: read
/// the values off a node you trust, review them, and commit them to config.
fn print_pin_block(body: &serde_json::Value) -> Result<()> {
    let report = body
        .get("report")
        .context("the node returned no report to pin; it may already be verified")?;

    let pcrs = report
        .pointer("/combined/tpm_quote/pcr_values/values")
        .and_then(|v| v.as_object())
        .context("the report contains no PCR values")?;

    println!("# Measurements read from the node. Review them before committing:");
    println!("# these values are what the node will be checked against from now on.");
    println!("[attestation.expected]");
    println!(
        "mrenclave = \"{}\"",
        report
            .pointer("/combined/tee_quote/mrenclave")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
    );
    println!(
        "mrsigner = \"{}\"",
        report
            .pointer("/combined/tee_quote/mrsigner")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
    );
    println!("min_isv_svn = 0");
    println!();
    println!("[attestation.expected.pcr_values]");

    let mut indices: Vec<i64> = pcrs.keys().filter_map(|k| k.parse().ok()).collect();
    indices.sort_unstable();
    for index in indices {
        if let Some(value) = pcrs.get(&index.to_string()).and_then(|v| v.as_str()) {
            println!("{} = \"{}\"", index, value);
        }
    }
    Ok(())
}

fn print_default_config(mode: &str) -> Result<()> {
    let node_id = "REPLACE_ME_node_id".to_string();
    let deployment_id = "REPLACE_ME_deployment_id".to_string();

    let mut config = CordonConfig::default_light(node_id, deployment_id);
    let mode = match mode.to_lowercase().as_str() {
        "light" => DeploymentMode::Light,
        "island" => DeploymentMode::Island,
        "vault" => DeploymentMode::Vault,
        "sovereign_cloud" | "sovereign-cloud" => DeploymentMode::SovereignCloud,
        "dark" => DeploymentMode::Dark,
        other => bail!(
            "unknown mode '{}'. One of: light, island, vault, sovereign_cloud, dark",
            other
        ),
    };

    // A generated file should describe the deployment people actually want, so
    // the supervised runtime is the default in every mode. `backend = "none"`
    // stays available in Light mode for exercising the control plane without a
    // model, but it is opt-in rather than the shape of the template.
    config.runtime.backend = RuntimeBackend::Supervised;
    config.runtime.model_path = Some(PathBuf::from("REPLACE_ME_path_to_model.gguf"));

    if mode != DeploymentMode::Light {
        // Hardened defaults, so the printed file is a starting point that
        // reflects what the mode requires rather than one that will be refused.
        config.mode = mode.clone();
        config.tee.preferred = cordon_core::config::TeePreference::AmdSevSnp;
        config.attestation.measurement_source = cordon_core::MeasurementSource::Tpm2;
        config.attestation.halt_until_verified = true;
        config.boot.tpm_required = true;
        config.boot.secure_boot = true;
        config.boot.dm_verity = true;
        config.network.require_mtls = true;
        config.network.client_ca_path = Some(PathBuf::from("/etc/cordon/tls/client-ca.crt"));
        config.runtime.backend = RuntimeBackend::Supervised;
        config.ui.enabled = false;
        config.inference.multi_tenant = mode != DeploymentMode::Dark;
        config.hsm.fips_level = if mode == DeploymentMode::Dark { 4 } else { 3 };
        config.client_registry_path = Some(PathBuf::from("/etc/cordon/clients.json"));
    }

    println!("# Cordon configuration — {} mode", mode);
    println!("# Generated by cordon {}", env!("CARGO_PKG_VERSION"));
    println!("#");
    println!("# Replace every REPLACE_ME value before use. node_id names this node;");
    println!("# deployment_id feeds every derived key and must stay stable across");
    println!("# restarts and match what cordon-keygen was run with.");
    if mode == DeploymentMode::Light {
        println!("#");
        println!("# To exercise the control plane without a model, set");
        println!("# runtime.backend = \"none\". Responses are then clearly-labelled");
        println!("# placeholders rather than generated text.");
    }
    println!();
    println!("{}", toml::to_string_pretty(&config)?);

    if mode != DeploymentMode::Light {
        // `toml` cannot emit comments, so the block a hardened mode requires is
        // appended here. Printing it commented out — rather than omitting it —
        // means the operator sees exactly what is missing and where it goes,
        // instead of discovering it from a startup refusal.
        println!();
        println!("# ── Required before this node will start ───────────────────────────");
        println!("#");
        println!(
            "# {} mode refuses to boot without pinned expected measurements: with",
            mode
        );
        println!("# nothing to check against, attestation verification would accept any");
        println!("# report, including one from an impostor.");
        println!("#");
        println!("# Start the node once on trusted hardware, read its measurements, review");
        println!("# them, and paste the result here:");
        println!("#");
        println!("#     cordon attest --pin --api https://127.0.0.1:8443");
        println!("#");
        println!("# [attestation.expected]");
        println!("# mrenclave   = \"<64 hex characters>\"");
        println!("# mrsigner    = \"<64 hex characters>\"");
        println!("# min_isv_svn = 0");
        println!("#");
        println!("# [attestation.expected.pcr_values]");
        println!("# 0  = \"sha256:...\"   # UEFI firmware");
        println!("# 4  = \"sha256:...\"   # bootloader");
        println!("# 7  = \"sha256:...\"   # secure boot state");
        println!("# 11 = \"sha256:...\"   # Cordon runtime");
    }
    Ok(())
}
