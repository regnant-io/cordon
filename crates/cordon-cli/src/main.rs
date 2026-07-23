//! Cordon — Private Inference Engine v2.0
//!
//! Main server binary. Starts the Cordon node and API server.
//!
//! Usage:
//!   cordon serve [--config <path>] [--bind <addr>] [--mode <light|vault|...>]
//!   cordon status [--api <url>]
//!   cordon attest [--api <url>] [--nonce <nonce>]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::{EnvFilter, fmt};

use cordon_core::{
    config::CordonConfig,
    node::CordonNode,
};
use cordon_api::{
    server::ApiServer,
    tls::{TlsConfig, TlsMode},
};

#[derive(Parser)]
#[command(
    name = "cordon",
    about = "Cordon — Private Inference Engine v2.0",
    long_about = "Cordon provides hardware-enforced private AI inference.\n\
        All computation occurs inside a verified TEE. Weights are encrypted.\n\
        Zero egress. Client-held keys. Immutable audit log.",
    version = env!("CARGO_PKG_VERSION"),
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Cordon inference server
    Serve {
        /// Configuration file path
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,

        /// Bind address (overrides config)
        #[arg(short, long, default_value = "0.0.0.0:8443")]
        bind: String,

        /// Deployment mode (overrides config)
        #[arg(short, long)]
        mode: Option<String>,

        /// Node ID (generated if not specified)
        #[arg(long)]
        node_id: Option<String>,

        /// Deployment ID
        #[arg(long)]
        deployment_id: Option<String>,

        /// Data directory for audit logs, model store, etc.
        #[arg(short, long, default_value = "/var/lib/cordon")]
        data_dir: PathBuf,

        /// TLS certificate path
        #[arg(long)]
        tls_cert: Option<PathBuf>,

        /// TLS key path
        #[arg(long)]
        tls_key: Option<PathBuf>,

        /// Disable TLS (development only)
        #[arg(long)]
        no_tls: bool,
    },

    /// Check node status
    Status {
        /// API endpoint
        #[arg(short, long, default_value = "http://localhost:8443")]
        api: String,
    },

    /// Request and display attestation report
    Attest {
        /// API endpoint
        #[arg(short, long, default_value = "http://localhost:8443")]
        api: String,

        /// Anti-replay nonce (generated if not specified)
        #[arg(short, long)]
        nonce: Option<String>,
    },

    /// Print default configuration
    DefaultConfig {
        /// Deployment mode
        #[arg(short, long, default_value = "light")]
        mode: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve {
            config,
            bind,
            mode,
            node_id,
            deployment_id,
            data_dir,
            tls_cert,
            tls_key,
            no_tls,
        } => {
            serve(config, bind, mode, node_id, deployment_id, data_dir, tls_cert, tls_key, no_tls).await
        }

        Commands::Status { api } => {
            status(&api).await
        }

        Commands::Attest { api, nonce } => {
            attest(&api, nonce).await
        }

        Commands::DefaultConfig { mode } => {
            print_default_config(&mode)
        }
    }
}

async fn serve(
    config_path: Option<PathBuf>,
    bind: String,
    _mode_override: Option<String>,
    node_id: Option<String>,
    deployment_id: Option<String>,
    data_dir: PathBuf,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    no_tls: bool,
) -> Result<()> {
    // Load or build config
    let mut config = if let Some(path) = config_path {
        CordonConfig::from_file(&path).context("Failed to load config")?
    } else {
        let nid = node_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let did = deployment_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        CordonConfig::default_light(nid, did)
    };

    // Override data directories
    config.audit.log_path = data_dir.join("audit");
    config.model_store.path = data_dir.join("bundles");

    // Init logging
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.log_level));
    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .json()
        .init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        node_id = %config.node_id,
        deployment_id = %config.deployment_id,
        mode = %config.mode,
        "Cordon starting"
    );

    // Create data directories
    std::fs::create_dir_all(&config.audit.log_path)
        .context("Cannot create audit log directory")?;
    std::fs::create_dir_all(&config.model_store.path)
        .context("Cannot create model store directory")?;

    // Build node
    let node = Arc::new(CordonNode::build(config.clone())
        .context("Failed to build Cordon node")?);

    // Start background services
    node.start_background_services();

    // Mark operational
    node.go_operational().context("Failed to go operational")?;

    tracing::info!("Cordon node operational — TEE: {}", config.tee.preferred);

    // TLS configuration
    let tls_config = if no_tls {
        tracing::warn!("TLS disabled — NOT for production use");
        None
    } else {
        let cert = tls_cert.unwrap_or_else(|| data_dir.join("tls/server.crt"));
        let key = tls_key.unwrap_or_else(|| data_dir.join("tls/server.key"));
        Some(TlsConfig {
            cert_path: cert,
            key_path: key,
            client_ca_path: config.network.client_ca_path.clone(),
            mode: if config.network.require_mtls {
                TlsMode::Mutual
            } else {
                TlsMode::ServerOnly
            },
        })
    };

    // Start API server
    let addr: SocketAddr = bind.parse().context("Invalid bind address")?;
    let server = ApiServer::new(node, addr, tls_config);

    tracing::info!("Cordon API server ready on {}", addr);
    server.run().await.context("Server failed")?;

    Ok(())
}

async fn status(api_url: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/v1/health/detailed", api_url))
        .header("x-client-id", "cli-operator")
        .send()
        .await
        .context("Failed to connect to Cordon API")?;

    let _status = resp.status();
    let body: serde_json::Value = resp.json().await.context("Failed to parse response")?;

    println!("Cordon Node Status");
    println!("═══════════════════");
    println!("Overall:   {}", body["status"].as_str().unwrap_or("unknown"));
    println!("Enclave:   {}", body["enclave"]["status"].as_str().unwrap_or("unknown"));
    println!("TEE type:  {}", body["enclave"]["tee_type"].as_str().unwrap_or("unknown"));
    println!("MRENCLAVE: {}", body["enclave"]["mrenclave"].as_str().unwrap_or("unknown"));
    println!("Runtime:   {}", body["inference"]["runtime"].as_str().unwrap_or("unknown"));
    println!("Active:    {} requests", body["inference"]["active_requests"].as_u64().unwrap_or(0));
    println!("Attested:  {}", body["enclave"]["attestation_valid"].as_bool().unwrap_or(false));
    println!("Integrity: {}", body["integrity"]["weight_check_result"].as_str().unwrap_or("unknown"));
    println!("Audit:     {} entries", body["audit"]["entries_total"].as_u64().unwrap_or(0));
    println!("Uptime:    {}s", body["uptime_seconds"].as_u64().unwrap_or(0));

    if body["integrity"]["tamper_detected"].as_bool().unwrap_or(false) {
        println!("\n⚠️  TAMPER DETECTED — operator recovery required");
    }

    Ok(())
}

async fn attest(api_url: &str, nonce: Option<String>) -> Result<()> {
    let nonce = nonce.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    println!("Requesting attestation with nonce: {}", nonce);

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/attestation/verify", api_url))
        .header("x-client-id", "cli-operator")
        .json(&serde_json::json!({ "nonce": nonce }))
        .send()
        .await
        .context("Failed to connect")?;

    let body: serde_json::Value = resp.json().await.context("Failed to parse")?;
    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
}

fn print_default_config(mode: &str) -> Result<()> {
    let config = match mode {
        "light" | "Light" => CordonConfig::default_light(
            "node-example-id".to_string(),
            "deployment-example-id".to_string(),
        ),
        _ => {
            eprintln!("Unknown mode: {}. Supported: light", mode);
            std::process::exit(1);
        }
    };

    let toml_str = toml::to_string_pretty(&config)
        .context("Failed to serialize config")?;
    println!("# Cordon v2.0 Configuration\n# Generated default for mode: {}\n", mode);
    println!("{}", toml_str);
    Ok(())
}
