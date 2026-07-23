//! TLS and mTLS configuration for the Cordon API server
//!
//! Enforces TLS 1.3 only. In production, client certificates are required
//! and verified against the client CA. Vendor CA is never in the trust store.

use std::path::Path;
use anyhow::{Context, Result};

/// TLS mode for the server
#[derive(Debug, Clone)]
pub enum TlsMode {
    /// TLS only (no client cert required — Light mode only)
    ServerOnly,
    /// Mutual TLS (client certificate required)
    Mutual,
}

/// TLS configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Path to server certificate (PEM)
    pub cert_path: std::path::PathBuf,
    /// Path to server private key (PEM)
    pub key_path: std::path::PathBuf,
    /// Path to client CA certificate (PEM) — required for mTLS
    pub client_ca_path: Option<std::path::PathBuf>,
    /// TLS mode
    pub mode: TlsMode,
}

/// Generate a self-signed certificate for development/testing
///
/// In production, certificates are provisioned via HSM and client-enrolled
/// Secure Boot keys; vendor CA is never trusted.
pub fn generate_self_signed_cert(
    common_name: &str,
    cert_out: &Path,
    key_out: &Path,
) -> Result<()> {
    use rcgen::{CertificateParams, DistinguishedName, DnType};

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("localhost".to_string()),
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
    ];

    let cert = rcgen::Certificate::from_params(params)
        .context("Failed to generate certificate")?;

    let cert_pem = cert.serialize_pem()
        .context("Failed to serialize certificate")?;
    let key_pem = cert.serialize_private_key_pem();

    std::fs::create_dir_all(cert_out.parent().unwrap_or(Path::new(".")))
        .context("Cannot create cert directory")?;
    std::fs::write(cert_out, cert_pem)
        .context("Cannot write certificate")?;
    std::fs::write(key_out, key_pem)
        .context("Cannot write private key")?;

    tracing::info!("Generated self-signed cert: {:?}", cert_out);
    Ok(())
}

/// Ensure TLS certificates exist, generating self-signed ones if needed (dev only)
pub fn ensure_tls_certs(config: &TlsConfig) -> Result<()> {
    if !config.cert_path.exists() || !config.key_path.exists() {
        tracing::warn!(
            "TLS certificates not found at {:?} — generating self-signed (NOT for production)",
            config.cert_path
        );
        generate_self_signed_cert("cordon-server", &config.cert_path, &config.key_path)?;
    }
    Ok(())
}
