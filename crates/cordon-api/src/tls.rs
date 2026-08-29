//! TLS configuration and development certificate generation.

use anyhow::{Context, Result};
use std::path::Path;

/// Whether client certificates are required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// Server authentication only. The server proves who it is; the client does
    /// not. Light mode only — without a client certificate, identity comes from
    /// a header and any caller can claim any client ID.
    ServerOnly,
    /// Mutual authentication. The client must present a certificate the
    /// configured CA issued, and that certificate determines its identity.
    Mutual,
}

/// TLS material and mode.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Server certificate chain, PEM.
    pub cert_path: std::path::PathBuf,
    /// Server private key, PEM.
    pub key_path: std::path::PathBuf,
    /// Client CA certificate, PEM. Required for mutual TLS.
    pub client_ca_path: Option<std::path::PathBuf>,
    /// Whether client certificates are required.
    pub mode: TlsMode,
}

/// Generate a self-signed certificate for local development.
///
/// The private key is written with owner-only permissions. A world-readable key
/// beside a service that exists to protect a trust boundary is worth refusing
/// outright, so a failure to restrict it removes the file rather than leaving it
/// readable.
pub fn generate_self_signed_cert(common_name: &str, cert_out: &Path, key_out: &Path) -> Result<()> {
    use rcgen::{CertificateParams, DistinguishedName, DnType};

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn.push(DnType::OrganizationName, "Cordon Development");
    params.distinguished_name = dn;
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("localhost".to_string()),
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        rcgen::SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
    ];

    let cert = rcgen::Certificate::from_params(params).context("cannot generate a certificate")?;

    if let Some(parent) = cert_out.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    if let Some(parent) = key_out.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }

    std::fs::write(
        cert_out,
        cert.serialize_pem().context("serialising certificate")?,
    )
    .with_context(|| format!("cannot write {}", cert_out.display()))?;

    write_private_key(key_out, &cert.serialize_private_key_pem())?;

    tracing::warn!(
        cert = %cert_out.display(),
        "Generated a self-signed development certificate. Clients cannot verify it \
         against any CA; provision a real certificate before deploying."
    );
    Ok(())
}

/// Write a private key readable only by its owner.
fn write_private_key(path: &Path, pem: &str) -> Result<()> {
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
    let write_result = file
        .write_all(pem.as_bytes())
        .and_then(|_| file.sync_all())
        .with_context(|| format!("cannot write {}", path.display()));

    if write_result.is_err() {
        // Never leave a partially written key behind.
        let _ = std::fs::remove_file(path);
    }
    write_result?;

    #[cfg(not(unix))]
    tracing::debug!(
        path = %path.display(),
        "Private key permissions follow the parent directory ACL on this platform"
    );

    Ok(())
}

/// Ensure TLS material exists, generating a development certificate if not.
pub fn ensure_tls_certs(config: &TlsConfig) -> Result<()> {
    if config.cert_path.exists() && config.key_path.exists() {
        return Ok(());
    }
    tracing::warn!(
        cert = %config.cert_path.display(),
        "No TLS certificate found; generating a self-signed one"
    );
    generate_self_signed_cert("cordon-node", &config.cert_path, &config.key_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_usable_certificate_pair() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("tls/server.crt");
        let key = dir.path().join("tls/server.key");

        generate_self_signed_cert("test-node", &cert, &key).unwrap();

        assert!(cert.exists() && key.exists());
        let cert_pem = std::fs::read_to_string(&cert).unwrap();
        let key_pem = std::fs::read_to_string(&key).unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("PRIVATE KEY"));
    }

    #[cfg(unix)]
    #[test]
    fn the_private_key_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("server.crt");
        let key = dir.path().join("server.key");

        generate_self_signed_cert("test-node", &cert, &key).unwrap();

        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "private key mode was {:o}", mode);
    }

    #[test]
    fn existing_material_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("server.crt");
        let key = dir.path().join("server.key");
        std::fs::write(&cert, "sentinel-cert").unwrap();
        std::fs::write(&key, "sentinel-key").unwrap();

        ensure_tls_certs(&TlsConfig {
            cert_path: cert.clone(),
            key_path: key.clone(),
            client_ca_path: None,
            mode: TlsMode::ServerOnly,
        })
        .unwrap();

        assert_eq!(std::fs::read_to_string(&cert).unwrap(), "sentinel-cert");
        assert_eq!(std::fs::read_to_string(&key).unwrap(), "sentinel-key");
    }
}
