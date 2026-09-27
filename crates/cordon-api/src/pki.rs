//! A private certificate authority for mutual TLS.
//!
//! Exposing a node beyond its own machine is only defensible when every
//! caller proves who it is with a certificate, and that needs a CA. Running
//! `openssl` by hand is where most deployments go wrong, so this module does
//! the whole job: it creates a CA, keeps a server certificate current for the
//! names the node is reached by, and issues one client certificate per caller.
//!
//! Everything is ECDSA P-256, which rustls and every mainstream client accept.
//! The CA key is the one secret here: whoever holds it can mint a certificate
//! for any client ID, so it stays in the directory this module owns and is
//! never exported. A client's identity is its certificate's subject CN, which
//! is what [`parse_client_identity_from_cert`] reads on the other side.
//!
//! [`parse_client_identity_from_cert`]: cordon_core::identity::parse_client_identity_from_cert

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::Engine;
use chrono::{Datelike, Duration, Utc};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// How long the CA is valid.
const CA_DAYS: i64 = 3650;
/// How long a server certificate is valid. Renewed well before it lapses.
const SERVER_DAYS: i64 = 397;
/// A server certificate with less than this left is renewed.
const RENEW_WITHIN_DAYS: i64 = 30;

/// The CA's subject, fixed so the CA can be rebuilt from its key for signing.
const CA_COMMON_NAME: &str = "Cordon private CA";
const ORGANIZATION: &str = "Cordon";

/// Client IDs a certificate may not claim: the console's own identity, and
/// names that read as something they are not.
const RESERVED_CLIENT_IDS: &[&str] = &["console", "anonymous", "operator-console"];

/// A certificate issued to a client, with everything that client needs.
#[derive(Debug, Clone, Serialize)]
pub struct IssuedClient {
    /// The client ID, which is the certificate's CN.
    pub client_id: String,
    /// The client certificate, PEM.
    pub cert_pem: String,
    /// The client's private key, PEM. Shown once; not kept here.
    pub key_pem: String,
    /// The CA certificate the client should trust the server with, PEM.
    pub ca_pem: String,
    /// SHA-256 of the certificate DER, lowercase hex, as the node pins it.
    pub fingerprint: String,
    /// Serial number, lowercase hex.
    pub serial: String,
    /// When the certificate stops being valid.
    pub not_after: chrono::DateTime<Utc>,
}

/// What the current server certificate covers.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ServerCertInfo {
    /// DNS names and IP addresses in the certificate.
    pub names: Vec<String>,
    /// When it stops being valid.
    pub not_after: Option<chrono::DateTime<Utc>>,
    /// SHA-256 of the certificate DER, lowercase hex.
    pub fingerprint: String,
}

/// A certificate authority kept in one directory.
#[derive(Debug, Clone)]
pub struct Pki {
    dir: PathBuf,
}

impl Pki {
    /// A CA rooted at `dir`. Nothing is created until it is needed.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The CA certificate, PEM. Clients trust the server with it.
    pub fn ca_cert_path(&self) -> PathBuf {
        self.dir.join("ca.crt")
    }

    fn ca_key_path(&self) -> PathBuf {
        self.dir.join("ca.key")
    }

    /// The server certificate, PEM.
    pub fn server_cert_path(&self) -> PathBuf {
        self.dir.join("server.crt")
    }

    /// The server private key, PEM.
    pub fn server_key_path(&self) -> PathBuf {
        self.dir.join("server.key")
    }

    fn server_info_path(&self) -> PathBuf {
        self.dir.join("server.json")
    }

    /// Whether a CA exists here.
    pub fn has_ca(&self) -> bool {
        self.ca_cert_path().is_file() && self.ca_key_path().is_file()
    }

    /// Create the CA if there is none. Returns whether one was created.
    pub fn ensure_ca(&self) -> Result<bool> {
        if self.has_ca() {
            return Ok(false);
        }
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("cannot create {}", self.dir.display()))?;

        let mut params = ca_params(KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)?);
        set_validity(&mut params, -1, CA_DAYS);
        params.serial_number = Some(random_serial());
        let ca = Certificate::from_params(params).context("cannot create the CA")?;

        write_private(&self.ca_key_path(), &ca.serialize_private_key_pem())?;
        write_public(
            &self.ca_cert_path(),
            &ca.serialize_pem().context("cannot encode the CA")?,
        )?;
        tracing::info!(dir = %self.dir.display(), "Created a private certificate authority");
        Ok(true)
    }

    /// The CA, rebuilt from its key for signing.
    ///
    /// Issuer name and key identifier both follow from the fixed subject and
    /// the key, so certificates it signs chain to the `ca.crt` on disk.
    fn signer(&self) -> Result<Certificate> {
        let pem = std::fs::read_to_string(self.ca_key_path())
            .context("the certificate authority has no key; create it first")?;
        let key = KeyPair::from_pem(&pem).context("the CA key is unreadable")?;
        Certificate::from_params(ca_params(key)).context("cannot load the CA")
    }

    /// The server certificate's current coverage, if one exists.
    pub fn server_info(&self) -> Option<ServerCertInfo> {
        let text = std::fs::read_to_string(self.server_info_path()).ok()?;
        let info: ServerCertInfo = serde_json::from_str(&text).ok()?;
        (self.server_cert_path().is_file() && self.server_key_path().is_file()).then_some(info)
    }

    /// Make sure a server certificate exists that covers `names` and is not
    /// about to expire, issuing a new one otherwise. Returns whether it did.
    pub fn ensure_server(&self, names: &[String]) -> Result<bool> {
        self.ensure_ca()?;
        let mut wanted: Vec<String> = names
            .iter()
            .map(|n| n.trim().to_ascii_lowercase())
            .filter(|n| !n.is_empty())
            .collect();
        wanted.sort();
        wanted.dedup();
        if wanted.is_empty() {
            bail!("a server certificate needs at least one name");
        }

        if let Some(current) = self.server_info() {
            let fresh = current
                .not_after
                .is_some_and(|t| t - Utc::now() > Duration::days(RENEW_WITHIN_DAYS));
            if fresh && current.names == wanted {
                return Ok(false);
            }
        }

        let ca = self.signer()?;
        let mut params = CertificateParams::default();
        params.distinguished_name = dn(wanted.first().map(String::as_str).unwrap_or("cordon"));
        params.subject_alt_names = wanted.iter().map(|n| san(n)).collect::<Result<_>>()?;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.serial_number = Some(random_serial());
        set_validity(&mut params, -1, SERVER_DAYS);
        let cert = Certificate::from_params(params).context("cannot create the server key")?;
        let der = cert
            .serialize_der_with_signer(&ca)
            .context("cannot sign the server certificate")?;

        write_private(&self.server_key_path(), &cert.serialize_private_key_pem())?;
        write_public(&self.server_cert_path(), &pem_encode("CERTIFICATE", &der))?;
        let info = ServerCertInfo {
            names: wanted,
            not_after: Some(Utc::now() + Duration::days(SERVER_DAYS)),
            fingerprint: hex::encode(Sha256::digest(&der)),
        };
        write_public(
            &self.server_info_path(),
            &serde_json::to_string_pretty(&info)?,
        )?;
        tracing::info!(names = ?info.names, "Issued a server certificate");
        Ok(true)
    }

    /// Issue a client certificate whose CN is `client_id`, valid for `days`.
    ///
    /// The private key is returned and not kept: handing it over is the only
    /// time it exists outside the client.
    pub fn issue_client(&self, client_id: &str, days: u32) -> Result<IssuedClient> {
        let client_id = validate_client_id(client_id)?;
        if !(1..=3650).contains(&days) {
            bail!("a client certificate must be valid for 1 to 3,650 days");
        }
        self.ensure_ca()?;
        let ca = self.signer()?;

        let serial = random_serial();
        let serial_hex = hex::encode(serial.to_bytes());
        let mut params = CertificateParams::default();
        params.distinguished_name = dn(&client_id);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.use_authority_key_identifier_extension = true;
        params.serial_number = Some(serial);
        set_validity(&mut params, -1, days as i64);
        let cert = Certificate::from_params(params).context("cannot create the client key")?;
        let der = cert
            .serialize_der_with_signer(&ca)
            .context("cannot sign the client certificate")?;

        Ok(IssuedClient {
            fingerprint: hex::encode(Sha256::digest(&der)),
            cert_pem: pem_encode("CERTIFICATE", &der),
            key_pem: cert.serialize_private_key_pem(),
            ca_pem: std::fs::read_to_string(self.ca_cert_path())?,
            serial: serial_hex,
            not_after: Utc::now() + Duration::days(days as i64),
            client_id,
        })
    }
}

/// Check a client ID is something a certificate CN and a registry entry can
/// both carry without surprises.
pub fn validate_client_id(raw: &str) -> Result<String> {
    let id = raw.trim();
    if id.is_empty() || id.len() > 64 {
        bail!("a client name must be 1 to 64 characters");
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'))
    {
        bail!("a client name may contain only letters, digits, '-', '_', '.' and '@'");
    }
    if RESERVED_CLIENT_IDS
        .iter()
        .any(|r| r.eq_ignore_ascii_case(id))
    {
        bail!("'{}' is reserved; choose another name", id);
    }
    Ok(id.to_string())
}

/// The names a node is reachable by on this machine: loopback, the host name,
/// and the address of the interface that routes outward.
///
/// Finding that address opens a UDP socket and asks the OS which local address
/// it would use; no packet is sent.
pub fn local_names() -> Vec<String> {
    let mut names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    if let Some(host) = host_name() {
        names.push(host);
    }
    if let Some(ip) = primary_ipv4() {
        names.push(ip.to_string());
    }
    names
}

/// This machine's host name, if the platform says.
pub fn host_name() -> Option<String> {
    let from_env = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok();
    from_env
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| {
            !h.is_empty()
                && h.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        })
}

/// The IPv4 address outbound traffic would leave from, if there is a route.
pub fn primary_ipv4() -> Option<std::net::Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    match socket.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() => Some(ip),
        _ => None,
    }
}

fn ca_params(key: KeyPair) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params.distinguished_name = dn(CA_COMMON_NAME);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.key_pair = Some(key);
    params
}

fn dn(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn.push(DnType::OrganizationName, ORGANIZATION);
    dn
}

fn san(name: &str) -> Result<SanType> {
    if let Ok(ip) = name.parse::<std::net::IpAddr>() {
        return Ok(SanType::IpAddress(ip));
    }
    let valid = !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        });
    if !valid {
        bail!("'{}' is neither an IP address nor a host name", name);
    }
    Ok(SanType::DnsName(name.to_string()))
}

fn random_serial() -> SerialNumber {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    // Positive, as DER INTEGER serials must be.
    bytes[0] &= 0x7f;
    bytes[0] |= 0x01;
    SerialNumber::from_slice(&bytes)
}

/// Set a validity window in whole days from today. `from` is negative to
/// tolerate a peer whose clock runs a little behind.
fn set_validity(params: &mut CertificateParams, from: i64, to: i64) {
    let day = |offset: i64| {
        let d = Utc::now() + Duration::days(offset);
        rcgen::date_time_ymd(d.year(), d.month() as u8, d.day() as u8)
    };
    params.not_before = day(from);
    params.not_after = day(to);
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {}-----\n", label);
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {}-----\n", label));
    out
}

fn write_public(path: &Path, contents: &str) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents).with_context(|| format!("cannot write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("cannot write {}", path.display()))
}

fn write_private(path: &Path, pem: &str) -> Result<()> {
    crate::tls::write_private_key(path, pem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordon_core::identity::parse_client_identity_from_cert;
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::CertificateDer;

    fn der(pem: &str) -> Vec<u8> {
        CertificateDer::from_pem_slice(pem.as_bytes())
            .unwrap()
            .as_ref()
            .to_vec()
    }

    #[test]
    fn a_client_certificate_carries_its_name_and_pins_to_its_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let pki = Pki::new(dir.path());
        let issued = pki.issue_client("laptop-1", 30).unwrap();

        let cert = der(&issued.cert_pem);
        let identity = parse_client_identity_from_cert(&cert).unwrap();
        assert_eq!(identity.client_id, "laptop-1");
        assert_eq!(identity.fingerprint, issued.fingerprint);
        assert!(identity.issuer_dn.contains(CA_COMMON_NAME));
        assert!(issued.key_pem.contains("PRIVATE KEY"));
    }

    /// The certificates chain to the CA on disk, so the server's verifier and
    /// a client's trust store both accept them.
    #[test]
    fn issued_certificates_verify_against_the_ca() {
        use rustls::server::WebPkiClientVerifier;
        use rustls::RootCertStore;
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let pki = Pki::new(dir.path());
        pki.ensure_server(&local_names()).unwrap();
        let issued = pki.issue_client("svc", 30).unwrap();

        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(der(&std::fs::read_to_string(
                pki.ca_cert_path(),
            )
            .unwrap())))
            .unwrap();
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        let client = CertificateDer::from(der(&issued.cert_pem));
        verifier
            .verify_client_cert(&client, &[], rustls_pki_types::UnixTime::now())
            .expect("the client certificate must chain to the CA");
    }

    #[test]
    fn the_server_certificate_is_reissued_only_when_its_names_change() {
        let dir = tempfile::tempdir().unwrap();
        let pki = Pki::new(dir.path());
        let names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        assert!(pki.ensure_server(&names).unwrap());
        assert!(!pki.ensure_server(&names).unwrap());
        let mut more = names.clone();
        more.push("cordon.example.com".into());
        assert!(pki.ensure_server(&more).unwrap());
        assert!(pki
            .server_info()
            .unwrap()
            .names
            .contains(&"cordon.example.com".to_string()));
    }

    #[test]
    fn reserved_and_malformed_client_names_are_refused() {
        assert!(validate_client_id("console").is_err());
        assert!(validate_client_id("a b").is_err());
        assert!(validate_client_id("../x").is_err());
        assert!(validate_client_id("").is_err());
        assert_eq!(validate_client_id(" build-bot ").unwrap(), "build-bot");
    }

    #[test]
    fn host_names_and_addresses_become_the_right_san() {
        assert!(matches!(san("10.0.0.5").unwrap(), SanType::IpAddress(_)));
        assert!(matches!(
            san("node.example.com").unwrap(),
            SanType::DnsName(_)
        ));
        assert!(san("bad name").is_err());
        assert!(san("-x.example").is_err());
    }
}
