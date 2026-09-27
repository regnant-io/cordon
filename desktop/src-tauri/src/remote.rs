//! Access from other machines.
//!
//! Exposure is only offered in one shape, the strictest one Cordon supports:
//!
//! * TLS 1.3 only, with a server certificate from the app's own CA.
//! * Every connection presents a client certificate that CA issued, or the
//!   handshake fails before a byte of HTTP is read.
//! * Every certificate is pinned by fingerprint in the client registry, and
//!   unknown clients are denied, so revoking a client is removing its entry.
//! * The operator console stays on loopback whatever this says.
//!
//! There is no password or API-key mode to fall back to, and no plain-HTTP
//! listener while this is on, including for callers on this machine.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use cordon_api::pki::{self, IssuedClient, Pki};
use cordon_core::identity::ClientPolicy;

use crate::settings::{Paths, Settings};

/// Requests per minute an issued client may make, unless changed.
const DEFAULT_REQUESTS_PER_MINUTE: u32 = 60;

/// A client the app issued a certificate to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRecord {
    /// Client ID, the certificate's CN.
    pub id: String,
    /// SHA-256 of the certificate, pinned in the registry.
    pub fingerprint: String,
    /// Certificate serial number.
    pub serial: String,
    /// When it was issued.
    pub issued_at: chrono::DateTime<chrono::Utc>,
    /// When it stops being valid.
    pub not_after: chrono::DateTime<chrono::Utc>,
    /// When it was revoked, if it was.
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Requests per minute.
    pub requests_per_minute: u32,
}

/// What the app shows about remote access.
#[derive(Debug, Clone, Serialize, Default)]
pub struct RemoteView {
    /// Whether a CA exists.
    pub ca_ready: bool,
    /// Names the server certificate covers.
    pub certificate_names: Vec<String>,
    /// When the server certificate expires.
    pub certificate_expires: Option<chrono::DateTime<chrono::Utc>>,
    /// SHA-256 of the server certificate.
    pub certificate_fingerprint: Option<String>,
    /// Addresses on this machine clients can use.
    pub addresses: Vec<String>,
    /// Issued clients, newest first.
    pub clients: Vec<ClientRecord>,
}

fn records_path(paths: &Paths) -> PathBuf {
    paths.data_dir.join("remote-clients.json")
}

/// The client registry the node loads while remote access is on.
pub fn registry_path(paths: &Paths) -> PathBuf {
    paths.data_dir.join("clients.json")
}

/// The certificate authority.
pub fn pki(paths: &Paths) -> Pki {
    Pki::new(&paths.pki_dir)
}

/// Issued clients.
pub fn records(paths: &Paths) -> Vec<ClientRecord> {
    std::fs::read_to_string(records_path(paths))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save_records(paths: &Paths, records: &[ClientRecord]) -> Result<()> {
    std::fs::create_dir_all(&paths.data_dir)?;
    let path = records_path(paths);
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(records)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Names the server certificate must cover.
pub fn server_names(settings: &Settings) -> Vec<String> {
    let mut names = pki::local_names();
    names.extend(settings.remote.names.iter().map(|n| n.trim().to_string()));
    names.retain(|n| !n.is_empty());
    names
}

/// What the app shows.
pub fn view(paths: &Paths, settings: &Settings) -> RemoteView {
    let pki = pki(paths);
    let info = pki.server_info();
    let mut clients = records(paths);
    clients.sort_by_key(|c| std::cmp::Reverse(c.issued_at));
    let port = settings.remote.port;
    let mut addresses: Vec<String> = Vec::new();
    if let Some(ip) = pki::primary_ipv4() {
        addresses.push(format!("https://{}:{}", ip, port));
    }
    if let Some(host) = pki::host_name() {
        addresses.push(format!("https://{}:{}", host, port));
    }
    for name in &settings.remote.names {
        if !name.trim().is_empty() {
            addresses.push(format!("https://{}:{}", name.trim(), port));
        }
    }
    RemoteView {
        ca_ready: pki.has_ca(),
        certificate_names: info.as_ref().map(|i| i.names.clone()).unwrap_or_default(),
        certificate_expires: info.as_ref().and_then(|i| i.not_after),
        certificate_fingerprint: info.map(|i| i.fingerprint),
        addresses,
        clients,
    }
}

/// Issue a client a certificate and record it.
pub fn issue(paths: &Paths, id: &str, days: u32) -> Result<IssuedClient> {
    let id = pki::validate_client_id(id)?;
    let mut all = records(paths);
    if all.iter().any(|r| r.id == id && r.revoked_at.is_none()) {
        bail!("A client named '{}' already has a certificate. Revoke it first, or choose another name.", id);
    }
    let issued = pki(paths).issue_client(&id, days)?;
    all.push(ClientRecord {
        id: issued.client_id.clone(),
        fingerprint: issued.fingerprint.clone(),
        serial: issued.serial.clone(),
        issued_at: chrono::Utc::now(),
        not_after: issued.not_after,
        revoked_at: None,
        requests_per_minute: DEFAULT_REQUESTS_PER_MINUTE,
    });
    save_records(paths, &all)?;
    tracing::info!(client = %issued.client_id, "Issued a client certificate");
    Ok(issued)
}

/// Revoke a client's certificate. It takes effect when the node next starts,
/// which the app does straight away when it is running.
pub fn revoke(paths: &Paths, fingerprint: &str) -> Result<()> {
    let mut all = records(paths);
    let record = all
        .iter_mut()
        .find(|r| r.fingerprint == fingerprint)
        .context("No such client.")?;
    if record.revoked_at.is_none() {
        record.revoked_at = Some(chrono::Utc::now());
        tracing::warn!(client = %record.id, "Revoked a client certificate");
    }
    save_records(paths, &all)
}

/// Forget revoked clients.
pub fn clear_revoked(paths: &Paths) -> Result<()> {
    let mut all = records(paths);
    all.retain(|r| r.revoked_at.is_none());
    save_records(paths, &all)
}

/// Write the client registry the node enforces: every live, unexpired issued
/// client pinned to its certificate, and the local console.
///
/// A registry with entries makes the node deny every client not in it, which
/// is what turns "the CA issued it" into "the CA issued it and it has not been
/// revoked".
pub fn write_registry(paths: &Paths) -> Result<PathBuf> {
    let now = chrono::Utc::now();
    let mut policies: Vec<ClientPolicy> = records(paths)
        .into_iter()
        .filter(|r| r.revoked_at.is_none() && r.not_after > now)
        .map(|r| ClientPolicy {
            active: true,
            max_requests_per_minute: r.requests_per_minute,
            cert_pins: vec![r.fingerprint],
            policy_expires_at: Some(r.not_after),
            ..ClientPolicy::default_for(&r.id)
        })
        .collect();
    // The console on loopback identifies itself by header. Its entry carries
    // no pin, and a certificate cannot claim its name: the CA refuses to
    // issue one.
    policies.push(ClientPolicy {
        log_export_allowed: true,
        max_requests_per_minute: 600,
        ..ClientPolicy::default_for("console")
    });
    let path = registry_path(paths);
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&policies)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

/// Write a client's certificate, key, the CA and a short README into `folder`.
pub fn save_client_files(folder: &Path, issued: &IssuedClient, url: &str) -> Result<PathBuf> {
    let dir = folder.join(format!("cordon-{}", issued.client_id));
    if dir.exists() {
        bail!("{} already exists.", dir.display());
    }
    std::fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    std::fs::write(dir.join("client.crt"), &issued.cert_pem)?;
    std::fs::write(dir.join("ca.crt"), &issued.ca_pem)?;
    {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(dir.join("client.key"))
            .and_then(|mut f| f.write_all(issued.key_pem.as_bytes()))
            .context("cannot write client.key")?;
    }
    std::fs::write(dir.join("README.txt"), readme(issued, url))?;
    Ok(dir)
}

fn readme(issued: &IssuedClient, url: &str) -> String {
    format!(
        "Cordon client certificate for \"{id}\"\n\
         Valid until {until}. Fingerprint {fp}\n\
         \n\
         client.crt  this client's certificate\n\
         client.key  its private key. Keep it secret; anyone holding it is \"{id}\".\n\
         ca.crt      the certificate authority to trust the server with\n\
         \n\
         curl:\n\
         \x20 curl --cert client.crt --key client.key --cacert ca.crt {url}/v1/health\n\
         \n\
         Python (httpx):\n\
         \x20 import httpx\n\
         \x20 client = httpx.Client(base_url=\"{url}\", verify=\"ca.crt\",\n\
         \x20                       cert=(\"client.crt\", \"client.key\"))\n\
         \x20 client.post(\"/v1/inference\", json={{\"messages\": [{{\"role\": \"user\", \"content\": \"Hello\"}}]}})\n",
        id = issued.client_id,
        until = issued.not_after.format("%Y-%m-%d"),
        fp = issued.fingerprint,
        url = url,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordon_core::identity::IdentityRegistry;

    fn paths() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().to_path_buf(), dir.path().join("logs"));
        (dir, paths)
    }

    #[test]
    fn a_revoked_client_leaves_the_registry_and_unknown_clients_are_denied() {
        let (_dir, paths) = paths();
        let kept = issue(&paths, "laptop", 30).unwrap();
        let gone = issue(&paths, "phone", 30).unwrap();
        assert!(
            issue(&paths, "laptop", 30).is_err(),
            "one live certificate per name"
        );
        revoke(&paths, &gone.fingerprint).unwrap();

        let registry = IdentityRegistry::load_from_file(&write_registry(&paths).unwrap()).unwrap();
        assert_eq!(
            registry.unknown_client_policy(),
            cordon_core::identity::UnknownClientPolicy::Deny
        );

        let parse = |pem: &str| {
            use rustls_pki_types::pem::PemObject;
            let der = rustls_pki_types::CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();
            cordon_core::identity::parse_client_identity_from_cert(der.as_ref()).unwrap()
        };
        assert!(registry.verify(&parse(&kept.cert_pem)).is_ok());
        assert!(registry.verify(&parse(&gone.cert_pem)).is_err());

        // Revoked names can be issued again once cleared.
        clear_revoked(&paths).unwrap();
        issue(&paths, "phone", 30).unwrap();
    }

    #[test]
    fn client_files_are_complete() {
        let (dir, paths) = paths();
        let issued = issue(&paths, "svc", 30).unwrap();
        let saved = save_client_files(dir.path(), &issued, "https://10.0.0.2:8443").unwrap();
        for f in ["client.crt", "client.key", "ca.crt", "README.txt"] {
            assert!(saved.join(f).is_file(), "{}", f);
        }
        assert!(std::fs::read_to_string(saved.join("README.txt"))
            .unwrap()
            .contains("https://10.0.0.2:8443/v1/health"));
    }
}
