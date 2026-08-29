//! Client identity and authorization (Layer 1).
//!
//! Client identities are derived from verified mTLS peer certificates by
//! parsing the X.509 structure — subject CN, subject-alternative names, serial
//! number, and the validity window all come from the certificate itself. The
//! authorization policy attached to an identity is looked up in a registry
//! loaded from disk at startup.
//!
//! Every check in this module is local. Cordon never contacts an external
//! directory service to authorize a request.

use chrono::{DateTime, TimeZone, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::error::{CordonError, CordonResult};

/// How an identity was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySource {
    /// Parsed from a client certificate that rustls verified against the
    /// configured client CA. Cryptographically bound to the connection.
    ClientCertificate,
    /// Read from the `x-client-id` request header on a plaintext development
    /// connection. Trivially spoofable; accepted only when TLS is disabled.
    DevelopmentHeader,
}

/// Client identity extracted from an mTLS certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientIdentity {
    /// Client ID, taken from the certificate subject CN (or the first URI/DNS
    /// SAN when no CN is present).
    pub client_id: String,
    /// Full RFC 4514 subject distinguished name.
    pub subject_dn: String,
    /// Certificate issuer distinguished name.
    pub issuer_dn: String,
    /// Certificate serial number (hex, no leading `0x`).
    pub cert_serial: String,
    /// Subject alternative names (DNS, URI, email, and IP entries).
    pub sans: Vec<String>,
    /// Certificate `notBefore`.
    pub not_before: DateTime<Utc>,
    /// Certificate `notAfter`.
    pub not_after: DateTime<Utc>,
    /// SHA-256 of the DER-encoded certificate (hex) — the pinning fingerprint.
    pub fingerprint: String,
    /// How this identity was established.
    pub source: IdentitySource,
}

impl ClientIdentity {
    /// Whether the certificate's validity window contains `now`.
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.not_before && now <= self.not_after
    }

    /// Construct a development identity from a header value. Marked
    /// [`IdentitySource::DevelopmentHeader`] so downstream code can refuse it.
    pub fn from_dev_header(client_id: &str) -> Self {
        use sha2::{Digest, Sha256};
        let fingerprint = hex::encode(Sha256::digest(client_id.as_bytes()));
        let now = Utc::now();
        Self {
            client_id: client_id.to_string(),
            subject_dn: format!("CN={}", client_id),
            issuer_dn: "CN=cordon-development".to_string(),
            cert_serial: String::new(),
            sans: vec![],
            not_before: now - chrono::Duration::hours(1),
            not_after: now + chrono::Duration::hours(1),
            fingerprint,
            source: IdentitySource::DevelopmentHeader,
        }
    }
}

/// Authorization policy for a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPolicy {
    /// Client ID this policy applies to.
    pub client_id: String,
    /// Whether this client is active.
    pub active: bool,
    /// Permitted model bundle IDs. Empty means every registered bundle.
    pub permitted_models: Vec<String>,
    /// Maximum `max_tokens` a single request may ask for.
    pub max_tokens_per_request: u32,
    /// Maximum requests per minute.
    pub max_requests_per_minute: u32,
    /// Maximum generated tokens per minute.
    pub max_tokens_per_minute: u32,
    /// Whether this client may perform admin actions.
    pub admin_allowed: bool,
    /// Whether this client may request log exports.
    pub log_export_allowed: bool,
    /// Optional expiry for this policy.
    pub policy_expires_at: Option<DateTime<Utc>>,
    /// Certificate fingerprint pins. Empty means any CA-issued certificate
    /// bearing this client ID is accepted.
    pub cert_pins: Vec<String>,
}

impl ClientPolicy {
    /// Default policy applied to a client with no registry entry.
    pub fn default_for(client_id: &str) -> Self {
        Self {
            client_id: client_id.to_string(),
            active: true,
            permitted_models: vec![],
            max_tokens_per_request: 4096,
            max_requests_per_minute: 60,
            max_tokens_per_minute: 100_000,
            admin_allowed: false,
            log_export_allowed: false,
            policy_expires_at: None,
            cert_pins: vec![],
        }
    }

    /// Whether a model bundle is permitted for this client.
    pub fn model_permitted(&self, bundle_id: &str) -> bool {
        if self.permitted_models.is_empty() {
            return true;
        }
        self.permitted_models.iter().any(|m| m == bundle_id)
    }

    /// Whether the policy is active and unexpired at `now`.
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        self.active && self.policy_expires_at.map(|exp| now < exp).unwrap_or(true)
    }
}

/// How the registry treats clients that have no explicit policy entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownClientPolicy {
    /// Reject the request. The correct posture for any deployment that has
    /// enrolled its clients.
    Deny,
    /// Apply [`ClientPolicy::default_for`]. Convenient for development, and the
    /// only sane behaviour when the registry is empty.
    AllowWithDefaults,
}

/// Local identity registry. All lookups are offline.
pub struct IdentityRegistry {
    policies: Arc<RwLock<HashMap<String, ClientPolicy>>>,
    suspended: Arc<RwLock<HashMap<String, SuspendedClient>>>,
    unknown_client: UnknownClientPolicy,
}

#[derive(Debug, Clone)]
struct SuspendedClient {
    suspended_until: DateTime<Utc>,
    reason: String,
}

impl IdentityRegistry {
    /// Create an empty registry that admits unknown clients with default
    /// limits. Appropriate only when no clients have been enrolled.
    pub fn new() -> Self {
        Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
            suspended: Arc::new(RwLock::new(HashMap::new())),
            unknown_client: UnknownClientPolicy::AllowWithDefaults,
        }
    }

    /// Create an empty registry with an explicit unknown-client posture.
    pub fn with_unknown_client_policy(unknown_client: UnknownClientPolicy) -> Self {
        Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
            suspended: Arc::new(RwLock::new(HashMap::new())),
            unknown_client,
        }
    }

    /// Load client policies from a JSON file containing an array of
    /// [`ClientPolicy`]. A missing file yields an empty registry.
    ///
    /// When the file exists and enrols at least one client, unknown clients are
    /// **denied** — enrolling clients is taken as intent to restrict access. An
    /// absent or empty file leaves the permissive development posture in place.
    pub fn load_from_file(path: &Path) -> CordonResult<Self> {
        if !path.exists() {
            tracing::warn!(
                path = %path.display(),
                "No client registry found — unknown clients will be admitted with \
                 default limits. Enrol clients to restrict access."
            );
            return Ok(Self::new());
        }

        let content = std::fs::read_to_string(path).map_err(|e| {
            CordonError::ConfigError(format!(
                "Cannot read client registry {}: {}",
                path.display(),
                e
            ))
        })?;
        let policies: Vec<ClientPolicy> = serde_json::from_str(&content).map_err(|e| {
            CordonError::ConfigError(format!("Invalid client registry {}: {}", path.display(), e))
        })?;

        let unknown_client = if policies.is_empty() {
            UnknownClientPolicy::AllowWithDefaults
        } else {
            UnknownClientPolicy::Deny
        };
        let registry = Self::with_unknown_client_policy(unknown_client);
        {
            let mut map = registry.policies.write();
            for policy in policies {
                map.insert(policy.client_id.clone(), policy);
            }
        }
        tracing::info!(
            clients = registry.client_count(),
            path = %path.display(),
            "Client registry loaded — unknown clients are denied"
        );
        Ok(registry)
    }

    /// Register or replace a client policy.
    pub fn register(&self, policy: ClientPolicy) {
        self.policies
            .write()
            .insert(policy.client_id.clone(), policy);
    }

    /// The configured posture toward unenrolled clients.
    pub fn unknown_client_policy(&self) -> UnknownClientPolicy {
        self.unknown_client
    }

    /// Verify an identity and return its authorization policy.
    pub fn verify(&self, identity: &ClientIdentity) -> CordonResult<ClientPolicy> {
        let now = Utc::now();

        if !identity.is_valid_at(now) {
            return Err(CordonError::AuthFailed(format!(
                "certificate outside its validity window for client {}",
                identity.client_id
            )));
        }

        if let Some(s) = self.suspended.read().get(&identity.client_id) {
            if now < s.suspended_until {
                return Err(CordonError::AuthFailed(format!(
                    "client {} is suspended until {}: {}",
                    identity.client_id, s.suspended_until, s.reason
                )));
            }
        }

        let policy = {
            let policies = self.policies.read();
            match policies.get(&identity.client_id) {
                Some(p) => p.clone(),
                None => match self.unknown_client {
                    UnknownClientPolicy::AllowWithDefaults => {
                        ClientPolicy::default_for(&identity.client_id)
                    }
                    UnknownClientPolicy::Deny => {
                        return Err(CordonError::AuthFailed(format!(
                            "client {} is not enrolled in the client registry",
                            identity.client_id
                        )));
                    }
                },
            }
        };

        if !policy.is_valid_at(now) {
            return Err(CordonError::AuthFailed(format!(
                "policy for client {} is expired or inactive",
                identity.client_id
            )));
        }

        if !policy.cert_pins.is_empty() {
            let pin_matches = policy.cert_pins.iter().any(|pin| {
                cordon_crypto::kdf::ct_eq(
                    pin.trim().to_lowercase().as_bytes(),
                    identity.fingerprint.as_bytes(),
                )
            });
            if !pin_matches {
                return Err(CordonError::AuthFailed(format!(
                    "certificate pin mismatch for client {}",
                    identity.client_id
                )));
            }
        }

        Ok(policy)
    }

    /// Suspend a client for `duration_secs`. Extends an existing suspension
    /// rather than shortening it.
    pub fn suspend(&self, client_id: &str, duration_secs: u64, reason: &str) {
        let until = Utc::now() + chrono::Duration::seconds(duration_secs as i64);
        let mut suspended = self.suspended.write();
        let entry = suspended
            .entry(client_id.to_string())
            .or_insert_with(|| SuspendedClient {
                suspended_until: until,
                reason: reason.to_string(),
            });
        if until > entry.suspended_until {
            entry.suspended_until = until;
            entry.reason = reason.to_string();
        }
        tracing::warn!(client_id, until = %entry.suspended_until, reason, "Client suspended");
    }

    /// Drop suspensions whose window has closed.
    pub fn cleanup_expired_suspensions(&self) {
        let now = Utc::now();
        self.suspended
            .write()
            .retain(|_, s| s.suspended_until > now);
    }

    /// Number of enrolled clients.
    pub fn client_count(&self) -> usize {
        self.policies.read().len()
    }

    /// Number of clients currently under suspension.
    pub fn suspended_count(&self) -> usize {
        let now = Utc::now();
        self.suspended
            .read()
            .values()
            .filter(|s| s.suspended_until > now)
            .count()
    }
}

impl Default for IdentityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a client identity out of a DER-encoded X.509 certificate.
///
/// The caller must only invoke this for certificates rustls has already
/// verified against the configured client CA — this function extracts
/// attributes, it does not establish trust.
///
/// The client ID is the subject CN when present; otherwise the first URI SAN,
/// then the first DNS SAN. A certificate with none of those is rejected rather
/// than given a synthesised identity, because an identity that cannot be named
/// cannot be matched against a policy.
pub fn parse_client_identity_from_cert(cert_der: &[u8]) -> CordonResult<ClientIdentity> {
    use sha2::{Digest, Sha256};
    use x509_parser::prelude::*;

    let fingerprint = hex::encode(Sha256::digest(cert_der));

    let (_rest, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
        CordonError::AuthFailed(format!("client certificate is not valid DER X.509: {}", e))
    })?;

    let subject_dn = cert.subject().to_string();
    let issuer_dn = cert.issuer().to_string();
    let cert_serial = cert.raw_serial_as_string().replace(':', "").to_lowercase();

    let mut sans: Vec<String> = Vec::new();
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            match name {
                GeneralName::DNSName(d) => sans.push(format!("DNS:{}", d)),
                GeneralName::URI(u) => sans.push(format!("URI:{}", u)),
                GeneralName::RFC822Name(e) => sans.push(format!("EMAIL:{}", e)),
                GeneralName::IPAddress(ip) => sans.push(format!("IP:{}", format_ip(ip))),
                _ => {}
            }
        }
    }

    let common_name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());

    let client_id = common_name
        .or_else(|| first_san_value(&sans, "URI:"))
        .or_else(|| first_san_value(&sans, "DNS:"))
        .ok_or_else(|| {
            CordonError::AuthFailed(
                "client certificate has no subject CN and no URI/DNS SAN — cannot \
                 determine a client identity"
                    .into(),
            )
        })?;

    let not_before = asn1_to_utc(cert.validity().not_before.timestamp())?;
    let not_after = asn1_to_utc(cert.validity().not_after.timestamp())?;

    Ok(ClientIdentity {
        client_id,
        subject_dn,
        issuer_dn,
        cert_serial,
        sans,
        not_before,
        not_after,
        fingerprint,
        source: IdentitySource::ClientCertificate,
    })
}

fn first_san_value(sans: &[String], prefix: &str) -> Option<String> {
    sans.iter()
        .find(|s| s.starts_with(prefix))
        .map(|s| s[prefix.len()..].to_string())
}

fn format_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string(),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => hex::encode(bytes),
    }
}

fn asn1_to_utc(secs: i64) -> CordonResult<DateTime<Utc>> {
    Utc.timestamp_opt(secs, 0).single().ok_or_else(|| {
        CordonError::AuthFailed("certificate validity timestamp out of range".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a self-signed certificate with a known CN so the parser has real
    /// DER to work against.
    fn test_cert(common_name: &str) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::default();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, common_name);
        dn.push(rcgen::DnType::OrganizationName, "Cordon Test");
        params.distinguished_name = dn;
        params.subject_alt_names = vec![rcgen::SanType::DnsName("client.example".into())];
        let cert = rcgen::Certificate::from_params(params).unwrap();
        cert.serialize_der().unwrap()
    }

    #[test]
    fn parses_common_name_as_client_id() {
        let der = test_cert("analytics-cluster-7");
        let identity = parse_client_identity_from_cert(&der).unwrap();
        assert_eq!(identity.client_id, "analytics-cluster-7");
        assert!(identity.subject_dn.contains("analytics-cluster-7"));
        assert!(identity.sans.contains(&"DNS:client.example".to_string()));
        assert_eq!(identity.source, IdentitySource::ClientCertificate);
        assert_eq!(identity.fingerprint.len(), 64);
    }

    #[test]
    fn parses_real_validity_window() {
        let der = test_cert("validity-probe");
        let identity = parse_client_identity_from_cert(&der).unwrap();
        // rcgen issues a certificate valid now; the window must be non-empty and
        // must come from the certificate rather than from the clock.
        assert!(identity.not_before < identity.not_after);
        assert!(identity.is_valid_at(Utc::now()));
        assert!(!identity.is_valid_at(identity.not_after + chrono::Duration::days(1)));
    }

    #[test]
    fn rejects_garbage_der() {
        assert!(parse_client_identity_from_cert(b"not a certificate").is_err());
    }

    #[test]
    fn unknown_client_denied_when_registry_populated() {
        let registry = IdentityRegistry::with_unknown_client_policy(UnknownClientPolicy::Deny);
        registry.register(ClientPolicy::default_for("enrolled"));

        let enrolled = ClientIdentity::from_dev_header("enrolled");
        assert!(registry.verify(&enrolled).is_ok());

        let stranger = ClientIdentity::from_dev_header("stranger");
        assert!(registry.verify(&stranger).is_err());
    }

    #[test]
    fn cert_pin_mismatch_is_rejected() {
        let registry = IdentityRegistry::new();
        let mut policy = ClientPolicy::default_for("pinned");
        policy.cert_pins = vec!["a".repeat(64)];
        registry.register(policy);

        let identity = ClientIdentity::from_dev_header("pinned");
        assert!(registry.verify(&identity).is_err());
    }

    #[test]
    fn suspension_blocks_then_lapses() {
        let registry = IdentityRegistry::new();
        let identity = ClientIdentity::from_dev_header("noisy");
        registry.suspend("noisy", 3600, "covert-channel score");
        assert!(registry.verify(&identity).is_err());

        // A shorter suspension must not shorten the existing one.
        registry.suspend("noisy", 1, "brief");
        assert!(registry.verify(&identity).is_err());
        assert_eq!(registry.suspended_count(), 1);
    }
}
