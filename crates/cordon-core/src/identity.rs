//! Client Identity and Authorization — Layer 1, §4.2
//!
//! Manages client identities, certificates, and authorization policies.
//! All identity checks are local — no LDAP/AD calls in dark mode.

use std::collections::HashMap;
use std::path::Path;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use parking_lot::RwLock;
use std::sync::Arc;

use crate::error::{CordonError, CordonResult};

/// Client identity extracted from mTLS certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientIdentity {
    /// Client ID from certificate CN or SAN
    pub client_id: String,
    /// Certificate subject DN
    pub subject_dn: String,
    /// Certificate serial number (hex)
    pub cert_serial: String,
    /// Certificate not-before
    pub not_before: DateTime<Utc>,
    /// Certificate not-after
    pub not_after: DateTime<Utc>,
    /// Certificate fingerprint (SHA-256 hex)
    pub fingerprint: String,
}

impl ClientIdentity {
    /// Check if the certificate is currently valid
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.not_before && now <= self.not_after
    }
}

/// Authorization policy for a client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPolicy {
    /// Client ID this policy applies to
    pub client_id: String,
    /// Whether this client is active
    pub active: bool,
    /// Permitted model bundle IDs (empty = all)
    pub permitted_models: Vec<String>,
    /// Maximum tokens per request
    pub max_tokens_per_request: u32,
    /// Maximum requests per minute
    pub max_requests_per_minute: u32,
    /// Maximum tokens per minute
    pub max_tokens_per_minute: u32,
    /// Whether this client can perform admin actions
    pub admin_allowed: bool,
    /// Whether this client can request log exports
    pub log_export_allowed: bool,
    /// Optional expiry time for this policy
    pub policy_expires_at: Option<DateTime<Utc>>,
    /// Certificate fingerprint pins (empty = any valid cert for this client_id)
    pub cert_pins: Vec<String>,
}

impl ClientPolicy {
    /// Default policy for a new client (restrictive)
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

    /// Check whether a model is permitted for this client
    pub fn model_permitted(&self, bundle_id: &str) -> bool {
        if self.permitted_models.is_empty() {
            return true; // empty = all models permitted
        }
        self.permitted_models.iter().any(|m| m == bundle_id)
    }

    /// Check whether the policy is still valid
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        self.active && self.policy_expires_at.map(|exp| now < exp).unwrap_or(true)
    }
}

/// Suspended client entry
#[derive(Debug, Clone)]
struct SuspendedClient {
    client_id: String,
    suspended_until: DateTime<Utc>,
    reason: String,
}

/// Local identity registry — all checks are offline
pub struct IdentityRegistry {
    policies: Arc<RwLock<HashMap<String, ClientPolicy>>>,
    suspended: Arc<RwLock<Vec<SuspendedClient>>>,
}

impl IdentityRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
            suspended: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Load policies from a JSON file
    pub fn load_from_file(path: &Path) -> CordonResult<Self> {
        let registry = Self::new();
        if path.exists() {
            let content = std::fs::read_to_string(path)
                .map_err(|e| CordonError::ConfigError(format!("Cannot read identity registry: {}", e)))?;
            let policies: Vec<ClientPolicy> = serde_json::from_str(&content)
                .map_err(|e| CordonError::ConfigError(format!("Invalid identity registry: {}", e)))?;
            let mut map = registry.policies.write();
            for policy in policies {
                map.insert(policy.client_id.clone(), policy);
            }
        }
        Ok(registry)
    }

    /// Register a client policy
    pub fn register(&self, policy: ClientPolicy) {
        self.policies.write().insert(policy.client_id.clone(), policy);
    }

    /// Verify a client identity and return its authorization policy
    pub fn verify(&self, identity: &ClientIdentity) -> CordonResult<ClientPolicy> {
        let now = Utc::now();

        // Check certificate validity
        if !identity.is_valid_at(now) {
            return Err(CordonError::AuthFailed(
                format!("Certificate expired or not yet valid for client {}", identity.client_id)
            ));
        }

        // Check if client is suspended
        {
            let suspended = self.suspended.read();
            for s in suspended.iter() {
                if s.client_id == identity.client_id && now < s.suspended_until {
                    return Err(CordonError::AuthFailed(
                        format!("Client {} is suspended until {}: {}", identity.client_id, s.suspended_until, s.reason)
                    ));
                }
            }
        }

        // Look up policy
        let policies = self.policies.read();
        let policy = policies.get(&identity.client_id)
            .cloned()
            .unwrap_or_else(|| ClientPolicy::default_for(&identity.client_id));

        if !policy.is_valid_at(now) {
            return Err(CordonError::AuthFailed(
                format!("Policy for client {} is expired or inactive", identity.client_id)
            ));
        }

        // Check certificate pin if configured
        if !policy.cert_pins.is_empty() {
            let pin_matches = policy.cert_pins.iter()
                .any(|pin| cordon_crypto::kdf::ct_eq(pin.as_bytes(), identity.fingerprint.as_bytes()));
            if !pin_matches {
                return Err(CordonError::AuthFailed(
                    format!("Certificate pin mismatch for client {}", identity.client_id)
                ));
            }
        }

        Ok(policy)
    }

    /// Suspend a client for a duration
    pub fn suspend(&self, client_id: &str, duration_secs: u64, reason: &str) {
        let until = Utc::now() + chrono::Duration::seconds(duration_secs as i64);
        self.suspended.write().push(SuspendedClient {
            client_id: client_id.to_string(),
            suspended_until: until,
            reason: reason.to_string(),
        });
        tracing::warn!("Client {} suspended until {}: {}", client_id, until, reason);
    }

    /// Remove expired suspensions
    pub fn cleanup_expired_suspensions(&self) {
        let now = Utc::now();
        self.suspended.write().retain(|s| s.suspended_until > now);
    }

    /// Get the number of registered clients
    pub fn client_count(&self) -> usize {
        self.policies.read().len()
    }
}

impl Default for IdentityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a client identity from a TLS certificate (simplified — production uses
/// x509-parser or rustls certificate inspection)
pub fn parse_client_identity_from_cert(
    cert_der: &[u8],
) -> CordonResult<ClientIdentity> {
    // In production this uses x509-parser to extract CN, SAN, serial, validity.
    // For the portable implementation we use a mock that reads from environment
    // or accept the cert DER and compute fingerprint.
    use sha2::{Digest, Sha256};

    let fingerprint = hex::encode(Sha256::digest(cert_der));

    // For real deployments, replace with x509-parser extraction:
    // let (_, cert) = x509_parser::parse_x509_certificate(cert_der)?;
    // let client_id = cert.subject().iter_common_name()...

    Ok(ClientIdentity {
        client_id: format!("client-{}", &fingerprint[..16]),
        subject_dn: "CN=cordon-client".to_string(),
        cert_serial: fingerprint[..32].to_string(),
        not_before: Utc::now() - chrono::Duration::hours(1),
        not_after: Utc::now() + chrono::Duration::days(365),
        fingerprint,
    })
}
