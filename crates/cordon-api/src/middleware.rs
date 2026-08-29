//! Request middleware: identity propagation, request IDs, logging, and
//! response hardening.

use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, Request},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use uuid::Uuid;

use cordon_core::identity::{ClientIdentity, IdentitySource};

/// A client identity attached to a request, with the strength of its
/// authentication.
///
/// * `ClientCertificate` — parsed from a certificate rustls verified against the
///   configured client CA. Bound to the connection and trustworthy.
/// * `DevelopmentHeader` — read from `x-client-id` on a plaintext connection.
///   Trivially spoofable, and accepted only when TLS is disabled.
#[derive(Clone, Debug)]
pub struct VerifiedIdentity {
    /// The client identity.
    pub identity: ClientIdentity,
    /// Where it came from.
    pub source: IdentitySource,
}

impl VerifiedIdentity {
    /// Whether the identity is cryptographically bound to the connection.
    pub fn is_verified(&self) -> bool {
        self.source == IdentitySource::ClientCertificate
    }
}

/// The request's unique identifier.
#[derive(Clone, Copy, Debug)]
pub struct RequestId(pub Uuid);

/// The peer address, when the listener provided one.
#[derive(Clone, Copy, Debug)]
pub struct PeerAddr(pub Option<SocketAddr>);

/// Ensure every request carries a [`VerifiedIdentity`].
///
/// The TLS accept loop inserts a certificate-derived identity before the router
/// runs; that is left untouched. Otherwise a header-derived identity is inserted
/// and marked unverified, and the handlers decide whether the deployment mode
/// tolerates that.
pub async fn populate_identity(mut req: Request, next: Next) -> Response {
    if req.extensions().get::<VerifiedIdentity>().is_none() {
        let client_id = req
            .headers()
            .get("x-client-id")
            .and_then(|v| v.to_str().ok())
            .map(sanitize_client_id)
            .unwrap_or_else(|| "anonymous".to_string());

        req.extensions_mut().insert(VerifiedIdentity {
            identity: ClientIdentity::from_dev_header(&client_id),
            source: IdentitySource::DevelopmentHeader,
        });
    }
    next.run(req).await
}

/// Restrict a header-supplied client ID to characters that cannot corrupt a log
/// line or a filesystem path, and bound its length.
fn sanitize_client_id(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'))
        .take(128)
        .collect();
    if cleaned.is_empty() {
        "anonymous".to_string()
    } else {
        cleaned
    }
}

/// Attach a request ID and echo it back on the response.
pub async fn inject_request_id(mut req: Request, next: Next) -> Response {
    let id = Uuid::new_v4();
    req.extensions_mut().insert(RequestId(id));

    let mut response = next.run(req).await;
    if let Ok(value) = HeaderValue::from_str(&id.to_string()) {
        response.headers_mut().insert("x-cordon-request-id", value);
    }
    response
}

/// Record the peer address for handlers that need it, notably the metrics
/// endpoint's loopback check.
pub async fn inject_peer_addr(mut req: Request, next: Next) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| *addr);
    req.extensions_mut().insert(PeerAddr(peer));
    next.run(req).await
}

/// Log the start and end of each request.
///
/// The path and status are recorded; query strings, bodies, and headers are not,
/// because they carry client content and this log is not the audit log.
pub async fn request_logging(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let started = std::time::Instant::now();

    let response = next.run(req).await;

    let status = response.status();
    let latency_ms = started.elapsed().as_millis();

    if status.is_server_error() {
        tracing::error!(%method, path, %status, latency_ms, "Request failed");
    } else if status.is_client_error() {
        tracing::warn!(%method, path, %status, latency_ms, "Request rejected");
    } else {
        tracing::info!(%method, path, %status, latency_ms, "Request completed");
    }

    response
}

/// Apply response headers that harden a browser's handling of API output.
pub async fn security_headers(req: Request, next: Next) -> Response {
    let is_tls = req.uri().scheme_str() == Some("https")
        || req
            .headers()
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            == Some("https");

    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
    );
    // Responses may echo model output. A restrictive policy means a browser
    // that renders one directly cannot be induced to execute anything.
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("geolocation=(), camera=(), microphone=(), interest-cohort=()"),
    );

    // HSTS instructs a browser to refuse plaintext for a year. Sending it over
    // plaintext, as the previous implementation did, would pin a development
    // node's host into HTTPS-only in every developer's browser.
    if is_tls {
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }

    if let Ok(version) = HeaderValue::from_str(env!("CARGO_PKG_VERSION")) {
        headers.insert("x-cordon-version", version);
    }

    response
}

/// Reject requests to the metrics endpoint that did not arrive over loopback.
///
/// The router comment used to claim this was "enforced at the network layer",
/// which nothing did. Prometheus output names clients, models, and traffic
/// volumes, so it is enforced here.
pub async fn require_loopback(req: Request, next: Next) -> Response {
    let peer = req
        .extensions()
        .get::<PeerAddr>()
        .and_then(|PeerAddr(addr)| *addr);

    let allowed = match peer {
        Some(addr) => is_loopback(addr.ip()),
        // No peer address means the listener did not supply one. Refuse rather
        // than assume: an unknown origin is not a local one.
        None => false,
    };

    if !allowed {
        tracing::warn!(
            ?peer,
            "Refused non-loopback request to the metrics endpoint"
        );
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "forbidden",
                "message": "the metrics endpoint is reachable only from localhost",
            })),
        )
            .into_response();
    }

    next.run(req).await
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                // An IPv4 loopback arriving over a dual-stack socket appears as
                // ::ffff:127.0.0.1 and is still local.
                || v6.to_ipv4_mapped().map(|v4| v4.is_loopback()).unwrap_or(false)
        }
    }
}

/// Extract a client identity from headers, for the plaintext development path.
pub fn extract_client_identity(headers: &HeaderMap) -> ClientIdentity {
    let client_id = headers
        .get("x-client-id")
        .and_then(|v| v.to_str().ok())
        .map(sanitize_client_id)
        .unwrap_or_else(|| "anonymous".to_string());
    ClientIdentity::from_dev_header(&client_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn loopback_covers_v4_v6_and_mapped() {
        assert!(is_loopback(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_loopback(IpAddr::V4(Ipv4Addr::new(127, 3, 2, 1))));
        assert!(is_loopback(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_loopback("::ffff:127.0.0.1".parse().unwrap()));

        assert!(!is_loopback(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_loopback(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(!is_loopback("::ffff:8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn client_ids_are_sanitized() {
        assert_eq!(sanitize_client_id("analytics-7"), "analytics-7");
        assert_eq!(sanitize_client_id("svc@example.com"), "svc@example.com");
        // Newlines would let a caller forge log lines.
        assert_eq!(sanitize_client_id("evil\nINFO fake"), "evilINFOfake");
        // Path separators would let a caller reach outside a per-client path.
        assert_eq!(sanitize_client_id("../../etc/passwd"), "....etcpasswd");
        assert_eq!(sanitize_client_id(""), "anonymous");
        assert_eq!(sanitize_client_id("   "), "anonymous");
    }

    #[test]
    fn client_ids_are_length_bounded() {
        assert_eq!(sanitize_client_id(&"a".repeat(1000)).len(), 128);
    }

    #[test]
    fn header_identity_is_marked_unverified() {
        let mut headers = HeaderMap::new();
        headers.insert("x-client-id", HeaderValue::from_static("dev"));
        let identity = extract_client_identity(&headers);
        assert_eq!(identity.client_id, "dev");
        assert_eq!(identity.source, IdentitySource::DevelopmentHeader);
    }
}
