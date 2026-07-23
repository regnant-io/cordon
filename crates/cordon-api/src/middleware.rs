//! Axum middleware — request ID injection, client identity extraction, logging

use axum::{
    extract::Request,
    http::{HeaderMap, HeaderValue, header},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

use cordon_core::identity::ClientIdentity;

/// A client identity attached to a request, together with how strongly it is
/// authenticated. Stored in request extensions; handlers read it via the
/// `Extension<VerifiedIdentity>` extractor.
///
/// * `verified == true`  → identity came from a **verified mTLS client
///   certificate** (injected by the TLS accept loop). Trustworthy.
/// * `verified == false` → identity came from the `x-client-id` header on a
///   plaintext (`--no-tls`) dev connection. NOT trustworthy — spoofable.
#[derive(Clone, Debug)]
pub struct VerifiedIdentity {
    /// The client identity.
    pub identity: ClientIdentity,
    /// Whether it was cryptographically verified via mTLS.
    pub verified: bool,
}

/// Middleware: ensure every request carries a `VerifiedIdentity`.
///
/// If the TLS layer already inserted a certificate-derived identity, it is left
/// untouched. Otherwise (plaintext dev connection) a header-derived identity is
/// inserted with `verified = false` so downstream code can decide whether that
/// is acceptable for the deployment mode.
pub async fn populate_identity(mut req: Request, next: Next) -> Response {
    if req.extensions().get::<VerifiedIdentity>().is_none() {
        let identity = extract_client_identity(req.headers());
        req.extensions_mut().insert(VerifiedIdentity { identity, verified: false });
    }
    next.run(req).await
}

/// Key for storing request ID in request extensions
#[derive(Clone)]
pub struct RequestId(pub Uuid);

/// Key for storing client identity in request extensions
#[derive(Clone)]
pub struct ExtractedClientId(pub String);

/// Middleware: inject a unique request ID into every request
pub async fn inject_request_id(
    mut req: Request,
    next: Next,
) -> Response {
    let id = Uuid::new_v4();
    req.extensions_mut().insert(RequestId(id));
    let mut response = next.run(req).await;
    response.headers_mut().insert(
        "x-cordon-request-id",
        HeaderValue::from_str(&id.to_string()).unwrap_or(HeaderValue::from_static("unknown")),
    );
    response
}

/// Middleware: log request start/end with timing
pub async fn request_logging(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let started = std::time::Instant::now();

    let response = next.run(req).await;

    let status = response.status();
    let latency_ms = started.elapsed().as_millis();

    if status.is_success() {
        tracing::info!(
            method = %method,
            path = %uri.path(),
            status = %status,
            latency_ms = latency_ms,
            "Request completed"
        );
    } else {
        tracing::warn!(
            method = %method,
            path = %uri.path(),
            status = %status,
            latency_ms = latency_ms,
            "Request failed"
        );
    }

    response
}

/// Middleware: add security headers to all responses
pub async fn security_headers(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    // Prevent content type sniffing
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    // No caching of responses
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    // Identify as Cordon
    headers.insert(
        "x-cordon-version",
        HeaderValue::from_str(env!("CARGO_PKG_VERSION"))
            .unwrap_or(HeaderValue::from_static("2.0.0")),
    );
    // Strict transport security (TLS only)
    headers.insert(
        "strict-transport-security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );

    response
}

/// Extract a client identity from request headers or TLS metadata.
/// In production: extracts from mTLS client certificate via TLS layer.
/// Here: reads from X-Client-Id header (development) or simulates cert extraction.
pub fn extract_client_identity(headers: &HeaderMap) -> ClientIdentity {
    use sha2::{Digest, Sha256};
    use chrono::Utc;

    // In production: extract from TLS client certificate via axum-server's
    // certificate extraction middleware or via a custom connector.
    // For portable implementation: read from special header or use fixed test identity.
    let client_id = headers
        .get("x-client-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("default-client")
        .to_string();

    let fingerprint = hex::encode(Sha256::digest(client_id.as_bytes()));

    ClientIdentity {
        client_id: client_id.clone(),
        subject_dn: format!("CN={}", client_id),
        cert_serial: fingerprint[..32].to_string(),
        not_before: Utc::now() - chrono::Duration::hours(1),
        not_after: Utc::now() + chrono::Duration::days(365),
        fingerprint,
    }
}
