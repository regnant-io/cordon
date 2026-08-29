//! The operator console.
//!
//! A single page served on its own loopback listener. It has no authentication
//! of its own — reachability is its access control — so
//! [`CordonConfig::validate`](cordon_core::CordonConfig::validate) refuses to
//! enable it outside Light mode or on a routable address, and
//! [`ApiServer`](crate::server::ApiServer) checks the bind address again before
//! binding.
//!
//! The page is a static asset compiled into the binary. Node state reaches it
//! through [`status`], which serializes structured JSON rather than
//! interpolating values into markup — string substitution into HTML is how a
//! node ID or a model name becomes an injection vector.

use axum::{
    extract::{Request, State},
    http::{header, HeaderValue},
    middleware::Next,
    response::{Html, IntoResponse, Response},
    Json,
};

use crate::handlers::AppState;

/// The console page.
const CONSOLE_HTML: &str = include_str!("../../../ui/console.html");

/// `GET /` — serve the console.
pub async fn console() -> Html<&'static str> {
    Html(CONSOLE_HTML)
}

/// Response headers for the console.
///
/// The page ships its own inline stylesheet and script, loads nothing from the
/// network, and calls only its own origin — inference is proxied through this
/// listener rather than reaching across to the API port. That lets the policy
/// forbid every other origin outright.
pub async fn console_headers(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'none'; \
             style-src 'unsafe-inline'; \
             script-src 'unsafe-inline'; \
             connect-src 'self'; \
             img-src data:; \
             form-action 'none'; \
             base-uri 'none'; \
             frame-ancestors 'none'",
        ),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, must-revalidate"),
    );

    response
}

/// `GET /api/status` — node state for the console, as JSON.
pub async fn status(State(state): State<AppState>) -> impl IntoResponse {
    let node = &state.node;

    let backend = node.inference.backend_name();
    // The placeholder backend must be unmistakable in the console: an operator
    // seeing plausible text from a node with no model attached is exactly the
    // confusion this flag exists to prevent.
    let is_placeholder = backend.starts_with("deterministic");

    let (chain_valid, chain_checked_at) = match state.chain_health.get() {
        Some((valid, at)) => (Some(valid), Some(at)),
        None => (None, None),
    };

    // Await before taking the state lock: a `parking_lot` guard is not `Send`,
    // and holding one across an await would make this handler's future non-Send.
    let runtime_ready = node.inference.is_ready().await;
    let loaded_model = node.inference.loaded_model().await;

    let node_state = node.state.read();
    let status = node_state.status.to_string();
    let latency_p50 = node_state.stats.latency_ms_p50;
    let latency_p99 = node_state.stats.latency_ms_p99;
    drop(node_state);

    Json(serde_json::json!({
        "status": status,
        "mode": node.config.mode.to_string(),
        "node_id": node.config.node_id,
        "cordon_version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": node.started_at.elapsed().as_secs(),

        "runtime": {
            "backend": backend,
            "is_placeholder": is_placeholder,
            "ready": runtime_ready,
            "model": loaded_model,
            "active_requests": node.inference.active_requests(),
            "max_concurrent": node.inference.max_concurrent(),
            "active_sessions": node.inference.kv_cache().session_count(),
            "latency_ms_p50": latency_p50,
            "latency_ms_p99": latency_p99,
        },

        "trust": {
            "key_provenance": node.key_provenance().as_str(),
            "measurement_source": node.attestation.measurement_source().to_string(),
            "hardware_measurements": node.attestation.has_hardware_measurements(),
            "measurements_pinned": node.attestation.pinned_measurements().is_some(),
            "mrenclave": node.attestation.mrenclave(),
            "verified_clients": node.attestation.verified_client_count(),
        },

        "audit": {
            "entries_total": node.audit.sequence(),
            "chain_head": node.audit.tail_hash(),
            "chain_valid": chain_valid,
            "chain_checked_at": chain_checked_at,
            "log_verifying_key": node.log_verifying_key_hex(),
        },

        "integrity": {
            "last_check": node.integrity_monitor.last_check_time(),
            "last_check_passed": node.integrity_monitor.last_check_passed(),
            "tamper_detected": node.integrity_monitor.is_tamper_detected(),
        },

        "bundles": node.model_store.list_bundles(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_console_asset_is_present_and_self_contained() {
        assert!(CONSOLE_HTML.contains("<!DOCTYPE html>"));
        assert!(CONSOLE_HTML.contains("Operator Console"));

        // The page must load nothing from the network: a console that reaches
        // out to a CDN is a console that leaks the existence of a Cordon
        // deployment, and one that breaks entirely on an air-gapped host.
        for remote in [
            "http://",
            "https://",
            "//cdn",
            "<script src",
            "<link rel=\"stylesheet\"",
        ] {
            assert!(
                !CONSOLE_HTML.contains(remote),
                "console references a remote resource: {}",
                remote
            );
        }
    }
}
