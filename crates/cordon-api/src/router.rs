//! Route table.
//!
//! Three routers are built here, and they are mounted on different listeners:
//!
//! * [`build_api_router`] — the client API, on the configured bind address.
//! * [`build_metrics_router`] — Prometheus output, refused unless the peer is on
//!   loopback.
//! * [`build_ui_router`] — the operator console, mounted only when the console
//!   is enabled and only on its own loopback listener.
//!
//! Keeping them separate is what makes the console's loopback restriction real:
//! it is not a path prefix that middleware has to remember to guard, it is a
//! socket that is never bound to a routable address.

use std::time::Duration;

use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use crate::{
    handlers::{self, AppState},
    middleware::{
        inject_peer_addr, inject_request_id, populate_identity, request_logging, require_loopback,
        security_headers,
    },
    ui,
};

/// Build the client-facing API router.
pub fn build_api_router(state: AppState) -> Router {
    let max_body = state.node.config.limits.max_request_bytes;
    // The router-level timeout is a backstop well above the per-request
    // inference deadline, which the node enforces itself. Streaming responses
    // must not be cut off by it.
    let request_timeout = Duration::from_secs(
        state
            .node
            .config
            .inference
            .default_timeout_seconds
            .saturating_mul(2)
            .max(60),
    );

    let public = Router::new().route("/v1/health", get(handlers::health_basic));

    let authenticated = Router::new()
        .route("/v1/health/detailed", get(handlers::health_detailed))
        .route("/v1/health/runtime", get(handlers::health_runtime))
        .route("/v1/inference", post(handlers::inference))
        .route("/v1/inference/stream", post(handlers::inference_stream))
        .route("/v1/attestation", get(handlers::get_attestation))
        .route("/v1/attestation/verify", post(handlers::verify_attestation))
        .route(
            "/v1/models",
            get(handlers::list_models).post(handlers::provision_model),
        )
        .route("/v1/audit/verify", get(handlers::audit_verify))
        .route("/v1/audit/tail", get(handlers::audit_tail))
        .route("/v1/audit/anchor", get(handlers::audit_anchor))
        .route("/v1/admin/teardown", post(handlers::admin_teardown))
        .route("/v1/admin/recover", post(handlers::admin_recover))
        .route("/v1/admin/quarantine", post(handlers::admin_quarantine))
        .route(
            "/v1/admin/suspend-client",
            post(handlers::admin_suspend_client),
        );

    Router::new()
        .merge(public)
        .merge(authenticated)
        .with_state(state)
        .layer(
            ServiceBuilder::new()
                .layer(middleware::from_fn(security_headers))
                .layer(middleware::from_fn(request_logging))
                .layer(middleware::from_fn(inject_request_id))
                .layer(middleware::from_fn(inject_peer_addr))
                .layer(middleware::from_fn(populate_identity))
                // Bound the body before it is buffered, so an oversized request
                // is refused rather than held in memory.
                .layer(RequestBodyLimitLayer::new(max_body))
                .layer(TimeoutLayer::new(request_timeout)),
        )
}

/// Build the metrics router. Mounted on the API listener but refused for any
/// peer that is not on loopback.
pub fn build_metrics_router(state: AppState) -> Router {
    Router::new()
        .route("/metrics", get(handlers::metrics))
        .with_state(state)
        .layer(
            ServiceBuilder::new()
                .layer(middleware::from_fn(security_headers))
                .layer(middleware::from_fn(inject_peer_addr))
                .layer(middleware::from_fn(require_loopback))
                .layer(TimeoutLayer::new(Duration::from_secs(10))),
        )
}

/// Build the operator console router.
///
/// The console is served on its own loopback listener. It has no authentication
/// of its own — reachability *is* its access control — which is why
/// [`CordonConfig::validate`](cordon_core::CordonConfig::validate) refuses to
/// enable it outside Light mode or on a routable address.
///
/// Inference is mounted here too, rather than the page calling the API listener
/// directly. The console is a different origin from the API, so a direct call
/// would need cross-origin headers on the API — and widening the API's CORS
/// policy to accommodate a development console is a poor trade. Proxying keeps
/// the console same-origin and leaves the API's policy closed.
///
/// These routes run the identical pipeline as their API counterparts, including
/// identity resolution: a console request is audited under the client ID it
/// claims, and is refused outright if the deployment requires mTLS.
pub fn build_ui_router(state: AppState) -> Router {
    let max_body = state.node.config.limits.max_request_bytes;
    let request_timeout = Duration::from_secs(
        state
            .node
            .config
            .inference
            .default_timeout_seconds
            .saturating_mul(2)
            .max(60),
    );

    Router::new()
        .route("/", get(ui::console))
        .route("/api/status", get(ui::status))
        .route("/api/inference", post(handlers::inference))
        .route("/api/inference/stream", post(handlers::inference_stream))
        .with_state(state)
        .layer(
            ServiceBuilder::new()
                .layer(middleware::from_fn(ui::console_headers))
                .layer(middleware::from_fn(request_logging))
                .layer(middleware::from_fn(inject_request_id))
                .layer(middleware::from_fn(populate_identity))
                .layer(RequestBodyLimitLayer::new(max_body))
                .layer(TimeoutLayer::new(request_timeout)),
        )
}
