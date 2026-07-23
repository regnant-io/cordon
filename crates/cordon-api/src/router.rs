//! Axum router — mounts all API endpoints with middleware

use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use tower::ServiceBuilder;
use tower_http::timeout::TimeoutLayer;
use std::time::Duration;

use crate::{
    handlers::{self, AppState},
    middleware::{inject_request_id, populate_identity, request_logging, security_headers},
    ui,
};

/// Build the full Axum router with all routes and middleware
pub fn build_router(state: AppState) -> Router {
    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/v1/health", get(handlers::health_basic));

    // UI routes (no auth — dev tool)
    let ui_routes = Router::new()
        .route("/ui", get(ui::ui_landing))
        .route("/ui/chat", get(ui::ui_chat))
        .route("/ui/endpoints", get(ui::ui_endpoints))
        .route("/ui/docs", get(ui::ui_docs))
        .with_state(state.clone());

    // Authenticated routes
    let authed_routes = Router::new()
        // Health
        .route("/v1/health/detailed", get(handlers::health_detailed))

        // Inference
        .route("/v1/inference", post(handlers::inference))
        .route("/v1/inference/stream", post(handlers::inference_stream))

        // Attestation
        .route("/v1/attestation", get(handlers::get_attestation))
        .route("/v1/attestation/verify", post(handlers::verify_attestation))
        .route("/v1/attestation/refresh", post(handlers::refresh_attestation))

        // Models
        .route("/v1/models", get(handlers::list_models).post(handlers::provision_model))

        // Audit
        .route("/v1/audit/verify", get(handlers::audit_verify))
        .route("/v1/audit/tail", get(handlers::audit_tail))
        .route("/v1/audit/anchor", post(handlers::audit_anchor))

        // Admin
        .route("/v1/admin/teardown", post(handlers::admin_teardown))
        .route("/v1/admin/recover", post(handlers::admin_recover))
        .route("/v1/admin/quarantine", post(handlers::admin_quarantine))
        .route("/v1/admin/key-rotate", post(handlers::admin_key_rotate))
        .route("/v1/admin/update", post(handlers::admin_update));

    // Metrics (localhost-only — enforced at network layer)
    let metrics_routes = Router::new()
        .route("/metrics", get(handlers::metrics));

    // Combine all routes with shared state and middleware
    Router::new()
        .merge(public_routes)
        .merge(ui_routes)
        .merge(authed_routes)
        .merge(metrics_routes)
        .with_state(state)
        .layer(
            ServiceBuilder::new()
                .layer(middleware::from_fn(security_headers))
                .layer(middleware::from_fn(request_logging))
                .layer(middleware::from_fn(inject_request_id))
                // Ensure every request carries a VerifiedIdentity (cert-derived
                // when mTLS; header-derived + unverified on --no-tls dev).
                .layer(middleware::from_fn(populate_identity))
                .layer(TimeoutLayer::new(Duration::from_secs(300))),
        )
}
