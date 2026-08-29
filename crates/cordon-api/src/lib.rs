//! Cordon API Server — §17
//!
//! Implements all endpoints: /v1/inference, /v1/attestation, /v1/models,
//! /v1/audit, /v1/admin, /v1/health.
//! All endpoints require mTLS with client-issued certificates (except basic health).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod handlers;
pub mod middleware;
pub mod router;
pub mod server;
pub mod tls;
pub mod types;
pub mod ui;

pub use router::{build_api_router, build_metrics_router, build_ui_router};
pub use server::ApiServer;
