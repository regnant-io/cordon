//! Cordon API Server — §17
//!
//! Implements all endpoints: /v1/inference, /v1/attestation, /v1/models,
//! /v1/audit, /v1/admin, /v1/health.
//! All endpoints require mTLS with client-issued certificates (except basic health).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod handlers;
pub mod middleware;
pub mod router;
pub mod tls;
pub mod server;
pub mod types;
pub mod error;
pub mod ui;

pub use server::ApiServer;
pub use router::build_router;
