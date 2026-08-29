//! Cordon Core — runtime, configuration, request processing, all layers
//!
//! This crate implements the full Cordon v2.0 architecture from §2 of the spec:
//! Layer 0 (Hardware RoT), Layer 1 (Perimeter), Layer 2 (TEE),
//! Layer 3 (Model Store), Layer 4 (Inference), Layer 5 (Response Pipeline),
//! Layer 6 (Audit), plus cross-cutting concerns.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod attack_detector;
pub mod attestation_service;
pub mod config;
pub mod covert_channel;
pub mod error;
pub mod hub;
pub mod identity;
pub mod inference;
pub mod integrity_monitor;
pub mod metrics;
pub mod model_store;
pub mod node;
pub mod output_filter;
pub mod rate_limiter;
pub mod runtime;
pub mod state;
pub mod timing;
pub mod tpm;

pub use config::{
    AuditConfig, CordonConfig, DeploymentMode, MeasurementSource, NetworkConfig, RuntimeBackend,
    TeeConfig,
};
pub use error::{CordonError, CordonResult};
pub use node::{CordonNode, KeyProvenance};
pub use state::{EnclaveState, NodeState, NodeStatus};
