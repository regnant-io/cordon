//! Cordon Core — runtime, configuration, request processing, all layers
//!
//! This crate implements the full Cordon v2.0 architecture from §2 of the spec:
//! Layer 0 (Hardware RoT), Layer 1 (Perimeter), Layer 2 (TEE),
//! Layer 3 (Model Store), Layer 4 (Inference), Layer 5 (Response Pipeline),
//! Layer 6 (Audit), plus cross-cutting concerns.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod error;
pub mod state;
pub mod identity;
pub mod rate_limiter;
pub mod model_store;
pub mod inference;
pub mod output_filter;
pub mod covert_channel;
pub mod timing;
pub mod attestation_service;
pub mod tpm;
pub mod integrity_monitor;
pub mod attack_detector;
pub mod metrics;
pub mod node;

pub use config::{CordonConfig, DeploymentMode, TeeConfig, NetworkConfig, AuditConfig};
pub use error::{CordonError, CordonResult};
pub use state::{NodeState, EnclaveState, NodeStatus};
pub use node::{CordonNode, KeyProvenance};
