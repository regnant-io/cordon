//! Cordon Audit Log — Merkle-chained, append-only, client-verifiable
//!
//! Implements §9 of the Cordon spec. Every entry is hashed with its predecessor
//! and signed with the deployment's log signing key. Neither the vendor nor the
//! operator can modify, insert, or delete entries without detection.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod error;
pub mod events;
pub mod export;
pub mod log;
pub mod verify;

pub use error::{AuditError, AuditResult};
pub use events::{
    AdminEvent, AlertSeverity, AlertType, AttestationEvent, AttestationTrigger, AuditEvent,
    AutoAction, EnclaveState as AuditEnclaveState, FinishReason, InferenceEvent, KeyRotationEvent,
    LifecycleEvent, LifecycleEventType, SecurityAlertEvent, TamperEvent,
};
pub use export::{ExportMethod, ExportOptions};
pub use log::{AuditEntry, AuditLog, LogConfig};
pub use verify::{summarize_events, verify_log_chain, VerificationResult};
