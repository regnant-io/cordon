//! Cordon Audit Log — Merkle-chained, append-only, client-verifiable
//!
//! Implements §9 of the Cordon spec. Every entry is hashed with its predecessor
//! and signed with the deployment's log signing key. Neither the vendor nor the
//! operator can modify, insert, or delete entries without detection.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod error;
pub mod log;
pub mod events;
pub mod verify;
pub mod export;

pub use error::{AuditError, AuditResult};
pub use log::{AuditLog, AuditEntry, LogConfig};
pub use events::{
    AuditEvent, InferenceEvent, SecurityAlertEvent, AdminEvent, AttestationEvent,
    KeyRotationEvent, TamperEvent, AlertSeverity, AlertType, AutoAction,
    FinishReason, EnclaveState as AuditEnclaveState, LifecycleEvent, LifecycleEventType,
    AttestationTrigger,
};
pub use verify::{verify_log_chain, VerificationResult, summarize_events};
pub use export::{ExportOptions, ExportMethod};
