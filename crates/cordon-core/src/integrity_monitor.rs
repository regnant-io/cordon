//! Continuous integrity monitor.
//!
//! Every `integrity_check_interval_minutes`, every ciphertext shard of every
//! registered bundle is streamed and hashed against its manifest digest. A
//! mismatch withdraws the bundle from service and, when `halt_on_tamper` is set,
//! quarantines the node.
//!
//! The interval is also the lifetime of a verdict on the serving path, so a
//! monitor that stops running takes the node out of service rather than leaving
//! it serving weights nobody has confirmed lately.
//!
//! # Why the check runs on a blocking thread
//!
//! [`ModelStore::run_integrity_check`] streams whole shards off disk. On a
//! multi-gigabyte bundle that is seconds to minutes of uninterrupted
//! synchronous I/O and hashing. Running it directly inside a `tokio::spawn`
//! would occupy one of the runtime's worker threads for that whole time, and
//! every request scheduled onto that worker would stall behind it; turning a
//! background integrity check into a periodic latency spike. It runs on
//! `spawn_blocking` instead.

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::{interval, Duration};

use cordon_audit::events::{AuditEvent, TamperEvent, TamperSource};
use cordon_audit::AuditLog;

use crate::error::CordonResult;
use crate::model_store::ModelStore;
use crate::state::SharedNodeState;

/// Integrity monitor state
pub struct IntegrityMonitor {
    model_store: Arc<ModelStore>,
    node_state: SharedNodeState,
    /// Flag set to true if tamper is detected; caller should halt
    tamper_detected: Arc<AtomicBool>,
    /// Last check time
    last_check: Mutex<Option<DateTime<Utc>>>,
    /// Last check result
    last_result: Mutex<bool>,
    /// Check interval in minutes
    interval_minutes: u64,
    /// Whether to halt on tamper
    halt_on_tamper: bool,
    /// Where tamper findings are recorded.
    ///
    /// A weight-integrity violation used to reach `tracing` and nothing else,
    /// so the one event most worth having a durable, tamper-evident record of
    /// left none. Optional because the monitor is constructed before the log in
    /// some orders; a monitor without one still quarantines.
    audit: Mutex<Option<Arc<AuditLog>>>,
}

impl IntegrityMonitor {
    /// Create a new integrity monitor
    pub fn new(
        model_store: Arc<ModelStore>,
        node_state: SharedNodeState,
        interval_minutes: u64,
        halt_on_tamper: bool,
    ) -> (Self, Arc<AtomicBool>) {
        let tamper_flag = Arc::new(AtomicBool::new(false));
        let monitor = Self {
            model_store,
            node_state,
            tamper_detected: tamper_flag.clone(),
            last_check: Mutex::new(None),
            last_result: Mutex::new(true),
            interval_minutes,
            halt_on_tamper,
            audit: Mutex::new(None),
        };
        (monitor, tamper_flag)
    }

    /// Record tamper findings to this audit log.
    pub fn attach_audit_log(&self, audit: Arc<AuditLog>) {
        *self.audit.lock() = Some(audit);
    }

    /// Run a single integrity check cycle.
    ///
    /// **Blocking.** Hashes every shard of every bundle. Call it from
    /// [`Self::run_check_blocking`], or from your own `spawn_blocking`, never
    /// directly from an async task.
    pub fn run_check(&self) -> CordonResult<bool> {
        let bundle_ids = self.model_store.bundle_ids();

        let mut all_passed = true;

        for bundle_id in &bundle_ids {
            match self.model_store.run_integrity_check(bundle_id) {
                Ok(true) => {
                    tracing::debug!("Integrity check passed for bundle {}", bundle_id);
                }
                Ok(false) => {
                    tracing::error!(
                        "INTEGRITY VIOLATION: bundle {} failed ciphertext hash check",
                        bundle_id
                    );
                    all_passed = false;
                    self.record_tamper(bundle_id);

                    if self.halt_on_tamper {
                        self.tamper_detected.store(true, Ordering::SeqCst);
                        tracing::error!(
                            "HALTING INFERENCE: integrity violation in bundle {}",
                            bundle_id
                        );
                        self.node_state.enter_quarantine();
                    }
                }
                Err(e) => {
                    tracing::error!("Integrity check error for {}: {}", bundle_id, e);
                    all_passed = false;
                }
            }
        }

        *self.last_check.lock() = Some(Utc::now());
        *self.last_result.lock() = all_passed;

        Ok(all_passed)
    }

    /// Run one check cycle on a blocking thread, off the async runtime.
    ///
    /// This is the entry point every async caller should use.
    pub async fn run_check_blocking(self: Arc<Self>) -> CordonResult<bool> {
        tokio::task::spawn_blocking(move || self.run_check())
            .await
            .map_err(|e| {
                crate::error::CordonError::Internal(format!("integrity check task failed: {}", e))
            })?
    }

    /// Start the background integrity monitoring loop.
    pub fn start(self: Arc<Self>) {
        let interval_secs = self.interval_minutes.max(1) * 60;
        tokio::spawn(async move {
            // Initial delay; let the node finish coming up before the first check.
            tokio::time::sleep(Duration::from_secs(30)).await;

            let mut ticker = interval(Duration::from_secs(interval_secs));
            loop {
                ticker.tick().await;

                // Once tamper is confirmed the bundle is already out of service
                // and the node is quarantined; re-hashing it every interval adds
                // nothing but I/O.
                if self.tamper_detected.load(Ordering::SeqCst) {
                    tracing::warn!("Integrity monitor: tamper already detected; skipping check");
                    continue;
                }

                // Hashing every shard is long, synchronous work. Handing it to a
                // blocking thread keeps it off the runtime's workers, where it
                // would otherwise stall every request scheduled behind it.
                match self.clone().run_check_blocking().await {
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::error!("Integrity monitor: check FAILED");
                    }
                    Err(e) => {
                        tracing::error!("Integrity monitor: check error: {}", e);
                    }
                }
            }
        });
    }

    /// Write a tamper record, so the finding survives the process that made it.
    fn record_tamper(&self, bundle_id: &str) {
        let Some(audit) = self.audit.lock().clone() else {
            return;
        };
        let _ = audit.append(AuditEvent::Tamper(TamperEvent {
            source: TamperSource::WeightIntegrity,
            // Cordon holds no HSM and does not zeroize on tamper; it withdraws
            // the bundle and quarantines. Reporting a response that did not
            // happen would be worse than reporting none.
            hsm_zeroized: false,
            enclave_zeroized: self.halt_on_tamper,
            recovery_required: vec![
                format!("bundle {} failed its ciphertext digest check", bundle_id),
                "restore the bundle from provisioning media, or re-encrypt it with                  cordon-provision"
                    .to_string(),
                "then POST /v1/admin/recover with an admin signature".to_string(),
            ],
        }));
    }

    /// Get last check time
    pub fn last_check_time(&self) -> Option<DateTime<Utc>> {
        *self.last_check.lock()
    }

    /// Get last check result
    pub fn last_check_passed(&self) -> bool {
        *self.last_result.lock()
    }

    /// Whether tamper has been detected
    pub fn is_tamper_detected(&self) -> bool {
        self.tamper_detected.load(Ordering::SeqCst)
    }

    /// Reset tamper flag (operator recovery only)
    pub fn reset_tamper(&self) {
        self.tamper_detected.store(false, Ordering::SeqCst);
        *self.last_result.lock() = true;
        tracing::info!("Integrity monitor tamper flag reset by operator");
    }
}
