//! Continuous Integrity Monitor — §6.5
//!
//! Background process: every 15 minutes, samples 5–10% of ciphertext weight
//! shards, hashes them, compares against manifest. Any mismatch → halt immediately.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use tokio::time::{interval, Duration};

use crate::error::CordonResult;
use crate::model_store::ModelStore;
use crate::state::SharedNodeState;

/// Integrity monitor state
pub struct IntegrityMonitor {
    model_store: Arc<ModelStore>,
    node_state: SharedNodeState,
    /// Flag set to true if tamper is detected — caller should halt
    tamper_detected: Arc<AtomicBool>,
    /// Last check time
    last_check: Mutex<Option<DateTime<Utc>>>,
    /// Last check result
    last_result: Mutex<bool>,
    /// Check interval in minutes
    interval_minutes: u64,
    /// Whether to halt on tamper
    halt_on_tamper: bool,
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
        };
        (monitor, tamper_flag)
    }

    /// Run a single integrity check cycle
    pub fn run_check(&self) -> CordonResult<bool> {
        let bundle_ids: Vec<String> = self.model_store
            .list_bundles()
            .into_iter()
            .map(|(id, _)| id)
            .collect();

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

    /// Start the background integrity monitoring loop
    pub fn start(self: Arc<Self>) {
        let interval_secs = self.interval_minutes * 60;
        tokio::spawn(async move {
            // Initial delay — let system initialize before first check
            tokio::time::sleep(Duration::from_secs(30)).await;

            let mut ticker = interval(Duration::from_secs(interval_secs));
            loop {
                ticker.tick().await;

                // Don't check if tamper already detected
                if self.tamper_detected.load(Ordering::SeqCst) {
                    tracing::warn!("Integrity monitor: tamper already detected — skipping check");
                    continue;
                }

                match self.run_check() {
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
