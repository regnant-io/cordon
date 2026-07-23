//! Sustained Attack Detector — §10
#![allow(missing_docs)] // AttackPattern variant fields are self-describing
//!
//! Detects attack patterns: brute force auth, replay probes,
//! covert channel attempts, session flooding, and enclave probing.

use std::collections::HashMap;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;

use crate::config::AttackDetectorConfig;

/// Type of detected attack pattern
#[derive(Debug, Clone)]
pub enum AttackPattern {
    /// Too many auth failures from one IP
    AuthFailureFlood {
        source: String,
        count: u32,
    },
    /// Global auth failure rate too high
    GlobalAuthFailureFlood {
        count: u32,
    },
    /// Requests to invalid model IDs
    InvalidModelProbe {
        client_id: String,
        count: u32,
    },
    /// Replay probing (identical inputs)
    ReplayProbe {
        client_id: String,
        input_hash: String,
        count: u32,
    },
    /// High covert channel score repeated
    CovertChannelSuspected {
        client_id: String,
        count: u32,
        max_score: f32,
    },
    /// Rapid session create/teardown
    SessionFlood {
        client_id: String,
        sessions_per_minute: u32,
    },
    /// Elevated enclave exception rate
    EnclaveExceptionFlood {
        exceptions_per_minute: u32,
        baseline: f64,
    },
}

/// Counters per tracked key in a sliding window
struct WindowCounter {
    counts: Vec<(DateTime<Utc>, u32)>,
    window_seconds: i64,
}

impl WindowCounter {
    fn new(window_seconds: i64) -> Self {
        Self {
            counts: Vec::new(),
            window_seconds,
        }
    }

    fn increment(&mut self) -> u32 {
        let now = Utc::now();
        self.counts.push((now, 1));
        self.total_in_window()
    }

    fn total_in_window(&mut self) -> u32 {
        let cutoff = Utc::now() - chrono::Duration::seconds(self.window_seconds);
        self.counts.retain(|(t, _)| *t > cutoff);
        self.counts.iter().map(|(_, c)| c).sum()
    }
}

/// Inner state of the detector
struct DetectorState {
    /// Auth failures per source (IP or client_id)
    auth_failures: HashMap<String, WindowCounter>,
    /// Global auth failure counter
    global_auth_failures: WindowCounter,
    /// Invalid model ID probes per client
    invalid_model_probes: HashMap<String, WindowCounter>,
    /// Identical input hash counts per (client, hash)
    replay_probes: HashMap<(String, String), WindowCounter>,
    /// Covert channel high-score events per client
    covert_channel_events: HashMap<String, (WindowCounter, f32)>,
    /// Session create/teardown events per client
    session_events: HashMap<String, WindowCounter>,
    /// Enclave exceptions
    enclave_exceptions: WindowCounter,
    /// Baseline enclave exception rate (per minute)
    enclave_exception_baseline: f64,
    /// Suspended clients (until when, reason)
    suspended_clients: HashMap<String, (DateTime<Utc>, String)>,
    /// Blocked IPs (until when)
    blocked_ips: HashMap<String, DateTime<Utc>>,
}

impl DetectorState {
    fn new() -> Self {
        Self {
            auth_failures: HashMap::new(),
            global_auth_failures: WindowCounter::new(60),
            invalid_model_probes: HashMap::new(),
            replay_probes: HashMap::new(),
            covert_channel_events: HashMap::new(),
            session_events: HashMap::new(),
            enclave_exceptions: WindowCounter::new(60),
            enclave_exception_baseline: 0.5,
            suspended_clients: HashMap::new(),
            blocked_ips: HashMap::new(),
        }
    }
}

/// Callback type for attack detection events
pub type AttackCallback = Arc<dyn Fn(AttackPattern) + Send + Sync>;

/// Sustained attack detector
pub struct AttackDetector {
    config: AttackDetectorConfig,
    state: Mutex<DetectorState>,
    callbacks: Vec<AttackCallback>,
}

impl AttackDetector {
    /// Create a new attack detector
    pub fn new(config: AttackDetectorConfig) -> Self {
        Self {
            config,
            state: Mutex::new(DetectorState::new()),
            callbacks: Vec::new(),
        }
    }

    /// Add a callback for attack events
    pub fn on_attack<F>(&mut self, f: F)
    where
        F: Fn(AttackPattern) + Send + Sync + 'static,
    {
        self.callbacks.push(Arc::new(f));
    }

    /// Record an authentication failure
    pub fn record_auth_failure(&self, source: &str) {
        let mut state = self.state.lock();

        // Per-source counter
        let per_source = state.auth_failures
            .entry(source.to_string())
            .or_insert_with(|| WindowCounter::new(60));
        let count = per_source.increment();

        // Global counter
        let global = state.global_auth_failures.increment();

        let threshold = self.config.auth_failure_threshold_per_minute;
        let global_threshold = self.config.global_failure_threshold_per_minute;

        if count >= threshold {
            // Block the source IP
            let until = Utc::now() + chrono::Duration::seconds(3600);
            state.blocked_ips.insert(source.to_string(), until);
            let pattern = AttackPattern::AuthFailureFlood {
                source: source.to_string(),
                count,
            };
            drop(state);
            self.fire(pattern);
            tracing::warn!("IP {} blocked for 1 hour: {} auth failures in last minute", source, count);
            return;
        }

        if global >= global_threshold {
            let pattern = AttackPattern::GlobalAuthFailureFlood { count: global };
            drop(state);
            self.fire(pattern);
            tracing::warn!("Global auth failure rate: {}/min — possible distributed attack", global);
        }
    }

    /// Check whether a source IP is currently blocked
    pub fn is_ip_blocked(&self, source: &str) -> bool {
        let mut state = self.state.lock();
        let now = Utc::now();
        if let Some(until) = state.blocked_ips.get(source) {
            if *until > now {
                return true;
            } else {
                state.blocked_ips.remove(source);
            }
        }
        false
    }

    /// Record an invalid model ID probe
    pub fn record_invalid_model(&self, client_id: &str) {
        let mut state = self.state.lock();
        let counter = state.invalid_model_probes
            .entry(client_id.to_string())
            .or_insert_with(|| WindowCounter::new(300)); // 5-min window
        let count = counter.increment();

        if count >= 5 {
            let pattern = AttackPattern::InvalidModelProbe {
                client_id: client_id.to_string(),
                count,
            };
            let until = Utc::now() + chrono::Duration::seconds(3600);
            state.suspended_clients.insert(
                client_id.to_string(),
                (until, format!("Invalid model probe: {} attempts", count))
            );
            drop(state);
            self.fire(pattern);
            tracing::warn!("Client {} suspended: {} invalid model probes", client_id, count);
        }
    }

    /// Record a replay probe (identical input hash)
    pub fn record_input_hash(&self, client_id: &str, input_hash: &str) -> bool {
        let mut state = self.state.lock();
        let key = (client_id.to_string(), input_hash.to_string());
        let counter = state.replay_probes
            .entry(key)
            .or_insert_with(|| WindowCounter::new(3600)); // 1-hour window
        let count = counter.increment();

        if count >= self.config.replay_probe_threshold {
            let pattern = AttackPattern::ReplayProbe {
                client_id: client_id.to_string(),
                input_hash: input_hash.to_string(),
                count,
            };
            drop(state);
            self.fire(pattern);
            tracing::warn!(
                "Replay probe detected: client {} sent identical input {} times",
                client_id, count
            );
            return true; // Caller should rate-limit
        }
        false
    }

    /// Record a high covert channel score
    pub fn record_covert_channel_score(&self, client_id: &str, score: f32) -> bool {
        let threshold = self.config.covert_channel_score_threshold;
        if score < threshold {
            return false;
        }

        let mut state = self.state.lock();
        let entry = state.covert_channel_events
            .entry(client_id.to_string())
            .or_insert_with(|| (WindowCounter::new(3600), 0.0));

        entry.0.increment();
        entry.1 = entry.1.max(score);
        let count = entry.0.total_in_window();
        let max_score = entry.1;

        if count >= 3 {
            let pattern = AttackPattern::CovertChannelSuspected {
                client_id: client_id.to_string(),
                count,
                max_score,
            };
            let until = Utc::now() + chrono::Duration::seconds(3600);
            state.suspended_clients.insert(
                client_id.to_string(),
                (until, format!("Covert channel suspected: score {:.2}, {} events", max_score, count))
            );
            drop(state);
            self.fire(pattern);
            tracing::warn!(
                "Client {} suspended: covert channel suspected (score {:.2}, {} events)",
                client_id, max_score, count
            );
            return true;
        }
        false
    }

    /// Record a session creation/teardown event
    pub fn record_session_event(&self, client_id: &str) {
        let mut state = self.state.lock();
        let counter = state.session_events
            .entry(client_id.to_string())
            .or_insert_with(|| WindowCounter::new(60));
        let count = counter.increment();

        if count >= 100 {
            let pattern = AttackPattern::SessionFlood {
                client_id: client_id.to_string(),
                sessions_per_minute: count,
            };
            drop(state);
            self.fire(pattern);
        }
    }

    /// Record an enclave exception
    pub fn record_enclave_exception(&self) {
        let mut state = self.state.lock();
        let count = state.enclave_exceptions.increment();
        let baseline = state.enclave_exception_baseline;

        // Alert if >3 sigma above baseline
        let expected_per_minute = baseline;
        let z_score = if expected_per_minute > 0.0 {
            (count as f64 - expected_per_minute) / expected_per_minute.sqrt()
        } else {
            count as f64
        };

        if z_score > 3.0 {
            let pattern = AttackPattern::EnclaveExceptionFlood {
                exceptions_per_minute: count,
                baseline,
            };
            drop(state);
            self.fire(pattern);
            tracing::warn!(
                "Enclave exception rate {}x above baseline — possible TEE probing attack",
                count as f64 / baseline.max(0.1)
            );
        }
    }

    /// Check whether a client is currently suspended
    pub fn is_client_suspended(&self, client_id: &str) -> Option<String> {
        let mut state = self.state.lock();
        let now = Utc::now();
        if let Some((until, reason)) = state.suspended_clients.get(client_id) {
            if *until > now {
                return Some(reason.clone());
            } else {
                state.suspended_clients.remove(client_id);
            }
        }
        None
    }

    /// Fire a callback for all registered listeners
    fn fire(&self, pattern: AttackPattern) {
        for cb in &self.callbacks {
            cb(pattern.clone());
        }
    }

    /// Prune expired entries
    pub fn cleanup(&self) {
        let now = Utc::now();
        let mut state = self.state.lock();
        state.blocked_ips.retain(|_, until| *until > now);
        state.suspended_clients.retain(|_, (until, _)| *until > now);
    }
}
