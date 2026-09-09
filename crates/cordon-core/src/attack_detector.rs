//! Sustained attack detector.
#![allow(missing_docs)] // AttackPattern variant fields are self-describing
//!
//! Detects patterns that only show up across requests: brute-forced
//! authentication, replay probing, repeated covert-channel hits, session
//! flooding, and enclave probing.
//!
//! # Every counter here is bounded
//!
//! This module tracks per-source and per-client state keyed on values the
//! caller controls — a client ID, a peer fingerprint, and, for replay
//! detection, the hash of a prompt. Left alone, each of those maps grows
//! without limit: a client varying its prompt adds an entry per distinct
//! request, forever, and `cleanup` used to prune only blocks and suspensions.
//! That is a slow memory exhaustion available to any authenticated caller, and
//! it contradicts the bound the architecture document claims.
//!
//! Two mechanisms keep it bounded. Each map has a hard capacity, and reaching
//! it evicts entries whose window has already lapsed before admitting anything
//! new — falling back to refusing the new entry if every entry is still live,
//! which degrades detection rather than memory. And `cleanup`, which the node
//! runs on a timer, now prunes every map rather than two of them.
//!
//! Within a window, each counter stores one timestamp per event, so a
//! counter is also capped: a burst beyond the cap is counted as the cap, which
//! is above every threshold that matters anyway.

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::AttackDetectorConfig;

/// Type of detected attack pattern
#[derive(Debug, Clone)]
pub enum AttackPattern {
    /// Too many auth failures from one IP
    AuthFailureFlood { source: String, count: u32 },
    /// Global auth failure rate too high
    GlobalAuthFailureFlood { count: u32 },
    /// Requests to invalid model IDs
    InvalidModelProbe { client_id: String, count: u32 },
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

/// Most distinct keys any one detector map will hold.
///
/// Reaching this evicts lapsed entries first; if every entry is still within
/// its window, the new key is not admitted. Losing detection fidelity under a
/// flood is the right trade against unbounded growth — the flood itself is
/// already being counted by the global auth-failure counter, which is a single
/// entry and cannot be evicted.
const MAX_TRACKED_KEYS: usize = 16_384;

/// Most events one counter retains inside its window.
///
/// Every threshold in this module is in the tens, so a counter that saturates
/// here still fires everything it should. It exists to stop a single key from
/// accumulating one timestamp per request for the length of its window — an
/// hour, for replay probing.
const MAX_EVENTS_PER_COUNTER: usize = 512;

/// Counters per tracked key in a sliding window.
struct WindowCounter {
    /// Timestamps of events still inside the window, oldest first.
    events: Vec<DateTime<Utc>>,
    /// Events dropped because the counter was already at capacity, so a
    /// saturated counter still reports a total above every threshold.
    saturated_by: u32,
    window_seconds: i64,
}

impl WindowCounter {
    fn new(window_seconds: i64) -> Self {
        Self {
            events: Vec::new(),
            saturated_by: 0,
            window_seconds,
        }
    }

    fn increment(&mut self) -> u32 {
        self.prune();
        if self.events.len() >= MAX_EVENTS_PER_COUNTER {
            self.saturated_by = self.saturated_by.saturating_add(1);
        } else {
            self.events.push(Utc::now());
        }
        self.total()
    }

    /// Drop events that have fallen out of the window.
    ///
    /// Timestamps are pushed in order, so the live events are always a suffix
    /// and the lapsed ones a prefix — found by binary search rather than by
    /// scanning, which matters for a counter holding hundreds of entries that
    /// is touched on every request.
    fn prune(&mut self) {
        let cutoff = Utc::now() - chrono::Duration::seconds(self.window_seconds);
        let first_live = self.events.partition_point(|t| *t <= cutoff);
        if first_live > 0 {
            self.events.drain(..first_live);
            // A counter that has emptied has nothing left to saturate over.
            if self.events.is_empty() {
                self.saturated_by = 0;
            }
        }
    }

    fn total(&self) -> u32 {
        (self.events.len() as u32).saturating_add(self.saturated_by)
    }

    fn total_in_window(&mut self) -> u32 {
        self.prune();
        self.total()
    }

    /// Whether this counter holds no events inside its window, and so can be
    /// evicted without losing anything.
    fn is_lapsed(&mut self) -> bool {
        self.prune();
        self.events.is_empty()
    }
}

/// How often a saturated map is swept for lapsed entries.
///
/// Sweeping is linear in the size of the map. Doing it on every insert once the
/// map is full makes admission quadratic in the number of distinct keys, which
/// hands an attacker a cheaper denial of service than the memory growth the cap
/// was added to prevent. Once per second bounds the sweeping work to a fixed
/// fraction of a core no matter how fast keys arrive.
const SWEEP_INTERVAL_SECONDS: i64 = 1;

/// A capacity-bounded map of sliding-window counters.
///
/// Admission evicts entries whose window has lapsed before it refuses anything.
/// When every entry is still live and the map is full, a new key is simply not
/// tracked: detection fidelity degrades, memory does not grow.
struct BoundedCounters<K> {
    counters: HashMap<K, WindowCounter>,
    window_seconds: i64,
    last_sweep: DateTime<Utc>,
}

impl<K: std::hash::Hash + Eq> BoundedCounters<K> {
    fn new(window_seconds: i64) -> Self {
        Self {
            counters: HashMap::new(),
            window_seconds,
            last_sweep: Utc::now(),
        }
    }

    /// Count one event against `key`, returning the total inside the window.
    ///
    /// `None` means the map was full of live entries and the key was not
    /// admitted.
    fn record(&mut self, key: K) -> Option<u32> {
        if !self.counters.contains_key(&key) && self.counters.len() >= MAX_TRACKED_KEYS {
            self.sweep_if_due();
            if self.counters.len() >= MAX_TRACKED_KEYS {
                return None;
            }
        }
        let window = self.window_seconds;
        Some(
            self.counters
                .entry(key)
                .or_insert_with(|| WindowCounter::new(window))
                .increment(),
        )
    }

    /// Drop every counter whose window has lapsed.
    fn prune_lapsed(&mut self) {
        self.counters.retain(|_, counter| !counter.is_lapsed());
        self.last_sweep = Utc::now();
    }

    /// Sweep, but no more than once per [`SWEEP_INTERVAL_SECONDS`].
    fn sweep_if_due(&mut self) {
        let now = Utc::now();
        if (now - self.last_sweep).num_seconds() < SWEEP_INTERVAL_SECONDS {
            return;
        }
        let before = self.counters.len();
        self.prune_lapsed();
        if self.counters.len() >= MAX_TRACKED_KEYS {
            tracing::warn!(
                tracked = self.counters.len(),
                freed = before - self.counters.len(),
                "Attack detector is at capacity with live entries; new keys are not \
                 being tracked. Detection fidelity is reduced until windows lapse."
            );
        }
    }

    fn len(&self) -> usize {
        self.counters.len()
    }
}

/// Inner state of the detector.
///
/// Every map keyed on something a caller controls is a [`BoundedCounters`].
/// The two bare [`WindowCounter`]s are global, single-entry totals that no
/// caller can multiply.
struct DetectorState {
    /// Auth failures per source (peer fingerprint).
    auth_failures: BoundedCounters<String>,
    /// Global auth failure counter — one entry, never evicted.
    global_auth_failures: WindowCounter,
    /// Invalid model ID probes per client.
    invalid_model_probes: BoundedCounters<String>,
    /// Identical input hash counts per (client, prompt digest).
    replay_probes: BoundedCounters<(String, String)>,
    /// Covert channel high-score events per client, with the highest score seen.
    covert_channel_events: HashMap<String, (WindowCounter, f32)>,
    /// Session create/teardown events per client.
    session_events: BoundedCounters<String>,
    /// Enclave exceptions — one entry, never evicted.
    enclave_exceptions: WindowCounter,
    /// Baseline enclave exception rate (per minute).
    enclave_exception_baseline: f64,
    /// Suspended clients (until when, reason).
    suspended_clients: HashMap<String, (DateTime<Utc>, String)>,
    /// Blocked sources (until when).
    blocked_ips: HashMap<String, DateTime<Utc>>,
}

impl DetectorState {
    fn new() -> Self {
        Self {
            auth_failures: BoundedCounters::new(60),
            global_auth_failures: WindowCounter::new(60),
            invalid_model_probes: BoundedCounters::new(300),
            replay_probes: BoundedCounters::new(3600),
            covert_channel_events: HashMap::new(),
            session_events: BoundedCounters::new(60),
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

        // Per-source counter. When the map is saturated the source is not
        // tracked individually, but the global counter below still sees it —
        // which is the counter that matters during a distributed flood.
        let count = state.auth_failures.record(source.to_string()).unwrap_or(0);

        // Global counter. A single entry, never evicted.
        let global = state.global_auth_failures.increment();

        let threshold = self.config.auth_failure_threshold_per_minute;
        let global_threshold = self.config.global_failure_threshold_per_minute;

        if count > 0 && count >= threshold {
            // Block the source IP
            let until = Utc::now() + chrono::Duration::seconds(3600);
            state.blocked_ips.insert(source.to_string(), until);
            let pattern = AttackPattern::AuthFailureFlood {
                source: source.to_string(),
                count,
            };
            drop(state);
            self.fire(pattern);
            tracing::warn!(
                "IP {} blocked for 1 hour: {} auth failures in last minute",
                source,
                count
            );
            return;
        }

        if global >= global_threshold {
            let pattern = AttackPattern::GlobalAuthFailureFlood { count: global };
            drop(state);
            self.fire(pattern);
            tracing::warn!(
                "Global auth failure rate: {}/min — possible distributed attack",
                global
            );
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
        let Some(count) = state.invalid_model_probes.record(client_id.to_string()) else {
            return;
        };

        if count >= 5 {
            let pattern = AttackPattern::InvalidModelProbe {
                client_id: client_id.to_string(),
                count,
            };
            let until = Utc::now() + chrono::Duration::seconds(3600);
            state.suspended_clients.insert(
                client_id.to_string(),
                (until, format!("Invalid model probe: {} attempts", count)),
            );
            drop(state);
            self.fire(pattern);
            tracing::warn!(
                "Client {} suspended: {} invalid model probes",
                client_id,
                count
            );
        }
    }

    /// Record a replay probe (identical input hash)
    pub fn record_input_hash(&self, client_id: &str, input_hash: &str) -> bool {
        let mut state = self.state.lock();
        // Keyed on (client, prompt digest) over a 1-hour window. This is the
        // map a client can grow fastest — one entry per distinct prompt — so
        // the capacity bound matters most here.
        let key = (client_id.to_string(), input_hash.to_string());
        let Some(count) = state.replay_probes.record(key) else {
            return false;
        };

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
                client_id,
                count
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
        let entry = state
            .covert_channel_events
            .entry(client_id.to_string())
            .or_insert_with(|| (WindowCounter::new(3600), 0.0));

        // Unlike the other maps this one is only reached by a client whose
        // output already scored above the detection threshold, so it cannot be
        // grown cheaply. `cleanup` prunes it on the same timer as the rest.
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
                (
                    until,
                    format!(
                        "Covert channel suspected: score {:.2}, {} events",
                        max_score, count
                    ),
                ),
            );
            drop(state);
            self.fire(pattern);
            tracing::warn!(
                "Client {} suspended: covert channel suspected (score {:.2}, {} events)",
                client_id,
                max_score,
                count
            );
            return true;
        }
        false
    }

    /// Record a session creation/teardown event
    pub fn record_session_event(&self, client_id: &str) {
        let mut state = self.state.lock();
        let Some(count) = state.session_events.record(client_id.to_string()) else {
            return;
        };

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

    /// Prune every expired entry, in every map.
    ///
    /// Called on a timer by the node. An earlier version pruned only blocks and
    /// suspensions, which left the five counter maps — including the one keyed
    /// on prompt digests — growing for the life of the process.
    pub fn cleanup(&self) {
        let now = Utc::now();
        let mut state = self.state.lock();

        state.blocked_ips.retain(|_, until| *until > now);
        state.suspended_clients.retain(|_, (until, _)| *until > now);

        state.auth_failures.prune_lapsed();
        state.invalid_model_probes.prune_lapsed();
        state.replay_probes.prune_lapsed();
        state.session_events.prune_lapsed();
        state
            .covert_channel_events
            .retain(|_, (counter, _)| !counter.is_lapsed());

        state.global_auth_failures.prune();
        state.enclave_exceptions.prune();
    }

    /// Total keys tracked across every counter map. For tests and diagnostics.
    pub fn tracked_keys(&self) -> usize {
        let state = self.state.lock();
        state.auth_failures.len()
            + state.invalid_model_probes.len()
            + state.replay_probes.len()
            + state.session_events.len()
            + state.covert_channel_events.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> AttackDetector {
        AttackDetector::new(AttackDetectorConfig::default())
    }

    #[test]
    fn a_source_is_blocked_after_enough_auth_failures() {
        let d = detector();
        let threshold = d.config.auth_failure_threshold_per_minute;
        assert!(!d.is_ip_blocked("10.0.0.1"));

        for _ in 0..threshold {
            d.record_auth_failure("10.0.0.1");
        }
        assert!(d.is_ip_blocked("10.0.0.1"));
        assert!(!d.is_ip_blocked("10.0.0.2"), "blocks must be per source");
    }

    #[test]
    fn repeated_identical_input_is_reported_as_probing() {
        let d = detector();
        let threshold = d.config.replay_probe_threshold;

        for _ in 0..threshold - 1 {
            assert!(!d.record_input_hash("alice", "hash-a"));
        }
        assert!(d.record_input_hash("alice", "hash-a"));

        // A different prompt, and a different client, are counted separately.
        assert!(!d.record_input_hash("alice", "hash-b"));
        assert!(!d.record_input_hash("bob", "hash-a"));
    }

    #[test]
    fn invalid_model_probing_suspends_the_client() {
        let d = detector();
        assert!(d.is_client_suspended("prober").is_none());
        for _ in 0..5 {
            d.record_invalid_model("prober");
        }
        assert!(d.is_client_suspended("prober").is_some());
    }

    /// The bound this module exists to hold: a client varying its prompt must
    /// not be able to grow the replay-probe map without limit.
    #[test]
    fn the_replay_map_is_capped_however_many_distinct_prompts_arrive() {
        let d = detector();
        for i in 0..(MAX_TRACKED_KEYS * 2) {
            d.record_input_hash("noisy", &format!("hash-{}", i));
        }
        assert!(
            d.tracked_keys() <= MAX_TRACKED_KEYS,
            "replay map grew to {} keys",
            d.tracked_keys()
        );
    }

    #[test]
    fn distinct_sources_cannot_grow_the_auth_map_without_limit() {
        let d = detector();
        for i in 0..(MAX_TRACKED_KEYS * 2) {
            d.record_auth_failure(&format!("10.0.{}.{}", i / 256, i % 256));
        }
        assert!(
            d.tracked_keys() <= MAX_TRACKED_KEYS,
            "auth-failure map grew to {} keys",
            d.tracked_keys()
        );
    }

    /// One key must not accumulate a timestamp per request for the length of
    /// its window — an hour, for replay detection.
    #[test]
    fn a_single_counter_saturates_rather_than_growing() {
        let mut counter = WindowCounter::new(3600);
        for _ in 0..(MAX_EVENTS_PER_COUNTER * 4) {
            counter.increment();
        }
        assert_eq!(counter.events.len(), MAX_EVENTS_PER_COUNTER);
        // A saturated counter still reports a total above every threshold.
        assert!(counter.total() as usize > MAX_EVENTS_PER_COUNTER);
    }

    #[test]
    fn events_outside_the_window_stop_counting() {
        let mut counter = WindowCounter::new(60);
        counter.events = vec![
            Utc::now() - chrono::Duration::seconds(120),
            Utc::now() - chrono::Duration::seconds(90),
        ];
        assert_eq!(counter.total_in_window(), 0);
        assert!(counter.is_lapsed());

        counter.increment();
        assert_eq!(counter.total_in_window(), 1);
        assert!(!counter.is_lapsed());
    }

    #[test]
    fn cleanup_prunes_every_map_not_only_blocks_and_suspensions() {
        let d = detector();
        d.record_input_hash("alice", "hash-a");
        d.record_invalid_model("alice");
        d.record_session_event("alice");
        d.record_auth_failure("10.0.0.9");
        assert!(d.tracked_keys() > 0);

        // Age every counter past its window.
        {
            let mut state = d.state.lock();
            let stale = Utc::now() - chrono::Duration::seconds(7200);
            for c in state.auth_failures.counters.values_mut() {
                c.events = vec![stale];
            }
            for c in state.invalid_model_probes.counters.values_mut() {
                c.events = vec![stale];
            }
            for c in state.replay_probes.counters.values_mut() {
                c.events = vec![stale];
            }
            for c in state.session_events.counters.values_mut() {
                c.events = vec![stale];
            }
        }

        d.cleanup();
        assert_eq!(d.tracked_keys(), 0, "cleanup left lapsed counters behind");
    }

    /// Admission must not become quadratic once the map is full: sweeping for
    /// lapsed entries on every insert would hand an attacker a cheaper denial
    /// of service than the memory growth the cap was added to prevent.
    #[test]
    fn admission_stays_cheap_when_the_map_is_saturated() {
        let d = detector();
        for i in 0..MAX_TRACKED_KEYS {
            d.record_input_hash("noisy", &format!("fill-{}", i));
        }

        let started = std::time::Instant::now();
        for i in 0..20_000 {
            d.record_input_hash("noisy", &format!("overflow-{}", i));
        }
        let elapsed = started.elapsed();

        assert!(d.tracked_keys() <= MAX_TRACKED_KEYS);
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "20k rejected insertions took {:?} — admission is superlinear",
            elapsed
        );
    }

    #[test]
    fn a_lapsed_block_stops_blocking() {
        let d = detector();
        {
            let mut state = d.state.lock();
            state
                .blocked_ips
                .insert("10.0.0.5".into(), Utc::now() - chrono::Duration::seconds(1));
        }
        assert!(!d.is_ip_blocked("10.0.0.5"));
    }
}
