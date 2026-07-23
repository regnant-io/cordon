//! Node state machine — tracks the operational state of a Cordon node

use std::sync::Arc;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// High-level node status for health checks
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    /// Normal operation
    Healthy,
    /// Degraded but operational (e.g., non-critical alert)
    Degraded,
    /// In quarantine mode
    Quarantine,
    /// Locked — awaiting operator recovery
    Locked,
    /// Key material zeroized — must re-provision
    Zeroized,
    /// Starting up
    Initializing,
}

impl std::fmt::Display for NodeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeStatus::Healthy => write!(f, "healthy"),
            NodeStatus::Degraded => write!(f, "degraded"),
            NodeStatus::Quarantine => write!(f, "quarantine"),
            NodeStatus::Locked => write!(f, "locked"),
            NodeStatus::Zeroized => write!(f, "zeroized"),
            NodeStatus::Initializing => write!(f, "initializing"),
        }
    }
}

/// State of the TEE enclave
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnclaveState {
    /// Active and serving inference
    Active,
    /// Restarting after fault
    Restarting,
    /// Locked — awaiting recovery
    Locked,
    /// Key material zeroized
    Zeroized,
    /// Not yet initialized
    Uninitialized,
}

/// Runtime statistics for the node
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeStats {
    /// Total inference requests processed
    pub requests_processed: u64,
    /// Total tokens generated
    pub tokens_generated: u64,
    /// Total security alerts raised
    pub security_alerts: u64,
    /// Uptime in seconds
    pub uptime_seconds: u64,
    /// Active sessions
    pub active_sessions: u32,
    /// Current queue depth
    pub queue_depth: u32,
    /// P50 latency in ms
    pub latency_ms_p50: u64,
    /// P99 latency in ms
    pub latency_ms_p99: u64,
}

/// Full node state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeState {
    /// Node ID
    pub node_id: String,
    /// Deployment ID
    pub deployment_id: String,
    /// Cordon version
    pub cordon_version: String,
    /// Current node status
    pub status: NodeStatus,
    /// Current enclave state
    pub enclave_state: EnclaveState,
    /// Currently loaded model bundle ID
    pub active_model_id: Option<String>,
    /// When the node booted
    pub boot_time: DateTime<Utc>,
    /// Last attestation time
    pub last_attested: Option<DateTime<Utc>>,
    /// Whether current attestation is valid
    pub attestation_valid: bool,
    /// Last integrity check time
    pub last_integrity_check: Option<DateTime<Utc>>,
    /// Last integrity check result
    pub integrity_check_passed: bool,
    /// Runtime statistics
    pub stats: NodeStats,
    /// Audit log tail hash
    pub audit_log_tail_hash: Option<String>,
    /// Total audit log entries
    pub audit_log_entries: u64,
}

impl NodeState {
    /// Create initial state
    pub fn new(node_id: String, deployment_id: String) -> Self {
        Self {
            node_id,
            deployment_id,
            cordon_version: env!("CARGO_PKG_VERSION").to_string(),
            status: NodeStatus::Initializing,
            enclave_state: EnclaveState::Uninitialized,
            active_model_id: None,
            boot_time: Utc::now(),
            last_attested: None,
            attestation_valid: false,
            last_integrity_check: None,
            integrity_check_passed: false,
            stats: NodeStats::default(),
            audit_log_tail_hash: None,
            audit_log_entries: 0,
        }
    }

    /// Whether the node can serve inference requests
    pub fn can_serve(&self) -> bool {
        matches!(self.status, NodeStatus::Healthy | NodeStatus::Degraded)
            && matches!(self.enclave_state, EnclaveState::Active)
    }

    /// Transition to quarantine
    pub fn enter_quarantine(&mut self) {
        self.status = NodeStatus::Quarantine;
    }

    /// Transition to locked
    pub fn enter_locked(&mut self) {
        self.status = NodeStatus::Locked;
        self.enclave_state = EnclaveState::Locked;
    }

    /// Transition to zeroized
    pub fn enter_zeroized(&mut self) {
        self.status = NodeStatus::Zeroized;
        self.enclave_state = EnclaveState::Zeroized;
        self.active_model_id = None;
        self.attestation_valid = false;
    }

    /// Mark as operational
    pub fn go_operational(&mut self) {
        self.status = NodeStatus::Healthy;
        self.enclave_state = EnclaveState::Active;
    }
}

/// Thread-safe shared node state
#[derive(Clone)]
pub struct SharedNodeState {
    inner: Arc<RwLock<NodeState>>,
}

impl SharedNodeState {
    /// Create new shared state
    pub fn new(state: NodeState) -> Self {
        Self {
            inner: Arc::new(RwLock::new(state)),
        }
    }

    /// Read the current state
    pub fn read(&self) -> parking_lot::RwLockReadGuard<'_, NodeState> {
        self.inner.read()
    }

    /// Mutate the state
    pub fn write(&self) -> parking_lot::RwLockWriteGuard<'_, NodeState> {
        self.inner.write()
    }

    /// Get the current status
    pub fn status(&self) -> NodeStatus {
        self.inner.read().status.clone()
    }

    /// Check if node can serve
    pub fn can_serve(&self) -> bool {
        self.inner.read().can_serve()
    }

    /// Enter quarantine
    pub fn enter_quarantine(&self) {
        self.inner.write().enter_quarantine();
    }

    /// Record a completed inference
    pub fn record_inference(&self, tokens: u64) {
        let mut state = self.inner.write();
        state.stats.requests_processed += 1;
        state.stats.tokens_generated += tokens;
    }

    /// Update latency stats (simplified EMA)
    pub fn update_latency(&self, latency_ms: u64) {
        let mut state = self.inner.write();
        // Simple EMA with α=0.1
        if state.stats.latency_ms_p50 == 0 {
            state.stats.latency_ms_p50 = latency_ms;
            state.stats.latency_ms_p99 = latency_ms;
        } else {
            state.stats.latency_ms_p50 =
                (state.stats.latency_ms_p50 * 9 + latency_ms) / 10;
            if latency_ms > state.stats.latency_ms_p99 {
                state.stats.latency_ms_p99 =
                    (state.stats.latency_ms_p99 * 19 + latency_ms) / 20;
            }
        }
    }
}
