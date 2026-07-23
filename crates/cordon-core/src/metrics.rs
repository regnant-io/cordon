//! Prometheus metrics — §9.5
#![allow(missing_docs)] // metric fields are self-describing
//!
//! All metrics exposed on localhost:9090 only.
//! No client_id or content in metrics — only aggregate operational data.

use prometheus::{
    Gauge, Histogram, HistogramOpts, IntCounter, IntGauge, Registry, register_gauge_with_registry,
    register_histogram_with_registry, register_int_counter_with_registry,
    register_int_gauge_with_registry,
};

/// Cordon metrics collection
pub struct CordonMetrics {
    pub registry: Registry,

    // Inference
    pub inference_requests_total: IntCounter,
    pub inference_requests_failed: IntCounter,
    pub inference_latency_seconds: Histogram,
    pub tokens_generated_total: IntCounter,
    pub tokens_prompt_total: IntCounter,
    pub queue_depth: IntGauge,
    pub active_requests: IntGauge,

    // Security
    pub security_alerts_total: IntCounter,
    pub security_alerts_critical: IntCounter,
    pub auth_failures_total: IntCounter,
    pub rate_limit_hits_total: IntCounter,
    pub content_policy_hits_total: IntCounter,
    pub covert_channel_detections_total: IntCounter,
    pub integrity_check_failures_total: IntCounter,

    // Attestation
    pub attestation_cycles_total: IntCounter,
    pub attestation_failures_total: IntCounter,
    pub last_attestation_timestamp: Gauge,

    // Audit
    pub audit_log_entries_total: IntCounter,
    pub audit_log_write_failures: IntCounter,

    // System
    pub enclave_status: IntGauge, // 1=active, 0=inactive
    pub uptime_seconds: Gauge,
    pub key_rotation_total: IntCounter,
    pub model_bundles_loaded: IntGauge,
}

impl CordonMetrics {
    /// Create and register all metrics
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        macro_rules! int_counter {
            ($name:expr, $help:expr) => {
                register_int_counter_with_registry!($name, $help, registry)?
            };
        }
        macro_rules! int_gauge {
            ($name:expr, $help:expr) => {
                register_int_gauge_with_registry!($name, $help, registry)?
            };
        }
        macro_rules! gauge {
            ($name:expr, $help:expr) => {
                register_gauge_with_registry!($name, $help, registry)?
            };
        }

        let inference_latency_seconds = register_histogram_with_registry!(
            HistogramOpts::new(
                "cordon_inference_latency_seconds",
                "Inference request latency in seconds"
            ).buckets(vec![0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]),
            registry
        )?;

        Ok(Self {
            // Inference
            inference_requests_total: int_counter!(
                "cordon_inference_requests_total",
                "Total inference requests processed"
            ),
            inference_requests_failed: int_counter!(
                "cordon_inference_requests_failed",
                "Total inference requests that failed"
            ),
            inference_latency_seconds,
            tokens_generated_total: int_counter!(
                "cordon_tokens_generated_total",
                "Total completion tokens generated"
            ),
            tokens_prompt_total: int_counter!(
                "cordon_tokens_prompt_total",
                "Total prompt tokens processed"
            ),
            queue_depth: int_gauge!(
                "cordon_queue_depth",
                "Current inference request queue depth"
            ),
            active_requests: int_gauge!(
                "cordon_active_requests",
                "Currently active inference requests"
            ),

            // Security
            security_alerts_total: int_counter!(
                "cordon_security_alerts_total",
                "Total security alerts raised"
            ),
            security_alerts_critical: int_counter!(
                "cordon_security_alerts_critical",
                "Critical severity security alerts"
            ),
            auth_failures_total: int_counter!(
                "cordon_auth_failures_total",
                "Total authentication failures"
            ),
            rate_limit_hits_total: int_counter!(
                "cordon_rate_limit_hits_total",
                "Total rate limit hits"
            ),
            content_policy_hits_total: int_counter!(
                "cordon_content_policy_hits_total",
                "Total content policy rule triggers"
            ),
            covert_channel_detections_total: int_counter!(
                "cordon_covert_channel_detections_total",
                "Total covert channel anomalies detected"
            ),
            integrity_check_failures_total: int_counter!(
                "cordon_integrity_check_failures_total",
                "Total model weight integrity check failures"
            ),

            // Attestation
            attestation_cycles_total: int_counter!(
                "cordon_attestation_cycles_total",
                "Total attestation cycles completed"
            ),
            attestation_failures_total: int_counter!(
                "cordon_attestation_failures_total",
                "Total attestation failures"
            ),
            last_attestation_timestamp: gauge!(
                "cordon_last_attestation_timestamp",
                "Unix timestamp of last successful attestation"
            ),

            // Audit
            audit_log_entries_total: int_counter!(
                "cordon_audit_log_entries_total",
                "Total audit log entries written"
            ),
            audit_log_write_failures: int_counter!(
                "cordon_audit_log_write_failures_total",
                "Total audit log write failures (fatal events)"
            ),

            // System
            enclave_status: int_gauge!(
                "cordon_enclave_status",
                "Enclave status (1=active, 0=inactive/error)"
            ),
            uptime_seconds: gauge!(
                "cordon_uptime_seconds",
                "Node uptime in seconds"
            ),
            key_rotation_total: int_counter!(
                "cordon_key_rotation_total",
                "Total key rotation operations"
            ),
            model_bundles_loaded: int_gauge!(
                "cordon_model_bundles_loaded",
                "Number of model bundles currently loaded"
            ),

            registry,
        })
    }

    /// Render metrics as Prometheus text format
    pub fn render(&self) -> String {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let mut buf = Vec::new();
        encoder.encode(&self.registry.gather(), &mut buf)
            .unwrap_or_default();
        String::from_utf8(buf).unwrap_or_default()
    }

    /// Record a completed inference
    pub fn record_inference_completed(
        &self,
        latency_secs: f64,
        prompt_tokens: u32,
        completion_tokens: u32,
    ) {
        self.inference_requests_total.inc();
        self.inference_latency_seconds.observe(latency_secs);
        self.tokens_generated_total.inc_by(completion_tokens as u64);
        self.tokens_prompt_total.inc_by(prompt_tokens as u64);
    }

    /// Record a failed inference
    pub fn record_inference_failed(&self) {
        self.inference_requests_failed.inc();
    }

    /// Update enclave status
    pub fn set_enclave_active(&self, active: bool) {
        self.enclave_status.set(if active { 1 } else { 0 });
    }
}

impl Default for CordonMetrics {
    fn default() -> Self {
        Self::new().expect("Failed to create metrics")
    }
}
