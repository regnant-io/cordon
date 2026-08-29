//! Request and response bodies for the HTTP API.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─── Inference ───────────────────────────────────────────────────────────────

/// `POST /v1/inference` and `POST /v1/inference/stream` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRequest {
    /// Model bundle ID to serve.
    pub model_id: String,
    /// Conversation messages.
    pub messages: Vec<ApiMessage>,
    /// Sampling parameters.
    #[serde(default)]
    pub inference_params: ApiInferenceParams,
    /// Session ID, to continue a multi-turn conversation.
    pub session_id: Option<Uuid>,
    /// Requested timeout in seconds. Clamped to the node's configured ceiling.
    pub timeout_seconds: Option<u64>,
}

/// One conversation message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiMessage {
    /// `system`, `user`, `assistant`, or `tool`.
    pub role: String,
    /// Message content.
    pub content: String,
}

/// Sampling parameters. Every field has a default, so a minimal request body is
/// just a model and a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiInferenceParams {
    /// Maximum tokens to generate.
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    /// Sampling temperature.
    #[serde(default = "default_temperature")]
    pub temperature: f32,
    /// Top-p nucleus sampling.
    #[serde(default = "default_top_p")]
    pub top_p: f32,
    /// Top-k sampling. Zero disables it.
    #[serde(default)]
    pub top_k: u32,
    /// Stop sequences.
    #[serde(default)]
    pub stop: Vec<String>,
    /// Repetition penalty.
    #[serde(default = "default_repetition_penalty")]
    pub repetition_penalty: f32,
}

fn default_max_tokens() -> u32 {
    512
}
fn default_temperature() -> f32 {
    0.7
}
fn default_top_p() -> f32 {
    0.9
}
fn default_repetition_penalty() -> f32 {
    1.0
}

impl Default for ApiInferenceParams {
    fn default() -> Self {
        Self {
            max_tokens: default_max_tokens(),
            temperature: default_temperature(),
            top_p: default_top_p(),
            top_k: 0,
            stop: vec![],
            repetition_penalty: default_repetition_penalty(),
        }
    }
}

/// `POST /v1/inference` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceResponse {
    /// Unique request identifier, also present in the audit log.
    pub request_id: Uuid,
    /// Session this request was served under. Pass it back to continue.
    pub session_id: Uuid,
    /// Model that served the request.
    pub model_id: String,
    /// Authenticated client.
    pub client_id: String,
    /// Response timestamp. Feeds the signature payload as epoch milliseconds.
    pub timestamp: DateTime<Utc>,
    /// Token accounting.
    pub usage: TokenUsage,
    /// Generated choices.
    pub choices: Vec<Choice>,
    /// Content policy outcome.
    pub content_policy: ContentPolicyStatus,
    /// Covert-channel analysis outcome.
    pub covert_channel: CovertChannelStatus,
    /// Ed25519 signature over the canonical response payload.
    pub signature: ResponseSignature,
    /// Node and measurement provenance.
    pub enclave_info: EnclaveInfo,
}

/// Token accounting.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TokenUsage {
    /// Tokens consumed by the prompt.
    pub prompt_tokens: u32,
    /// Tokens generated.
    pub completion_tokens: u32,
    /// Sum of both.
    pub total_tokens: u32,
}

/// One generated choice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Choice {
    /// Index within `choices`.
    pub index: u32,
    /// The generated message.
    pub message: ApiMessage,
    /// Why generation stopped.
    pub finish_reason: String,
}

/// Content policy outcome for one response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentPolicyStatus {
    /// Whether any rule fired.
    pub triggered: bool,
    /// Rule IDs that fired.
    pub rules_matched: Vec<String>,
}

/// Covert-channel analysis outcome.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CovertChannelStatus {
    /// Whether the score crossed the configured threshold.
    pub anomaly_detected: bool,
    /// The score, between 0.0 and 1.0.
    pub anomaly_score: f32,
}

/// An Ed25519 signature over a response.
///
/// `key_provenance` states whether the signature means anything to a third
/// party: `cmk_derived` signatures verify against a key the client derives
/// independently, while `ephemeral` signatures are self-certified by the node
/// and prove only that the response was not altered in transit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseSignature {
    /// Short identifier for the signing key.
    pub enclave_key_id: String,
    /// Always `ed25519`.
    pub algorithm: String,
    /// Signature, hex encoded.
    pub value: String,
    /// Where the signing key came from.
    pub key_provenance: String,
    /// Fields covered by the signature, in order.
    pub signed_fields: Vec<String>,
}

/// Node and measurement provenance attached to a response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveInfo {
    /// Configured TEE technology.
    pub tee_type: String,
    /// `tpm2` or `software_measurement`.
    pub measurement_source: String,
    /// Cordon version.
    pub cordon_version: String,
    /// Current enclave measurement.
    pub mrenclave: String,
}

// ─── Health ──────────────────────────────────────────────────────────────────

/// `GET /v1/health/detailed` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedHealthResponse {
    /// Overall node status.
    pub status: String,
    /// When this snapshot was taken.
    pub timestamp: DateTime<Utc>,
    /// Enclave and key posture.
    pub enclave: EnclaveHealth,
    /// Boot chain configuration.
    pub boot_chain: BootChainStatus,
    /// Inference statistics.
    pub inference: InferenceHealth,
    /// Audit log status.
    pub audit: AuditHealth,
    /// Model integrity status.
    pub integrity: IntegrityHealth,
    /// Access-control status.
    pub security: SecurityHealth,
}

/// Enclave and key posture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveHealth {
    /// Enclave state.
    pub status: String,
    /// Configured TEE technology.
    pub tee_type: String,
    /// `tpm2` or `software_measurement`.
    pub measurement_source: String,
    /// Whether measurements come from hardware.
    pub hardware_measurements: bool,
    /// Current enclave measurement.
    pub mrenclave: String,
    /// When a report was last generated.
    pub last_attested: Option<DateTime<Utc>>,
    /// Clients holding a live attestation verification.
    pub verified_clients: usize,
    /// `cmk_derived` or `ephemeral`.
    pub key_provenance: String,
}

/// Boot chain configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootChainStatus {
    /// Whether a TPM is required by configuration.
    pub tpm_required: bool,
    /// TPM version string.
    pub tpm_version: String,
    /// Whether Secure Boot is required.
    pub secure_boot: bool,
    /// Whether dm-verity is required.
    pub dm_verity: bool,
    /// When measurements were last taken.
    pub last_pcr_verification: Option<DateTime<Utc>>,
}

/// Inference statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceHealth {
    /// Backend name.
    pub runtime: String,
    /// Generations in flight.
    pub active_requests: u32,
    /// Concurrency ceiling.
    pub max_concurrent: u32,
    /// Live sessions.
    pub active_sessions: usize,
    /// Smoothed median latency.
    pub latency_ms_p50: u64,
    /// Smoothed tail latency.
    pub latency_ms_p99: u64,
}

/// Audit log status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditHealth {
    /// Entries written by this process.
    pub entries_total: u64,
    /// Current chain head.
    pub last_entry_hash: Option<String>,
    /// Last chain verdict. `null` means no verification has completed yet.
    pub chain_valid: Option<bool>,
    /// When that verdict was taken. Verification runs on a timer, not per
    /// request, so this can lag.
    pub chain_checked_at: Option<DateTime<Utc>>,
}

/// Model integrity status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityHealth {
    /// When the monitor last ran.
    pub last_weight_check: Option<DateTime<Utc>>,
    /// `valid` or `failed`.
    pub weight_check_result: String,
    /// When the next check is due.
    pub next_scheduled_check: Option<DateTime<Utc>>,
    /// Whether tampering has been detected.
    pub tamper_detected: bool,
}

/// Access-control status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHealth {
    /// Clients in the registry.
    pub enrolled_clients: usize,
    /// Clients currently suspended.
    pub suspended_clients: usize,
    /// Whether the node is quarantined.
    pub quarantine_mode: bool,
}

// ─── Attestation ─────────────────────────────────────────────────────────────

/// `POST /v1/attestation/verify` request body.
///
/// The caller supplies only a nonce. Expected measurements are pinned by the
/// operator in configuration and cannot be supplied here — a verifier that
/// accepts the values it is checking against verifies nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationVerifyRequest {
    /// Client-chosen nonce, at least 16 characters, for anti-replay.
    pub nonce: String,
}

// ─── Models ──────────────────────────────────────────────────────────────────

/// `POST /v1/models` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionModelRequest {
    /// The bundle manifest.
    pub manifest: serde_json::Value,
    /// Directory name **inside the configured model store**. A single path
    /// component; anything else is refused.
    pub bundle_directory: String,
    /// Ed25519 admin signature over
    /// `CORDON_ADMIN:provision-model:{bundle_directory}`.
    pub admin_signature: String,
}

// ─── Audit ───────────────────────────────────────────────────────────────────

/// `GET /v1/audit/tail` query parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTailQuery {
    /// Entries to return, clamped to 1..=1000.
    pub n: Option<u64>,
}

/// `GET /v1/audit/verify` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditVerifyResponse {
    /// Whether the whole chain verified.
    pub valid: bool,
    /// Entries checked.
    pub entries_verified: usize,
    /// Timestamp of the first entry.
    pub first_entry: Option<DateTime<Utc>>,
    /// Timestamp of the last entry.
    pub last_entry: Option<DateTime<Utc>>,
    /// Chain head.
    pub log_tail_hash: Option<String>,
    /// Every violation found, if any.
    pub violations: Vec<String>,
    /// Public half of the log signing key, so a client can repeat the check
    /// offline with `cordon-verify-log`.
    pub log_verifying_key: String,
    /// Whether that key is CMK-derived and therefore independently verifiable.
    pub key_provenance: String,
}

// ─── Admin ───────────────────────────────────────────────────────────────────

/// An admin command carrying only a reason string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminReasonRequest {
    /// Ed25519 admin signature over `CORDON_ADMIN:{action}:{reason}`.
    pub admin_signature: String,
    /// Operator's reason, recorded in the audit log.
    pub reason: String,
}

/// `POST /v1/admin/suspend-client` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspendClientRequest {
    /// Ed25519 admin signature over
    /// `CORDON_ADMIN:suspend-client:{client_id}:{duration_seconds}`.
    pub admin_signature: String,
    /// Client to suspend.
    pub client_id: String,
    /// Suspension length in seconds.
    pub duration_seconds: u64,
    /// Operator's reason, recorded in the audit log.
    pub reason: String,
}

/// A generic admin response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminResponse {
    /// Whether the command succeeded.
    pub success: bool,
    /// Human-readable outcome.
    pub message: String,
    /// When the command completed.
    pub timestamp: DateTime<Utc>,
}

impl AdminResponse {
    /// A successful outcome.
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
            timestamp: Utc::now(),
        }
    }
}

// ─── Errors ──────────────────────────────────────────────────────────────────

/// The error body returned by every failing endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    /// Stable machine-readable code, safe to branch on.
    pub error: String,
    /// Human-readable message. Never contains internal paths or stack detail.
    pub message: String,
    /// Request identifier, for correlating with the audit log.
    pub request_id: Option<Uuid>,
}

impl ApiError {
    /// Build an error body.
    pub fn new(error: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            message: message.into(),
            request_id: None,
        }
    }

    /// Attach a request identifier.
    pub fn with_request_id(mut self, id: Uuid) -> Self {
        self.request_id = Some(id);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minimal_request_body_parses() {
        let json = r#"{"model_id":"m","messages":[{"role":"user","content":"hi"}]}"#;
        let req: InferenceRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.model_id, "m");
        assert_eq!(req.inference_params.max_tokens, default_max_tokens());
        assert!(req.session_id.is_none());
    }

    #[test]
    fn sampling_parameters_override_defaults() {
        let json = r#"{
            "model_id":"m",
            "messages":[],
            "inference_params":{"max_tokens":64,"temperature":0.1}
        }"#;
        let req: InferenceRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.inference_params.max_tokens, 64);
        assert!((req.inference_params.temperature - 0.1).abs() < f32::EPSILON);
        // Unspecified fields still take their defaults.
        assert!((req.inference_params.top_p - default_top_p()).abs() < f32::EPSILON);
    }

    #[test]
    fn attestation_verify_accepts_only_a_nonce() {
        // Expected measurements must not be a caller-controlled input.
        let json = r#"{"nonce":"0123456789abcdef","expected_measurements":{"mrenclave":"ff"}}"#;
        let req: AttestationVerifyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.nonce, "0123456789abcdef");
    }
}
