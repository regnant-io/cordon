//! API request and response types — §17.2 and §17.3
#![allow(missing_docs)] // request/response DTOs are self-describing

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─── Inference ────────────────────────────────────────────────────────────────

/// POST /v1/inference — request body
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRequest {
    /// Model bundle ID
    pub model_id: String,
    /// Conversation messages
    pub messages: Vec<ApiMessage>,
    /// Sampling parameters
    #[serde(default)]
    pub inference_params: ApiInferenceParams,
    /// Session ID for multi-turn (optional)
    pub session_id: Option<Uuid>,
    /// Request priority
    #[serde(default)]
    pub priority: RequestPriority,
    /// Timeout override in seconds
    pub timeout_seconds: Option<u64>,
}

/// A single message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiMessage {
    /// Role: system, user, or assistant
    pub role: String,
    /// Message content
    pub content: String,
}

/// Sampling parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiInferenceParams {
    /// Maximum tokens to generate
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    /// Sampling temperature
    #[serde(default = "default_temperature")]
    pub temperature: f32,
    /// Top-p nucleus sampling
    #[serde(default = "default_top_p")]
    pub top_p: f32,
    /// Top-k sampling
    #[serde(default)]
    pub top_k: u32,
    /// Stop sequences
    #[serde(default)]
    pub stop: Vec<String>,
    /// Repetition penalty
    #[serde(default = "default_rep_penalty")]
    pub repetition_penalty: f32,
}

fn default_max_tokens() -> u32 { 2048 }
fn default_temperature() -> f32 { 0.7 }
fn default_top_p() -> f32 { 0.9 }
fn default_rep_penalty() -> f32 { 1.0 }

impl Default for ApiInferenceParams {
    fn default() -> Self {
        Self {
            max_tokens: default_max_tokens(),
            temperature: default_temperature(),
            top_p: default_top_p(),
            top_k: 0,
            stop: vec![],
            repetition_penalty: default_rep_penalty(),
        }
    }
}

/// Request priority
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestPriority {
    /// Standard priority
    #[default]
    Standard,
    /// High priority
    High,
    /// Batch (lower priority)
    Batch,
}

/// POST /v1/inference — response body (§8.2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceResponse {
    /// Request ID
    pub request_id: Uuid,
    /// Model bundle ID
    pub model_id: String,
    /// Model version
    pub model_version: String,
    /// Client ID
    pub client_id: String,
    /// Response timestamp
    pub timestamp: DateTime<Utc>,
    /// Token usage
    pub usage: TokenUsage,
    /// Generated choices
    pub choices: Vec<Choice>,
    /// Content policy status
    pub content_policy: ContentPolicyStatus,
    /// Covert channel status
    pub covert_channel: CovertChannelStatus,
    /// Response signature
    pub signature: ResponseSignature,
    /// Enclave info
    pub enclave_info: EnclaveInfo,
}

/// Token usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsage {
    /// Tokens in the prompt
    pub prompt_tokens: u32,
    /// Tokens generated
    pub completion_tokens: u32,
    /// Total tokens
    pub total_tokens: u32,
}

/// A generated choice
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Choice {
    /// Choice index
    pub index: u32,
    /// The generated message
    pub message: ApiMessage,
    /// Why generation stopped
    pub finish_reason: String,
}

/// Content policy evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentPolicyStatus {
    /// Whether any policy rule triggered
    pub triggered: bool,
    /// Rule IDs that matched
    pub rules_matched: Vec<String>,
}

/// Covert channel detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CovertChannelStatus {
    /// Whether anomaly was detected
    pub anomaly_detected: bool,
    /// Anomaly score (0.0–1.0)
    pub anomaly_score: f32,
}

/// Ed25519 response signature from enclave ephemeral key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseSignature {
    /// Ephemeral key ID
    pub enclave_key_id: String,
    /// Algorithm
    pub algorithm: String,
    /// Signature value (hex)
    pub value: String,
    /// Fields included in the signature
    pub signed_fields: Vec<String>,
}

/// Enclave information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveInfo {
    /// TEE type
    pub tee_type: String,
    /// Cordon version
    pub cordon_version: String,
    /// MRENCLAVE
    pub mrenclave: String,
}

// ─── Health ───────────────────────────────────────────────────────────────────

/// GET /v1/health/detailed — response body (§17.3)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedHealthResponse {
    /// Overall status
    pub status: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Enclave health
    pub enclave: EnclaveHealth,
    /// Boot chain status
    pub boot_chain: BootChainStatus,
    /// Inference stats
    pub inference: InferenceHealth,
    /// Audit log status
    pub audit: AuditHealth,
    /// Integrity status
    pub integrity: IntegrityHealth,
    /// Security status
    pub security: SecurityHealth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveHealth {
    pub status: String,
    pub tee_type: String,
    pub mrenclave: String,
    pub last_attested: Option<DateTime<Utc>>,
    pub attestation_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootChainStatus {
    pub tpm_present: bool,
    pub tpm_version: String,
    pub secure_boot: bool,
    pub dm_verity: bool,
    pub last_pcr_verification: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceHealth {
    pub runtime: String,
    pub active_requests: u32,
    pub queue_depth: u32,
    pub latency_ms_p50: u64,
    pub latency_ms_p99: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditHealth {
    pub entries_total: u64,
    pub last_entry_hash: Option<String>,
    pub chain_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityHealth {
    pub last_weight_check: Option<DateTime<Utc>>,
    pub weight_check_result: String,
    pub next_scheduled_check: Option<DateTime<Utc>>,
    pub tamper_detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHealth {
    pub sustained_attack_detector: String,
    pub alerts_last_24h: u64,
    pub quarantine_mode: bool,
}

// ─── Attestation ──────────────────────────────────────────────────────────────

/// POST /v1/attestation/verify — request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationVerifyRequest {
    /// Client-provided nonce (base64)
    pub nonce: String,
    /// Expected measurements (optional — if absent, just return current report)
    pub expected_measurements: Option<serde_json::Value>,
}

/// GET /v1/attestation — response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResponse {
    /// Whether this report has been client-verified
    pub client_verified: bool,
    /// The attestation report
    pub report: serde_json::Value,
    /// Timestamp
    pub generated_at: DateTime<Utc>,
}

// ─── Models ───────────────────────────────────────────────────────────────────

/// Model bundle entry in list response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelBundleEntry {
    pub bundle_id: String,
    pub model_name: String,
    pub model_version: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub manifest_hash: String,
}

/// POST /v1/models — provision new bundle (request is multipart or JSON manifest)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionModelRequest {
    /// The bundle manifest (as JSON).
    pub manifest: serde_json::Value,
    /// Filesystem path of the encrypted bundle directory on the node.
    pub bundle_path: String,
    /// K_admin signature authorizing provisioning (hex).
    pub admin_signature: String,
}

// ─── Audit ────────────────────────────────────────────────────────────────────

/// GET /v1/audit/export — query params
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditExportQuery {
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub limit: Option<u64>,
}

/// GET /v1/audit/tail — query params
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTailQuery {
    pub n: Option<u64>,
}

/// Audit verification response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditVerifyResponse {
    pub valid: bool,
    pub entries_verified: usize,
    pub first_entry: Option<DateTime<Utc>>,
    pub last_entry: Option<DateTime<Utc>>,
    pub log_tail_hash: Option<String>,
    pub violations: Vec<String>,
}

// ─── Admin ────────────────────────────────────────────────────────────────────

/// POST /v1/admin/key-rotate — request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotateRequest {
    /// K_admin signature over the rotation command (hex)
    pub admin_signature: String,
    /// Bundle ID to rotate
    pub bundle_id: String,
    /// Whether this is an emergency rotation
    pub emergency: bool,
}

/// POST /v1/admin/update — request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRequest {
    /// Path to the update package
    pub package_path: String,
    /// K_admin signature authorizing the update (hex)
    pub admin_signature: String,
}

/// POST /v1/admin/recover — request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverRequest {
    /// K_admin signature authorizing recovery (hex)
    pub admin_signature: String,
    /// Reason for recovery
    pub reason: String,
}

/// Generic admin response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminResponse {
    pub success: bool,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

impl AdminResponse {
    pub fn ok(msg: impl Into<String>) -> Self {
        Self {
            success: true,
            message: msg.into(),
            timestamp: Utc::now(),
        }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            message: msg.into(),
            timestamp: Utc::now(),
        }
    }
}

// ─── Error ────────────────────────────────────────────────────────────────────

/// Standard error response body
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    /// Error code
    pub error: String,
    /// Human-readable message
    pub message: String,
    /// Request ID if applicable
    pub request_id: Option<Uuid>,
}

impl ApiError {
    pub fn new(error: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            message: message.into(),
            request_id: None,
        }
    }
    pub fn with_request_id(mut self, id: Uuid) -> Self {
        self.request_id = Some(id);
        self
    }
}
