//! Audit event types — §9.2 of the Cordon spec

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// All possible audit event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum AuditEvent {
    /// Inference request completed
    Inference(InferenceEvent),
    /// Security alert raised
    SecurityAlert(SecurityAlertEvent),
    /// Administrative action performed
    Admin(AdminEvent),
    /// Attestation cycle completed
    Attestation(AttestationEvent),
    /// Key rotation performed
    KeyRotation(KeyRotationEvent),
    /// Physical or logical tamper detected
    Tamper(TamperEvent),
    /// Node lifecycle event (boot, shutdown, quarantine)
    Lifecycle(LifecycleEvent),
    /// Log export event
    LogExport(LogExportEvent),
    /// Model bundle operation
    ModelBundle(ModelBundleEvent),
}

impl AuditEvent {
    /// Get the event type as a string
    pub fn event_type_str(&self) -> &'static str {
        match self {
            AuditEvent::Inference(_) => "inference",
            AuditEvent::SecurityAlert(_) => "security_alert",
            AuditEvent::Admin(_) => "admin",
            AuditEvent::Attestation(_) => "attestation",
            AuditEvent::KeyRotation(_) => "key_rotation",
            AuditEvent::Tamper(_) => "tamper",
            AuditEvent::Lifecycle(_) => "lifecycle",
            AuditEvent::LogExport(_) => "log_export",
            AuditEvent::ModelBundle(_) => "model_bundle",
        }
    }

    /// Get the client_id associated with this event, if any
    pub fn client_id(&self) -> Option<&str> {
        match self {
            AuditEvent::Inference(e) => Some(&e.client_id),
            AuditEvent::Admin(e) => Some(&e.client_id),
            AuditEvent::LogExport(e) => Some(&e.requester_client_id),
            _ => None,
        }
    }
}

/// Inference request completed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceEvent {
    /// Unique request ID
    pub request_id: Uuid,
    /// Client identifier
    pub client_id: String,
    /// Session ID (if multi-turn)
    pub session_id: Option<Uuid>,
    /// Model bundle ID
    pub model_id: String,
    /// Enclave measurement at time of inference
    pub mrenclave: String,
    /// SHA-256 of the input (NOT the plaintext — hash only)
    pub input_hash: String,
    /// SHA-256 of the output
    pub output_hash: String,
    /// Tokens in the prompt
    pub prompt_tokens: u32,
    /// Tokens generated
    pub completion_tokens: u32,
    /// Total latency in milliseconds
    pub latency_ms: u64,
    /// Why generation stopped
    pub finish_reason: FinishReason,
    /// Whether any content policy rule was triggered
    pub content_policy_triggered: bool,
    /// Content policy rules matched (rule IDs only, not content)
    pub policy_rules_matched: Vec<String>,
    /// Covert channel anomaly score (0.0–1.0)
    pub covert_channel_score: f32,
    /// Timing normalization bucket applied (ms)
    pub timing_bucket_ms: Option<u64>,
}

/// Why inference generation stopped
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    /// Natural stop token
    Stop,
    /// Max tokens reached
    Length,
    /// Content filter triggered
    ContentFilter,
    /// Request timeout
    Timeout,
    /// Internal error
    Error,
}

/// Security alert raised
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlertEvent {
    /// Alert type
    pub alert_type: AlertType,
    /// Severity level
    pub severity: AlertSeverity,
    /// SHA-256 of detailed alert data (actual data stored separately if sensitive)
    pub detail_hash: String,
    /// Human-readable summary (non-sensitive)
    pub summary: String,
    /// Automatic action taken
    pub automatic_action: AutoAction,
    /// Enclave state after action
    pub enclave_state_after: EnclaveState,
    /// Source IP or client_id if applicable (may be hashed)
    pub source_identifier: Option<String>,
}

/// Type of security alert
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertType {
    /// Physical or logical tamper detected
    TamperDetected,
    /// Attestation verification failed
    AttestationFailure,
    /// Weight or log integrity check failed
    IntegrityViolation,
    /// Sustained probing pattern detected
    SustainedProbe,
    /// Covert channel suspected in output
    CovertChannelSuspected,
    /// Unauthorized administrative command attempted
    UnauthorizedAdmin,
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Authentication failure
    AuthFailure,
    /// Replay attack detected
    ReplayAttack,
}

/// Alert severity
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    /// Low — logged, monitoring
    Low,
    /// Medium — operator notification
    Medium,
    /// High — possible attack
    High,
    /// Critical — confirmed attack or tamper
    Critical,
}

/// Automatic action taken in response to a security event
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoAction {
    /// No action taken
    Continue,
    /// Node entered quarantine mode
    Quarantine,
    /// Node halted — no more inference
    Halt,
    /// Key material zeroized
    Zeroize,
    /// Client suspended
    SuspendClient,
    /// IP blocked
    BlockIp,
}

/// State of the enclave after an event
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnclaveState {
    /// Normal operation
    Operational,
    /// Quarantine mode — no new requests
    Quarantine,
    /// Locked — awaiting operator recovery
    Locked,
    /// Key material zeroized — must re-provision
    Zeroized,
}

/// Administrative action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminEvent {
    /// Client who authorized the action
    pub client_id: String,
    /// Key ID used to sign the command
    pub actor_key_id: String,
    /// Action type
    pub action: AdminAction,
    /// Whether the authorization signature was valid
    pub authorization_sig_valid: bool,
    /// SHA-256 of action parameters
    pub parameters_hash: String,
    /// Whether the action succeeded
    pub result: ActionResult,
    /// Failure reason if applicable
    pub failure_reason: Option<String>,
}

/// Type of administrative action
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminAction {
    /// Key rotation initiated
    KeyRotation,
    /// Model bundle update
    ModelUpdate,
    /// Configuration change
    ConfigChange,
    /// Node teardown
    Teardown,
    /// Recovery from quarantine/lock
    Recovery,
    /// Log export authorized
    LogExport,
    /// Node re-attestation requested
    ReAttestation,
    /// Cordon software update applied
    SoftwareUpdate,
}

/// Result of an action
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionResult {
    /// Action completed successfully
    Success,
    /// Action failed
    Failure,
    /// Action rejected (bad auth or policy)
    Rejected,
}

/// Attestation cycle event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEvent {
    /// What triggered the attestation
    pub trigger: AttestationTrigger,
    /// SHA-256 of the full TPM PCR snapshot
    pub tpm_pcr_snapshot_hash: String,
    /// MRENCLAVE value attested
    pub mrenclave: String,
    /// Whether the client verified this attestation
    pub client_verified: bool,
    /// Whether key material was released as a result
    pub key_released: bool,
    /// Nonce used (base64)
    pub nonce: String,
}

/// What triggered an attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationTrigger {
    /// Boot-time attestation
    Boot,
    /// Scheduled re-attestation
    Scheduled,
    /// Client-requested
    ClientRequest,
    /// Post-update attestation
    PostUpdate,
}

/// Key rotation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationEvent {
    /// Bundle ID being rotated
    pub bundle_id: String,
    /// Previous key epoch
    pub previous_epoch: u32,
    /// New key epoch
    pub new_epoch: u32,
    /// Whether this was an emergency rotation (due to suspected compromise)
    pub emergency: bool,
    /// In-flight requests dropped (emergency only)
    pub requests_dropped: u32,
}

/// Tamper event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperEvent {
    /// Tamper source
    pub source: TamperSource,
    /// Whether HSM zeroization was triggered
    pub hsm_zeroized: bool,
    /// Whether enclave memory was zeroized
    pub enclave_zeroized: bool,
    /// Recovery steps required
    pub recovery_required: Vec<String>,
}

/// Source of a tamper event
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TamperSource {
    /// Chassis intrusion sensor
    ChassisIntrusion,
    /// HSM tamper detect
    HsmTamperDetect,
    /// Unexpected PCR change
    PcrChange,
    /// Weight integrity check failed
    WeightIntegrity,
    /// Log chain broken
    LogChainBroken,
}

/// Node lifecycle event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleEvent {
    /// Event type
    pub event: LifecycleEventType,
    /// Cordon version
    pub cordon_version: String,
    /// TEE type
    pub tee_type: String,
    /// Node ID
    pub node_id: String,
}

/// Type of lifecycle event
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleEventType {
    /// Node booted
    Boot,
    /// Node graceful shutdown
    Shutdown,
    /// Entered quarantine
    QuarantineEnter,
    /// Exited quarantine
    QuarantineExit,
    /// Enclave restarted
    EnclaveRestart,
}

/// Log export event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogExportEvent {
    /// Who requested the export
    pub requester_client_id: String,
    /// Export method used
    pub export_method: String,
    /// Time range exported (start)
    pub range_start: DateTime<Utc>,
    /// Time range exported (end)
    pub range_end: DateTime<Utc>,
    /// Number of entries exported
    pub entries_exported: u64,
    /// Hash of export package
    pub export_hash: String,
    /// Recipient key ID
    pub recipient_key_id: String,
}

/// Model bundle event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelBundleEvent {
    /// Bundle ID
    pub bundle_id: String,
    /// Action
    pub action: BundleAction,
    /// SHA-256 of bundle manifest
    pub manifest_hash: String,
    /// Whether client signature was verified
    pub client_sig_verified: bool,
    /// Whether vendor signature was verified
    pub vendor_sig_verified: bool,
}

/// Bundle action type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleAction {
    /// Bundle loaded
    Loaded,
    /// Bundle integrity check passed
    IntegrityCheckPassed,
    /// Bundle integrity check failed
    IntegrityCheckFailed,
    /// Bundle unloaded
    Unloaded,
}
