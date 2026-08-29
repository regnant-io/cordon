//! Cordon deployment configuration — §11.3
//!
//! Implements the full configuration schema from the spec.
//! Configuration is loaded from a TOML file and validated at startup.

use crate::error::{CordonError, CordonResult};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Deployment mode — controls security level and available features
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentMode {
    /// Maximum security — no network, physical media only, FIPS L4, single tenant
    Dark,
    /// High security — private LAN, FIPS L3, government/critical infra
    Island,
    /// Regulated enterprise — private + management channel, FIPS L3
    Vault,
    /// Cloud deployment in client VPC
    SovereignCloud,
    /// Development/low-sensitivity — software isolation, no TEE required
    Light,
}

impl std::fmt::Display for DeploymentMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeploymentMode::Dark => write!(f, "dark"),
            DeploymentMode::Island => write!(f, "island"),
            DeploymentMode::Vault => write!(f, "vault"),
            DeploymentMode::SovereignCloud => write!(f, "sovereign_cloud"),
            DeploymentMode::Light => write!(f, "light"),
        }
    }
}

/// TEE configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeConfig {
    /// Preferred TEE technology
    pub preferred: TeePreference,
    /// Minimum security version number
    pub minimum_security_version: u16,
    /// Re-attestation interval in hours
    pub re_attestation_interval_hours: u64,
    /// Halt all inference if attestation fails
    pub halt_on_attestation_failure: bool,
    /// Enable Intel CAT / AMD QoS cache partitioning
    pub cache_partitioning: bool,
}

impl Default for TeeConfig {
    fn default() -> Self {
        Self {
            preferred: TeePreference::AmdSevSnp,
            minimum_security_version: 3,
            re_attestation_interval_hours: 24,
            halt_on_attestation_failure: true,
            cache_partitioning: true,
        }
    }
}

/// TEE technology preference
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeePreference {
    /// Intel SGX v2 — for ≤13B models, per-request isolation
    SgxV2,
    /// AMD SEV-SNP — for ≥30B models, full VM isolation (recommended)
    AmdSevSnp,
    /// ARM TrustZone — edge deployments
    ArmTrustZone,
    /// Simulation — NOT for production; testing only
    Simulation,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Inbound whitelist rules
    pub inbound_whitelist: Vec<InboundRule>,
    /// Outbound policy (always zero-egress in production)
    pub outbound_policy: OutboundPolicy,
    /// Hardware firewall type
    pub hardware_firewall: FirewallType,
    /// Whether SmartNIC ACLs are enforced
    pub smartnic_acl: bool,
    /// Management channel (Vault mode only)
    pub mgmt_channel: Option<MgmtChannelConfig>,
    /// Bind address for the API server
    pub bind_address: String,
    /// API port
    pub api_port: u16,
    /// TLS certificate path
    pub tls_cert_path: PathBuf,
    /// TLS key path
    pub tls_key_path: PathBuf,
    /// Client CA certificate path (for mTLS)
    pub client_ca_path: Option<PathBuf>,
    /// Whether to require mTLS
    pub require_mtls: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            inbound_whitelist: vec![],
            outbound_policy: OutboundPolicy::ZeroEgress,
            hardware_firewall: FirewallType::DedicatedAppliance,
            smartnic_acl: false,
            mgmt_channel: None,
            bind_address: "0.0.0.0".to_string(),
            api_port: 8443,
            tls_cert_path: PathBuf::from("/etc/cordon/tls/server.crt"),
            tls_key_path: PathBuf::from("/etc/cordon/tls/server.key"),
            client_ca_path: Some(PathBuf::from("/etc/cordon/tls/client-ca.crt")),
            require_mtls: true,
        }
    }
}

/// Inbound whitelist rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundRule {
    /// Source CIDR
    pub cidr: String,
    /// Allowed port
    pub port: u16,
    /// Protocol
    pub protocol: String,
}

/// Outbound policy
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundPolicy {
    /// Zero egress — all outbound dropped
    ZeroEgress,
    /// Restricted — only management channel
    Restricted,
}

/// Hardware firewall type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallType {
    /// Palo Alto PA-Series
    PaloAlto,
    /// Juniper SRX
    JuniperSrx,
    /// pfSense on dedicated hardware
    PfSense,
    /// Dedicated appliance (generic)
    DedicatedAppliance,
    /// None (development/Light mode only)
    None,
}

/// Management channel configuration (Vault mode)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MgmtChannelConfig {
    /// Management endpoint
    pub endpoint: String,
    /// Certificate pin (sha256 hex)
    pub certificate_pin: String,
}

/// Side-channel mitigation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SideChannelConfig {
    /// Enforce constant-time execution paths
    pub constant_time_enforcement: bool,
    /// Zero memory on inference completion
    pub memory_zeroize_on_completion: bool,
    /// Response size padding
    pub response_size_padding: bool,
    /// Timing normalization settings
    pub timing_normalization: TimingNormalizationConfig,
}

impl Default for SideChannelConfig {
    fn default() -> Self {
        Self {
            constant_time_enforcement: true,
            memory_zeroize_on_completion: true,
            response_size_padding: true,
            timing_normalization: TimingNormalizationConfig::default(),
        }
    }
}

/// Timing normalization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingNormalizationConfig {
    /// Whether timing normalization is enabled
    pub enabled: bool,
    /// Normalization mode
    pub mode: TimingMode,
    /// Bucket size in milliseconds (for Bucket mode)
    pub bucket_ms: u64,
    /// Fixed floor in milliseconds (for FixedFloor mode)
    pub fixed_floor_ms: u64,
}

impl Default for TimingNormalizationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: TimingMode::Bucket,
            bucket_ms: 100,
            fixed_floor_ms: 1000,
        }
    }
}

/// Timing normalization mode
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimingMode {
    /// Fixed floor — response never faster than floor_ms
    FixedFloor,
    /// Bucket — round up to nearest bucket_ms increment
    Bucket,
    /// No normalization (Light mode / performance priority)
    None,
}

/// HSM configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmConfig {
    /// HSM provider
    pub provider: HsmProvider,
    /// FIPS level required
    pub fips_level: u8,
    /// HSM slot ID
    pub slot_id: u32,
    /// HSM PIN (from environment variable, not config file)
    pub pin_env_var: String,
}

impl Default for HsmConfig {
    fn default() -> Self {
        Self {
            provider: HsmProvider::SoftHsm2,
            fips_level: 3,
            slot_id: 0,
            pin_env_var: "CORDON_HSM_PIN".to_string(),
        }
    }
}

/// HSM provider
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HsmProvider {
    /// Thales Luna HSM
    ThalesLuna,
    /// Entrust nShield
    EntrustNshield,
    /// SoftHSM2 (development/Light mode)
    SoftHsm2,
    /// AWS CloudHSM (SovereignCloud mode)
    AwsCloudHsm,
    /// YubiHSM (compact deployments)
    YubiHsm,
}

/// Boot/TPM configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootConfig {
    /// Require TPM 2.0
    pub tpm_required: bool,
    /// TPM version string
    pub tpm_version: String,
    /// Require UEFI Secure Boot
    pub secure_boot: bool,
    /// Require dm-verity on root filesystem
    pub dm_verity: bool,
    /// PCR policy — required PCR indices and expected values
    pub pcr_policy: PcrPolicy,
}

impl Default for BootConfig {
    fn default() -> Self {
        Self {
            tpm_required: true,
            tpm_version: "2.0".to_string(),
            secure_boot: true,
            dm_verity: true,
            pcr_policy: PcrPolicy::default(),
        }
    }
}

/// PCR policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrPolicy {
    /// Required PCR indices
    pub required_pcrs: Vec<u8>,
    /// Expected PCR values (hex) — populated at provisioning time
    pub expected_values: std::collections::HashMap<u8, String>,
}

impl Default for PcrPolicy {
    fn default() -> Self {
        Self {
            required_pcrs: vec![0, 4, 7, 8, 11, 13],
            expected_values: std::collections::HashMap::new(),
        }
    }
}

/// Model store configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelStoreConfig {
    /// Directory where model bundles are stored
    pub path: PathBuf,
    /// Integrity check interval in minutes. Also the lifetime of an integrity
    /// verdict on the serving path: a bundle whose last check is older than this
    /// is withdrawn from service until the monitor confirms it again.
    pub integrity_check_interval_minutes: u64,
    /// Halt inference immediately on integrity violation
    pub halt_on_tamper: bool,
    /// Directory a bundle is decrypted into before the runtime loads it.
    ///
    /// Point this at a memory-backed filesystem (`tmpfs`, `ramfs`) in any
    /// deployment where plaintext weights must not touch persistent storage.
    #[serde(default)]
    pub staging_dir: Option<PathBuf>,
}

impl Default for ModelStoreConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/cordon/bundles"),
            integrity_check_interval_minutes: 15,
            halt_on_tamper: true,
            staging_dir: None,
        }
    }
}

/// Inference engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceConfig {
    /// Maximum concurrent requests
    pub max_concurrent_requests: u32,
    /// Default request timeout in seconds
    pub default_timeout_seconds: u64,
    /// Enforce per-client KV cache isolation
    pub client_kv_cache_isolation: bool,
    /// Zero KV cache on session end
    pub kv_cache_zero_on_session_end: bool,
    /// Whether multi-tenant operation is allowed
    pub multi_tenant: bool,
    /// Maximum input tokens
    pub max_input_tokens: u32,
    /// Maximum output tokens
    pub max_output_tokens: u32,
}

impl Default for InferenceConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 32,
            default_timeout_seconds: 120,
            client_kv_cache_isolation: true,
            kv_cache_zero_on_session_end: true,
            multi_tenant: false,
            max_input_tokens: 32768,
            max_output_tokens: 4096,
        }
    }
}

/// Audit log configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Audit log directory
    pub log_path: PathBuf,
    /// Log format (always jsonl)
    pub log_format: String,
    /// Export method
    pub export_method: String,
    /// Log retention days
    pub retention_days: u32,
    /// Use enclave-derived signing key
    pub signing_key_from_enclave: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_path: PathBuf::from("/cordon/audit"),
            log_format: "jsonl".to_string(),
            export_method: "operator_pull".to_string(),
            retention_days: 365,
            signing_key_from_enclave: true,
        }
    }
}

/// Update configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfig {
    /// Update source
    pub source: UpdateSource,
    /// Require vendor signature on updates
    pub require_vendor_signature: bool,
    /// Require client (operator) signature on updates
    pub require_client_signature: bool,
    /// Use staged A/B rollout
    pub staged_rollout: bool,
    /// Auto-apply updates without operator review
    pub auto_apply: bool,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            source: UpdateSource::MgmtChannel,
            require_vendor_signature: true,
            require_client_signature: true,
            staged_rollout: true,
            auto_apply: false,
        }
    }
}

/// Update source
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateSource {
    /// Physical media only (Dark mode)
    PhysicalMedia,
    /// Internal mirror
    InternalMirror,
    /// Management channel
    MgmtChannel,
}

/// Sustained attack detector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackDetectorConfig {
    /// Auth failures per minute to trigger IP block
    pub auth_failure_threshold_per_minute: u32,
    /// Global auth failures per minute to alert operator
    pub global_failure_threshold_per_minute: u32,
    /// Covert channel score threshold to suspend client
    pub covert_channel_score_threshold: f32,
    /// Enter quarantine on critical attack pattern
    pub quarantine_on_critical: bool,
    /// Repeated identical input hashes to trigger rate-limit
    pub replay_probe_threshold: u32,
}

impl Default for AttackDetectorConfig {
    fn default() -> Self {
        Self {
            auth_failure_threshold_per_minute: 10,
            global_failure_threshold_per_minute: 50,
            covert_channel_score_threshold: 0.7,
            quarantine_on_critical: true,
            replay_probe_threshold: 20,
        }
    }
}

/// Which model runtime Cordon dispatches to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeBackend {
    /// Cordon spawns and owns a `llama-server` child bound to loopback with its
    /// web UI unreachable. The recommended posture: Cordon is the only network
    /// surface, so no request can bypass its policy and audit layers.
    Supervised,
    /// Cordon forwards to an OpenAI-compatible endpoint the operator runs.
    /// Cordon cannot vouch for that endpoint's exposure or its access control.
    External,
    /// No model runtime. The control plane runs and returns clearly-labelled
    /// placeholder text. Permitted only in Light mode.
    None,
}

/// Model runtime configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    /// Which backend to use.
    pub backend: RuntimeBackend,
    /// Path to the `llama-server` binary. When absent, Cordon searches
    /// `CORDON_LLAMA_SERVER`, then `PATH`, then the conventional install
    /// locations.
    pub binary: Option<PathBuf>,
    /// Path to the GGUF model file for the supervised backend.
    pub model_path: Option<PathBuf>,
    /// Directory holding models fetched by `cordon pull`.
    pub model_dir: PathBuf,
    /// Endpoint root for the external backend, e.g. `http://127.0.0.1:8000`.
    pub endpoint_url: Option<String>,
    /// Environment variable holding the external endpoint's API key. The key
    /// itself is never written to the config file.
    pub endpoint_api_key_env: Option<String>,
    /// Context window passed to the runtime.
    pub context_size: u32,
    /// Layers to offload to the GPU. Zero keeps the model on the CPU.
    pub gpu_layers: u32,
    /// Generation threads. `None` lets the runtime choose.
    pub threads: Option<u32>,
    /// Parallel decode slots. Raised to Cordon's concurrency limit if lower.
    pub parallel_slots: u32,
    /// How long to wait for the runtime to become healthy at startup.
    pub startup_timeout_seconds: u64,
    /// Additional arguments appended to the runtime command line verbatim.
    pub extra_args: Vec<String>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            backend: RuntimeBackend::Supervised,
            binary: None,
            model_path: None,
            model_dir: PathBuf::from("/var/lib/cordon/models"),
            endpoint_url: None,
            endpoint_api_key_env: None,
            context_size: 4096,
            gpu_layers: 0,
            threads: None,
            parallel_slots: 4,
            startup_timeout_seconds: 180,
            extra_args: Vec::new(),
        }
    }
}

/// Operator console configuration.
///
/// The console is an operator tool, not a public surface. It is disabled by
/// default, is bound to loopback independently of the API listener, and is
/// refused outside Light mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    /// Whether to serve the console at all.
    pub enabled: bool,
    /// Address the console listens on. Forced to loopback by `validate`.
    pub bind_address: String,
    /// Console port.
    pub port: u16,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: "127.0.0.1".to_string(),
            port: 8478,
        }
    }
}

/// Where the platform measurements in an attestation report come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementSource {
    /// PCR values read from a TPM 2.0 device via `tpm2-tools`.
    Tpm2,
    /// A digest of the running configuration and build. This is a **software
    /// integrity measurement**, not a hardware root of trust: it attests that
    /// the node's configuration is what the operator expects, and nothing about
    /// the platform underneath it. Permitted only in Light mode.
    SoftwareMeasurement,
}

impl std::fmt::Display for MeasurementSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MeasurementSource::Tpm2 => write!(f, "tpm2"),
            MeasurementSource::SoftwareMeasurement => write!(f, "software_measurement"),
        }
    }
}

/// Attestation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationConfig {
    /// Measurement source. Non-Light modes require `tpm2`.
    pub measurement_source: MeasurementSource,
    /// Measurements a report must match before the node is considered verified.
    ///
    /// These are **pinned by the operator at deployment time**. A caller cannot
    /// supply them: accepting caller-supplied expectations would let anyone read
    /// the node's own measurements back to it and mark it verified.
    pub expected: Option<ExpectedMeasurementsConfig>,
    /// Re-attestation interval in hours.
    pub interval_hours: u64,
    /// Refuse to serve until a client has verified attestation.
    pub halt_until_verified: bool,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            measurement_source: MeasurementSource::Tpm2,
            expected: None,
            interval_hours: 24,
            halt_until_verified: true,
        }
    }
}

/// Operator-pinned expected measurements.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExpectedMeasurementsConfig {
    /// Expected PCR values, by index.
    #[serde(default)]
    pub pcr_values: std::collections::HashMap<u8, String>,
    /// Expected enclave measurement.
    #[serde(default)]
    pub mrenclave: Option<String>,
    /// Expected enclave signer measurement.
    #[serde(default)]
    pub mrsigner: Option<String>,
    /// Minimum acceptable security version number.
    #[serde(default)]
    pub min_isv_svn: u16,
}

impl ExpectedMeasurementsConfig {
    /// Whether the operator pinned anything at all. An empty pin set cannot
    /// distinguish a genuine node from an impostor, so verification treats it
    /// as unconfigured rather than as trivially satisfied.
    pub fn is_empty(&self) -> bool {
        self.pcr_values.is_empty() && self.mrenclave.is_none() && self.mrsigner.is_none()
    }
}

/// API request limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Maximum request body size in bytes.
    pub max_request_bytes: usize,
    /// Maximum messages in one inference request.
    pub max_messages: usize,
    /// Maximum total characters across all messages.
    pub max_prompt_chars: usize,
    /// Maximum concurrent TLS connections.
    pub max_connections: usize,
    /// Seconds allowed for a TLS handshake before the connection is dropped.
    pub tls_handshake_timeout_seconds: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_request_bytes: 1024 * 1024,
            max_messages: 256,
            max_prompt_chars: 256 * 1024,
            max_connections: 1024,
            tls_handshake_timeout_seconds: 15,
        }
    }
}

/// Full Cordon deployment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CordonConfig {
    /// Deployment mode
    pub mode: DeploymentMode,
    /// Unique node ID
    pub node_id: String,
    /// Deployment name
    pub deployment_name: String,
    /// Deployment ID (used in key derivation)
    pub deployment_id: String,
    /// Network configuration
    pub network: NetworkConfig,
    /// TEE configuration
    pub tee: TeeConfig,
    /// Side-channel mitigation configuration
    pub side_channel: SideChannelConfig,
    /// HSM configuration
    pub hsm: HsmConfig,
    /// Boot/TPM configuration
    pub boot: BootConfig,
    /// Model store configuration
    pub model_store: ModelStoreConfig,
    /// Inference engine configuration
    pub inference: InferenceConfig,
    /// Audit log configuration
    pub audit: AuditConfig,
    /// Update configuration
    pub updates: UpdateConfig,
    /// Sustained attack detector configuration
    pub sustained_attack: AttackDetectorConfig,
    /// Model runtime configuration
    #[serde(default)]
    pub runtime: RuntimeConfig,
    /// Operator console configuration
    #[serde(default)]
    pub ui: UiConfig,
    /// Attestation configuration
    #[serde(default)]
    pub attestation: AttestationConfig,
    /// API request limits
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Path to the client authorization registry (a JSON array of ClientPolicy)
    #[serde(default)]
    pub client_registry_path: Option<PathBuf>,
    /// Log level (trace/debug/info/warn/error)
    pub log_level: String,
}

impl CordonConfig {
    /// Load configuration from a TOML file
    pub fn from_file(path: &std::path::Path) -> CordonResult<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| CordonError::ConfigError(format!("Cannot read config file: {}", e)))?;
        let config: CordonConfig = toml::from_str(&content)
            .map_err(|e| CordonError::ConfigError(format!("Invalid config: {}", e)))?;
        config.validate()?;
        Ok(config)
    }

    /// Create a default Light mode configuration for development/testing
    pub fn default_light(node_id: String, deployment_id: String) -> Self {
        Self {
            mode: DeploymentMode::Light,
            node_id,
            deployment_name: "cordon-dev".to_string(),
            deployment_id,
            network: NetworkConfig {
                require_mtls: false,
                client_ca_path: None,
                ..NetworkConfig::default()
            },
            tee: TeeConfig {
                preferred: TeePreference::Simulation,
                halt_on_attestation_failure: false,
                ..TeeConfig::default()
            },
            side_channel: SideChannelConfig {
                timing_normalization: TimingNormalizationConfig {
                    enabled: false,
                    mode: TimingMode::None,
                    ..TimingNormalizationConfig::default()
                },
                ..SideChannelConfig::default()
            },
            hsm: HsmConfig {
                provider: HsmProvider::SoftHsm2,
                fips_level: 1,
                ..HsmConfig::default()
            },
            boot: BootConfig {
                tpm_required: false,
                secure_boot: false,
                dm_verity: false,
                ..BootConfig::default()
            },
            model_store: ModelStoreConfig::default(),
            inference: InferenceConfig {
                multi_tenant: true,
                ..InferenceConfig::default()
            },
            audit: AuditConfig::default(),
            updates: UpdateConfig::default(),
            sustained_attack: AttackDetectorConfig::default(),
            runtime: RuntimeConfig {
                backend: RuntimeBackend::None,
                model_dir: PathBuf::from("./data/models"),
                ..RuntimeConfig::default()
            },
            ui: UiConfig::default(),
            attestation: AttestationConfig {
                measurement_source: MeasurementSource::SoftwareMeasurement,
                halt_until_verified: false,
                ..AttestationConfig::default()
            },
            limits: LimitsConfig::default(),
            client_registry_path: None,
            log_level: "info".to_string(),
        }
    }

    /// Validate the configuration, refusing any combination that would present
    /// a weaker guarantee than the selected deployment mode advertises.
    ///
    /// Every check here fails closed. A configuration that cannot deliver its
    /// mode's guarantees is rejected at startup rather than degraded silently at
    /// runtime, because a node that quietly downgrades is worse than one that
    /// refuses to boot: operators believe the stronger claim either way.
    pub fn validate(&self) -> CordonResult<()> {
        let is_light = self.mode == DeploymentMode::Light;

        if self.deployment_id.trim().is_empty() {
            return Err(CordonError::ConfigError(
                "deployment_id must not be empty — it is an input to every derived key".into(),
            ));
        }
        if self.node_id.trim().is_empty() {
            return Err(CordonError::ConfigError("node_id must not be empty".into()));
        }

        if self.mode == DeploymentMode::Dark {
            if self.hsm.fips_level < 4 {
                return Err(CordonError::ConfigError(
                    "Dark mode requires a FIPS 140-2 Level 4 HSM".into(),
                ));
            }
            if self.inference.multi_tenant {
                return Err(CordonError::ConfigError(
                    "Dark mode does not permit multi-tenant operation".into(),
                ));
            }
        }

        // ── Hardware root of trust ──────────────────────────────────────────
        // Outside Light mode the measurements in an attestation report must come
        // from a TPM. A configuration digest describes the software Cordon was
        // told to run; it says nothing about the platform, so it cannot back a
        // hardware-attestation claim.
        if !is_light {
            if self.tee.preferred == TeePreference::Simulation {
                return Err(CordonError::ConfigError(format!(
                    "tee.preferred = \"simulation\" is not permitted in {} mode. \
                     Select a hardware TEE, or run in Light mode.",
                    self.mode
                )));
            }
            if self.attestation.measurement_source != MeasurementSource::Tpm2 {
                return Err(CordonError::ConfigError(format!(
                    "attestation.measurement_source = \"{}\" is not permitted in {} \
                     mode. A software measurement is a configuration digest, not a \
                     hardware root of trust. Set it to \"tpm2\".",
                    self.attestation.measurement_source, self.mode
                )));
            }
            if !self.boot.tpm_required {
                return Err(CordonError::ConfigError(format!(
                    "{} mode requires boot.tpm_required = true",
                    self.mode
                )));
            }
            match &self.attestation.expected {
                Some(expected) if !expected.is_empty() => {}
                _ => {
                    return Err(CordonError::ConfigError(format!(
                        "{} mode requires pinned attestation.expected measurements. \
                         Without them the node cannot distinguish a genuine platform \
                         from an impostor. Capture them with `cordon attest --pin`.",
                        self.mode
                    )));
                }
            }
        }

        // ── Transport ───────────────────────────────────────────────────────
        if !is_light {
            if !self.network.require_mtls {
                return Err(CordonError::ConfigError(format!(
                    "{} mode requires network.require_mtls = true — client identity \
                     must be bound to a certificate, not asserted in a header",
                    self.mode
                )));
            }
            if self.network.client_ca_path.is_none() {
                return Err(CordonError::ConfigError(
                    "mTLS requires network.client_ca_path so client certificates can \
                     be verified against a CA"
                        .into(),
                ));
            }
        }
        if self.network.require_mtls && self.network.client_ca_path.is_none() {
            return Err(CordonError::ConfigError(
                "network.require_mtls = true requires network.client_ca_path".into(),
            ));
        }

        // ── Operator console ────────────────────────────────────────────────
        if self.ui.enabled {
            if !is_light {
                return Err(CordonError::ConfigError(format!(
                    "the operator console is not permitted in {} mode — it is an \
                     unauthenticated HTML surface. Use the CLI or the API instead.",
                    self.mode
                )));
            }
            if !Self::is_loopback_address(&self.ui.bind_address) {
                return Err(CordonError::ConfigError(format!(
                    "ui.bind_address must be a loopback address, not {}. The console \
                     has no authentication of its own and must never be reachable off \
                     the host.",
                    self.ui.bind_address
                )));
            }
        }

        // ── Model runtime ───────────────────────────────────────────────────
        match self.runtime.backend {
            RuntimeBackend::None if !is_light => {
                return Err(CordonError::ConfigError(format!(
                    "runtime.backend = \"none\" returns placeholder text and is not \
                     permitted in {} mode",
                    self.mode
                )));
            }
            RuntimeBackend::External if self.runtime.endpoint_url.is_none() => {
                return Err(CordonError::ConfigError(
                    "runtime.backend = \"external\" requires runtime.endpoint_url".into(),
                ));
            }
            _ => {}
        }

        // ── Limits ──────────────────────────────────────────────────────────
        if self.inference.max_concurrent_requests == 0 {
            return Err(CordonError::ConfigError(
                "inference.max_concurrent_requests must be at least 1".into(),
            ));
        }
        if self.limits.max_request_bytes == 0 {
            return Err(CordonError::ConfigError(
                "limits.max_request_bytes must be greater than zero".into(),
            ));
        }
        if self.inference.max_output_tokens == 0 {
            return Err(CordonError::ConfigError(
                "inference.max_output_tokens must be greater than zero".into(),
            ));
        }

        Ok(())
    }

    /// Whether the deployment mode's guarantees rest on hardware.
    pub fn requires_hardware_tee(&self) -> bool {
        self.mode != DeploymentMode::Light
    }

    /// Whether this configuration requires mTLS.
    pub fn requires_mtls(&self) -> bool {
        self.network.require_mtls
    }

    /// Whether this deployment mode permits reaching the public internet to
    /// fetch a model. Air-gapped modes acquire models from physical media
    /// through `cordon-provision` instead.
    pub fn permits_model_download(&self) -> bool {
        matches!(
            self.mode,
            DeploymentMode::Light | DeploymentMode::SovereignCloud
        )
    }

    /// Whether the attestation report's measurements come from hardware.
    pub fn has_hardware_measurements(&self) -> bool {
        self.attestation.measurement_source == MeasurementSource::Tpm2
    }

    /// Whether a hostname or address refers to the local machine.
    ///
    /// Accepts a bare host, `host:port`, and the bracketed IPv6 forms. A bare
    /// IPv6 address such as `::1` contains colons that are not a port
    /// separator, so the port is only stripped when the form is unambiguous.
    fn is_loopback_address(addr: &str) -> bool {
        let addr = addr.trim();

        let host = if let Some(rest) = addr.strip_prefix('[') {
            // "[::1]" or "[::1]:8478"
            match rest.split_once(']') {
                Some((inner, _)) => inner,
                None => return false,
            }
        } else if addr.matches(':').count() == 1 {
            // "host:port" — a single colon cannot be an IPv6 address.
            addr.split_once(':').map(|(h, _)| h).unwrap_or(addr)
        } else {
            // A bare host, or a bare IPv6 address.
            addr
        };

        if host.eq_ignore_ascii_case("localhost") {
            return true;
        }
        host.parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
    }
}

impl Default for CordonConfig {
    fn default() -> Self {
        Self::default_light(
            uuid::Uuid::new_v4().to_string(),
            uuid::Uuid::new_v4().to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn light() -> CordonConfig {
        CordonConfig::default_light("node-1".into(), "deployment-1".into())
    }

    /// Build a config that a non-Light mode should accept, so each test can
    /// break exactly one invariant and assert that it is the reason for refusal.
    fn hardened(mode: DeploymentMode) -> CordonConfig {
        let mut c = light();
        c.mode = mode;
        c.tee.preferred = TeePreference::AmdSevSnp;
        c.boot.tpm_required = true;
        c.network.require_mtls = true;
        c.network.client_ca_path = Some(PathBuf::from("/etc/cordon/tls/client-ca.crt"));
        c.runtime.backend = RuntimeBackend::Supervised;
        c.ui.enabled = false;
        c.inference.multi_tenant = false;
        c.hsm.fips_level = 4;
        c.attestation = AttestationConfig {
            measurement_source: MeasurementSource::Tpm2,
            expected: Some(ExpectedMeasurementsConfig {
                mrenclave: Some("a".repeat(64)),
                ..ExpectedMeasurementsConfig::default()
            }),
            ..AttestationConfig::default()
        };
        c
    }

    #[test]
    fn light_default_is_valid() {
        assert!(light().validate().is_ok());
    }

    #[test]
    fn hardened_baseline_is_valid() {
        for mode in [
            DeploymentMode::Island,
            DeploymentMode::Vault,
            DeploymentMode::SovereignCloud,
            DeploymentMode::Dark,
        ] {
            assert!(
                hardened(mode.clone()).validate().is_ok(),
                "hardened baseline rejected for {}",
                mode
            );
        }
    }

    #[test]
    fn software_measurement_is_refused_outside_light_mode() {
        let mut c = hardened(DeploymentMode::Vault);
        c.attestation.measurement_source = MeasurementSource::SoftwareMeasurement;
        let err = c.validate().unwrap_err().to_string();
        assert!(
            err.contains("measurement_source"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn simulation_tee_is_refused_outside_light_mode() {
        let mut c = hardened(DeploymentMode::Island);
        c.tee.preferred = TeePreference::Simulation;
        assert!(c.validate().is_err());
    }

    #[test]
    fn unpinned_measurements_are_refused_outside_light_mode() {
        let mut c = hardened(DeploymentMode::Vault);
        c.attestation.expected = None;
        assert!(c.validate().is_err());

        // An empty pin set is not a pin set.
        c.attestation.expected = Some(ExpectedMeasurementsConfig::default());
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("pinned"), "unexpected error: {}", err);
    }

    #[test]
    fn mtls_is_mandatory_outside_light_mode() {
        let mut c = hardened(DeploymentMode::Vault);
        c.network.require_mtls = false;
        assert!(c.validate().is_err());
    }

    #[test]
    fn mtls_without_a_client_ca_is_refused() {
        let mut c = light();
        c.network.require_mtls = true;
        c.network.client_ca_path = None;
        assert!(c.validate().is_err());
    }

    #[test]
    fn console_is_refused_outside_light_mode() {
        let mut c = hardened(DeploymentMode::Vault);
        c.ui.enabled = true;
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("console"), "unexpected error: {}", err);
    }

    #[test]
    fn console_must_bind_loopback() {
        let mut c = light();
        c.ui.enabled = true;
        c.ui.bind_address = "0.0.0.0".into();
        assert!(c.validate().is_err());

        for addr in ["127.0.0.1", "::1", "localhost", "127.0.0.1:8478"] {
            c.ui.bind_address = addr.into();
            assert!(c.validate().is_ok(), "loopback address {} rejected", addr);
        }
    }

    #[test]
    fn placeholder_runtime_is_refused_outside_light_mode() {
        let mut c = hardened(DeploymentMode::Island);
        c.runtime.backend = RuntimeBackend::None;
        assert!(c.validate().is_err());
    }

    #[test]
    fn external_runtime_requires_an_endpoint() {
        let mut c = light();
        c.runtime.backend = RuntimeBackend::External;
        c.runtime.endpoint_url = None;
        assert!(c.validate().is_err());
    }

    #[test]
    fn dark_mode_rejects_multi_tenancy_and_weak_hsm() {
        let mut c = hardened(DeploymentMode::Dark);
        c.inference.multi_tenant = true;
        assert!(c.validate().is_err());

        let mut c = hardened(DeploymentMode::Dark);
        c.hsm.fips_level = 3;
        assert!(c.validate().is_err());
    }

    #[test]
    fn empty_identifiers_are_refused() {
        let mut c = light();
        c.deployment_id = String::new();
        assert!(c.validate().is_err());

        let mut c = light();
        c.node_id = "   ".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn zero_limits_are_refused() {
        let mut c = light();
        c.inference.max_concurrent_requests = 0;
        assert!(c.validate().is_err());

        let mut c = light();
        c.limits.max_request_bytes = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn only_connected_modes_may_download_models() {
        assert!(light().permits_model_download());
        assert!(hardened(DeploymentMode::SovereignCloud).permits_model_download());
        assert!(!hardened(DeploymentMode::Dark).permits_model_download());
        assert!(!hardened(DeploymentMode::Island).permits_model_download());
        assert!(!hardened(DeploymentMode::Vault).permits_model_download());
    }

    #[test]
    fn config_round_trips_through_toml() {
        let original = light();
        let text = toml::to_string_pretty(&original).unwrap();
        let parsed: CordonConfig = toml::from_str(&text).unwrap();
        assert_eq!(parsed.mode, original.mode);
        assert_eq!(parsed.runtime.backend, original.runtime.backend);
        assert_eq!(parsed.ui.enabled, original.ui.enabled);
        assert!(parsed.validate().is_ok());
    }

    #[test]
    fn loopback_detection() {
        assert!(CordonConfig::is_loopback_address("127.0.0.1"));
        assert!(CordonConfig::is_loopback_address("127.5.5.5"));
        assert!(CordonConfig::is_loopback_address("::1"));
        assert!(CordonConfig::is_loopback_address("[::1]:8478"));
        assert!(CordonConfig::is_loopback_address("localhost"));
        assert!(!CordonConfig::is_loopback_address("0.0.0.0"));
        assert!(!CordonConfig::is_loopback_address("192.168.1.10"));
    }
}
