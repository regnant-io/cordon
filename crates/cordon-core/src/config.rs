//! Cordon deployment configuration — §11.3
//!
//! Implements the full configuration schema from the spec.
//! Configuration is loaded from a TOML file and validated at startup.

use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use crate::error::{CordonError, CordonResult};

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
    /// Integrity check interval in minutes
    pub integrity_check_interval_minutes: u64,
    /// Halt inference immediately on integrity violation
    pub halt_on_tamper: bool,
}

impl Default for ModelStoreConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/cordon/bundles"),
            integrity_check_interval_minutes: 15,
            halt_on_tamper: true,
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
            log_level: "info".to_string(),
        }
    }

    /// Validate configuration consistency
    pub fn validate(&self) -> CordonResult<()> {
        // Dark mode requirements
        if self.mode == DeploymentMode::Dark {
            if self.hsm.fips_level < 4 {
                return Err(CordonError::ConfigError(
                    "Dark mode requires FIPS 140-2 Level 4 HSM".into(),
                ));
            }
            if self.inference.multi_tenant {
                return Err(CordonError::ConfigError(
                    "Dark mode does not permit multi-tenant operation".into(),
                ));
            }
        }

        // Light mode must be explicitly selected
        if self.mode == DeploymentMode::Light && self.tee.preferred != TeePreference::Simulation {
            // Light mode with a real TEE is fine; just warn
        }

        // TEE must be mandatory for non-light modes
        if self.mode != DeploymentMode::Light
            && self.tee.preferred == TeePreference::Simulation
        {
            return Err(CordonError::ConfigError(
                "Simulation TEE is not permitted in non-Light deployment modes".into(),
            ));
        }

        Ok(())
    }

    /// Whether this configuration requires hardware TEE
    pub fn requires_hardware_tee(&self) -> bool {
        self.mode != DeploymentMode::Light
    }

    /// Whether this configuration requires mTLS
    pub fn requires_mtls(&self) -> bool {
        self.network.require_mtls
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
