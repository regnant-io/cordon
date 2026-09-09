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
    /// Preferred TEE technology. Reported in every attestation report and
    /// checked against the pinned `tee_type` during verification.
    pub preferred: TeePreference,
    /// Minimum security version number, reported as the report's ISV SVN.
    pub minimum_security_version: u16,
}

impl Default for TeeConfig {
    fn default() -> Self {
        Self {
            preferred: TeePreference::AmdSevSnp,
            minimum_security_version: 3,
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
    /// What outbound access Cordon may use. See [`OutboundPolicy`].
    pub outbound_policy: OutboundPolicy,
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
            outbound_policy: OutboundPolicy::ZeroEgress,
            bind_address: "0.0.0.0".to_string(),
            api_port: 8443,
            tls_cert_path: PathBuf::from("/etc/cordon/tls/server.crt"),
            tls_key_path: PathBuf::from("/etc/cordon/tls/server.key"),
            client_ca_path: Some(PathBuf::from("/etc/cordon/tls/client-ca.crt")),
            require_mtls: true,
        }
    }
}

/// What outbound network access this deployment permits.
///
/// # What Cordon can and cannot enforce
///
/// Cordon is a process. It cannot stop packets leaving the host — that is a
/// firewall's job, and the deployment guide says so. What it *can* do, and now
/// does, is refuse to initiate egress itself: under [`Self::ZeroEgress`] the
/// model downloader is disabled and a non-loopback runtime endpoint is refused,
/// so no code path in Cordon opens a connection off the machine.
///
/// That is a real property and a narrower one than "no egress". State it that
/// way to operators rather than letting a configuration field imply the network
/// is sealed when only Cordon's own behaviour is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundPolicy {
    /// Cordon initiates no outbound connections. Models arrive as encrypted
    /// bundles through `cordon-provision`, and the model runtime must be local.
    ZeroEgress,
    /// Cordon may reach the network — to fetch models from the Hugging Face
    /// Hub, and to reach a runtime endpoint the operator configured.
    Restricted,
}

/// Side-channel mitigation configuration.
///
/// Only timing normalisation is here, because it is the only one Cordon
/// implements. This section previously also carried `constant_time_enforcement`,
/// `memory_zeroize_on_completion` and `response_size_padding`, none of which any
/// code read — an operator could set all three, read the file back as a summary
/// of the node's defences, and be wrong about all of them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SideChannelConfig {
    /// Timing normalization settings.
    pub timing_normalization: TimingNormalizationConfig,
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

/// Key-custody declaration.
///
/// Cordon does not talk to an HSM. The Client Master Key reaches it through
/// `CORDON_CMK_FILE`, and where that file comes from — an HSM export, a secrets
/// manager, a tmpfs — is the operator's arrangement.
///
/// `fips_level` is therefore an operator *declaration*, not something Cordon
/// verifies, and it is used only to refuse a configuration that contradicts its
/// own mode: Dark mode claims a FIPS 140-2 Level 4 HSM, so a Dark configuration
/// declaring less is refused as internally inconsistent. The previous version
/// of this section also carried a provider name, a slot ID and a PIN variable,
/// which together looked like PKCS#11 integration and were read by nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmConfig {
    /// The FIPS 140-2 level the operator asserts their key custody meets.
    pub fips_level: u8,
}

impl Default for HsmConfig {
    fn default() -> Self {
        Self { fips_level: 3 }
    }
}

/// Boot/TPM configuration.
///
/// `secure_boot` and `dm_verity` are operator declarations reported on the
/// health endpoint; Cordon does not verify them itself, and a TPM-attested
/// deployment gets the real answer from PCR 7 and the pinned values. The
/// `pcr_policy` block that used to live here duplicated
/// `[attestation.expected.pcr_values]` and was read by nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootConfig {
    /// Require a TPM 2.0 device. Enforced when the measurement source is
    /// `tpm2`.
    pub tpm_required: bool,
    /// TPM version string, reported on the health endpoint.
    pub tpm_version: String,
    /// Whether the operator asserts UEFI Secure Boot is enabled.
    pub secure_boot: bool,
    /// Whether the operator asserts dm-verity protects the root filesystem.
    pub dm_verity: bool,
}

impl Default for BootConfig {
    fn default() -> Self {
        Self {
            tpm_required: true,
            tpm_version: "2.0".to_string(),
            secure_boot: true,
            dm_verity: true,
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
    /// Zero KV cache on session end
    pub kv_cache_zero_on_session_end: bool,
    /// Whether multi-tenant operation is allowed
    pub multi_tenant: bool,
    /// Maximum output tokens
    pub max_output_tokens: u32,
}

impl Default for InferenceConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 32,
            default_timeout_seconds: 120,
            kv_cache_zero_on_session_end: true,
            multi_tenant: false,
            max_output_tokens: 4096,
        }
    }
}

/// Audit log configuration.
///
/// The format is JSONL and the export method is "read the files"; both were
/// configurable and neither was ever consulted. `retention_days` implied the
/// node rotated old entries out, which it does not — an append-only log that
/// deleted its own history would defeat the point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Directory the audit log is written to.
    pub log_path: PathBuf,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_path: PathBuf::from("/cordon/audit"),
        }
    }
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
    /// Repeated identical input hashes to trigger rate-limit
    pub replay_probe_threshold: u32,
}

impl Default for AttackDetectorConfig {
    fn default() -> Self {
        Self {
            auth_failure_threshold_per_minute: 10,
            global_failure_threshold_per_minute: 50,
            covert_channel_score_threshold: 0.7,
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
///
/// These are not interchangeable, and the differences are the whole subject.
/// A software measurement describes what Cordon was configured to run. A TPM
/// describes how the machine booted — but the operator still owns the machine
/// afterwards and can read its memory. A confidential VM describes a running
/// guest whose memory the operator *cannot* read, which is the only one of the
/// three that closes the gap between "a control plane" and "a trusted execution
/// environment".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementSource {
    /// PCR values read from a TPM 2.0 device via `tpm2-tools`.
    ///
    /// Attests the boot chain. It does not make the node's memory private from
    /// the host, so root on the host still reads prompts and completions.
    Tpm2,
    /// An AMD SEV-SNP attestation report, read through the kernel's
    /// `configfs-tsm` interface.
    ///
    /// Cordon, the model runtime, the weights, and the prompts are all inside
    /// the encrypted guest; the hypervisor is outside it. This is the source
    /// that lets a deployment claim confidentiality against the operator rather
    /// than merely against the network.
    SevSnp,
    /// An AWS Nitro Enclaves attestation document, signed by the Nitro Security
    /// Module.
    ///
    /// The same confidentiality property SEV-SNP provides, reached differently:
    /// the enclave's memory is carved out of the parent EC2 instance and is not
    /// readable from it. See `SECURITY.md` for the constraints an enclave puts
    /// on the rest of Cordon — no persistent storage and no network but vsock —
    /// which are why this source is not yet usable for the node's own runtime.
    NitroEnclave,
    /// A digest of the running configuration and build. This is a **software
    /// integrity measurement**, not a hardware root of trust: it attests that
    /// the node's configuration is what the operator expects, and nothing about
    /// the platform underneath it. Permitted only in Light mode.
    SoftwareMeasurement,
}

impl MeasurementSource {
    /// Whether this source rests on hardware the operator cannot forge.
    pub fn is_hardware(&self) -> bool {
        matches!(
            self,
            MeasurementSource::Tpm2 | MeasurementSource::SevSnp | MeasurementSource::NitroEnclave
        )
    }

    /// Whether this source also makes the node's memory private from the host.
    ///
    /// Only a confidential VM does. A TPM attests how a machine booted and
    /// leaves its memory readable by anyone with root on it, which is why
    /// `ARCHITECTURE.md` lists that adversary as undefended in every mode that
    /// is not running in one.
    pub fn provides_memory_confidentiality(&self) -> bool {
        matches!(
            self,
            MeasurementSource::SevSnp | MeasurementSource::NitroEnclave
        )
    }
}

impl std::fmt::Display for MeasurementSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MeasurementSource::Tpm2 => write!(f, "tpm2"),
            MeasurementSource::SevSnp => write!(f, "sev_snp"),
            MeasurementSource::NitroEnclave => write!(f, "nitro_enclave"),
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
    ///
    /// A `BTreeMap` so the values an operator reviews, and the file they are
    /// written into, are always in ascending index order. With a `HashMap` the
    /// generated block came out shuffled differently on every run, which makes
    /// a diff between two pinnings unreadable — and reviewing that diff is the
    /// entire point of pinning by hand.
    #[serde(default)]
    pub pcr_values: std::collections::BTreeMap<u8, String>,
    /// Expected enclave measurement.
    #[serde(default)]
    pub mrenclave: Option<String>,
    /// Expected enclave signer measurement.
    #[serde(default)]
    pub mrsigner: Option<String>,
    /// Minimum acceptable security version number.
    #[serde(default)]
    pub min_isv_svn: u16,
    /// Pins for an AMD SEV-SNP platform.
    ///
    /// Required when `measurement_source = "sev_snp"`: without a pinned AMD
    /// root there is nothing for the chip's endorsement key to chain to, and a
    /// report proves only that it is internally consistent.
    #[serde(default)]
    pub sev_snp: Option<SevSnpPinsConfig>,
    /// Pins for an AWS Nitro Enclaves platform.
    ///
    /// Required when `measurement_source = "nitro_enclave"`, for the same
    /// reason [`Self::sev_snp`] is: a document that supplies its own root
    /// certificate proves only that whoever wrote it owns a key.
    #[serde(default)]
    pub nitro: Option<NitroPinsConfig>,
}

/// Operator pins for an AWS Nitro Enclaves platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NitroPinsConfig {
    /// The AWS Nitro Enclaves root CA certificate, base64 DER.
    ///
    /// AWS publishes this; download it once, check its fingerprint against
    /// AWS's published value, and commit it. Taking it from the attestation
    /// document instead would mean trusting the document to vouch for itself.
    pub root_der_b64: String,
    /// Expected PCR values, lowercase hex, by index.
    ///
    /// PCR0 measures the enclave image file, PCR1 the kernel and bootstrap,
    /// PCR2 the application. Pin at least PCR0 — it is what says the enclave is
    /// running the image you built. PCR3 (IAM role) and PCR4 (parent instance
    /// ID) tie a deployment to one role or one machine, which is occasionally
    /// what an operator wants and usually not.
    #[serde(default)]
    pub pcr_values: std::collections::BTreeMap<u8, String>,
    /// How stale a document may be, in seconds.
    ///
    /// The challenge nonce is the primary defence against replay; this is a
    /// second bound for a document presented outside a challenge exchange. Zero
    /// disables it.
    #[serde(default = "default_nitro_max_age")]
    pub max_age_seconds: u64,
}

fn default_nitro_max_age() -> u64 {
    300
}

impl Default for NitroPinsConfig {
    fn default() -> Self {
        Self {
            root_der_b64: String::new(),
            pcr_values: std::collections::BTreeMap::new(),
            max_age_seconds: default_nitro_max_age(),
        }
    }
}

/// Operator pins for an AMD SEV-SNP platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SevSnpPinsConfig {
    /// The AMD Root Key certificate, base64 DER.
    ///
    /// Pinned by the operator rather than taken from the platform's own
    /// certificate cache: a chain that supplies its own root establishes only
    /// that it is self-consistent. Download it once from AMD, review it, and
    /// commit it.
    pub amd_root_der_b64: String,
    /// Minimum acceptable bootloader SVN.
    #[serde(default)]
    pub min_bootloader_svn: u8,
    /// Minimum acceptable TEE (ASP OS) SVN.
    #[serde(default)]
    pub min_tee_svn: u8,
    /// Minimum acceptable SNP firmware SVN.
    #[serde(default)]
    pub min_snp_svn: u8,
    /// Minimum acceptable microcode SVN.
    ///
    /// This is the one that moves when AMD publishes a microcode fix. Leaving
    /// it at zero accepts a platform running firmware with known, patched
    /// vulnerabilities.
    #[serde(default)]
    pub min_microcode_svn: u8,
    /// Refuse a guest whose launch policy permits debugging.
    ///
    /// Defaults to true and should stay that way: a debuggable guest's memory
    /// is readable by the hypervisor, which is exactly the party a confidential
    /// VM excludes.
    #[serde(default = "default_refuse_debuggable")]
    pub refuse_debuggable_guest: bool,
    /// The VMPL a report must have been produced at. Cordon runs at 0.
    #[serde(default)]
    pub expected_vmpl: u32,
}

fn default_refuse_debuggable() -> bool {
    true
}

impl Default for SevSnpPinsConfig {
    fn default() -> Self {
        Self {
            amd_root_der_b64: String::new(),
            min_bootloader_svn: 0,
            min_tee_svn: 0,
            min_snp_svn: 0,
            min_microcode_svn: 0,
            refuse_debuggable_guest: true,
            expected_vmpl: 0,
        }
    }
}

impl ExpectedMeasurementsConfig {
    /// Whether the operator pinned anything at all. An empty pin set cannot
    /// distinguish a genuine node from an impostor, so verification treats it
    /// as unconfigured rather than as trivially satisfied.
    pub fn is_empty(&self) -> bool {
        self.pcr_values.is_empty() && self.mrenclave.is_none() && self.mrsigner.is_none()
    }
}

/// Output content policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContentPolicyConfig {
    /// A JSON policy applied to every client that does not name its own.
    ///
    /// Absent means the built-in default, which flags personally identifying
    /// information and alters nothing. A client can override this by setting
    /// `content_policy_path` in the client registry.
    #[serde(default)]
    pub default_path: Option<PathBuf>,
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
    /// Output content policy
    #[serde(default)]
    pub content_policy: ContentPolicyConfig,
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
                // Light mode is the mode you pull a model in, so it has to be
                // able to reach the Hub. Every other mode defaults to no egress.
                outbound_policy: OutboundPolicy::Restricted,
                ..NetworkConfig::default()
            },
            tee: TeeConfig {
                preferred: TeePreference::Simulation,
                ..TeeConfig::default()
            },
            side_channel: SideChannelConfig {
                timing_normalization: TimingNormalizationConfig {
                    enabled: false,
                    mode: TimingMode::None,
                    ..TimingNormalizationConfig::default()
                },
            },
            hsm: HsmConfig { fips_level: 1 },
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
            content_policy: ContentPolicyConfig::default(),
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
            if !self.attestation.measurement_source.is_hardware() {
                return Err(CordonError::ConfigError(format!(
                    "attestation.measurement_source = \"{}\" is not permitted in {} \
                     mode. A software measurement is a configuration digest, not a \
                     hardware root of trust. Set it to \"sev_snp\" for a confidential \
                     VM, or \"tpm2\" for a TPM-attested host.",
                    self.attestation.measurement_source, self.mode
                )));
            }
            // A TPM is required only when the measurements come from one. A
            // confidential VM attests through its own hardware and need not
            // also expose a vTPM.
            if self.attestation.measurement_source == MeasurementSource::Tpm2
                && !self.boot.tpm_required
            {
                return Err(CordonError::ConfigError(format!(
                    "{} mode with attestation.measurement_source = \"tpm2\" requires \
                     boot.tpm_required = true",
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

            // A SEV-SNP report is signed by a per-chip key certified by AMD.
            // Without a pinned root there is nothing for that certificate to
            // chain to, and the report degrades to a self-consistent blob.
            if self.attestation.measurement_source == MeasurementSource::SevSnp {
                let root = self
                    .attestation
                    .expected
                    .as_ref()
                    .and_then(|e| e.sev_snp.as_ref())
                    .map(|snp| snp.amd_root_der_b64.trim())
                    .unwrap_or("");
                if root.is_empty() {
                    return Err(CordonError::ConfigError(format!(
                        "attestation.measurement_source = \"sev_snp\" in {} mode requires \
                         a pinned AMD root certificate under \
                         [attestation.expected.sev_snp]. Without one the chip's \
                         endorsement key chains to nothing, and the attestation proves \
                         only that the report is internally consistent.",
                        self.mode
                    )));
                }
            }

            // The same requirement for Nitro, for the same reason: a document
            // carries its own certificate bundle, so the only thing that makes
            // the bundle mean anything is a root that did not come with it.
            if self.attestation.measurement_source == MeasurementSource::NitroEnclave {
                let pins = self
                    .attestation
                    .expected
                    .as_ref()
                    .and_then(|e| e.nitro.as_ref());
                let root = pins.map(|n| n.root_der_b64.trim()).unwrap_or("");
                if root.is_empty() {
                    return Err(CordonError::ConfigError(format!(
                        "attestation.measurement_source = \"nitro_enclave\" in {} mode                          requires a pinned AWS Nitro root certificate under                          [attestation.expected.nitro]. Without one the document's                          certificate chains only to the bundle the document itself                          supplied, which proves nothing.",
                        self.mode
                    )));
                }
                // PCR0 identifies the enclave image. A chain to the AWS root
                // without it says "some genuine Nitro enclave", which is not
                // the same as "the enclave you built".
                if pins.map_or(true, |n| !n.pcr_values.contains_key(&0)) {
                    return Err(CordonError::ConfigError(format!(
                        "attestation.measurement_source = \"nitro_enclave\" in {} mode                          requires a pinned PCR0 under                          [attestation.expected.nitro.pcr_values]. Without it the                          attestation establishes that some genuine Nitro enclave                          answered, not that yours did.",
                        self.mode
                    )));
                }
            }
        }

        // ── Egress ──────────────────────────────────────────────────────────
        // Vault, Island and Dark are documented as having no outbound access.
        // Nothing checked that, so a configuration could claim one of those
        // modes while leaving Cordon free to reach the Hub.
        if matches!(
            self.mode,
            DeploymentMode::Vault | DeploymentMode::Island | DeploymentMode::Dark
        ) && self.permits_egress()
        {
            return Err(CordonError::ConfigError(format!(
                "{} mode requires network.outbound_policy = \"zero_egress\". The mode \
                 is documented as having no outbound access; a configuration that \
                 claims it while permitting egress is claiming something it does not \
                 deliver.",
                self.mode
            )));
        }

        if !self.permits_egress() {
            if let Some(url) = &self.runtime.endpoint_url {
                if self.runtime.backend == RuntimeBackend::External
                    && !crate::runtime::is_loopback_url(url)
                {
                    return Err(CordonError::ConfigError(format!(
                        "network.outbound_policy is \"zero_egress\" but \
                         runtime.endpoint_url is {}, which is not on this host. Every \
                         prompt would leave the machine. Use runtime.backend = \
                         \"supervised\", or point at a loopback address.",
                        url
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

    /// Whether Cordon may open outbound connections.
    pub fn permits_egress(&self) -> bool {
        self.network.outbound_policy != OutboundPolicy::ZeroEgress
    }

    /// Whether this deployment may reach the public internet to fetch a model.
    ///
    /// Both the mode and the declared outbound policy have to allow it. The
    /// mode alone used to decide, which meant an operator could set
    /// `outbound_policy = "zero_egress"` on a Sovereign Cloud node, read that
    /// back as a guarantee, and still have `cordon pull` reach the Hub.
    /// Air-gapped deployments acquire models from physical media through
    /// `cordon-provision`.
    pub fn permits_model_download(&self) -> bool {
        matches!(
            self.mode,
            DeploymentMode::Light | DeploymentMode::SovereignCloud
        ) && self.permits_egress()
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
        c.mode = mode.clone();
        c.tee.preferred = TeePreference::AmdSevSnp;
        c.boot.tpm_required = true;
        c.network.require_mtls = true;
        c.network.client_ca_path = Some(PathBuf::from("/etc/cordon/tls/client-ca.crt"));
        c.runtime.backend = RuntimeBackend::Supervised;
        c.ui.enabled = false;
        c.inference.multi_tenant = false;
        c.hsm.fips_level = 4;
        // Sovereign Cloud is the one hardened mode that may reach the network.
        c.network.outbound_policy = if mode == DeploymentMode::SovereignCloud {
            OutboundPolicy::Restricted
        } else {
            OutboundPolicy::ZeroEgress
        };
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

    /// A confidential-VM source is only worth configuring if the report it
    /// produces can be chained to something. These tests cover the two
    /// requirements that make that true, for both sources.
    #[test]
    fn sev_snp_without_a_pinned_amd_root_is_refused() {
        let mut c = hardened(DeploymentMode::Vault);
        c.attestation.measurement_source = MeasurementSource::SevSnp;

        let refusal = c.validate().unwrap_err().to_string();
        assert!(
            refusal.contains("[attestation.expected.sev_snp]"),
            "the refusal must name the section to fill in: {}",
            refusal
        );
        assert!(
            refusal.contains("chains to nothing"),
            "and must say why it matters: {}",
            refusal
        );
    }

    #[test]
    fn sev_snp_with_a_pinned_amd_root_is_accepted() {
        let mut c = hardened(DeploymentMode::Vault);
        c.attestation.measurement_source = MeasurementSource::SevSnp;
        if let Some(expected) = c.attestation.expected.as_mut() {
            expected.sev_snp = Some(SevSnpPinsConfig {
                amd_root_der_b64: "Zm9ybS1vZi1hLXJvb3QtY2VydGlmaWNhdGU=".into(),
                ..SevSnpPinsConfig::default()
            });
        }
        c.validate().unwrap();
    }

    /// A confidential VM does not need a TPM as well. Requiring one would rule
    /// out every cloud confidential VM that does not expose a vTPM.
    #[test]
    fn a_confidential_vm_does_not_also_require_a_tpm() {
        let mut c = hardened(DeploymentMode::Vault);
        c.attestation.measurement_source = MeasurementSource::SevSnp;
        c.boot.tpm_required = false;
        if let Some(expected) = c.attestation.expected.as_mut() {
            expected.sev_snp = Some(SevSnpPinsConfig {
                amd_root_der_b64: "Zm9ybS1vZi1hLXJvb3QtY2VydGlmaWNhdGU=".into(),
                ..SevSnpPinsConfig::default()
            });
        }
        c.validate().unwrap();
    }

    #[test]
    fn nitro_without_a_pinned_aws_root_is_refused() {
        let mut c = hardened(DeploymentMode::SovereignCloud);
        c.attestation.measurement_source = MeasurementSource::NitroEnclave;

        let refusal = c.validate().unwrap_err().to_string();
        assert!(
            refusal.contains("[attestation.expected.nitro]"),
            "{}",
            refusal
        );
    }

    /// A chain to the AWS root proves "some genuine Nitro enclave". PCR0 is
    /// what makes it "the enclave you built", so a configuration without it is
    /// refused rather than quietly delivering the weaker claim.
    #[test]
    fn nitro_with_a_root_but_no_pinned_pcr0_is_refused() {
        let mut c = hardened(DeploymentMode::SovereignCloud);
        c.attestation.measurement_source = MeasurementSource::NitroEnclave;
        if let Some(expected) = c.attestation.expected.as_mut() {
            expected.nitro = Some(NitroPinsConfig {
                root_der_b64: "Zm9ybS1vZi1hLXJvb3QtY2VydGlmaWNhdGU=".into(),
                ..NitroPinsConfig::default()
            });
        }

        let refusal = c.validate().unwrap_err().to_string();
        assert!(refusal.contains("PCR0"), "{}", refusal);
        assert!(
            refusal.contains("not that yours did"),
            "the refusal must explain the difference it makes: {}",
            refusal
        );
    }

    #[test]
    fn nitro_with_a_root_and_pcr0_is_accepted_by_validation() {
        let mut c = hardened(DeploymentMode::SovereignCloud);
        c.attestation.measurement_source = MeasurementSource::NitroEnclave;
        if let Some(expected) = c.attestation.expected.as_mut() {
            let mut pcr_values = std::collections::BTreeMap::new();
            pcr_values.insert(0u8, "ab".repeat(48));
            expected.nitro = Some(NitroPinsConfig {
                root_der_b64: "Zm9ybS1vZi1hLXJvb3QtY2VydGlmaWNhdGU=".into(),
                pcr_values,
                ..NitroPinsConfig::default()
            });
        }
        // Validation accepts it; starting a node with it does not, because
        // Cordon cannot obtain a Nitro document. That refusal lives in
        // `AttestationService::take_measurements`, which is where the node
        // learns it cannot do what the configuration asks.
        c.validate().unwrap();
    }

    /// Both confidential-VM sources make memory private from the host; a TPM
    /// and a configuration digest do not. Getting this backwards would let a
    /// deployment claim confidentiality it does not have.
    #[test]
    fn only_a_confidential_vm_claims_memory_confidentiality() {
        assert!(MeasurementSource::SevSnp.provides_memory_confidentiality());
        assert!(MeasurementSource::NitroEnclave.provides_memory_confidentiality());
        assert!(!MeasurementSource::Tpm2.provides_memory_confidentiality());
        assert!(!MeasurementSource::SoftwareMeasurement.provides_memory_confidentiality());

        assert!(MeasurementSource::SevSnp.is_hardware());
        assert!(MeasurementSource::NitroEnclave.is_hardware());
        assert!(MeasurementSource::Tpm2.is_hardware());
        assert!(!MeasurementSource::SoftwareMeasurement.is_hardware());
    }

    /// Every source's name round-trips between its `Display` form and the
    /// string an operator writes in the configuration file. A mismatch would
    /// mean a value the node prints is one it will not read back.
    #[test]
    fn every_measurement_source_name_round_trips() {
        for source in [
            MeasurementSource::Tpm2,
            MeasurementSource::SevSnp,
            MeasurementSource::NitroEnclave,
            MeasurementSource::SoftwareMeasurement,
        ] {
            let written = source.to_string();
            let read: MeasurementSource = toml::from_str(&format!("v = \"{}\"", written))
                .map(|t: toml::Value| t["v"].clone().try_into().unwrap())
                .unwrap_or_else(|e| panic!("`{}` does not parse back: {}", written, e));
            assert_eq!(read.to_string(), written);
        }
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

    /// Vault, Island and Dark are documented as having no outbound access, and
    /// nothing used to check it — a configuration could claim one of those
    /// modes while leaving Cordon free to reach the Hub.
    #[test]
    fn air_gapped_modes_must_declare_zero_egress() {
        for mode in [
            DeploymentMode::Vault,
            DeploymentMode::Island,
            DeploymentMode::Dark,
        ] {
            let mut c = hardened(mode.clone());
            c.network.outbound_policy = OutboundPolicy::Restricted;
            let err = c.validate().unwrap_err().to_string();
            assert!(
                err.contains("zero_egress"),
                "{} should require zero egress: {}",
                mode,
                err
            );
        }

        // Sovereign Cloud exists to pull models, so it may reach the network.
        let mut c = hardened(DeploymentMode::SovereignCloud);
        c.network.outbound_policy = OutboundPolicy::Restricted;
        assert!(c.validate().is_ok());
    }

    /// The declared policy has to bind, not merely describe. An operator who
    /// sets zero egress and reads it back as a guarantee should not find that
    /// `cordon pull` still reaches the Hub.
    #[test]
    fn declaring_zero_egress_disables_model_downloads() {
        let mut c = light();
        assert!(c.permits_model_download());

        c.network.outbound_policy = OutboundPolicy::ZeroEgress;
        assert!(!c.permits_egress());
        assert!(
            !c.permits_model_download(),
            "a zero-egress node must not fetch models over the network"
        );
    }

    #[test]
    fn zero_egress_refuses_a_remote_runtime_endpoint() {
        let mut c = light();
        c.network.outbound_policy = OutboundPolicy::ZeroEgress;
        c.runtime.backend = RuntimeBackend::External;
        c.runtime.endpoint_url = Some("http://10.0.0.5:8000".into());

        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("zero_egress"), "unexpected: {}", err);

        // A loopback endpoint involves no egress and is fine.
        c.runtime.endpoint_url = Some("http://127.0.0.1:8000".into());
        assert!(c.validate().is_ok());
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
