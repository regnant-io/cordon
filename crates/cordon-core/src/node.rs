//! The Cordon node.
//!
//! [`CordonNode`] owns every layer and sequences them into one request
//! pipeline. It is built once at startup, held behind an `Arc`, and shared by
//! the API server.
//!
//! # Request pipeline
//!
//! ```text
//! can serve?          node is not quarantined, locked, or zeroized
//! attestation gate    hardware modes: this client has verified the node
//! source block        the peer's fingerprint is not blocked
//! identity            certificate is valid, client is enrolled, policy applies
//! suspension          the client is not serving a suspension
//! model permission    the policy admits this model
//! request limits      message count, prompt size, token budget
//! model store gate    the bundle is registered and passed integrity recently
//! rate limit          a request slot and an output-token reservation
//! admission           a concurrency slot and a session
//! audit pre-write     log before processing; a failed write rejects the request
//! generate            the model runtime produces output
//! settle              unused output-token reservation is refunded
//! output filter       policy rules redact, truncate, or block
//! covert channel      statistical analysis of the released text
//! timing              latency is normalised to a bucket or floor
//! audit post-write    the completed record, with true policy values
//! sign                Ed25519 over a canonical, reconstructable payload
//! ```
//!
//! Every stage that can refuse does so before the next one runs, and the audit
//! pre-write happens before any model computation, so a request that is
//! processed is always a request that was logged.

use chrono::Utc;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

use cordon_audit::{
    events::{
        AuditEvent, FinishReason as AuditFinishReason, InferenceEvent, LifecycleEvent,
        LifecycleEventType,
    },
    AuditLog, LogConfig,
};
use cordon_crypto::hierarchy::{BundleKey, MasterKey};
use cordon_crypto::signing::{Signature, SigningKey, VerifyingKey};

use crate::{
    attack_detector::AttackDetector,
    attestation_service::AttestationService,
    config::CordonConfig,
    covert_channel::{CovertChannelConfig, CovertChannelDetector},
    error::{CordonError, CordonResult},
    identity::{ClientIdentity, IdentityRegistry},
    inference::{
        FinishReason, InferenceEngine, InferenceParams, InferenceRequest, Message, TokenStream,
    },
    integrity_monitor::IntegrityMonitor,
    metrics::CordonMetrics,
    model_store::{ModelStore, StagedModel},
    output_filter::{ContentPolicy, OutputFilter},
    rate_limiter::RateLimiter,
    runtime::{self, LlamaSupervisor},
    state::{NodeState, SharedNodeState},
    timing::TimingNormalizer,
};

/// Where the deployment's signing keys came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProvenance {
    /// Derived from the Client Master Key. Audit signatures and response
    /// signatures are verifiable by any party holding the CMK, so the node
    /// cannot rewrite history or forge a response undetectably.
    CmkDerived,
    /// Generated at boot because no CMK was provisioned. The node self-certifies,
    /// so its signatures carry no cross-party guarantee. Development only.
    Ephemeral,
}

impl KeyProvenance {
    /// Wire representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyProvenance::CmkDerived => "cmk_derived",
            KeyProvenance::Ephemeral => "ephemeral",
        }
    }
}

/// Cryptographic material held by a running node. Every secret zeroizes on drop.
struct NodeKeys {
    /// Retained CMK, present only when provisioned, for deriving bundle keys.
    master: Option<MasterKey>,
    /// Principal used in key derivation.
    key_principal: String,
    /// Admin authorization verifying key. `None` disables the admin API.
    admin_vk: Option<VerifyingKey>,
    /// Response and attestation signing key.
    enclave_key: SigningKey,
    /// Where these keys came from.
    provenance: KeyProvenance,
    /// Development override permitting admin calls without a signature.
    insecure_admin: bool,
    /// Development override permitting models absent from the store.
    allow_unregistered_models: bool,
}

/// A complete Cordon node.
pub struct CordonNode {
    /// Validated node configuration.
    pub config: CordonConfig,
    keys: NodeKeys,
    /// Node state machine.
    pub state: SharedNodeState,
    /// Client authorization registry.
    pub identity: Arc<IdentityRegistry>,
    /// Per-client rate limiter.
    pub rate_limiter: Arc<RateLimiter>,
    /// Encrypted model store.
    pub model_store: Arc<ModelStore>,
    /// Inference engine.
    pub inference: Arc<InferenceEngine>,
    /// Output content filter.
    pub output_filter: Arc<OutputFilter>,
    /// Covert-channel detector.
    pub covert_channel: Arc<CovertChannelDetector>,
    /// Timing normalizer.
    pub timing: Arc<TimingNormalizer>,
    /// Attestation service.
    pub attestation: Arc<AttestationService>,
    /// Background integrity monitor.
    pub integrity_monitor: Arc<IntegrityMonitor>,
    /// Sustained-attack detector.
    pub attack_detector: Arc<AttackDetector>,
    /// Append-only audit log.
    pub audit: Arc<AuditLog>,
    /// Prometheus metrics.
    pub metrics: Arc<CordonMetrics>,
    /// Supervised runtime child, when one is in use.
    supervisor: Option<Arc<LlamaSupervisor>>,
    /// Staged plaintext weights, erased when the node drops.
    staged_model: Option<StagedModel>,
    /// Process start time.
    pub started_at: Instant,
}

/// The outcome of a completed inference request.
#[derive(Debug)]
#[allow(missing_docs)]
pub struct InferenceOutcome {
    pub request_id: Uuid,
    pub session_id: Uuid,
    pub model_id: String,
    pub client_id: String,
    pub output: String,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub finish_reason: FinishReason,
    pub latency_ms: u64,
    pub timing_bucket_ms: Option<u64>,
    pub content_policy_triggered: bool,
    pub policy_rules_matched: Vec<String>,
    pub covert_channel_score: f32,
    pub output_hash: String,
    pub mrenclave: String,
}

/// An admitted streaming generation: the request context plus the runtime's
/// chunk stream. Auditing and signing happen when the stream completes.
///
/// Holding this value holds the request's concurrency slot. Dropping it without
/// calling [`CordonNode::finish_streaming_inference`] releases the slot but
/// leaves the audit record open at its intake entry, which is the correct
/// representation of a stream the caller abandoned.
pub struct StreamingSession {
    /// Everything about the request except the stream itself. Cloneable, so a
    /// caller can hold it while consuming the stream — the stream is `Send` but
    /// not `Sync`, and separating the two keeps that from infecting the caller's
    /// future.
    pub meta: StreamingMeta,
    /// The runtime's chunk stream, unfiltered.
    pub stream: TokenStream,
    /// Concurrency slot and session lease, released on drop.
    _lease: crate::inference::InferenceLease,
}

/// Request context for a streaming generation.
#[derive(Debug, Clone)]
pub struct StreamingMeta {
    /// Identifier for this request.
    pub request_id: Uuid,
    /// Session the request is bound to.
    pub session_id: Uuid,
    /// Authenticated client.
    pub client_id: String,
    /// Model being served.
    pub model_id: String,
    /// Enclave measurement at the time of admission.
    pub mrenclave: String,
    /// Digest of the input, matching the intake audit record.
    pub input_hash: String,
    /// Output tokens reserved from the rate limiter, settled when the stream ends.
    pub reserved_tokens: u32,
    /// When admission completed, for latency accounting.
    pub started: Instant,
}

/// What a completed stream contributed to the audit record.
#[derive(Debug, Clone)]
pub struct StreamingRecord {
    /// SHA-256 of the released text, or empty if nothing was released.
    pub output_hash: String,
    /// End-to-end latency in milliseconds.
    pub latency_ms: u64,
    /// Whether the stream ended because policy stopped it.
    pub content_policy_triggered: bool,
    /// Policy rules that fired.
    pub policy_rules_matched: Vec<String>,
    /// Covert-channel anomaly score over the released text.
    pub covert_channel_score: f32,
}

impl CordonNode {
    /// Build a node from a validated configuration.
    ///
    /// This starts the model runtime, which for the supervised backend means
    /// spawning and health-checking a child process, so it is fallible and slow.
    /// Any failure here prevents the node from serving at all, which is the
    /// intent: a node that cannot establish its runtime should not accept
    /// traffic.
    pub async fn build(config: CordonConfig) -> CordonResult<Self> {
        config.validate()?;

        tracing::info!(
            mode = %config.mode,
            node_id = %config.node_id,
            deployment_id = %config.deployment_id,
            "Initializing Cordon node"
        );

        let state = SharedNodeState::new(NodeState::new(
            config.node_id.clone(),
            config.deployment_id.clone(),
        ));

        let identity = Arc::new(match &config.client_registry_path {
            Some(path) => IdentityRegistry::load_from_file(path)?,
            None => {
                tracing::warn!(
                    "No client_registry_path configured — every client is admitted with \
                     default limits. Enrol clients to apply per-client policy."
                );
                IdentityRegistry::new()
            }
        });

        let rate_limiter = Arc::new(RateLimiter::new(
            config.sustained_attack.auth_failure_threshold_per_minute,
        ));

        let model_store = Arc::new(ModelStore::with_verdict_ttl(
            config.model_store.path.clone(),
            None,
            config.model_store.integrity_check_interval_minutes as i64,
        )?);

        let keys = Self::provision_keys(&config)?;
        let (log_signing_key, keys) = keys;

        // Decrypt any registered bundle the runtime is meant to serve before the
        // runtime starts, so it has a plaintext file to load.
        let staged_model = Self::stage_configured_bundle(&config, &model_store, &keys).await?;

        let mut runtime_config = config.clone();
        if let Some(staged) = &staged_model {
            runtime_config.runtime.model_path = Some(staged.path().to_path_buf());
            // Memory mapping would keep the plaintext file open for the process
            // lifetime, which defeats erasing it after load. Reading it fully
            // into the runtime's address space lets the file be deleted at once.
            runtime_config
                .runtime
                .extra_args
                .push("--no-mmap".to_string());
        }

        let built = runtime::build_backend(&runtime_config).await?;

        // The runtime has the weights resident; the plaintext file has served
        // its purpose and is erased now rather than at shutdown.
        if let Some(staged) = &staged_model {
            staged.erase();
        }

        let inference = Arc::new(InferenceEngine::new(
            built.backend,
            config.inference.max_concurrent_requests,
            config.inference.kv_cache_zero_on_session_end,
            config.inference.max_concurrent_requests as usize * 64,
        ));

        let output_filter = Arc::new(OutputFilter::new(&ContentPolicy::default_permissive(
            "all",
        ))?);

        let covert_channel = Arc::new(CovertChannelDetector::new(CovertChannelConfig {
            detection_threshold: config.sustained_attack.covert_channel_score_threshold,
            ..CovertChannelConfig::default()
        }));

        let timing = Arc::new(TimingNormalizer::new(
            config.side_channel.timing_normalization.clone(),
        ));

        let attestation = Arc::new(AttestationService::new(config.clone())?);
        let attack_detector = Arc::new(AttackDetector::new(config.sustained_attack.clone()));

        let audit = Arc::new(AuditLog::open(
            LogConfig::new(
                config.audit.log_path.clone(),
                config.deployment_id.clone(),
                config.node_id.clone(),
            ),
            log_signing_key,
        )?);

        let (integrity_monitor, _tamper_flag) = IntegrityMonitor::new(
            model_store.clone(),
            state.clone(),
            config.model_store.integrity_check_interval_minutes,
            config.model_store.halt_on_tamper,
        );

        let metrics = Arc::new(
            CordonMetrics::new()
                .map_err(|e| CordonError::Internal(format!("metrics init failed: {}", e)))?,
        );

        Ok(Self {
            config,
            keys,
            state,
            identity,
            rate_limiter,
            model_store,
            inference,
            output_filter,
            covert_channel,
            timing,
            attestation,
            integrity_monitor: Arc::new(integrity_monitor),
            attack_detector,
            audit,
            metrics,
            supervisor: built.supervisor,
            staged_model,
            started_at: Instant::now(),
        })
    }

    /// Derive the deployment's key set from the CMK, or generate an ephemeral
    /// one when no CMK is provisioned.
    fn provision_keys(config: &CordonConfig) -> CordonResult<(SigningKey, NodeKeys)> {
        let key_principal =
            std::env::var("CORDON_CLIENT_ID").unwrap_or_else(|_| "operator".to_string());
        let insecure_admin = env_flag("CORDON_INSECURE_ADMIN");
        let allow_unregistered_models = env_flag("CORDON_ALLOW_UNREGISTERED_MODELS");

        // Development escape hatches must never be reachable in a mode that
        // claims a security guarantee.
        if config.mode != crate::config::DeploymentMode::Light {
            if insecure_admin {
                return Err(CordonError::ConfigError(format!(
                    "CORDON_INSECURE_ADMIN is set but the node is in {} mode. \
                     Unsigned admin commands are a development-only facility.",
                    config.mode
                )));
            }
            if allow_unregistered_models {
                return Err(CordonError::ConfigError(format!(
                    "CORDON_ALLOW_UNREGISTERED_MODELS is set but the node is in {} \
                     mode. Bypassing the model-store gate is a development-only facility.",
                    config.mode
                )));
            }
        }

        match load_cmk_hex() {
            Some(cmk_hex) => {
                let master = MasterKey::from_hex(cmk_hex.trim()).map_err(|e| {
                    CordonError::KeyError(format!("invalid Client Master Key: {}", e))
                })?;
                let log_key = master
                    .derive_log_signing_key(&config.deployment_id, &key_principal)
                    .map_err(|e| CordonError::KeyError(e.to_string()))?;
                let admin_vk = master
                    .derive_admin_key(&config.deployment_id, &key_principal)
                    .map_err(|e| CordonError::KeyError(e.to_string()))?
                    .verifying_key();
                let enclave_key = master
                    .derive_enclave_key(&config.deployment_id, &key_principal)
                    .map_err(|e| CordonError::KeyError(e.to_string()))?;

                tracing::info!(
                    principal = %key_principal,
                    "Keys derived from the Client Master Key — the audit log and \
                     responses are independently verifiable"
                );

                Ok((
                    log_key,
                    NodeKeys {
                        master: Some(master),
                        key_principal,
                        admin_vk: Some(admin_vk),
                        enclave_key,
                        provenance: KeyProvenance::CmkDerived,
                        insecure_admin,
                        allow_unregistered_models,
                    },
                ))
            }
            None => {
                if config.mode != crate::config::DeploymentMode::Light {
                    return Err(CordonError::KeyError(format!(
                        "no Client Master Key is provisioned, but the node is in {} \
                         mode. Without a CMK the node signs its own audit log with a \
                         key it generated, so the log carries no non-repudiation. Set \
                         CORDON_CMK_FILE, or run in Light mode.",
                        config.mode
                    )));
                }

                tracing::warn!(
                    "No Client Master Key provisioned — signing keys are ephemeral and \
                     self-certified. Audit and response signatures carry no cross-party \
                     guarantee. The admin API is {}.",
                    if insecure_admin {
                        "ENABLED WITHOUT SIGNATURES"
                    } else {
                        "disabled"
                    }
                );

                Ok((
                    SigningKey::generate(),
                    NodeKeys {
                        master: None,
                        key_principal,
                        admin_vk: None,
                        enclave_key: SigningKey::generate(),
                        provenance: KeyProvenance::Ephemeral,
                        insecure_admin,
                        allow_unregistered_models,
                    },
                ))
            }
        }
    }

    /// Decrypt the configured bundle to a staging file, if one is configured.
    async fn stage_configured_bundle(
        config: &CordonConfig,
        model_store: &Arc<ModelStore>,
        keys: &NodeKeys,
    ) -> CordonResult<Option<StagedModel>> {
        // A model_path pointing at an existing file is a plain model, not a
        // bundle: nothing to decrypt.
        if let Some(path) = &config.runtime.model_path {
            if path.exists() {
                return Ok(None);
            }
        }
        let Some(bundle_id) = config
            .runtime
            .model_path
            .as_ref()
            .and_then(|p| p.to_str())
            .filter(|id| model_store.is_registered(id))
        else {
            return Ok(None);
        };

        let Some(master) = &keys.master else {
            return Err(CordonError::KeyError(format!(
                "bundle '{}' is registered but no Client Master Key is provisioned, \
                 so its weights cannot be decrypted",
                bundle_id
            )));
        };
        let bundle_key = master
            .derive_bundle_key(bundle_id, &keys.key_principal)
            .map_err(|e| CordonError::KeyError(e.to_string()))?;

        let staging_dir = config
            .model_store
            .staging_dir
            .clone()
            .unwrap_or_else(|| config.model_store.path.join(".staging"));

        tracing::info!(bundle_id, "Decrypting bundle for the runtime");

        let store = model_store.clone();
        let bundle_id = bundle_id.to_string();
        let staged = tokio::task::spawn_blocking(move || {
            store.stage_plaintext(&bundle_id, &bundle_key, &staging_dir)
        })
        .await
        .map_err(|e| CordonError::Internal(format!("staging task failed: {}", e)))??;

        Ok(Some(staged))
    }

    /// Start the background tasks that keep node state fresh.
    pub fn start_background_services(self: &Arc<Self>) {
        self.integrity_monitor.clone().start();

        // Metrics refresh.
        {
            let node = self.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(15));
                loop {
                    ticker.tick().await;
                    let active = matches!(
                        node.state.read().enclave_state,
                        crate::state::EnclaveState::Active
                    );
                    node.metrics.set_enclave_active(active);
                    node.metrics
                        .uptime_seconds
                        .set(node.started_at.elapsed().as_secs_f64());
                }
            });
        }

        // Periodic reclamation: idle sessions are zeroized, lapsed suspensions
        // and rate-limit buckets are dropped, stale attestations expire.
        {
            let node = self.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(60));
                loop {
                    ticker.tick().await;
                    let expired = node.inference.kv_cache().cleanup_expired(900);
                    if expired > 0 {
                        tracing::debug!(expired, "Idle sessions reclaimed and zeroized");
                    }
                    node.identity.cleanup_expired_suspensions();
                    node.rate_limiter.prune_stale_buckets(3600);
                    node.attack_detector.cleanup();
                    node.attestation.expire_stale_verifications();
                }
            });
        }

        // Runtime supervision: restart the child if it dies underneath us.
        if let Some(supervisor) = &self.supervisor {
            let supervisor = supervisor.clone();
            let state = self.state.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(10));
                loop {
                    ticker.tick().await;
                    if supervisor.is_running() {
                        continue;
                    }
                    tracing::error!("Model runtime exited unexpectedly; restarting");
                    state.write().degrade("model runtime restarting");
                    match supervisor.restart().await {
                        Ok(()) => {
                            tracing::info!("Model runtime restarted");
                            state.write().go_operational();
                        }
                        Err(e) => {
                            tracing::error!("Model runtime restart failed: {}", e);
                            state.write().degrade("model runtime unavailable");
                        }
                    }
                }
            });
        }

        tracing::info!("Background services started");
    }

    /// Mark the node operational and record the boot event.
    pub fn go_operational(&self) -> CordonResult<()> {
        self.state.write().go_operational();
        self.metrics.set_enclave_active(true);

        self.audit.append(AuditEvent::Lifecycle(LifecycleEvent {
            event: LifecycleEventType::Boot,
            cordon_version: env!("CARGO_PKG_VERSION").to_string(),
            tee_type: self.config.tee.preferred.to_string(),
            node_id: self.config.node_id.clone(),
        }))?;

        tracing::info!("Cordon node operational");
        Ok(())
    }

    /// Stop the model runtime and erase any staged plaintext.
    pub async fn shutdown(&self) {
        tracing::info!("Shutting down");
        if let Err(e) = self.inference.shutdown().await {
            tracing::warn!("Runtime shutdown reported: {}", e);
        }
        if let Some(staged) = &self.staged_model {
            staged.erase();
        }
        let _ = self.audit.append(AuditEvent::Lifecycle(LifecycleEvent {
            event: LifecycleEventType::Shutdown,
            cordon_version: env!("CARGO_PKG_VERSION").to_string(),
            tee_type: self.config.tee.preferred.to_string(),
            node_id: self.config.node_id.clone(),
        }));
    }

    // ── Keys and authorization ──────────────────────────────────────────────

    /// Provenance of this node's signing keys.
    pub fn key_provenance(&self) -> KeyProvenance {
        self.keys.provenance
    }

    /// The enclave signing key's public half, hex encoded.
    pub fn enclave_verifying_key_hex(&self) -> String {
        self.keys.enclave_key.verifying_key().to_hex()
    }

    /// Short identifier for the enclave signing key.
    pub fn enclave_key_id(&self) -> String {
        let vk = self.enclave_verifying_key_hex();
        format!("enclave-{}", &vk[..16.min(vk.len())])
    }

    /// Sign a message with the enclave key.
    pub fn sign_enclave(&self, msg: &[u8]) -> Signature {
        self.keys.enclave_key.sign(msg)
    }

    /// The audit log signing key's public half, hex encoded.
    pub fn log_verifying_key_hex(&self) -> String {
        self.audit.verifying_key().to_hex()
    }

    /// Authorize an administrative command.
    ///
    /// The signature must be Ed25519 over `CORDON_ADMIN:{action}:{params}` under
    /// the CMK-derived admin key. With no admin key provisioned the API is
    /// refused outright, unless the operator set the development override — and
    /// that override is itself refused outside Light mode at startup.
    pub fn authorize_admin(
        &self,
        action: &str,
        params: &str,
        signature_hex: &str,
    ) -> CordonResult<()> {
        let Some(vk) = &self.keys.admin_vk else {
            if self.keys.insecure_admin {
                tracing::warn!(action, "Admin command accepted WITHOUT a signature");
                return Ok(());
            }
            return Err(CordonError::AdminRejected(
                "no admin key is provisioned, so the admin API is disabled. Provision \
                 a Client Master Key, or set CORDON_INSECURE_ADMIN=true in Light mode."
                    .into(),
            ));
        };

        let canonical = Self::admin_canonical(action, params);
        let signature = Signature::from_hex(signature_hex.trim()).map_err(|_| {
            CordonError::AdminRejected(
                "malformed admin signature (expected 128 hex characters)".into(),
            )
        })?;
        vk.verify(canonical.as_bytes(), &signature).map_err(|_| {
            CordonError::AdminRejected(format!("invalid admin signature for action '{}'", action))
        })
    }

    /// The canonical string an operator signs to authorize an action.
    pub fn admin_canonical(action: &str, params: &str) -> String {
        format!("CORDON_ADMIN:{}:{}", action, params)
    }

    /// Derive the bundle key for a model, when a CMK is held.
    pub fn bundle_key_for(&self, bundle_id: &str) -> Option<BundleKey> {
        let master = self.keys.master.as_ref()?;
        master
            .derive_bundle_key(bundle_id, &self.keys.key_principal)
            .ok()
    }

    /// Whether `client_id` may be served given the node's attestation posture.
    ///
    /// In hardware modes with `halt_until_verified`, a client must have verified
    /// this node's attestation before it is served. Verification is per-client:
    /// one caller's acceptance does not unlock the node for everyone.
    pub fn attestation_ready_for(&self, client_id: &str) -> bool {
        if !self.config.requires_hardware_tee() || !self.config.attestation.halt_until_verified {
            return true;
        }
        self.attestation.is_verified_by(client_id)
    }

    /// Verify the on-disk audit chain end to end. Linear in log size — call it
    /// from a blocking context, not on the request path.
    pub fn audit_chain_valid(&self) -> bool {
        let vk = self.audit.verifying_key();
        match cordon_audit::verify::verify_log_chain(
            &self.config.audit.log_path,
            &vk,
            &self.config.deployment_id,
        ) {
            Ok(r) => r.valid,
            Err(e) => {
                tracing::warn!("audit chain verification errored: {}", e);
                false
            }
        }
    }

    // ── Request pipeline ────────────────────────────────────────────────────

    /// Validate a request's shape against the configured limits.
    ///
    /// Runs before any expensive work so an oversized request is refused cheaply
    /// rather than after it has been hashed, logged, and dispatched.
    fn check_request_limits(
        &self,
        messages: &[Message],
        params: &InferenceParams,
        policy: &crate::identity::ClientPolicy,
    ) -> CordonResult<()> {
        let limits = &self.config.limits;

        if messages.is_empty() {
            return Err(CordonError::ValidationFailed(
                "a request must contain at least one message".into(),
            ));
        }
        if messages.len() > limits.max_messages {
            return Err(CordonError::RequestTooLarge(format!(
                "{} messages exceeds the limit of {}",
                messages.len(),
                limits.max_messages
            )));
        }

        let total_chars: usize = messages.iter().map(|m| m.content.len()).sum();
        if total_chars > limits.max_prompt_chars {
            return Err(CordonError::RequestTooLarge(format!(
                "prompt of {} bytes exceeds the limit of {}",
                total_chars, limits.max_prompt_chars
            )));
        }

        for message in messages {
            if !matches!(
                message.role.as_str(),
                "system" | "user" | "assistant" | "tool"
            ) {
                return Err(CordonError::ValidationFailed(format!(
                    "unknown message role '{}'",
                    message.role
                )));
            }
        }

        if params.max_tokens == 0 {
            return Err(CordonError::ValidationFailed(
                "max_tokens must be greater than zero".into(),
            ));
        }

        // The node-wide ceiling and the client's own ceiling both apply; the
        // tighter one wins.
        let ceiling = self
            .config
            .inference
            .max_output_tokens
            .min(policy.max_tokens_per_request);
        if params.max_tokens > ceiling {
            return Err(CordonError::ValidationFailed(format!(
                "max_tokens {} exceeds the limit of {} for this client",
                params.max_tokens, ceiling
            )));
        }

        if !(0.0..=2.0).contains(&params.temperature) {
            return Err(CordonError::ValidationFailed(
                "temperature must be between 0.0 and 2.0".into(),
            ));
        }
        if !(0.0..=1.0).contains(&params.top_p) {
            return Err(CordonError::ValidationFailed(
                "top_p must be between 0.0 and 1.0".into(),
            ));
        }

        Ok(())
    }

    /// Run every admission check and return the authorized policy.
    ///
    /// Shared by the unary and streaming paths so neither can diverge from the
    /// other — the streaming endpoint previously skipped most of this.
    fn admit(
        &self,
        client: &ClientIdentity,
        model_id: &str,
        messages: &[Message],
        params: &InferenceParams,
    ) -> CordonResult<crate::identity::ClientPolicy> {
        if !self.state.can_serve() {
            return Err(CordonError::Quarantined);
        }

        if !self.attestation_ready_for(&client.client_id) {
            return Err(CordonError::AttestationInvalid(
                "this client has not verified the node's attestation. Call \
                 POST /v1/attestation/verify before requesting inference."
                    .into(),
            ));
        }

        if self.attack_detector.is_ip_blocked(&client.fingerprint) {
            self.metrics.auth_failures_total.inc();
            return Err(CordonError::AuthFailed("source is blocked".into()));
        }

        let policy = self.identity.verify(client).map_err(|e| {
            self.metrics.auth_failures_total.inc();
            self.attack_detector
                .record_auth_failure(&client.fingerprint);
            e
        })?;

        if let Some(reason) = self.attack_detector.is_client_suspended(&client.client_id) {
            return Err(CordonError::AuthFailed(format!(
                "client suspended: {}",
                reason
            )));
        }

        if !policy.model_permitted(model_id) {
            self.attack_detector.record_invalid_model(&client.client_id);
            return Err(CordonError::AuthFailed(format!(
                "client {} is not permitted to use model {}",
                client.client_id, model_id
            )));
        }

        self.check_request_limits(messages, params, &policy)?;

        self.model_store
            .ensure_servable(model_id, self.keys.allow_unregistered_models)?;

        self.rate_limiter
            .check(&client.client_id, params.max_tokens, &policy)
            .map_err(|e| {
                self.metrics.rate_limit_hits_total.inc();
                e
            })?;

        Ok(policy)
    }

    /// Process an inference request through the full pipeline.
    pub async fn process_inference(
        &self,
        client: &ClientIdentity,
        model_id: &str,
        messages: Vec<Message>,
        params: InferenceParams,
        session_id: Option<Uuid>,
        timeout: Duration,
    ) -> CordonResult<InferenceOutcome> {
        let started = Instant::now();
        let request_id = Uuid::new_v4();

        self.admit(client, model_id, &messages, &params)?;

        let input_hash = hash_messages(&messages);

        if self
            .attack_detector
            .record_input_hash(&client.client_id, &input_hash)
        {
            tracing::warn!(
                client_id = %client.client_id,
                hash_prefix = &input_hash[..16],
                "Repeated identical input — possible probing"
            );
        }

        let request = InferenceRequest {
            request_id,
            client_id: client.client_id.clone(),
            session_id,
            model_id: model_id.to_string(),
            messages,
            params: params.clone(),
            timeout,
            input_hash: input_hash.clone(),
            created_at: Utc::now(),
        };

        // Admission also opens the session; the lease releases the concurrency
        // slot and tears down an ephemeral session when it drops, on every path
        // out of this function.
        let lease = self.inference.admit(&request)?;
        let session_id = lease.session_id();

        // Log before processing. A failed write rejects the request: an
        // unauditable inference is worse than a refused one.
        self.audit
            .append(AuditEvent::Inference(InferenceEvent {
                request_id,
                client_id: client.client_id.clone(),
                session_id: Some(session_id),
                model_id: model_id.to_string(),
                mrenclave: self.attestation.mrenclave(),
                input_hash: input_hash.clone(),
                output_hash: String::new(),
                prompt_tokens: 0,
                completion_tokens: 0,
                latency_ms: 0,
                finish_reason: AuditFinishReason::Stop,
                content_policy_triggered: false,
                policy_rules_matched: vec![],
                covert_channel_score: 0.0,
                timing_bucket_ms: self.timing.bucket_ms(),
            }))
            .map_err(|e| {
                tracing::error!("audit pre-write failed: {}", e);
                CordonError::AuditWriteFailed(e.to_string())
            })?;

        let raw = self.inference.run(&request).await?;

        self.rate_limiter.settle(
            &client.client_id,
            params.max_tokens,
            raw.completion_tokens(),
        );

        let filtered = self.output_filter.filter(raw.text.clone());

        if filtered.blocked {
            self.metrics.content_policy_hits_total.inc();
            let rule_id = filtered
                .matches
                .first()
                .map(|m| m.rule_id.clone())
                .unwrap_or_default();
            // The blocked outcome is still recorded: a policy block is exactly
            // the kind of event an audit log exists to capture.
            let _ = self.audit.append(AuditEvent::Inference(InferenceEvent {
                request_id,
                client_id: client.client_id.clone(),
                session_id: Some(session_id),
                model_id: model_id.to_string(),
                mrenclave: self.attestation.mrenclave(),
                input_hash,
                output_hash: String::new(),
                prompt_tokens: raw.prompt_tokens(),
                completion_tokens: raw.completion_tokens(),
                latency_ms: started.elapsed().as_millis() as u64,
                finish_reason: AuditFinishReason::ContentFilter,
                content_policy_triggered: true,
                policy_rules_matched: filtered.matches.iter().map(|m| m.rule_id.clone()).collect(),
                covert_channel_score: 0.0,
                timing_bucket_ms: self.timing.bucket_ms(),
            }));
            return Err(CordonError::ContentPolicyViolation { rule_id });
        }

        if filtered.triggered {
            self.metrics.content_policy_hits_total.inc();
        }

        let covert = self.covert_channel.analyze(&filtered.text);
        if covert.detected {
            self.metrics.covert_channel_detections_total.inc();
            let suspended = self
                .attack_detector
                .record_covert_channel_score(&client.client_id, covert.anomaly_score);
            if suspended {
                return Err(CordonError::CovertChannelDetected {
                    score: covert.anomaly_score,
                });
            }
        }

        self.timing.normalize(started).await;

        let latency_ms = started.elapsed().as_millis() as u64;
        let output_hash = hex::encode(Sha256::digest(filtered.text.as_bytes()));
        let policy_rules_matched: Vec<String> =
            filtered.matches.iter().map(|m| m.rule_id.clone()).collect();

        let _ = self.audit.append(AuditEvent::Inference(InferenceEvent {
            request_id,
            client_id: client.client_id.clone(),
            session_id: Some(session_id),
            model_id: model_id.to_string(),
            mrenclave: self.attestation.mrenclave(),
            input_hash,
            output_hash: output_hash.clone(),
            prompt_tokens: raw.prompt_tokens(),
            completion_tokens: raw.completion_tokens(),
            latency_ms,
            finish_reason: audit_finish_reason(raw.finish_reason),
            content_policy_triggered: filtered.triggered,
            policy_rules_matched: policy_rules_matched.clone(),
            covert_channel_score: covert.anomaly_score,
            timing_bucket_ms: self.timing.bucket_ms(),
        }));

        self.metrics.record_inference_completed(
            latency_ms as f64 / 1000.0,
            raw.prompt_tokens(),
            raw.completion_tokens(),
        );
        self.state.record_inference(raw.completion_tokens() as u64);
        self.state.update_latency(latency_ms);

        Ok(InferenceOutcome {
            request_id,
            session_id,
            model_id: model_id.to_string(),
            client_id: client.client_id.clone(),
            output: filtered.text,
            prompt_tokens: raw.prompt_tokens(),
            completion_tokens: raw.completion_tokens(),
            finish_reason: raw.finish_reason,
            latency_ms,
            timing_bucket_ms: self.timing.bucket_ms(),
            content_policy_triggered: filtered.triggered,
            policy_rules_matched,
            covert_channel_score: covert.anomaly_score,
            output_hash,
            mrenclave: self.attestation.mrenclave(),
        })
    }

    /// Begin a streaming generation.
    ///
    /// Runs the identical admission pipeline as [`Self::process_inference`] and
    /// writes the audit intake record, then opens the runtime's token stream.
    /// Every refusal therefore happens *before* the caller receives a single
    /// byte, so a blocked request cannot leak a partial response.
    ///
    /// The caller must pass each chunk through
    /// [`StreamingFilter`](crate::output_filter::StreamingFilter) and then call
    /// [`Self::finish_streaming_inference`] to close the audit record.
    pub async fn begin_streaming_inference(
        &self,
        client: &ClientIdentity,
        model_id: &str,
        messages: Vec<Message>,
        params: InferenceParams,
        session_id: Option<Uuid>,
        timeout: Duration,
    ) -> CordonResult<StreamingSession> {
        let request_id = Uuid::new_v4();
        self.admit(client, model_id, &messages, &params)?;

        let input_hash = hash_messages(&messages);
        if self
            .attack_detector
            .record_input_hash(&client.client_id, &input_hash)
        {
            tracing::warn!(
                client_id = %client.client_id,
                hash_prefix = &input_hash[..16],
                "Repeated identical input — possible probing"
            );
        }

        let request = InferenceRequest {
            request_id,
            client_id: client.client_id.clone(),
            session_id,
            model_id: model_id.to_string(),
            messages,
            params: params.clone(),
            timeout,
            input_hash: input_hash.clone(),
            created_at: Utc::now(),
        };

        let lease = self.inference.admit(&request)?;
        let session_id = lease.session_id();
        let mrenclave = self.attestation.mrenclave();

        self.audit
            .append(AuditEvent::Inference(InferenceEvent {
                request_id,
                client_id: client.client_id.clone(),
                session_id: Some(session_id),
                model_id: model_id.to_string(),
                mrenclave: mrenclave.clone(),
                input_hash: input_hash.clone(),
                output_hash: String::new(),
                prompt_tokens: 0,
                completion_tokens: 0,
                latency_ms: 0,
                finish_reason: AuditFinishReason::Stop,
                content_policy_triggered: false,
                policy_rules_matched: vec![],
                covert_channel_score: 0.0,
                timing_bucket_ms: self.timing.bucket_ms(),
            }))
            .map_err(|e| {
                tracing::error!("audit pre-write failed: {}", e);
                CordonError::AuditWriteFailed(e.to_string())
            })?;

        let stream = self.inference.run_stream(&request).await?;

        Ok(StreamingSession {
            meta: StreamingMeta {
                request_id,
                session_id,
                client_id: client.client_id.clone(),
                model_id: model_id.to_string(),
                mrenclave,
                input_hash,
                reserved_tokens: params.max_tokens,
                started: Instant::now(),
            },
            stream,
            // Held for the life of the session; dropping it releases the
            // concurrency slot and tears down an ephemeral session.
            _lease: lease,
        })
    }

    /// Close out a streaming generation: settle the token reservation, analyse
    /// the released text, and write the completion record to the audit log.
    ///
    /// `released` is the text the caller actually transmitted. Passing `None`
    /// records a failed or policy-terminated stream.
    pub fn finish_streaming_inference(
        &self,
        meta: &StreamingMeta,
        released: Option<&str>,
        usage: crate::inference::TokenUsage,
        finish_reason: FinishReason,
    ) -> StreamingRecord {
        self.rate_limiter.settle(
            &meta.client_id,
            meta.reserved_tokens,
            usage.completion_tokens,
        );

        let text = released.unwrap_or_default();
        let output_hash = if text.is_empty() {
            String::new()
        } else {
            hex::encode(Sha256::digest(text.as_bytes()))
        };

        // The covert-channel score is computed over exactly the text the caller
        // received, so a streamed response is scored on the same basis as a
        // unary one rather than being logged as zero.
        let covert = self.covert_channel.analyze(text);
        if covert.detected {
            self.metrics.covert_channel_detections_total.inc();
            self.attack_detector
                .record_covert_channel_score(&meta.client_id, covert.anomaly_score);
        }

        let latency_ms = meta.started.elapsed().as_millis() as u64;
        let content_policy_triggered = released.is_none();

        let _ = self.audit.append(AuditEvent::Inference(InferenceEvent {
            request_id: meta.request_id,
            client_id: meta.client_id.clone(),
            session_id: Some(meta.session_id),
            model_id: meta.model_id.clone(),
            mrenclave: meta.mrenclave.clone(),
            input_hash: meta.input_hash.clone(),
            output_hash: output_hash.clone(),
            prompt_tokens: usage.prompt_tokens,
            completion_tokens: usage.completion_tokens,
            latency_ms,
            finish_reason: audit_finish_reason(finish_reason),
            content_policy_triggered,
            policy_rules_matched: vec![],
            covert_channel_score: covert.anomaly_score,
            timing_bucket_ms: self.timing.bucket_ms(),
        }));

        if released.is_some() {
            self.metrics.record_inference_completed(
                latency_ms as f64 / 1000.0,
                usage.prompt_tokens,
                usage.completion_tokens,
            );
            self.state.record_inference(usage.completion_tokens as u64);
            self.state.update_latency(latency_ms);
        }

        StreamingRecord {
            output_hash,
            latency_ms,
            content_policy_triggered,
            policy_rules_matched: vec![],
            covert_channel_score: covert.anomaly_score,
        }
    }

    /// Health summary for the detailed health endpoint.
    ///
    /// `chain_valid` is expensive to compute, so the caller supplies it after
    /// running the verifier off the request path.
    pub fn health_summary(&self, chain_valid: Option<bool>) -> serde_json::Value {
        let state = self.state.read();
        serde_json::json!({
            "status": state.status.to_string(),
            "node_id": state.node_id,
            "cordon_version": env!("CARGO_PKG_VERSION"),
            "mode": self.config.mode.to_string(),
            "enclave": {
                "status": format!("{:?}", state.enclave_state).to_lowercase(),
                "tee_type": self.config.tee.preferred.to_string(),
                "measurement_source": self.attestation.measurement_source().to_string(),
                "hardware_measurements": self.attestation.has_hardware_measurements(),
                "mrenclave": self.attestation.mrenclave(),
                "last_attested": self.attestation.last_attestation_time(),
                "verified_clients": self.attestation.verified_client_count(),
                "signing_key": self.enclave_verifying_key_hex(),
                "key_provenance": self.keys.provenance.as_str(),
            },
            "inference": {
                "runtime": self.inference.backend_name(),
                "active_requests": self.inference.active_requests(),
                "max_concurrent": self.inference.max_concurrent(),
                "active_sessions": self.inference.kv_cache().session_count(),
                "latency_ms_p50": state.stats.latency_ms_p50,
                "latency_ms_p99": state.stats.latency_ms_p99,
            },
            "integrity": {
                "last_check": self.integrity_monitor.last_check_time(),
                "last_check_passed": self.integrity_monitor.last_check_passed(),
                "tamper_detected": self.integrity_monitor.is_tamper_detected(),
            },
            "audit": {
                "entries_total": self.audit.sequence(),
                "tail_hash": self.audit.tail_hash(),
                "chain_valid": chain_valid,
                "log_verifying_key": self.log_verifying_key_hex(),
                "key_provenance": self.keys.provenance.as_str(),
            },
            "uptime_seconds": self.started_at.elapsed().as_secs(),
        })
    }

    /// Recent runtime log lines, for diagnostics.
    pub fn runtime_logs(&self, n: usize) -> Vec<String> {
        self.supervisor
            .as_ref()
            .map(|s| s.recent_logs(n))
            .unwrap_or_default()
    }
}

fn hash_messages(messages: &[Message]) -> String {
    let mut hasher = Sha256::new();
    for message in messages {
        // Length-prefix each field so distinct message sequences cannot collide
        // by concatenating to the same byte string.
        hasher.update((message.role.len() as u64).to_le_bytes());
        hasher.update(message.role.as_bytes());
        hasher.update((message.content.len() as u64).to_le_bytes());
        hasher.update(message.content.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn audit_finish_reason(reason: FinishReason) -> AuditFinishReason {
    match reason {
        FinishReason::Stop => AuditFinishReason::Stop,
        FinishReason::Length => AuditFinishReason::Length,
        FinishReason::ContentFilter => AuditFinishReason::ContentFilter,
        FinishReason::Timeout => AuditFinishReason::Timeout,
        FinishReason::Error => AuditFinishReason::Error,
    }
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

/// Source the Client Master Key.
///
/// `CORDON_CMK_FILE` is preferred: a file on a memory-backed filesystem is not
/// visible in the process environment, which `/proc/<pid>/environ`, a crash
/// dump, or a child process can all expose. `CORDON_CMK` is accepted for
/// development and warns loudly. Production should source the key from an HSM
/// over PKCS#11, which plugs in here.
fn load_cmk_hex() -> Option<String> {
    if let Ok(path) = std::env::var("CORDON_CMK_FILE") {
        return match std::fs::read_to_string(&path) {
            Ok(contents) => {
                tracing::info!(path, "Client Master Key read from file");
                Some(contents)
            }
            Err(e) => {
                tracing::error!(path, "CORDON_CMK_FILE is unreadable: {}", e);
                None
            }
        };
    }
    if let Ok(hex) = std::env::var("CORDON_CMK") {
        tracing::warn!(
            "The Client Master Key was read from the CORDON_CMK environment variable, \
             where it is visible to every child process and to anyone who can read \
             this process's environment. Prefer CORDON_CMK_FILE on a tmpfs, or an HSM."
        );
        return Some(hex);
    }
    None
}

impl std::fmt::Display for crate::config::TeePreference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            crate::config::TeePreference::SgxV2 => write!(f, "intel_sgx_v2"),
            crate::config::TeePreference::AmdSevSnp => write!(f, "amd_sev_snp"),
            crate::config::TeePreference::ArmTrustZone => write!(f, "arm_trustzone"),
            crate::config::TeePreference::Simulation => write!(f, "simulation"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_hashing_is_prefix_free() {
        // Without length prefixing these two distinct conversations would hash
        // identically, letting a caller forge an audit-log input hash.
        let a = vec![
            Message {
                role: "user".into(),
                content: "ab".into(),
            },
            Message {
                role: "user".into(),
                content: "c".into(),
            },
        ];
        let b = vec![
            Message {
                role: "user".into(),
                content: "a".into(),
            },
            Message {
                role: "user".into(),
                content: "bc".into(),
            },
        ];
        assert_ne!(hash_messages(&a), hash_messages(&b));
    }

    #[test]
    fn message_hashing_is_deterministic() {
        let m = vec![Message {
            role: "user".into(),
            content: "hello".into(),
        }];
        assert_eq!(hash_messages(&m), hash_messages(&m));
        assert_eq!(hash_messages(&m).len(), 64);
    }

    #[test]
    fn admin_canonical_is_stable() {
        assert_eq!(
            CordonNode::admin_canonical("quarantine", "incident-123"),
            "CORDON_ADMIN:quarantine:incident-123"
        );
    }
}
