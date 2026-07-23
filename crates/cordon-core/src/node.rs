//! CordonNode — top-level orchestrator for all layers
//!
//! Brings together all layers into a running Cordon node.
//! This is the main entry point for the Cordon runtime.

use std::sync::Arc;
use std::time::Instant;
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use cordon_audit::{
    AuditLog, LogConfig,
    events::{
        AuditEvent, InferenceEvent, FinishReason as AuditFinishReason,
        LifecycleEvent, LifecycleEventType,
    },
};
use cordon_crypto::signing::{SigningKey, Signature, VerifyingKey};
use cordon_crypto::hierarchy::{MasterKey, BundleKey};

use crate::{
    attack_detector::AttackDetector,
    attestation_service::AttestationService,
    covert_channel::{CovertChannelDetector, CovertChannelConfig},
    error::{CordonError, CordonResult},
    identity::{ClientIdentity, IdentityRegistry},
    inference::{InferenceEngine, InferenceRequest},
    integrity_monitor::IntegrityMonitor,
    metrics::CordonMetrics,
    model_store::ModelStore,
    output_filter::{ContentPolicy, OutputFilter},
    rate_limiter::RateLimiter,
    state::{NodeState, SharedNodeState},
    timing::TimingNormalizer,
    config::CordonConfig,
};

/// Provenance of the deployment's signing keys — tells operators and clients
/// whether cryptographic guarantees actually hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProvenance {
    /// Keys derived from the Client Master Key (HKDF-SHA256). Audit
    /// non-repudiation and response-signature verification are meaningful:
    /// a client holding the CMK can verify them offline.
    CmkDerived,
    /// Keys randomly generated at boot because no CMK was provisioned.
    /// FOR DEVELOPMENT ONLY — the node self-certifies, so log signatures and
    /// response signatures carry no cross-party guarantee.
    Ephemeral,
}

impl KeyProvenance {
    /// String form for health/status output.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyProvenance::CmkDerived => "cmk_derived",
            KeyProvenance::Ephemeral => "ephemeral",
        }
    }
}

/// Cryptographic key material held by a running node.
///
/// In a real TEE these live only inside the enclave and are released after
/// attestation. Here they are held in process memory; every secret zeroizes on
/// drop (`MasterKey`/`SigningKey` are `ZeroizeOnDrop`).
struct NodeKeys {
    /// Retained CMK (present only when provisioned) for on-demand bundle-key
    /// derivation used to prove key possession during model gating.
    master: Option<MasterKey>,
    /// Client/operator id used as the key-derivation principal.
    key_principal: String,
    /// Admin authorization verifying key (K_admin_pub). `None` disables the
    /// admin API unless insecure dev override is set.
    admin_vk: Option<VerifyingKey>,
    /// Enclave response/attestation signing key (Ed25519).
    enclave_key: SigningKey,
    /// Where the signing keys came from.
    provenance: KeyProvenance,
    /// Dev-only: allow admin endpoints without a provisioned K_admin.
    insecure_admin: bool,
    /// Allow inference for models not present in the model store even when the
    /// store is non-empty (dev escape hatch).
    allow_unregistered_models: bool,
}

/// The complete Cordon node
pub struct CordonNode {
    /// Node configuration
    pub config: CordonConfig,
    /// Deployment signing keys and their provenance
    keys: NodeKeys,
    /// Shared node state
    pub state: SharedNodeState,
    /// Identity registry (client authorization)
    pub identity: Arc<IdentityRegistry>,
    /// Rate limiter
    pub rate_limiter: Arc<RateLimiter>,
    /// Model store
    pub model_store: Arc<ModelStore>,
    /// Inference engine
    pub inference: Arc<InferenceEngine>,
    /// Output filter
    pub output_filter: Arc<OutputFilter>,
    /// Covert channel detector
    pub covert_channel: Arc<CovertChannelDetector>,
    /// Timing normalizer
    pub timing: Arc<TimingNormalizer>,
    /// Attestation service
    pub attestation: Arc<AttestationService>,
    /// Integrity monitor
    pub integrity_monitor: Arc<IntegrityMonitor>,
    /// Attack detector
    pub attack_detector: Arc<AttackDetector>,
    /// Audit log
    pub audit: Arc<AuditLog>,
    /// Metrics
    pub metrics: Arc<CordonMetrics>,
    /// Start time
    pub started_at: std::time::Instant,
}

/// Processed inference response
#[derive(Debug)]
#[allow(missing_docs)]
pub struct InferenceResponse {
    pub request_id: Uuid,
    pub model_id: String,
    pub client_id: String,
    pub output: String,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub finish_reason: String,
    pub latency_ms: u64,
    pub timing_bucket_ms: Option<u64>,
    pub content_policy_triggered: bool,
    pub policy_rules_matched: Vec<String>,
    pub covert_channel_score: f32,
    pub output_hash: String,
    pub mrenclave: String,
}

impl CordonNode {
    /// Build a new CordonNode from configuration
    pub fn build(config: CordonConfig) -> CordonResult<Self> {
        tracing::info!(
            mode = %config.mode,
            node_id = %config.node_id,
            deployment_id = %config.deployment_id,
            "Initializing Cordon node"
        );

        // Node state
        let state = SharedNodeState::new(NodeState::new(
            config.node_id.clone(),
            config.deployment_id.clone(),
        ));

        // Identity registry
        let identity = Arc::new(IdentityRegistry::new());

        // Rate limiter
        let rate_limiter = Arc::new(RateLimiter::new(
            config.sustained_attack.auth_failure_threshold_per_minute,
        ));

        // Model store
        let model_store = Arc::new(ModelStore::new(
            config.model_store.path.clone(),
            None, // vendor VK loaded separately
        )?);

        // Inference engine backend selection:
        //   - CORDON_INFERENCE_URL set → always use real HTTP backend (overrides TEE mode)
        //   - CORDON_USE_MOCK_INFERENCE=true → always use mock
        //   - TEE mode is Simulation and no URL set → use mock
        //   - Otherwise → use real HTTP backend
        let inference_url = std::env::var("CORDON_INFERENCE_URL").ok();
        let force_mock = std::env::var("CORDON_USE_MOCK_INFERENCE").unwrap_or_default() == "true";

        let backend: Arc<dyn crate::inference::InferenceBackendTrait> =
            if force_mock {
                tracing::info!("Inference backend: mock (CORDON_USE_MOCK_INFERENCE=true)");
                Arc::new(crate::inference::MockInferenceBackend::new())
            } else if let Some(url) = inference_url {
                tracing::info!("Inference backend: HTTP → {}", url);
                Arc::new(crate::inference::HttpInferenceBackend::new(url))
            } else if config.tee.preferred == crate::config::TeePreference::Simulation {
                tracing::info!("Inference backend: mock (TEE=simulation, no CORDON_INFERENCE_URL set)");
                Arc::new(crate::inference::MockInferenceBackend::new())
            } else {
                let url = "http://127.0.0.1:8000/v1/chat/completions".to_string();
                tracing::info!("Inference backend: HTTP → {}", url);
                Arc::new(crate::inference::HttpInferenceBackend::new(url))
            };

        let inference = Arc::new(InferenceEngine::new(
            backend,
            config.inference.max_concurrent_requests,
            config.inference.kv_cache_zero_on_session_end,
        ));

        // Output filter with default permissive policy
        let default_policy = ContentPolicy::default_permissive("all");
        let output_filter = Arc::new(OutputFilter::new(&default_policy)?);

        // Covert channel detector
        let covert_channel = Arc::new(CovertChannelDetector::new(CovertChannelConfig {
            detection_threshold: config.sustained_attack.covert_channel_score_threshold,
            ..CovertChannelConfig::default()
        }));

        // Timing normalizer
        let timing = Arc::new(TimingNormalizer::new(
            config.side_channel.timing_normalization.clone(),
        ));

        // Attestation service
        let attestation = Arc::new(AttestationService::new(config.clone()));

        // Attack detector
        let attack_detector = Arc::new(AttackDetector::new(config.sustained_attack.clone()));

        // ── Key provisioning (Layer 2 / §6.2) ──────────────────────────────
        // The Client Master Key is the root of trust. When provisioned (via
        // CORDON_CMK, an HSM in production) the audit-log signing key, the
        // admin verifying key, and the enclave response-signing key are all
        // HKDF-derived from it — so a client holding the CMK can independently
        // verify audit-log signatures and response signatures, and authorize
        // admin commands. Without a CMK the node runs in an explicitly-marked
        // DEV posture with an ephemeral, self-certified key set.
        let key_principal = std::env::var("CORDON_CLIENT_ID")
            .unwrap_or_else(|_| "operator".to_string());
        let insecure_admin = std::env::var("CORDON_INSECURE_ADMIN")
            .map(|v| v == "true").unwrap_or(false);
        let allow_unregistered_models = std::env::var("CORDON_ALLOW_UNREGISTERED_MODELS")
            .map(|v| v == "true").unwrap_or(false);

        let (log_signing_key, keys) = match load_cmk_hex() {
            Some(cmk_hex) => {
                let master = MasterKey::from_hex(cmk_hex.trim())
                    .map_err(|e| CordonError::KeyError(format!("Invalid CORDON_CMK: {}", e)))?;
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
                    "Keys derived from CMK — audit log and responses are client-verifiable"
                );
                (log_key, NodeKeys {
                    master: Some(master),
                    key_principal: key_principal.clone(),
                    admin_vk: Some(admin_vk),
                    enclave_key,
                    provenance: KeyProvenance::CmkDerived,
                    insecure_admin,
                    allow_unregistered_models,
                })
            }
            None => {
                tracing::warn!(
                    "CORDON_CMK not set — using EPHEMERAL self-signed keys (DEV ONLY). \
                     Audit log and response signatures carry no cross-party guarantee. \
                     Admin API {} without CORDON_INSECURE_ADMIN=true.",
                    if insecure_admin { "ENABLED (insecure)" } else { "DISABLED" }
                );
                (SigningKey::generate(), NodeKeys {
                    master: None,
                    key_principal: key_principal.clone(),
                    admin_vk: None,
                    enclave_key: SigningKey::generate(),
                    provenance: KeyProvenance::Ephemeral,
                    insecure_admin,
                    allow_unregistered_models,
                })
            }
        };

        let audit_config = LogConfig::new(
            config.audit.log_path.clone(),
            config.deployment_id.clone(),
            config.node_id.clone(),
        );
        let audit = Arc::new(AuditLog::open(audit_config, log_signing_key)?);

        // Integrity monitor
        let (integrity_monitor, _tamper_flag) = IntegrityMonitor::new(
            model_store.clone(),
            state.clone(),
            config.model_store.integrity_check_interval_minutes,
            config.model_store.halt_on_tamper,
        );
        let integrity_monitor = Arc::new(integrity_monitor);

        // Metrics
        let metrics = Arc::new(CordonMetrics::new()
            .map_err(|e| CordonError::Internal(format!("Metrics init failed: {}", e)))?);

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
            integrity_monitor,
            attack_detector,
            audit,
            metrics,
            started_at: std::time::Instant::now(),
        })
    }

    /// Start background services (integrity monitor, session cleanup, metrics updater)
    pub fn start_background_services(&self) {
        // Integrity monitor
        self.integrity_monitor.clone().start();

        // Metrics updater
        let state = self.state.clone();
        let metrics = self.metrics.clone();
        let started = self.started_at;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(15));
            loop {
                ticker.tick().await;
                let node = state.read();
                metrics.set_enclave_active(
                    matches!(node.enclave_state, crate::state::EnclaveState::Active)
                );
                metrics.uptime_seconds.set(started.elapsed().as_secs_f64());
            }
        });

        // Periodic cleanup: expire idle KV-cache sessions (zeroizing them),
        // drop lapsed client suspensions, prune stale rate-limit buckets, and
        // expire attack-detector blocks. Keeps memory bounded and state fresh.
        let inference = self.inference.clone();
        let identity = self.identity.clone();
        let rate_limiter = self.rate_limiter.clone();
        let attack_detector = self.attack_detector.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                ticker.tick().await;
                inference.kv_cache().cleanup_expired(900); // 15-min idle → zeroized
                identity.cleanup_expired_suspensions();
                rate_limiter.prune_stale_buckets(3600);
                attack_detector.cleanup();
            }
        });

        tracing::info!("Background services started");
    }

    /// Mark node as operational
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

    /// Provenance of this node's signing keys.
    pub fn key_provenance(&self) -> KeyProvenance {
        self.keys.provenance
    }

    /// Hex-encoded verifying key for the enclave response-signing key.
    /// Clients holding the CMK can derive the same key and verify signatures.
    pub fn enclave_verifying_key_hex(&self) -> String {
        self.keys.enclave_key.verifying_key().to_hex()
    }

    /// Short key id for the enclave signing key (first 16 hex chars of pubkey).
    pub fn enclave_key_id(&self) -> String {
        let vk = self.keys.enclave_key.verifying_key().to_hex();
        format!("enclave-{}", &vk[..16.min(vk.len())])
    }

    /// Sign a message with the enclave response-signing key (Ed25519).
    pub fn sign_enclave(&self, msg: &[u8]) -> Signature {
        self.keys.enclave_key.sign(msg)
    }

    /// Hex-encoded verifying key for the audit log signing key (K_log_pub).
    pub fn log_verifying_key_hex(&self) -> String {
        self.audit.verifying_key().to_hex()
    }

    /// Authorize an administrative command by verifying an Ed25519 signature
    /// over the canonical command string with the provisioned K_admin.
    ///
    /// Canonical message: `CORDON_ADMIN:{action}:{params}`.
    /// Fails closed: with no provisioned admin key the API is rejected unless
    /// the operator explicitly set `CORDON_INSECURE_ADMIN=true` (dev only).
    pub fn authorize_admin(&self, action: &str, params: &str, signature_hex: &str) -> CordonResult<()> {
        let vk = match &self.keys.admin_vk {
            Some(vk) => vk,
            None => {
                if self.keys.insecure_admin {
                    tracing::warn!(action, "Admin command allowed WITHOUT signature (CORDON_INSECURE_ADMIN)");
                    return Ok(());
                }
                return Err(CordonError::AdminRejected(
                    "no admin key provisioned — admin API disabled (set CORDON_CMK, or CORDON_INSECURE_ADMIN=true for dev)".into(),
                ));
            }
        };
        let canonical = format!("CORDON_ADMIN:{}:{}", action, params);
        let sig = Signature::from_hex(signature_hex.trim())
            .map_err(|_| CordonError::AdminRejected("malformed admin signature (expected 128 hex chars)".into()))?;
        vk.verify(canonical.as_bytes(), &sig)
            .map_err(|_| CordonError::AdminRejected(format!("invalid admin signature for action '{}'", action)))?;
        Ok(())
    }

    /// The canonical string an operator must sign to authorize `action`/`params`.
    pub fn admin_canonical(action: &str, params: &str) -> String {
        format!("CORDON_ADMIN:{}:{}", action, params)
    }

    /// Derive the per-bundle key for a model, if a CMK is held.
    fn bundle_key_for(&self, bundle_id: &str) -> Option<BundleKey> {
        let master = self.keys.master.as_ref()?;
        master.derive_bundle_key(bundle_id, &self.keys.key_principal).ok()
    }

    /// Whether the node is permitted to serve given its attestation state.
    ///
    /// Light/dev deployments (no hardware TEE) always pass. Hardware-TEE modes
    /// with `halt_on_attestation_failure` require a prior successful client
    /// attestation — enforcing "keys/serving released only after attestation".
    pub fn attestation_ready(&self) -> bool {
        if !self.config.requires_hardware_tee() || !self.config.tee.halt_on_attestation_failure {
            return true;
        }
        self.attestation.is_client_verified()
    }

    /// Gate inference on the encrypted model store (§6). Returns Ok if the
    /// model may be served; a typed error otherwise.
    pub fn ensure_model_servable(&self, model_id: &str) -> CordonResult<()> {
        let bundle_key = self.bundle_key_for(model_id);
        self.model_store.ensure_servable(
            model_id,
            bundle_key.as_ref(),
            self.keys.allow_unregistered_models,
        )
    }

    /// Materialize a registered bundle's plaintext weights (decrypting every
    /// shard with the CMK-derived key, verifying the full-plaintext hash) and
    /// load them into the inference backend exactly once.
    ///
    /// This is the real "decrypt-in-enclave then load" path. The reconstructed
    /// plaintext lives in a memory-backed temp file that is deleted immediately
    /// after the backend consumes it. Requires a CMK (bundle key) to be present.
    pub fn ensure_model_loaded(&self, model_id: &str) -> CordonResult<()> {
        // Not a registered bundle (dev passthrough) → nothing to decrypt/load.
        if !self.model_store.is_registered(model_id) {
            return Ok(());
        }
        // Already loaded.
        if self.inference.loaded_model().as_deref() == Some(model_id) {
            return Ok(());
        }
        // No CMK → cannot decrypt; the store gate already governs servability.
        let bundle_key = match self.bundle_key_for(model_id) {
            Some(k) => k,
            None => return Ok(()),
        };
        let plaintext = self.model_store.materialize_plaintext(model_id, &bundle_key)?;
        // Hand the decrypted bytes to the backend; it owns secure disposal.
        self.inference.load_model(model_id, &[plaintext.as_slice()])?;
        // `plaintext` (a SecretVec) zeroizes on drop here.
        Ok(())
    }

    /// Verify the on-disk audit log chain end-to-end against this node's
    /// verifying key. Returns true only if the chain is intact and every
    /// signature checks out. (O(n) in log size — used for health/attestation.)
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

    /// Process an inference request through all layers
    pub async fn process_inference(
        &self,
        client_identity: &ClientIdentity,
        model_id: &str,
        _unused_messages: Vec<()>, // placeholder — callers pass raw_messages directly
        raw_messages: Vec<crate::inference::Message>,
        params: crate::inference::InferenceParams,
        session_id: Option<Uuid>,
        timeout_seconds: u64,
    ) -> CordonResult<InferenceResponse> {
        let started = Instant::now();
        let request_id = Uuid::new_v4();

        // === LAYER 1: Perimeter checks ===

        // Check node can serve
        if !self.state.can_serve() {
            return Err(CordonError::Quarantined);
        }

        // === LAYER 2 gate: attestation-before-serving ===
        // In hardware-TEE modes with halt-on-attestation-failure, the node must
        // have been successfully attested by a client before it will serve (and
        // before any bundle key is released). Light/dev mode skips this.
        if !self.attestation_ready() {
            return Err(CordonError::AttestationInvalid(
                "node has not been attested yet — client must verify attestation before inference".into(),
            ));
        }

        // Check IP block
        if self.attack_detector.is_ip_blocked(&client_identity.fingerprint) {
            self.metrics.auth_failures_total.inc();
            return Err(CordonError::AuthFailed("Source is blocked".into()));
        }

        // Verify client identity and get policy
        let policy = self.identity.verify(client_identity)?;

        // Check client suspension
        if let Some(reason) = self.attack_detector.is_client_suspended(&client_identity.client_id) {
            return Err(CordonError::AuthFailed(format!("Client suspended: {}", reason)));
        }

        // Check model permission
        if !policy.model_permitted(model_id) {
            self.attack_detector.record_invalid_model(&client_identity.client_id);
            return Err(CordonError::AuthFailed(
                format!("Client {} not permitted to use model {}", client_identity.client_id, model_id)
            ));
        }

        // === LAYER 3: Model store gate ===
        // Serving is bound to the encrypted model store: the requested bundle
        // must be registered and pass integrity, and (when a CMK is available)
        // the enclave must be able to decrypt it — proving it holds the right
        // key. Fails closed once any bundle is provisioned.
        self.ensure_model_servable(model_id)?;
        // Decrypt + load the plaintext weights into the backend (once) for
        // registered bundles. No-op for dev passthrough / no-CMK.
        self.ensure_model_loaded(model_id)?;

        // Rate limit check
        self.rate_limiter.check(
            &client_identity.client_id,
            params.max_tokens,
            &policy,
        ).map_err(|e| {
            self.metrics.rate_limit_hits_total.inc();
            e
        })?;

        // Compute input hash (for audit — NOT the plaintext)
        let input_hash = {
            let mut hasher = Sha256::new();
            for msg in &raw_messages {
                hasher.update(msg.content.as_bytes());
            }
            hex::encode(hasher.finalize())
        };

        // Replay probe detection
        if self.attack_detector.record_input_hash(&client_identity.client_id, &input_hash) {
            tracing::warn!("Replay probe: client {} input hash {}", client_identity.client_id, &input_hash[..16]);
        }

        // === AUDIT: pre-write (log-before-process) ===
        // Write intake event before processing begins
        let audit_written = self.audit.append(AuditEvent::Inference(InferenceEvent {
            request_id,
            client_id: client_identity.client_id.clone(),
            session_id,
            model_id: model_id.to_string(),
            mrenclave: self.attestation.mrenclave(),
            input_hash: input_hash.clone(),
            output_hash: String::new(), // filled in after completion
            prompt_tokens: 0,
            completion_tokens: 0,
            latency_ms: 0,
            finish_reason: AuditFinishReason::Stop,
            content_policy_triggered: false,
            policy_rules_matched: vec![],
            covert_channel_score: 0.0,
            timing_bucket_ms: self.timing.bucket_ms(),
        }));

        if let Err(e) = audit_written {
            // Write failure is FATAL — reject the request
            tracing::error!("FATAL: audit pre-write failed: {}", e);
            return Err(CordonError::AuditWriteFailed(e.to_string()));
        }

        // === LAYERS 2–4: TEE inference ===
        let inference_req = InferenceRequest {
            request_id,
            client_id: client_identity.client_id.clone(),
            session_id,
            model_id: model_id.to_string(),
            messages: raw_messages,
            params: params.clone(),
            timeout_seconds,
            input_hash: input_hash.clone(),
            created_at: Utc::now(),
        };

        let raw_output = self.inference.run(inference_req)?;

        // Settle the rate-limiter reservation: refund reserved-but-unused output
        // tokens now that the actual generated count is known.
        self.rate_limiter.settle(
            &client_identity.client_id,
            params.max_tokens,
            raw_output.completion_tokens,
        );

        // === LAYER 5: Response pipeline ===

        // Output filter
        let filter_result = self.output_filter.filter(raw_output.text.clone());

        if filter_result.blocked {
            self.metrics.content_policy_hits_total.inc();
            let rule_id = filter_result.matches.first()
                .map(|m| m.rule_id.clone())
                .unwrap_or_default();
            return Err(CordonError::ContentPolicyViolation { rule_id });
        }

        if filter_result.triggered {
            self.metrics.content_policy_hits_total.inc();
        }

        // Covert channel detection
        let cc_analysis = self.covert_channel.analyze(&filter_result.text);
        if cc_analysis.detected {
            self.metrics.covert_channel_detections_total.inc();
            let suspended = self.attack_detector.record_covert_channel_score(
                &client_identity.client_id,
                cc_analysis.anomaly_score,
            );
            if suspended {
                return Err(CordonError::CovertChannelDetected {
                    score: cc_analysis.anomaly_score,
                });
            }
        }

        // Timing normalization
        self.timing.normalize(started).await;

        let latency_ms = started.elapsed().as_millis() as u64;

        // Compute output hash
        let output_hash = hex::encode(Sha256::digest(filter_result.text.as_bytes()));

        // === LAYER 6: Post-inference audit entry ===
        let policy_rule_ids: Vec<String> = filter_result.matches.iter()
            .map(|m| m.rule_id.clone())
            .collect();

        let finish_reason_str = match &raw_output.finish_reason {
            crate::inference::FinishReason::Stop => "stop",
            crate::inference::FinishReason::Length => "length",
            crate::inference::FinishReason::ContentFilter => "content_filter",
            crate::inference::FinishReason::Timeout => "timeout",
            crate::inference::FinishReason::Error => "error",
        };

        let _ = self.audit.append(AuditEvent::Inference(InferenceEvent {
            request_id,
            client_id: client_identity.client_id.clone(),
            session_id,
            model_id: model_id.to_string(),
            mrenclave: self.attestation.mrenclave(),
            input_hash,
            output_hash: output_hash.clone(),
            prompt_tokens: raw_output.prompt_tokens,
            completion_tokens: raw_output.completion_tokens,
            latency_ms,
            finish_reason: AuditFinishReason::Stop,
            content_policy_triggered: filter_result.triggered,
            policy_rules_matched: policy_rule_ids.clone(),
            covert_channel_score: cc_analysis.anomaly_score,
            timing_bucket_ms: self.timing.bucket_ms(),
        }));

        // Update metrics
        self.metrics.record_inference_completed(
            latency_ms as f64 / 1000.0,
            raw_output.prompt_tokens,
            raw_output.completion_tokens,
        );
        self.state.record_inference(raw_output.completion_tokens as u64);
        self.state.update_latency(latency_ms);

        Ok(InferenceResponse {
            request_id,
            model_id: model_id.to_string(),
            client_id: client_identity.client_id.clone(),
            output: filter_result.text,
            prompt_tokens: raw_output.prompt_tokens,
            completion_tokens: raw_output.completion_tokens,
            finish_reason: finish_reason_str.to_string(),
            latency_ms,
            timing_bucket_ms: self.timing.bucket_ms(),
            content_policy_triggered: filter_result.triggered,
            policy_rules_matched: policy_rule_ids,
            covert_channel_score: cc_analysis.anomaly_score,
            output_hash,
            mrenclave: self.attestation.mrenclave(),
        })
    }

    /// Get the node's current status for health endpoint
    pub fn health_summary(&self) -> serde_json::Value {
        let state = self.state.read();
        serde_json::json!({
            "status": state.status.to_string(),
            "node_id": state.node_id,
            "cordon_version": env!("CARGO_PKG_VERSION"),
            "enclave": {
                "status": format!("{:?}", state.enclave_state).to_lowercase(),
                "tee_type": self.config.tee.preferred.to_string(),
                "mrenclave": self.attestation.mrenclave(),
                "last_attested": self.attestation.last_attestation_time(),
                "attestation_valid": self.attestation.is_client_verified(),
                "signing_key": self.enclave_verifying_key_hex(),
                "key_provenance": self.keys.provenance.as_str(),
            },
            "inference": {
                "runtime": self.inference.backend_name(),
                "active_requests": self.inference.active_requests(),
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
                "chain_valid": self.audit_chain_valid(),
                "log_verifying_key": self.log_verifying_key_hex(),
                "key_provenance": self.keys.provenance.as_str(),
            },
            "uptime_seconds": self.started_at.elapsed().as_secs(),
        })
    }
}

/// Source the Client Master Key hex from (in order): `CORDON_CMK` (env; least
/// safe — visible in the process environment), `CORDON_CMK_FILE` (a file path;
/// e.g. a tmpfs/ramfs secret). Production should instead source the CMK from an
/// HSM via PKCS#11 — the `HsmConfig` in `config.rs` describes that path; this
/// function is the seam where a PKCS#11 `KeySource` plugs in.
fn load_cmk_hex() -> Option<String> {
    if let Ok(hex) = std::env::var("CORDON_CMK") {
        tracing::warn!(
            "CMK sourced from CORDON_CMK env var — prefer CORDON_CMK_FILE, or an \
             HSM/PKCS#11 key source in production (env is visible to the process tree)"
        );
        return Some(hex);
    }
    if let Ok(path) = std::env::var("CORDON_CMK_FILE") {
        match std::fs::read_to_string(&path) {
            Ok(s) => {
                tracing::info!("CMK sourced from file {}", path);
                return Some(s);
            }
            Err(e) => {
                tracing::error!("CORDON_CMK_FILE={} is unreadable: {}", path, e);
                return None;
            }
        }
    }
    None
}

// Helper: format TeePreference as string
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
