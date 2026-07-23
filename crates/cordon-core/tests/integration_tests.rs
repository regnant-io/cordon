//! Cordon Integration Tests
//!
//! Tests all major subsystems end-to-end without a real TEE.
//! Uses simulation mode for TEE and mock inference backend.

use std::sync::Arc;
use uuid::Uuid;

use cordon_core::{
    config::CordonConfig,
    node::CordonNode,
    identity::{ClientIdentity, ClientPolicy},
    inference::{Message, InferenceParams},
};
use cordon_crypto::{
    hierarchy::MasterKey,
    signing::SigningKey,
};
use cordon_audit::{
    AuditLog, LogConfig,
    events::AuditEvent,
    verify::verify_log_chain,
};

// ─── Helper builders ─────────────────────────────────────────────────────────

fn test_config(test_name: &str) -> CordonConfig {
    let tmp = std::env::temp_dir().join(format!("cordon-test-{}", test_name));
    std::fs::create_dir_all(&tmp).unwrap();
    let mut config = CordonConfig::default_light(
        Uuid::new_v4().to_string(),
        Uuid::new_v4().to_string(),
    );
    config.audit.log_path = tmp.join("audit");
    config.model_store.path = tmp.join("bundles");
    config
}

fn test_client(client_id: &str) -> ClientIdentity {
    use sha2::{Digest, Sha256};
    use chrono::Utc;
    let fingerprint = hex::encode(Sha256::digest(client_id.as_bytes()));
    ClientIdentity {
        client_id: client_id.to_string(),
        subject_dn: format!("CN={}", client_id),
        cert_serial: fingerprint[..32].to_string(),
        not_before: Utc::now() - chrono::Duration::hours(1),
        not_after: Utc::now() + chrono::Duration::days(365),
        fingerprint,
    }
}

// ─── Crypto tests ─────────────────────────────────────────────────────────────

#[test]
fn test_key_hierarchy_full() {
    let cmk = MasterKey::from_bytes([0xABu8; 32]);

    let bundle_key = cmk.derive_bundle_key("bundle-1", "client-a").unwrap();
    let session_key = cmk.derive_session_key("deploy-1", "client-a").unwrap();
    let _log_key = cmk.derive_log_key("deploy-1", "client-a").unwrap();
    let _admin_key = cmk.derive_admin_key("deploy-1", "client-a").unwrap();

    // All keys are different
    assert_ne!(bundle_key.as_bytes(), session_key.as_bytes());

    // Keys are deterministic
    let cmk2 = MasterKey::from_bytes([0xABu8; 32]);
    let bundle_key2 = cmk2.derive_bundle_key("bundle-1", "client-a").unwrap();
    assert_eq!(bundle_key.as_bytes(), bundle_key2.as_bytes());

    // Shard keys derived from bundle key
    let shard0 = bundle_key.derive_shard_key(0).unwrap();
    let shard1 = bundle_key.derive_shard_key(1).unwrap();
    assert_ne!(shard0.as_bytes(), shard1.as_bytes());
}

#[test]
fn test_aes_gcm_encrypt_decrypt() {
    use cordon_crypto::symmetric::{AesGcmKey, encrypt_blob, decrypt_blob};

    let key = AesGcmKey::from_bytes([0x42u8; 32]);
    let plaintext = b"Sensitive model weight data for testing AES-256-GCM";

    let blob = encrypt_blob(&key, plaintext).unwrap();
    let decrypted = decrypt_blob(&key, &blob).unwrap();
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());

    // Wrong key fails
    let key2 = AesGcmKey::from_bytes([0x99u8; 32]);
    assert!(decrypt_blob(&key2, &blob).is_err());

    // Tamper detection
    let mut tampered = blob.clone();
    tampered.ciphertext_sha256 = "0".repeat(64);
    assert!(decrypt_blob(&key, &tampered).is_err());
}

#[test]
fn test_ed25519_sign_verify() {
    use cordon_crypto::signing::{SigningKey, sign_bytes, verify_bytes};

    let sk = SigningKey::generate();
    let vk = sk.verifying_key();
    let msg = b"Admin command: rotate-key deploy-1 bundle-1";
    let sig = sign_bytes(&sk, msg);

    assert!(verify_bytes(&vk, msg, &sig).is_ok());
    assert!(verify_bytes(&vk, b"tampered", &sig).is_err());
}

#[test]
fn test_attestation_verification() {
    use cordon_crypto::attestation::{
        ExpectedMeasurements, TeeType, TpmPcrSet, AttestationReport,
        CombinedAttestation, TeeQuote, TpmQuote, compute_combined_hash,
    };
    use chrono::Utc;

    let node_id = "test-node-1";
    let nonce = "test-nonce-abc123";

    // Build a report
    let mut pcrs = TpmPcrSet::new();
    pcrs.set(0, "sha256:aabb".to_string());
    pcrs.set(11, "sha256:ccdd".to_string());

    let tpm_quote = TpmQuote {
        pcr_values: pcrs.clone(),
        aik_public_key_hex: "aabbcc".to_string(),
        quote_signature_hex: "ddeeff".to_string(),
        nonce: nonce.to_string(),
        timestamp: Utc::now(),
        ek_cert_chain: vec![],
    };

    let tee_quote = TeeQuote {
        tee_type: TeeType::Simulation,
        mrenclave: "sha256:enclave_measurement".to_string(),
        mrsigner: "sha256:signer_measurement".to_string(),
        isv_svn: 3,
        raw_report_b64: "".to_string(),
        report_signature_b64: "".to_string(),
    };

    let combined_hash = compute_combined_hash(&tpm_quote, &tee_quote).unwrap();
    let combined = CombinedAttestation {
        tpm_quote,
        tee_quote,
        combined_hash,
        node_id: node_id.to_string(),
        cordon_version: "2.0.0".to_string(),
        generated_at: Utc::now(),
    };

    let report = AttestationReport {
        combined,
        client_nonce: nonce.to_string(),
    };

    // Verify against expected measurements
    let expected = ExpectedMeasurements {
        pcr_values: pcrs,
        mrenclave: "sha256:enclave_measurement".to_string(),
        mrsigner: "sha256:signer_measurement".to_string(),
        min_isv_svn: 3,
        tee_type: TeeType::Simulation,
    };

    assert!(report.verify(&expected, nonce).is_ok());

    // Wrong nonce fails
    assert!(report.verify(&expected, "wrong-nonce").is_err());

    // Wrong MRENCLAVE fails
    let mut wrong = expected.clone();
    wrong.mrenclave = "sha256:wrong".to_string();
    assert!(report.verify(&wrong, nonce).is_err());
}

// ─── Audit log tests ──────────────────────────────────────────────────────────

#[test]
fn test_audit_log_chain_integrity() {
    use cordon_audit::events::{LifecycleEvent, LifecycleEventType};
    use tempfile::TempDir;

    let tmp = TempDir::new().unwrap();
    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let config = LogConfig::new(
        tmp.path().to_path_buf(),
        "test-deployment".to_string(),
        "test-node".to_string(),
    );

    let log = AuditLog::open(config.clone(), signing_key).unwrap();

    // Write several entries
    for i in 0..10 {
        log.append(AuditEvent::Lifecycle(LifecycleEvent {
            event: LifecycleEventType::Boot,
            cordon_version: "2.0.0".to_string(),
            tee_type: "simulation".to_string(),
            node_id: format!("node-{}", i),
        })).unwrap();
    }

    // Verify the chain
    let result = verify_log_chain(
        tmp.path(),
        &verifying_key,
        "test-deployment",
    ).unwrap();

    assert!(result.valid, "Log chain should be valid: {:?}", result.violations);
    // 10 appended + 1 genesis lifecycle = 11+, but sequence = 10 entries written
    assert!(result.entries_verified >= 10);
}

#[test]
fn test_audit_log_tamper_detection() {
    use cordon_audit::events::{LifecycleEvent, LifecycleEventType};
    use tempfile::TempDir;

    let tmp = TempDir::new().unwrap();
    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let config = LogConfig::new(
        tmp.path().to_path_buf(),
        "test-deployment".to_string(),
        "test-node".to_string(),
    );

    let log = AuditLog::open(config, signing_key).unwrap();

    for i in 0..5 {
        log.append(AuditEvent::Lifecycle(LifecycleEvent {
            event: LifecycleEventType::Boot,
            cordon_version: "2.0.0".to_string(),
            tee_type: "simulation".to_string(),
            node_id: format!("node-{}", i),
        })).unwrap();
    }

    // Tamper with a log file
    let log_files: Vec<_> = std::fs::read_dir(tmp.path()).unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|e| e == "jsonl").unwrap_or(false))
        .collect();

    assert!(!log_files.is_empty(), "Should have at least one log file");
    let content = std::fs::read_to_string(&log_files[0]).unwrap();
    // Modify an entry's payload without recomputing its hashes/signature.
    // (Lifecycle events serialize the variant as snake_case "boot".)
    let tampered = content.replacen("\"event\":\"boot\"", "\"event\":\"shutdown\"", 1);
    assert_ne!(tampered, content, "tamper step must actually modify the log");
    std::fs::write(&log_files[0], tampered).unwrap();

    // Verification should fail
    let result = verify_log_chain(
        tmp.path(),
        &verifying_key,
        "test-deployment",
    ).unwrap();

    assert!(!result.valid, "Tampered log should fail verification");
    assert!(!result.violations.is_empty());
}

// ─── Node integration tests ───────────────────────────────────────────────────

#[tokio::test]
async fn test_node_builds_and_goes_operational() {
    let config = test_config("node-build");
    let node = CordonNode::build(config).unwrap();
    node.go_operational().unwrap();

    assert!(node.state.can_serve());
    let health = node.health_summary();
    assert_eq!(health["status"].as_str().unwrap(), "healthy");
}

#[tokio::test]
async fn test_inference_pipeline() {
    let config = test_config("inference-pipeline");
    let node = Arc::new(CordonNode::build(config).unwrap());
    node.go_operational().unwrap();

    // Register a client policy
    let policy = ClientPolicy {
        client_id: "test-client".to_string(),
        active: true,
        permitted_models: vec![], // all models
        max_tokens_per_request: 4096,
        max_requests_per_minute: 100,
        max_tokens_per_minute: 100_000,
        admin_allowed: false,
        log_export_allowed: false,
        policy_expires_at: None,
        cert_pins: vec![],
    };
    node.identity.register(policy);

    let client = test_client("test-client");
    let messages = vec![
        Message { role: "user".to_string(), content: "Hello, Cordon!".to_string() },
    ];

    let result = node.process_inference(
        &client,
        "test-model",
        vec![],
        messages,
        InferenceParams::default(),
        None,
        60,
    ).await.unwrap();

    assert!(!result.output.is_empty());
    assert!(result.prompt_tokens > 0);
    assert!(result.completion_tokens > 0);
    assert_eq!(result.client_id, "test-client");
    assert!(!result.mrenclave.is_empty());
}

#[tokio::test]
async fn test_rate_limiting() {
    let config = test_config("rate-limit");
    let node = Arc::new(CordonNode::build(config).unwrap());
    node.go_operational().unwrap();

    let policy = ClientPolicy {
        client_id: "rate-test-client".to_string(),
        active: true,
        permitted_models: vec![],
        max_tokens_per_request: 100,
        max_requests_per_minute: 2, // Very low limit
        max_tokens_per_minute: 1000,
        admin_allowed: false,
        log_export_allowed: false,
        policy_expires_at: None,
        cert_pins: vec![],
    };
    node.identity.register(policy);

    let client = test_client("rate-test-client");
    let messages = vec![Message {
        role: "user".to_string(),
        content: "test".to_string(),
    }];

    // First few requests succeed
    let r1 = node.process_inference(&client, "m", vec![], messages.clone(),
        InferenceParams { max_tokens: 10, ..Default::default() }, None, 30).await;
    assert!(r1.is_ok());

    let r2 = node.process_inference(&client, "m", vec![], messages.clone(),
        InferenceParams { max_tokens: 10, ..Default::default() }, None, 30).await;
    assert!(r2.is_ok());

    // Third should be rate limited
    let r3 = node.process_inference(&client, "m", vec![], messages.clone(),
        InferenceParams { max_tokens: 10, ..Default::default() }, None, 30).await;
    assert!(r3.is_err());
}

#[tokio::test]
async fn test_quarantine_blocks_inference() {
    let config = test_config("quarantine");
    let node = Arc::new(CordonNode::build(config).unwrap());
    node.go_operational().unwrap();

    // Enter quarantine
    node.state.enter_quarantine();
    assert!(!node.state.can_serve());

    let client = test_client("some-client");
    let messages = vec![Message { role: "user".to_string(), content: "test".to_string() }];

    let result = node.process_inference(
        &client, "m", vec![], messages,
        InferenceParams::default(), None, 30,
    ).await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("quarantine"));
}

#[tokio::test]
async fn test_audit_log_written_per_inference() {
    let config = test_config("audit-per-inference");
    let node = Arc::new(CordonNode::build(config).unwrap());
    node.go_operational().unwrap();

    let initial_seq = node.audit.sequence();

    node.identity.register(ClientPolicy {
        client_id: "audit-client".to_string(),
        active: true,
        permitted_models: vec![],
        max_tokens_per_request: 4096,
        max_requests_per_minute: 100,
        max_tokens_per_minute: 100_000,
        admin_allowed: false,
        log_export_allowed: false,
        policy_expires_at: None,
        cert_pins: vec![],
    });

    let client = test_client("audit-client");
    node.process_inference(
        &client, "test-model", vec![],
        vec![Message { role: "user".to_string(), content: "hello".to_string() }],
        InferenceParams::default(), None, 60,
    ).await.unwrap();

    // At least 2 audit entries written (pre-write + post-write)
    let final_seq = node.audit.sequence();
    assert!(
        final_seq >= initial_seq + 2,
        "Expected at least 2 audit entries, got {} (initial: {})",
        final_seq, initial_seq
    );
}

// ─── Covert channel tests ─────────────────────────────────────────────────────

#[test]
fn test_covert_channel_normal_text_clean() {
    use cordon_core::covert_channel::{CovertChannelDetector, CovertChannelConfig};

    let detector = CovertChannelDetector::new(CovertChannelConfig::default());
    let normal = "Machine learning models are trained on large datasets. \
        The training process involves optimization via gradient descent. \
        This allows models to generalize to new, unseen examples.";
    let result = detector.analyze(normal);
    assert!(!result.detected);
}

#[test]
fn test_output_filter_pii_detection() {
    use cordon_core::output_filter::{OutputFilter, ContentPolicy, PolicyRule, PolicyRuleType, PolicyAction, PiiType};

    let policy = ContentPolicy {
        version: "1.0".to_string(),
        client_id: "test".to_string(),
        rules: vec![
            PolicyRule {
                rule_id: "pii-email".to_string(),
                description: "Detect email addresses".to_string(),
                rule_type: PolicyRuleType::PiiDetector {
                    pii_types: vec![PiiType::Email],
                    redact: false,
                },
                action: PolicyAction::LogAndContinue,
                enabled: true,
            },
            PolicyRule {
                rule_id: "block-secret".to_string(),
                description: "Block secret keyword".to_string(),
                rule_type: PolicyRuleType::TokenBlocklist {
                    tokens: vec!["CLASSIFIED".to_string()],
                },
                action: PolicyAction::ReturnError,
                enabled: true,
            },
        ],
    };

    let filter = OutputFilter::new(&policy).unwrap();

    // Normal text passes
    let r = filter.filter("The weather today is sunny.".to_string());
    assert!(!r.blocked);
    assert!(!r.triggered);

    // PII detected but not blocked (LogAndContinue)
    let r = filter.filter("Contact: user@example.com for support".to_string());
    assert!(!r.blocked);
    assert!(r.triggered);
    assert_eq!(r.matches[0].rule_id, "pii-email");

    // Blocked keyword
    let r = filter.filter("This document is CLASSIFIED top secret".to_string());
    assert!(r.blocked);
}

// ─── Timing normalizer tests ──────────────────────────────────────────────────

#[test]
fn test_timing_bucket_arithmetic() {
    use cordon_core::timing::TimingNormalizer;
    use cordon_core::config::{TimingNormalizationConfig, TimingMode};

    let norm = TimingNormalizer::new(TimingNormalizationConfig {
        enabled: true,
        mode: TimingMode::Bucket,
        bucket_ms: 500,
        fixed_floor_ms: 0,
    });

    // 0ms elapsed → next bucket is 500ms
    assert_eq!(norm.target_ms(0), 500);
    // 499ms elapsed → still 500ms
    assert_eq!(norm.target_ms(499), 500);
    // 500ms elapsed → next bucket is 1000ms
    assert_eq!(norm.target_ms(500), 1000);
    // 1001ms elapsed → next bucket is 1500ms
    assert_eq!(norm.target_ms(1001), 1500);
}

// ─── Provisioning tests ───────────────────────────────────────────────────────

#[test]
fn test_shard_encryption_decryption() {
    use cordon_crypto::{
        hierarchy::MasterKey,
        symmetric::{encrypt_shard, decrypt_shard},
    };
    use rand::RngCore;

    let master = MasterKey::from_bytes([0x55u8; 32]);
    let bundle_key = master.derive_bundle_key("test-bundle", "test-client").unwrap();
    let shard_key = bundle_key.derive_shard_key(0).unwrap();

    let plaintext = b"These are fake model weights for testing purposes only. ".repeat(100);
    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);

    let ciphertext = encrypt_shard(&shard_key, &plaintext, &iv).unwrap();
    assert_ne!(ciphertext, plaintext.as_slice());

    let decrypted = decrypt_shard(&shard_key, &ciphertext, &iv).unwrap();
    assert_eq!(decrypted, plaintext.as_slice());
}

// ─── Security-fix regression tests ─────────────────────────────────────────────

/// Fix #3: admin commands are authorized by an Ed25519 signature over a
/// canonical string; the signature is bound to the exact (action, params).
#[test]
fn test_admin_command_signature_scheme() {
    use cordon_crypto::hierarchy::MasterKey;
    use cordon_core::node::CordonNode;

    let master = MasterKey::from_bytes([5u8; 32]);
    let admin = master.derive_admin_key("deploy-1", "operator").unwrap();
    let vk = admin.verifying_key();

    let canonical = CordonNode::admin_canonical("teardown", "planned-maintenance");
    let sig = admin.signing_key().sign(canonical.as_bytes());
    assert!(vk.verify(canonical.as_bytes(), &sig).is_ok());

    // A signature for one command must not authorize a different one.
    let tampered = CordonNode::admin_canonical("teardown", "malicious");
    assert!(vk.verify(tampered.as_bytes(), &sig).is_err());
    let other_action = CordonNode::admin_canonical("recover", "planned-maintenance");
    assert!(vk.verify(other_action.as_bytes(), &sig).is_err());
}

/// Fix #3: with no CMK (no admin key) and no insecure override, the admin API
/// fails closed — even a well-formed signature is rejected.
#[test]
fn test_admin_disabled_without_cmk() {
    // Skip if the ambient environment provisions admin (would flip the default).
    if std::env::var("CORDON_CMK").is_ok()
        || std::env::var("CORDON_INSECURE_ADMIN").map(|v| v == "true").unwrap_or(false)
    {
        return;
    }
    let node = CordonNode::build(test_config("admin-closed")).unwrap();
    let res = node.authorize_admin("teardown", "reason", &"0".repeat(128));
    assert!(res.is_err(), "admin must fail closed without a provisioned K_admin");
}

/// Fix #6: inference responses are signed with the enclave key, and a client
/// holding the CMK derives the same verifying key (offline verification).
#[test]
fn test_enclave_response_signature_roundtrip() {
    use cordon_crypto::hierarchy::MasterKey;

    let master = MasterKey::from_bytes([3u8; 32]);
    let sk = master.derive_enclave_key("deploy-1", "client-a").unwrap();
    let vk = sk.verifying_key();

    let payload = "CORDON_RESPONSE_v1|req-1|out-hash|model|2026-01-01T00:00:00Z|mre";
    let sig = sk.sign(payload.as_bytes());
    assert!(vk.verify(payload.as_bytes(), &sig).is_ok());
    assert!(vk.verify(b"tampered payload", &sig).is_err());

    // Same CMK → same enclave verifying key (client-side derivation matches).
    let master2 = MasterKey::from_bytes([3u8; 32]);
    let vk2 = master2.derive_enclave_key("deploy-1", "client-a").unwrap().verifying_key();
    assert_eq!(vk.to_hex(), vk2.to_hex());
}

/// Fix #7: inference is gated on the encrypted model store — a registered
/// bundle must pass integrity AND be decryptable with the derived key; unknown
/// models are rejected once the store is non-empty; a wrong key fails the proof.
#[test]
fn test_model_store_gate_and_decrypt_proof() {
    use cordon_core::model_store::{
        ModelStore, BundleManifest, ShardDescriptor,
        MinimumRequirements, TeeRequirements, HardwareRequirements,
    };
    use cordon_crypto::hierarchy::MasterKey;
    use cordon_crypto::symmetric::encrypt_shard;
    use sha2::{Digest, Sha256};
    use base64::Engine;
    use tempfile::TempDir;

    let tmp = TempDir::new().unwrap();
    let store_dir = tmp.path().join("bundles");
    let bundle_id = "gate-bundle";
    let client_id = "client-a";

    let master = MasterKey::from_bytes([7u8; 32]);
    let bundle_key = master.derive_bundle_key(bundle_id, client_id).unwrap();
    let shard_key = bundle_key.derive_shard_key(0).unwrap();

    let bundle_dir = store_dir.join(bundle_id);
    std::fs::create_dir_all(bundle_dir.join("weights")).unwrap();
    let plaintext = b"fake-weights-".repeat(50);
    let iv = [9u8; 12];
    let ct = encrypt_shard(&shard_key, &plaintext, &iv).unwrap();
    std::fs::write(bundle_dir.join("weights/shard0.enc"), &ct).unwrap();

    let manifest = BundleManifest {
        bundle_id: bundle_id.to_string(),
        model_name: "m".to_string(),
        model_version: "1".to_string(),
        created_at: chrono::Utc::now(),
        encryption_algorithm: "AES-256-GCM".to_string(),
        key_derivation: "HKDF-SHA256".to_string(),
        client_key_id: client_id.to_string(),
        shards: vec![ShardDescriptor {
            path: "weights/shard0.enc".to_string(),
            plaintext_sha256: hex::encode(Sha256::digest(&plaintext)),
            ciphertext_sha256: hex::encode(Sha256::digest(&ct)),
            iv_base64: base64::engine::general_purpose::STANDARD.encode(iv),
            size_bytes: ct.len() as u64,
            layer_index: 0,
        }],
        total_plaintext_sha256: hex::encode(Sha256::digest(&plaintext)),
        minimum_requirements: MinimumRequirements {
            cordon_version: "2.0.0".to_string(),
            tee: TeeRequirements { sgx_isv_svn_min: None, sev_snp_api_min: None },
            hardware: HardwareRequirements { min_gpu_vram_gb: 0, min_ram_gb: 0, ecc_memory_required: false },
        },
        policy_hash: String::new(),
        vendor_signature: "UNSIGNED".to_string(),
        client_approval_signature: "UNSIGNED".to_string(),
    };
    std::fs::write(
        bundle_dir.join("manifest.json"),
        serde_json::to_string(&manifest).unwrap(),
    ).unwrap();

    let store = ModelStore::new(store_dir, None).unwrap();

    // Registered + correct key → servable.
    assert!(store.ensure_servable(bundle_id, Some(&bundle_key), false).is_ok());
    // Unknown model while store is non-empty → rejected (fail closed).
    assert!(store.ensure_servable("no-such-model", Some(&bundle_key), false).is_err());
    // Wrong key → decryption proof fails.
    let wrong_key = master.derive_bundle_key("some-other-bundle", client_id).unwrap();
    assert!(store.ensure_servable(bundle_id, Some(&wrong_key), false).is_err());

    // Materialization: decrypt all shards, verify full-plaintext hash, get bytes.
    let materialized = store.materialize_plaintext(bundle_id, &bundle_key).unwrap();
    assert_eq!(materialized.as_slice(), plaintext.as_slice());
    // Wrong key cannot materialize.
    assert!(store.materialize_plaintext(bundle_id, &wrong_key).is_err());
}

/// Roadmap: hardware-TEE deployments must not serve until attested; Light does.
#[test]
fn test_attestation_gates_serving() {
    use cordon_core::config::{DeploymentMode, TeePreference};
    let mut cfg = test_config("attest-gate");
    cfg.mode = DeploymentMode::Vault;
    cfg.tee.preferred = TeePreference::AmdSevSnp;
    cfg.tee.halt_on_attestation_failure = true;
    let node = CordonNode::build(cfg).unwrap();

    assert!(!node.attestation_ready(), "hardware-TEE node must not serve before attestation");
    node.attestation.mark_client_verified();
    assert!(node.attestation_ready(), "node should serve after a successful attestation");
}

/// Roadmap: output tokens are reserved on admission and settled to actual usage.
#[test]
fn test_rate_limiter_reservation_and_settlement() {
    use cordon_core::rate_limiter::RateLimiter;
    use cordon_core::identity::ClientPolicy;

    let rl = RateLimiter::new(100);
    let mut policy = ClientPolicy::default_for("c");
    policy.max_requests_per_minute = 100;
    policy.max_tokens_per_minute = 100; // small token budget

    // Reserve 80 of 100 output tokens.
    assert!(rl.check("c", 80, &policy).is_ok());
    // Only ~20 remain → a 50-token reservation is refused.
    assert!(rl.check("c", 50, &policy).is_err());
    // Settle: only 10 were actually used → 70 refunded.
    rl.settle("c", 80, 10);
    // Now a 50-token reservation fits again.
    assert!(rl.check("c", 50, &policy).is_ok());
}

/// Roadmap: a session created by one client cannot be reused by another.
#[tokio::test]
async fn test_cross_client_session_rejected() {
    let node = Arc::new(CordonNode::build(test_config("session-iso")).unwrap());
    node.go_operational().unwrap();

    let sid = Uuid::new_v4();
    let msgs = vec![Message { role: "user".to_string(), content: "hi".to_string() }];

    // Client A establishes the session.
    let a = test_client("client-a");
    node.process_inference(&a, "m", vec![], msgs.clone(), InferenceParams::default(), Some(sid), 30)
        .await.unwrap();

    // Client B tries to reuse A's session id → rejected.
    let b = test_client("client-b");
    let res = node.process_inference(&b, "m", vec![], msgs, InferenceParams::default(), Some(sid), 30).await;
    assert!(res.is_err(), "cross-client session reuse must be rejected");
}
