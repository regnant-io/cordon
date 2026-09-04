//! Cordon Integration Tests
//!
//! Tests all major subsystems end-to-end without a real TEE.
//! Uses simulation mode for TEE and mock inference backend.

use std::sync::Arc;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::time::{sleep, Duration};
use uuid::Uuid;

use cordon_core::{
    config::CordonConfig,
    node::CordonNode,
    identity::{ClientIdentity, ClientPolicy, IdentityRegistry},
    inference::{Message, InferenceParams},
};
use cordon_crypto::{
    hierarchy::MasterKey,
    signing::SigningKey,
};
use cordon_audit::{
    AuditLog, LogConfig,
    events::{AuditEvent, InferenceEvent, FinishReason},
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
    let log_key = cmk.derive_log_key("deploy-1", "client-a").unwrap();
    let admin_key = cmk.derive_admin_key("deploy-1", "client-a").unwrap();

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
    let tampered = content.replace("Boot", "Shutdown"); // Modify an entry
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
    let mut config = test_config("rate-limit");
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


