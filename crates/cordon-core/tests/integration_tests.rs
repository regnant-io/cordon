//! End-to-end tests over an assembled node.
//!
//! These exercise the properties that only hold when the layers are wired
//! together: that the pipeline refuses in the right order, that the audit log
//! records what actually happened, and that each fail-closed path is closed.

use std::sync::Arc;
use std::time::Duration;

use cordon_core::{
    config::{CordonConfig, DeploymentMode, MeasurementSource, RuntimeBackend},
    identity::{ClientIdentity, ClientPolicy},
    inference::{InferenceParams, Message},
    node::CordonNode,
    CordonError,
};
use cordon_crypto::hierarchy::MasterKey;

const CMK_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";

/// A Light-mode configuration rooted in a temporary directory.
fn test_config(dir: &std::path::Path, name: &str) -> CordonConfig {
    let mut config = CordonConfig::default_light(format!("node-{}", name), format!("dep-{}", name));
    config.audit.log_path = dir.join("audit");
    config.model_store.path = dir.join("bundles");
    config.runtime.backend = RuntimeBackend::None;
    config.attestation.measurement_source = MeasurementSource::SoftwareMeasurement;
    config.inference.max_concurrent_requests = 4;
    config
}

fn client(client_id: &str) -> ClientIdentity {
    ClientIdentity::from_dev_header(client_id)
}

fn messages(text: &str) -> Vec<Message> {
    vec![Message {
        role: "user".into(),
        content: text.into(),
    }]
}

fn params() -> InferenceParams {
    InferenceParams {
        max_tokens: 64,
        ..InferenceParams::default()
    }
}

/// Build an operational node. Each test gets its own temporary directory, so
/// audit logs and stores never collide.
async fn build_node(dir: &std::path::Path, name: &str) -> Arc<CordonNode> {
    let node = Arc::new(CordonNode::build(test_config(dir, name)).await.unwrap());
    node.go_operational().unwrap();
    node
}

async fn infer(node: &CordonNode, who: &str, text: &str) -> Result<String, CordonError> {
    node.process_inference(
        &client(who),
        "test-model",
        messages(text),
        params(),
        None,
        Duration::from_secs(30),
    )
    .await
    .map(|outcome| outcome.output)
}

// ── Pipeline ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_node_builds_serves_and_signs() {
    let dir = tempfile::tempdir().unwrap();
    let node = build_node(dir.path(), "serves").await;

    let outcome = node
        .process_inference(
            &client("alice"),
            "test-model",
            messages("hello"),
            params(),
            None,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

    assert!(!outcome.output.is_empty());
    assert_eq!(outcome.output_hash.len(), 64);
    assert_eq!(outcome.client_id, "alice");

    // The signature must verify against the node's published verifying key.
    let signature = node.sign_enclave(outcome.output_hash.as_bytes());
    let vk =
        cordon_crypto::signing::VerifyingKey::from_hex(&node.enclave_verifying_key_hex()).unwrap();
    assert!(vk
        .verify(outcome.output_hash.as_bytes(), &signature)
        .is_ok());
}

/// With no model runtime attached, output must be unmistakably labelled. An
/// operator who cannot tell placeholder text from generated text will ship one
/// believing it is the other.
#[tokio::test]
async fn placeholder_output_is_labelled() {
    let dir = tempfile::tempdir().unwrap();
    let node = build_node(dir.path(), "placeholder").await;

    let output = infer(&node, "alice", "hello").await.unwrap();
    assert!(
        output.contains("[cordon:no-model]"),
        "placeholder output was not labelled: {}",
        output
    );
    assert!(node.inference.backend_name().contains("deterministic"));
}

#[tokio::test]
async fn every_inference_is_audited_before_and_after() {
    let dir = tempfile::tempdir().unwrap();
    let node = build_node(dir.path(), "audited").await;

    let before = node.audit.sequence();
    infer(&node, "alice", "audit me").await.unwrap();
    let after = node.audit.sequence();

    // One intake record and one completion record.
    assert_eq!(after - before, 2, "expected a pre-write and a post-write");

    let entries = node.audit.read_tail_entries(2).unwrap();
    assert_eq!(entries.len(), 2);
    for entry in &entries {
        assert_eq!(entry.payload.event_type_str(), "inference");
    }
    assert!(node.audit_chain_valid(), "the audit chain must verify");
}

/// The chain must detect a rewritten entry. This is the whole point of the log:
/// an operator who alters history has to break a hash to do it.
#[tokio::test]
async fn a_rewritten_audit_entry_breaks_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let node = build_node(dir.path(), "tamper").await;

    infer(&node, "alice", "first").await.unwrap();
    infer(&node, "alice", "second").await.unwrap();
    assert!(node.audit_chain_valid());

    // Rewrite a client ID in place, leaving the hashes as they were.
    let log_dir = node.config.audit.log_path.clone();
    let log_file = std::fs::read_dir(&log_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.extension().map(|e| e == "jsonl").unwrap_or(false))
        .expect("an audit log file");

    let contents = std::fs::read_to_string(&log_file).unwrap();
    std::fs::write(&log_file, contents.replace("alice", "mallory")).unwrap();

    assert!(
        !node.audit_chain_valid(),
        "a rewritten entry must break the chain"
    );
}

// ── Admission ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn quarantine_stops_inference() {
    let dir = tempfile::tempdir().unwrap();
    let node = build_node(dir.path(), "quarantine").await;

    infer(&node, "alice", "before").await.unwrap();
    node.state.enter_quarantine();

    assert!(matches!(
        infer(&node, "alice", "after").await,
        Err(CordonError::Quarantined)
    ));
}

#[tokio::test]
async fn rate_limits_are_enforced_per_client() {
    let dir = tempfile::tempdir().unwrap();
    let node = build_node(dir.path(), "ratelimit").await;

    node.identity.register(ClientPolicy {
        max_requests_per_minute: 3,
        max_tokens_per_minute: 10_000,
        ..ClientPolicy::default_for("throttled")
    });

    let mut refusals = 0;
    for _ in 0..12 {
        if matches!(
            infer(&node, "throttled", "spam").await,
            Err(CordonError::RateLimitExceeded { .. })
        ) {
            refusals += 1;
        }
    }
    assert!(
        refusals > 0,
        "a 3/minute client must be refused within 12 requests"
    );

    // Another client is unaffected: the limit is per client, not global.
    assert!(infer(&node, "unthrottled", "hello").await.is_ok());
}

#[tokio::test]
async fn model_permissions_are_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let node = build_node(dir.path(), "modelperm").await;

    node.identity.register(ClientPolicy {
        permitted_models: vec!["allowed-model".into()],
        ..ClientPolicy::default_for("restricted")
    });

    let denied = node
        .process_inference(
            &client("restricted"),
            "some-other-model",
            messages("hello"),
            params(),
            None,
            Duration::from_secs(30),
        )
        .await;
    assert!(matches!(denied, Err(CordonError::AuthFailed(_))));

    let allowed = node
        .process_inference(
            &client("restricted"),
            "allowed-model",
            messages("hello"),
            params(),
            None,
            Duration::from_secs(30),
        )
        .await;
    assert!(allowed.is_ok());
}

#[tokio::test]
async fn oversized_requests_are_refused_cheaply() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(dir.path(), "limits");
    config.limits.max_messages = 4;
    config.limits.max_prompt_chars = 200;
    let node = Arc::new(CordonNode::build(config).await.unwrap());
    node.go_operational().unwrap();

    let too_many: Vec<Message> = (0..10)
        .map(|i| Message {
            role: "user".into(),
            content: format!("message {}", i),
        })
        .collect();
    assert!(matches!(
        node.process_inference(
            &client("alice"),
            "m",
            too_many,
            params(),
            None,
            Duration::from_secs(30)
        )
        .await,
        Err(CordonError::RequestTooLarge(_))
    ));

    assert!(matches!(
        node.process_inference(
            &client("alice"),
            "m",
            messages(&"x".repeat(5000)),
            params(),
            None,
            Duration::from_secs(30)
        )
        .await,
        Err(CordonError::RequestTooLarge(_))
    ));
}

#[tokio::test]
async fn token_budgets_are_clamped_to_the_tighter_of_two_limits() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(dir.path(), "tokens");
    config.inference.max_output_tokens = 1000;
    let node = Arc::new(CordonNode::build(config).await.unwrap());
    node.go_operational().unwrap();

    node.identity.register(ClientPolicy {
        max_tokens_per_request: 100,
        ..ClientPolicy::default_for("small")
    });

    // Under the node ceiling but over the client's own: refused.
    let over = node
        .process_inference(
            &client("small"),
            "m",
            messages("hello"),
            InferenceParams {
                max_tokens: 500,
                ..params()
            },
            None,
            Duration::from_secs(30),
        )
        .await;
    assert!(matches!(over, Err(CordonError::ValidationFailed(_))));

    let under = node
        .process_inference(
            &client("small"),
            "m",
            messages("hello"),
            InferenceParams {
                max_tokens: 50,
                ..params()
            },
            None,
            Duration::from_secs(30),
        )
        .await;
    assert!(under.is_ok());
}

#[tokio::test]
async fn invalid_sampling_parameters_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let node = build_node(dir.path(), "sampling").await;

    for bad in [
        InferenceParams {
            max_tokens: 0,
            ..params()
        },
        InferenceParams {
            temperature: 9.0,
            ..params()
        },
        InferenceParams {
            top_p: 5.0,
            ..params()
        },
    ] {
        assert!(
            matches!(
                node.process_inference(
                    &client("alice"),
                    "m",
                    messages("hi"),
                    bad,
                    None,
                    Duration::from_secs(30)
                )
                .await,
                Err(CordonError::ValidationFailed(_))
            ),
            "invalid parameters were accepted"
        );
    }
}

#[tokio::test]
async fn a_session_cannot_be_used_by_another_client() {
    let dir = tempfile::tempdir().unwrap();
    let node = build_node(dir.path(), "sessions").await;

    let alice = node
        .process_inference(
            &client("alice"),
            "m",
            messages("first"),
            params(),
            None,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

    // Alice can continue her own session.
    assert!(node
        .process_inference(
            &client("alice"),
            "m",
            messages("second"),
            params(),
            Some(alice.session_id),
            Duration::from_secs(30),
        )
        .await
        .is_ok());

    // Mallory cannot.
    assert!(matches!(
        node.process_inference(
            &client("mallory"),
            "m",
            messages("steal"),
            params(),
            Some(alice.session_id),
            Duration::from_secs(30),
        )
        .await,
        Err(CordonError::AuthFailed(_))
    ));
}

#[tokio::test]
async fn unenrolled_clients_are_denied_once_a_registry_exists() {
    let dir = tempfile::tempdir().unwrap();
    let registry = dir.path().join("clients.json");
    std::fs::write(
        &registry,
        serde_json::to_string(&vec![ClientPolicy::default_for("enrolled")]).unwrap(),
    )
    .unwrap();

    let mut config = test_config(dir.path(), "registry");
    config.client_registry_path = Some(registry);
    let node = Arc::new(CordonNode::build(config).await.unwrap());
    node.go_operational().unwrap();

    assert!(infer(&node, "enrolled", "hello").await.is_ok());
    assert!(matches!(
        infer(&node, "stranger", "hello").await,
        Err(CordonError::AuthFailed(_))
    ));
}

// ── Admin authorization ──────────────────────────────────────────────────────

#[tokio::test]
async fn admin_is_refused_without_a_provisioned_key() {
    let dir = tempfile::tempdir().unwrap();
    let node = build_node(dir.path(), "adminclosed").await;

    // No CMK in this test process, so no admin key exists.
    assert!(matches!(
        node.authorize_admin("quarantine", "reason", &"00".repeat(64)),
        Err(CordonError::AdminRejected(_))
    ));
}

#[test]
fn admin_signatures_verify_only_for_their_own_command() {
    let master = MasterKey::from_hex(CMK_HEX).unwrap();
    let admin = master.derive_admin_key("dep-admin", "operator").unwrap();
    let vk = admin.verifying_key();

    let canonical = CordonNode::admin_canonical("quarantine", "incident-1");
    let signature = admin.signing_key().sign(canonical.as_bytes());
    assert!(vk.verify(canonical.as_bytes(), &signature).is_ok());

    // A signature over one command must not authorize another.
    for other in [
        CordonNode::admin_canonical("teardown", "incident-1"),
        CordonNode::admin_canonical("quarantine", "incident-2"),
    ] {
        assert!(
            vk.verify(other.as_bytes(), &signature).is_err(),
            "signature was reusable for: {}",
            other
        );
    }
}

// ── Configuration posture ────────────────────────────────────────────────────

/// A node in a hardened mode must not start without the key material that mode's
/// guarantees rest on.
#[tokio::test]
async fn hardened_modes_refuse_to_start_without_a_master_key() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(dir.path(), "nocmk");
    config.mode = DeploymentMode::Vault;
    config.tee.preferred = cordon_core::config::TeePreference::AmdSevSnp;
    config.attestation.measurement_source = MeasurementSource::Tpm2;
    config.attestation.expected = Some(cordon_core::config::ExpectedMeasurementsConfig {
        mrenclave: Some("a".repeat(64)),
        ..Default::default()
    });
    config.boot.tpm_required = true;
    config.network.require_mtls = true;
    config.network.client_ca_path = Some(dir.path().join("ca.crt"));
    config.runtime.backend = RuntimeBackend::Supervised;

    // Fails on either the missing CMK or the missing TPM; both are fail-closed
    // paths this mode must not get past.
    assert!(CordonNode::build(config).await.is_err());
}

#[tokio::test]
async fn development_overrides_are_refused_outside_light_mode() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(dir.path(), "override");
    config.mode = DeploymentMode::Island;
    config.tee.preferred = cordon_core::config::TeePreference::AmdSevSnp;
    config.attestation.measurement_source = MeasurementSource::Tpm2;
    config.attestation.expected = Some(cordon_core::config::ExpectedMeasurementsConfig {
        mrenclave: Some("a".repeat(64)),
        ..Default::default()
    });
    config.boot.tpm_required = true;
    config.network.require_mtls = true;
    config.network.client_ca_path = Some(dir.path().join("ca.crt"));
    config.runtime.backend = RuntimeBackend::Supervised;
    config.ui.enabled = true;

    // The console alone is enough to refuse this configuration.
    assert!(config.validate().is_err());
}

// ── Cryptography ─────────────────────────────────────────────────────────────

#[test]
fn the_key_hierarchy_separates_purposes() {
    let master = MasterKey::from_hex(CMK_HEX).unwrap();

    let log = master.derive_log_signing_key("dep", "client").unwrap();
    let admin = master.derive_admin_key("dep", "client").unwrap();
    let enclave = master.derive_enclave_key("dep", "client").unwrap();

    let keys = [
        log.verifying_key().to_hex(),
        admin.verifying_key().to_hex(),
        enclave.verifying_key().to_hex(),
    ];
    for (i, a) in keys.iter().enumerate() {
        for b in keys.iter().skip(i + 1) {
            assert_ne!(a, b, "derived keys for different purposes collided");
        }
    }

    // Derivation is deterministic: a client holding the CMK derives the same
    // public halves, which is what makes the signatures verifiable.
    let again = MasterKey::from_hex(CMK_HEX).unwrap();
    assert_eq!(
        again
            .derive_log_signing_key("dep", "client")
            .unwrap()
            .verifying_key()
            .to_hex(),
        keys[0]
    );

    // A different deployment or principal yields different keys.
    assert_ne!(
        again
            .derive_log_signing_key("other-dep", "client")
            .unwrap()
            .verifying_key()
            .to_hex(),
        keys[0]
    );
    assert_ne!(
        again
            .derive_log_signing_key("dep", "other-client")
            .unwrap()
            .verifying_key()
            .to_hex(),
        keys[0]
    );
}

#[test]
fn shard_encryption_detects_the_wrong_key_and_tampering() {
    use cordon_crypto::symmetric::{decrypt_shard, encrypt_shard};

    let master = MasterKey::from_hex(CMK_HEX).unwrap();
    let bundle = master.derive_bundle_key("bundle-a", "client").unwrap();
    let key = bundle.derive_shard_key(0).unwrap();
    let nonce = [7u8; 12];
    let plaintext = b"model weights would go here";

    let ciphertext = encrypt_shard(&key, plaintext, &nonce).unwrap();
    assert_ne!(ciphertext.as_slice(), plaintext.as_slice());
    assert_eq!(
        decrypt_shard(&key, &ciphertext, &nonce).unwrap().as_slice(),
        plaintext.as_slice()
    );

    // A different shard index is a different key.
    let other_shard = bundle.derive_shard_key(1).unwrap();
    assert!(decrypt_shard(&other_shard, &ciphertext, &nonce).is_err());

    // A different bundle is a different key.
    let other_bundle = master
        .derive_bundle_key("bundle-b", "client")
        .unwrap()
        .derive_shard_key(0)
        .unwrap();
    assert!(decrypt_shard(&other_bundle, &ciphertext, &nonce).is_err());

    // Flipping one ciphertext bit must fail the GCM tag.
    let mut corrupted = ciphertext.clone();
    corrupted[0] ^= 0x01;
    assert!(decrypt_shard(&key, &corrupted, &nonce).is_err());
}
