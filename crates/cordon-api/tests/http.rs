//! HTTP-level tests against a real node and server, in process.
//!
//! Every assertion here is about behaviour visible over the wire, so these are
//! the tests that would catch a regression a caller could actually exploit:
//! an endpoint that stops requiring authentication, an admin route that accepts
//! a bad signature, a metrics endpoint that answers a remote peer.
//!
//! The whole suite runs as one test because it manipulates process-wide
//! environment variables to provision the master key.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use cordon_api::server::ApiServer;
use cordon_core::{
    config::{CordonConfig, MeasurementSource, RuntimeBackend},
    node::CordonNode,
};
use cordon_crypto::hierarchy::MasterKey;

const DEPLOYMENT_ID: &str = "http-test-deployment";
const CMK_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn admin_signature(action: &str, params: &str) -> String {
    let master = MasterKey::from_hex(CMK_HEX).unwrap();
    let admin = master.derive_admin_key(DEPLOYMENT_ID, "operator").unwrap();
    let canonical = format!("CORDON_ADMIN:{}:{}", action, params);
    admin.signing_key().sign(canonical.as_bytes()).to_hex()
}

#[tokio::test]
async fn http_surface_behaves_as_specified() {
    std::env::set_var("CORDON_CMK", CMK_HEX);
    std::env::set_var("CORDON_CLIENT_ID", "operator");

    let tmp = tempfile::tempdir().unwrap();
    let mut config = CordonConfig::default_light("http-node".into(), DEPLOYMENT_ID.into());
    config.audit.log_path = tmp.path().join("audit");
    config.model_store.path = tmp.path().join("bundles");
    config.runtime.backend = RuntimeBackend::None;
    config.attestation.measurement_source = MeasurementSource::SoftwareMeasurement;
    std::fs::create_dir_all(&config.audit.log_path).unwrap();
    std::fs::create_dir_all(&config.model_store.path).unwrap();

    let node = Arc::new(CordonNode::build(config).await.unwrap());
    node.go_operational().unwrap();

    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();

    let server = ApiServer::new(node.clone(), addr, None);
    let serving = tokio::spawn(async move {
        let _ = server
            .run(async {
                let _ = stop_rx.await;
            })
            .await;
    });

    // Wait for the listener rather than sleeping a fixed interval.
    let base = format!("http://127.0.0.1:{}", port);
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap();
    for attempt in 0..100 {
        if http.get(format!("{}/v1/health", base)).send().await.is_ok() {
            break;
        }
        assert!(attempt < 99, "the server never came up");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // ── Liveness is public ───────────────────────────────────────────────
    let response = http
        .get(format!("{}/v1/health", base))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["status"], "healthy");
    assert_eq!(body["serving"], true);
    // Liveness must not disclose posture.
    assert!(body.get("enclave").is_none());

    // ── Security headers ─────────────────────────────────────────────────
    let response = http
        .get(format!("{}/v1/health", base))
        .send()
        .await
        .unwrap();
    let headers = response.headers();
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    assert!(headers.contains_key("content-security-policy"));
    assert!(headers.contains_key("x-cordon-request-id"));
    // HSTS over plaintext would pin this host to HTTPS in every browser that
    // saw it, so it must be absent here.
    assert!(
        !headers.contains_key("strict-transport-security"),
        "HSTS must not be sent over plaintext"
    );

    // ── Inference returns a real, verifiable signature ───────────────────
    let response = http
        .post(format!("{}/v1/inference", base))
        .header("x-client-id", "tester")
        .json(&serde_json::json!({
            "model_id": "test-model",
            "messages": [{"role": "user", "content": "hello"}],
            "inference_params": {"max_tokens": 64}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();

    assert_eq!(body["signature"]["algorithm"], "ed25519");
    assert_eq!(body["signature"]["value"].as_str().unwrap().len(), 128);
    assert_eq!(body["signature"]["key_provenance"], "cmk_derived");
    assert_eq!(body["client_id"], "tester");
    assert!(body["session_id"].is_string());

    // Reconstruct the signed payload from the response body alone and verify it
    // against the key a client derives from the CMK. This is the property the
    // signature exists to provide.
    {
        use cordon_crypto::signing::Signature;

        let timestamp: chrono::DateTime<chrono::Utc> =
            body["timestamp"].as_str().unwrap().parse().unwrap();
        let payload = format!(
            "CORDON_RESPONSE_v1|{}|{}|{}|{}|{}",
            body["request_id"].as_str().unwrap(),
            // The client recomputes the output hash from the text it received.
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                body["choices"][0]["message"]["content"]
                    .as_str()
                    .unwrap()
                    .as_bytes()
            )),
            body["model_id"].as_str().unwrap(),
            timestamp.timestamp_millis(),
            body["enclave_info"]["mrenclave"].as_str().unwrap()
        );

        let master = MasterKey::from_hex(CMK_HEX).unwrap();
        let vk = master
            .derive_enclave_key(DEPLOYMENT_ID, "operator")
            .unwrap()
            .verifying_key();
        let signature = Signature::from_hex(body["signature"]["value"].as_str().unwrap()).unwrap();

        assert!(
            vk.verify(payload.as_bytes(), &signature).is_ok(),
            "a client holding the CMK must be able to verify the response signature"
        );
    }

    // ── Streaming runs the same pipeline and terminates cleanly ──────────
    let response = http
        .post(format!("{}/v1/inference/stream", base))
        .header("x-client-id", "tester")
        .json(&serde_json::json!({
            "model_id": "test-model",
            "messages": [{"role": "user", "content": "stream please"}],
            "inference_params": {"max_tokens": 64}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let sse = response.text().await.unwrap();
    assert!(sse.contains("event: delta"), "no delta events: {}", sse);
    assert!(
        sse.contains("event: done"),
        "stream did not terminate: {}",
        sse
    );
    assert!(
        sse.contains("\"signature\""),
        "the done event must carry a signature"
    );

    // ── An oversized request is refused ──────────────────────────────────
    let response = http
        .post(format!("{}/v1/inference", base))
        .header("x-client-id", "tester")
        .json(&serde_json::json!({
            "model_id": "test-model",
            "messages": [{"role": "user", "content": "x".repeat(500_000)}]
        }))
        .send()
        .await
        .unwrap();
    assert!(
        response.status() == 413 || response.status() == 400,
        "an oversized request returned {}",
        response.status()
    );

    // ── Attestation cannot be self-verified ──────────────────────────────
    // The node pins no measurements, so no report can satisfy it. Supplying
    // measurements in the request must not change that — the field is not read.
    let response = http
        .post(format!("{}/v1/attestation/verify", base))
        .header("x-client-id", "tester")
        .json(&serde_json::json!({
            "nonce": "0123456789abcdef0123",
            "expected_measurements": {"mrenclave": "whatever"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        body["verified"], false,
        "a node with no pinned measurements must never report itself verified"
    );
    assert!(body["reason"].as_str().unwrap().contains("pinned"));

    // A caller cannot read the node's own measurements back to it and be
    // marked verified.
    let report = http
        .get(format!("{}/v1/attestation", base))
        .header("x-client-id", "tester")
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    let echoed = &report["report"]["combined"]["tee_quote"];
    let response = http
        .post(format!("{}/v1/attestation/verify", base))
        .header("x-client-id", "tester")
        .json(&serde_json::json!({
            "nonce": "0123456789abcdef0123",
            "expected_measurements": echoed
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap()["verified"],
        false,
        "echoing the node's own measurements back must not verify it"
    );

    // ── Admin routes fail closed ─────────────────────────────────────────
    let response = http
        .post(format!("{}/v1/admin/quarantine", base))
        .header("x-client-id", "operator")
        .json(&serde_json::json!({"admin_signature": "00", "reason": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        403,
        "a malformed signature must be refused"
    );

    // A signature over a different command must not be reusable.
    let wrong = admin_signature("teardown", "incident-1");
    let response = http
        .post(format!("{}/v1/admin/quarantine", base))
        .header("x-client-id", "operator")
        .json(&serde_json::json!({"admin_signature": wrong, "reason": "incident-1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        403,
        "a signature for one action must not authorize another"
    );

    // A signature over different parameters must not be reusable either.
    let wrong = admin_signature("quarantine", "incident-2");
    let response = http
        .post(format!("{}/v1/admin/quarantine", base))
        .header("x-client-id", "operator")
        .json(&serde_json::json!({"admin_signature": wrong, "reason": "incident-1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);

    // ── Audit endpoints ──────────────────────────────────────────────────
    let body = http
        .get(format!("{}/v1/audit/verify", base))
        .header("x-client-id", "tester")
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(body["valid"], true);
    assert_eq!(body["key_provenance"], "cmk_derived");
    assert!(body["entries_verified"].as_u64().unwrap() > 0);

    let body = http
        .get(format!("{}/v1/audit/anchor", base))
        .header("x-client-id", "tester")
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(body["signature"]["algorithm"], "ed25519");
    assert!(body["chain_head"].as_str().unwrap().len() == 64);

    // ── Metrics answer loopback ──────────────────────────────────────────
    let response = http.get(format!("{}/metrics", base)).send().await.unwrap();
    assert_eq!(
        response.status(),
        200,
        "metrics must answer a loopback peer"
    );
    assert!(response.text().await.unwrap().contains("cordon"));

    // ── Path traversal in model provisioning is refused ──────────────────
    let signature = admin_signature("provision-model", "../../etc");
    let response = http
        .post(format!("{}/v1/models", base))
        .header("x-client-id", "operator")
        .json(&serde_json::json!({
            "manifest": {},
            "bundle_directory": "../../etc",
            "admin_signature": signature
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        400,
        "a bundle directory outside the model store must be refused"
    );

    // ── Quarantine takes the node out of service ─────────────────────────
    let signature = admin_signature("quarantine", "incident-1");
    let response = http
        .post(format!("{}/v1/admin/quarantine", base))
        .header("x-client-id", "operator")
        .json(&serde_json::json!({"admin_signature": signature, "reason": "incident-1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        200,
        "a valid admin signature must be accepted"
    );

    let response = http
        .post(format!("{}/v1/inference", base))
        .header("x-client-id", "tester")
        .json(&serde_json::json!({
            "model_id": "test-model",
            "messages": [{"role": "user", "content": "after quarantine"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        503,
        "a quarantined node must refuse inference"
    );

    let _ = stop_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(10), serving).await;
}
