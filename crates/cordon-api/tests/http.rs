//! End-to-end HTTP tests: boot a real Cordon node + API server in-process
//! (Light mode, mock inference, CMK provisioned) and exercise the security
//! behaviors that were previously only checked by hand.
//!
//! All assertions run inside a single test so environment setup (CMK, mock
//! backend) is sequential and race-free.

use std::sync::Arc;
use std::net::SocketAddr;

use cordon_api::server::ApiServer;
use cordon_core::{config::CordonConfig, node::CordonNode};
use cordon_crypto::hierarchy::MasterKey;

const DEPLOYMENT_ID: &str = "http-test-deployment";
const CMK_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn admin_signature(action: &str, params: &str) -> String {
    let master = MasterKey::from_hex(CMK_HEX).unwrap();
    let admin = master.derive_admin_key(DEPLOYMENT_ID, "operator").unwrap();
    let canonical = format!("CORDON_ADMIN:{}:{}", action, params);
    admin.signing_key().sign(canonical.as_bytes()).to_hex()
}

#[tokio::test]
async fn http_end_to_end_security() {
    // Deterministic, isolated environment.
    std::env::set_var("CORDON_USE_MOCK_INFERENCE", "true");
    std::env::set_var("CORDON_CMK", CMK_HEX);
    std::env::set_var("CORDON_CLIENT_ID", "operator");

    let tmp = tempfile::tempdir().unwrap();
    let mut config = CordonConfig::default_light("http-node".into(), DEPLOYMENT_ID.into());
    config.audit.log_path = tmp.path().join("audit");
    config.model_store.path = tmp.path().join("bundles");

    let node = Arc::new(CordonNode::build(config).unwrap());
    node.go_operational().unwrap();

    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let server = ApiServer::new(node, addr, None);
    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let base = format!("http://127.0.0.1:{}", port);
    let http = reqwest::Client::new();

    // 1. Health
    let r = http.get(format!("{}/v1/health", base)).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.json::<serde_json::Value>().await.unwrap()["status"], "healthy");

    // 2. Inference → real ed25519 signature
    let r = http.post(format!("{}/v1/inference", base))
        .header("x-client-id", "tester")
        .json(&serde_json::json!({"model_id":"m","messages":[{"role":"user","content":"hello"}]}))
        .send().await.unwrap();
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["signature"]["algorithm"], "ed25519");
    assert_eq!(body["signature"]["value"].as_str().unwrap().len(), 128, "ed25519 sig is 64 bytes/128 hex");
    assert!(!body["choices"][0]["message"]["content"].as_str().unwrap().is_empty());

    // 3. Admin without signature → 403 (fail-closed)
    let r = http.post(format!("{}/v1/admin/quarantine", base))
        .json(&serde_json::json!({"admin_signature":"00","reason":"x"}))
        .send().await.unwrap();
    assert_eq!(r.status(), 403, "admin must reject an invalid signature");

    // 4. Admin with a valid K_admin signature → 200
    let sig = admin_signature("quarantine", "incident-1");
    let r = http.post(format!("{}/v1/admin/quarantine", base))
        .json(&serde_json::json!({"admin_signature": sig, "reason": "incident-1"}))
        .send().await.unwrap();
    assert_eq!(r.status(), 200, "valid K_admin signature must be accepted");

    // 5. Attestation verify without expected_measurements → verified:false (fail-closed)
    let r = http.post(format!("{}/v1/attestation/verify", base))
        .json(&serde_json::json!({"nonce":"abc"}))
        .send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.json::<serde_json::Value>().await.unwrap()["verified"], false);
}
