//! The OpenAI-compatible routes, over the wire.
//!
//! The property that matters is that the translation layer is only a
//! translation: a chat completion is admitted, audited, filtered and signed
//! exactly as `/v1/inference` would be, and the evidence comes back in a form
//! a Cordon-aware client can verify. These tests check that, and that ordinary
//! OpenAI clients get the shapes they expect.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use cordon_api::server::ApiServer;
use cordon_core::{
    config::{CordonConfig, MeasurementSource, RuntimeBackend},
    node::CordonNode,
};
use cordon_crypto::{hierarchy::MasterKey, signing::Signature};

const DEPLOYMENT_ID: &str = "openai-test-deployment";
const CMK_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";

#[tokio::test]
async fn openai_routes_translate_the_signed_pipeline() {
    std::env::set_var("CORDON_CMK", CMK_HEX);
    std::env::set_var("CORDON_CLIENT_ID", "operator");

    let tmp = tempfile::tempdir().unwrap();
    let mut config = CordonConfig::default_light("openai-node".into(), DEPLOYMENT_ID.into());
    config.audit.log_path = tmp.path().join("audit");
    config.model_store.path = tmp.path().join("bundles");
    config.runtime.backend = RuntimeBackend::None;
    config.attestation.measurement_source = MeasurementSource::SoftwareMeasurement;
    std::fs::create_dir_all(&config.audit.log_path).unwrap();
    std::fs::create_dir_all(&config.model_store.path).unwrap();

    let node = Arc::new(CordonNode::build(config).await.unwrap());
    node.go_operational().unwrap();

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
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

    // ── A unary completion, with the client named by the dev header ──────
    let response = http
        .post(format!("{}/openai/v1/chat/completions", base))
        .header("x-client-id", "knott")
        .json(&serde_json::json!({
            "model": "test-model",
            "messages": [
                {"role": "developer", "content": "Answer briefly."},
                {"role": "user", "content": [{"type": "text", "text": "hello"}]}
            ],
            "max_tokens": 64,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "user": "ignored-by-cordon"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let signature_header = response
        .headers()
        .get("x-cordon-signature")
        .expect("signature header")
        .to_str()
        .unwrap()
        .to_string();
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["object"], "chat.completion");
    assert_eq!(body["choices"][0]["message"]["role"], "assistant");
    assert!(body["choices"][0]["message"]["content"].is_string());
    assert!(body["usage"]["total_tokens"].as_u64().is_some());
    let cordon = &body["cordon"];
    assert_eq!(cordon["client_id"], "knott");
    assert_eq!(cordon["signature"]["value"], signature_header);

    // The signature verifies offline exactly as a /v1/inference one does.
    let timestamp: chrono::DateTime<chrono::Utc> =
        cordon["timestamp"].as_str().unwrap().parse().unwrap();
    let content = body["choices"][0]["message"]["content"].as_str().unwrap();
    let payload = format!(
        "CORDON_RESPONSE_v1|{}|{}|{}|{}|{}",
        cordon["request_id"].as_str().unwrap(),
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(content.as_bytes())),
        body["model"].as_str().unwrap(),
        timestamp.timestamp_millis(),
        cordon["mrenclave"].as_str().unwrap()
    );
    let vk = MasterKey::from_hex(CMK_HEX)
        .unwrap()
        .derive_enclave_key(DEPLOYMENT_ID, "operator")
        .unwrap()
        .verifying_key();
    let sig = Signature::from_hex(cordon["signature"]["value"].as_str().unwrap()).unwrap();
    assert!(
        vk.verify(payload.as_bytes(), &sig).is_ok(),
        "the chat completion's signature must verify against the CMK-derived key"
    );

    // ── An OpenAI SDK with no custom headers: the bearer names the client ─
    let response = http
        .post(format!("{}/v1/chat/completions", base))
        .bearer_auth("weave")
        .json(&serde_json::json!({
            "model": "test-model",
            "messages": [{"role": "user", "content": "hi"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["cordon"]["client_id"], "weave");

    // ── Streaming: OpenAI chunks, evidence on the last one, then [DONE] ──
    let response = http
        .post(format!("{}/openai/v1/chat/completions", base))
        .header("x-client-id", "knott")
        .json(&serde_json::json!({
            "model": "test-model",
            "messages": [{"role": "user", "content": "stream please"}],
            "stream": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let sse = response.text().await.unwrap();
    assert!(sse.contains("chat.completion.chunk"), "no chunks: {}", sse);
    assert!(
        sse.contains("\"finish_reason\":\"stop\""),
        "no finish: {}",
        sse
    );
    assert!(sse.contains("\"signature\""), "no evidence: {}", sse);
    assert!(
        sse.trim_end().ends_with("data: [DONE]"),
        "no [DONE]: {}",
        sse
    );

    // ── Model list in OpenAI's shape ─────────────────────────────────────
    let response = http
        .get(format!("{}/openai/v1/models", base))
        .header("x-client-id", "knott")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["object"], "list");
    assert!(body["data"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["id"] == "default"));

    // ── Errors come back in OpenAI's shape, with Cordon's code kept ──────
    let response = http
        .post(format!("{}/openai/v1/chat/completions", base))
        .header("x-client-id", "knott")
        .json(&serde_json::json!({
            "model": "test-model",
            "messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "x"}}]}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["type"], "invalid_request_error");
    assert!(body["error"]["code"].is_string());

    let _ = stop_tx.send(());
    let _ = serving.await;
}
