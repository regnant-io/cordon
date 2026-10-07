//! Tool calling through the OpenAI-compatible route.
//!
//! Agents (coding agents, operations agents) cannot work without tool calls,
//! so the route carries them: tool definitions and earlier calls reach the
//! runtime, the model's calls come back, and they are filtered, audited and
//! signed with the text. A fake OpenAI-compatible runtime stands in for
//! llama.cpp or Ollama, so the test checks exactly what crosses each boundary.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{routing::post, Json, Router};
use cordon_api::server::ApiServer;
use cordon_core::{
    config::{CordonConfig, MeasurementSource, RuntimeBackend},
    node::{output_digest, CordonNode},
};
use cordon_crypto::{hierarchy::MasterKey, signing::Signature};
use serde_json::{json, Value};

const DEPLOYMENT_ID: &str = "tools-test-deployment";
const CMK_HEX: &str = "4444444444444444444444444444444444444444444444444444444444444444";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A runtime that calls `read_file` when offered tools, and answers in text
/// once it has a tool result.
async fn fake_runtime(seen: Arc<Mutex<Vec<Value>>>) -> String {
    let port = free_port();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |Json(body): Json<Value>| {
            let seen = seen.clone();
            async move {
                seen.lock().unwrap().push(body.clone());
                let answered = body["messages"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|m| m["role"] == "tool");
                let message = if body.get("tools").is_some() && !answered {
                    json!({"role": "assistant", "content": null, "tool_calls": [{
                        "id": "call_1", "type": "function",
                        "function": {"name": "read_file", "arguments": "{\"path\":\"src/main.rs\"}"}
                    }]})
                } else {
                    json!({"role": "assistant", "content": "The file defines main."})
                };
                Json(json!({
                    "choices": [{"index": 0, "message": message,
                                 "finish_reason": if answered { "stop" } else { "tool_calls" }}],
                    "usage": {"prompt_tokens": 20, "completion_tokens": 8}
                }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://127.0.0.1:{}", port)
}

#[tokio::test]
async fn tool_calls_pass_through_and_are_signed() {
    std::env::set_var("CORDON_CMK", CMK_HEX);
    std::env::set_var("CORDON_CLIENT_ID", "operator");

    let seen = Arc::new(Mutex::new(Vec::new()));
    let runtime_url = fake_runtime(seen.clone()).await;

    let tmp = tempfile::tempdir().unwrap();
    let mut config = CordonConfig::default_light("tools-node".into(), DEPLOYMENT_ID.into());
    config.audit.log_path = tmp.path().join("audit");
    config.model_store.path = tmp.path().join("bundles");
    config.runtime.backend = RuntimeBackend::External;
    config.runtime.endpoint_url = Some(runtime_url);
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

    let tools = json!([{"type": "function", "function": {
        "name": "read_file", "description": "Read a file",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}}}}]);

    // ── 1. The model calls a tool ────────────────────────────────────────
    let response = http
        .post(format!("{}/openai/v1/chat/completions", base))
        .header("x-client-id", "bubbly")
        .json(&json!({
            "model": "coder",
            "messages": [{"role": "user", "content": "What is in main.rs?"}],
            "tools": tools, "tool_choice": "auto"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    let choice = &body["choices"][0];
    assert_eq!(choice["finish_reason"], "tool_calls");
    assert!(choice["message"]["content"].is_null());
    let call = &choice["message"]["tool_calls"][0];
    assert_eq!(call["function"]["name"], "read_file");
    assert_eq!(call["id"], "call_1");
    assert_eq!(body["cordon"]["output_hash_covers"], "text+tool_calls");

    // The runtime received the tools as sent.
    {
        let first = &seen.lock().unwrap()[0];
        assert_eq!(first["tools"], tools);
        assert_eq!(first["tool_choice"], "auto");
    }

    // The signature covers the call: recompute the documented output hash
    // from the text and the calls as returned, and verify.
    // Exactly the calls in the response, as compact JSON.
    let calls_as_returned = choice["message"]["tool_calls"].to_string();
    let digest = output_digest("", Some(&calls_as_returned));
    assert_eq!(body["cordon"]["output_hash"], digest);
    let timestamp: chrono::DateTime<chrono::Utc> = body["cordon"]["timestamp"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let payload = format!(
        "CORDON_RESPONSE_v1|{}|{}|{}|{}|{}",
        body["cordon"]["request_id"].as_str().unwrap(),
        digest,
        body["model"].as_str().unwrap(),
        timestamp.timestamp_millis(),
        body["cordon"]["mrenclave"].as_str().unwrap()
    );
    let vk = MasterKey::from_hex(CMK_HEX)
        .unwrap()
        .derive_enclave_key(DEPLOYMENT_ID, "operator")
        .unwrap()
        .verifying_key();
    let sig = Signature::from_hex(body["cordon"]["signature"]["value"].as_str().unwrap()).unwrap();
    assert!(vk.verify(payload.as_bytes(), &sig).is_ok());

    // ── 2. The tool result goes back; the model answers in text ──────────
    let response = http
        .post(format!("{}/openai/v1/chat/completions", base))
        .header("x-client-id", "bubbly")
        .json(&json!({
            "model": "coder",
            "messages": [
                {"role": "user", "content": "What is in main.rs?"},
                {"role": "assistant", "content": null, "tool_calls": [call]},
                {"role": "tool", "tool_call_id": "call_1", "content": "fn main() {}"}
            ],
            "tools": tools
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(
        body["choices"][0]["message"]["content"],
        "The file defines main."
    );
    assert_eq!(body["choices"][0]["finish_reason"], "stop");
    {
        let second = &seen.lock().unwrap()[1];
        let msgs = second["messages"].as_array().unwrap();
        assert_eq!(msgs[1]["tool_calls"][0]["id"], "call_1");
        assert_eq!(msgs[2]["role"], "tool");
        assert_eq!(msgs[2]["tool_call_id"], "call_1");
    }

    // ── 3. A streaming client with tools gets the call as a stream ───────
    let response = http
        .post(format!("{}/openai/v1/chat/completions", base))
        .header("x-client-id", "bubbly")
        .json(&json!({
            "model": "coder",
            "messages": [{"role": "user", "content": "And lib.rs?"}],
            "tools": tools, "stream": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let sse = response.text().await.unwrap();
    assert!(
        sse.contains("\"tool_calls\""),
        "no tool call chunk: {}",
        sse
    );
    assert!(
        sse.contains("\"index\":0"),
        "tool call chunk lacks index: {}",
        sse
    );
    assert!(sse.contains("\"finish_reason\":\"tool_calls\""), "{}", sse);
    assert!(sse.trim_end().ends_with("data: [DONE]"));

    let _ = stop_tx.send(());
    let _ = serving.await;
}
