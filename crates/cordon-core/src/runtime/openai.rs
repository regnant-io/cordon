//! OpenAI-compatible HTTP backend.
//!
//! Speaks `/v1/chat/completions` to either a Cordon-supervised llama.cpp server
//! or an endpoint the operator points Cordon at. A single pooled
//! [`reqwest::Client`] is shared across requests, and both the unary and the
//! streaming path are fully asynchronous — no request ever occupies a runtime
//! worker thread waiting on I/O.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::StreamExt;
use parking_lot::RwLock;
use serde_json::json;

use crate::error::{CordonError, CordonResult};
use crate::inference::{
    FinishReason, InferenceBackend, InferenceRequest, RawInferenceOutput, StreamChunk, TokenStream,
    TokenUsage,
};

use super::supervisor::LlamaSupervisor;

/// Where an [`OpenAiBackend`] sends its requests.
enum Upstream {
    /// A llama.cpp server Cordon spawned and owns.
    Supervised(Arc<LlamaSupervisor>),
    /// An endpoint the operator configured. Cordon does not control its
    /// lifecycle or its exposure.
    External {
        base_url: String,
        api_key: Option<String>,
    },
}

/// An OpenAI-compatible chat-completions backend.
pub struct OpenAiBackend {
    upstream: Upstream,
    http: reqwest::Client,
    /// Model identifier most recently served, for health reporting.
    last_model: RwLock<Option<String>>,
    backend_name: &'static str,
}

impl OpenAiBackend {
    /// Build a backend over a Cordon-supervised llama.cpp runtime.
    pub fn supervised(supervisor: Arc<LlamaSupervisor>) -> CordonResult<Self> {
        Ok(Self {
            upstream: Upstream::Supervised(supervisor),
            http: build_client(true)?,
            last_model: RwLock::new(None),
            backend_name: "llama.cpp (supervised)",
        })
    }

    /// Build a backend over an operator-provided endpoint.
    ///
    /// `base_url` is the server root (for example `http://127.0.0.1:8000`); the
    /// `/v1/chat/completions` path is appended by this backend.
    pub fn external(base_url: String, api_key: Option<String>) -> CordonResult<Self> {
        let base_url = base_url.trim_end_matches('/').to_string();
        let loopback_only = is_loopback_url(&base_url);
        Ok(Self {
            upstream: Upstream::External { base_url, api_key },
            http: build_client(loopback_only)?,
            last_model: RwLock::new(None),
            backend_name: "openai-compatible (external)",
        })
    }

    fn completions_url(&self) -> String {
        match &self.upstream {
            Upstream::Supervised(s) => format!("{}/v1/chat/completions", s.base_url()),
            Upstream::External { base_url, .. } => format!("{}/v1/chat/completions", base_url),
        }
    }

    fn health_url(&self) -> String {
        match &self.upstream {
            Upstream::Supervised(s) => format!("{}/health", s.base_url()),
            Upstream::External { base_url, .. } => format!("{}/health", base_url),
        }
    }

    fn auth_token(&self) -> Option<String> {
        match &self.upstream {
            Upstream::Supervised(s) => Some(s.api_key().to_string()),
            Upstream::External { api_key, .. } => api_key.clone(),
        }
    }

    fn apply_auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.auth_token() {
            Some(token) => builder.bearer_auth(token),
            None => builder,
        }
    }

    fn request_body(&self, request: &InferenceRequest, stream: bool) -> serde_json::Value {
        let mut body = json!({
            "model": request.model_id,
            "messages": request.messages,
            "max_tokens": request.params.max_tokens,
            "temperature": request.params.temperature,
            "top_p": request.params.top_p,
            "stream": stream,
        });

        // Omit optional knobs when unset so servers that reject them (or treat
        // zero as meaningful) behave predictably.
        if request.params.top_k > 0 {
            body["top_k"] = json!(request.params.top_k);
        }
        if (request.params.repetition_penalty - 1.0).abs() > f32::EPSILON {
            body["repeat_penalty"] = json!(request.params.repetition_penalty);
        }
        if !request.params.stop.is_empty() {
            body["stop"] = json!(request.params.stop);
        }
        if stream {
            body["stream_options"] = json!({ "include_usage": true });
        }
        body
    }

    async fn send(
        &self,
        request: &InferenceRequest,
        stream: bool,
    ) -> CordonResult<reqwest::Response> {
        let body = self.request_body(request, stream);
        let builder = self
            .http
            .post(self.completions_url())
            .timeout(request.timeout)
            .json(&body);

        let response = self.apply_auth(builder).send().await.map_err(|e| {
            CordonError::InferenceFailed(format!(
                "cannot reach the model runtime at {}: {}",
                self.completions_url(),
                e
            ))
        })?;

        let status = response.status();
        if !status.is_success() {
            // Surface the runtime's own message; it is the operator's most
            // useful diagnostic and contains no client plaintext.
            let detail = response
                .text()
                .await
                .unwrap_or_else(|_| "<no response body>".into());
            let detail = truncate(&detail, 512);
            return Err(CordonError::InferenceFailed(format!(
                "model runtime returned HTTP {}: {}",
                status, detail
            )));
        }

        *self.last_model.write() = Some(request.model_id.clone());
        Ok(response)
    }
}

#[async_trait]
impl InferenceBackend for OpenAiBackend {
    async fn infer(&self, request: &InferenceRequest) -> CordonResult<RawInferenceOutput> {
        let started = Instant::now();
        let response = self.send(request, false).await?;

        let body: serde_json::Value = response.json().await.map_err(|e| {
            CordonError::InferenceFailed(format!("model runtime returned malformed JSON: {}", e))
        })?;

        let choice = body.get("choices").and_then(|c| c.get(0)).ok_or_else(|| {
            CordonError::InferenceFailed("model runtime response contained no choices".into())
        })?;

        let text = choice
            .pointer("/message/content")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        let finish_reason = choice
            .get("finish_reason")
            .and_then(|v| v.as_str())
            .map(FinishReason::from_wire)
            .unwrap_or(FinishReason::Stop);

        let usage = parse_usage(body.get("usage"));

        Ok(RawInferenceOutput {
            text,
            usage,
            finish_reason,
            latency_ms: started.elapsed().as_millis() as u64,
        })
    }

    async fn infer_stream(&self, request: &InferenceRequest) -> CordonResult<TokenStream> {
        let response = self.send(request, true).await?;
        let byte_stream = response.bytes_stream();

        // Server-sent events arrive as `data: {json}` records separated by blank
        // lines, terminated by `data: [DONE]`. Records can be split across TCP
        // reads, so a buffer is carried between chunks.
        let stream = futures::stream::unfold(
            (byte_stream, String::new(), SseState::default()),
            |(mut bytes, mut buffer, mut state)| async move {
                loop {
                    // Drain anything already buffered before reading more.
                    if let Some(event) = take_event(&mut buffer) {
                        match parse_sse_event(&event, &mut state) {
                            SseOutcome::Chunk(chunk) => {
                                return Some((Ok(chunk), (bytes, buffer, state)))
                            }
                            SseOutcome::Finished => {
                                let done = StreamChunk::Done {
                                    finish_reason: state.finish_reason,
                                    usage: state.usage,
                                };
                                return Some((Ok(done), (bytes, buffer, state)));
                            }
                            SseOutcome::Continue => continue,
                        }
                    }

                    match bytes.next().await {
                        Some(Ok(part)) => match std::str::from_utf8(&part) {
                            Ok(text) => buffer.push_str(text),
                            Err(_) => {
                                // A multi-byte character split across reads is
                                // normal; append lossily only the valid prefix
                                // and keep the remainder for the next read.
                                let valid_up_to = match std::str::from_utf8(&part) {
                                    Ok(_) => part.len(),
                                    Err(e) => e.valid_up_to(),
                                };
                                buffer.push_str(&String::from_utf8_lossy(&part[..valid_up_to]));
                            }
                        },
                        Some(Err(e)) => {
                            let err = CordonError::InferenceFailed(format!(
                                "model runtime stream failed: {}",
                                e
                            ));
                            return Some((Err(err), (bytes, buffer, state)));
                        }
                        None => {
                            if state.terminated {
                                return None;
                            }
                            state.terminated = true;
                            let done = StreamChunk::Done {
                                finish_reason: state.finish_reason,
                                usage: state.usage,
                            };
                            return Some((Ok(done), (bytes, buffer, state)));
                        }
                    }
                }
            },
        );

        Ok(Box::pin(stream))
    }

    fn backend_name(&self) -> &'static str {
        self.backend_name
    }

    async fn loaded_model(&self) -> Option<String> {
        self.last_model.read().clone()
    }

    async fn is_ready(&self) -> bool {
        if let Upstream::Supervised(s) = &self.upstream {
            if !s.is_running() {
                return false;
            }
        }
        let builder = self
            .http
            .get(self.health_url())
            .timeout(Duration::from_secs(3));
        self.apply_auth(builder)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    async fn shutdown(&self) -> CordonResult<()> {
        if let Upstream::Supervised(s) = &self.upstream {
            s.terminate().await;
        }
        Ok(())
    }
}

/// Accumulated state across one SSE stream.
#[derive(Default, Clone, Copy)]
struct SseState {
    finish_reason: FinishReason,
    usage: TokenUsage,
    terminated: bool,
}

enum SseOutcome {
    Chunk(StreamChunk),
    Finished,
    Continue,
}

/// Pull one complete SSE record off the front of `buffer`, if one is present.
fn take_event(buffer: &mut String) -> Option<String> {
    let idx = buffer.find("\n\n").or_else(|| buffer.find("\r\n\r\n"))?;
    let sep_len = if buffer[idx..].starts_with("\r\n\r\n") {
        4
    } else {
        2
    };
    let event = buffer[..idx].to_string();
    buffer.drain(..idx + sep_len);
    Some(event)
}

fn parse_sse_event(event: &str, state: &mut SseState) -> SseOutcome {
    let mut payload = String::new();
    for line in event.lines() {
        if let Some(rest) = line.strip_prefix("data:") {
            payload.push_str(rest.trim());
        }
    }

    if payload.is_empty() {
        return SseOutcome::Continue;
    }
    if payload == "[DONE]" {
        state.terminated = true;
        return SseOutcome::Finished;
    }

    let value: serde_json::Value = match serde_json::from_str(&payload) {
        Ok(v) => v,
        Err(_) => return SseOutcome::Continue,
    };

    if let Some(usage) = value.get("usage") {
        if !usage.is_null() {
            state.usage = parse_usage(Some(usage));
        }
    }

    let Some(choice) = value.get("choices").and_then(|c| c.get(0)) else {
        return SseOutcome::Continue;
    };

    if let Some(reason) = choice.get("finish_reason").and_then(|v| v.as_str()) {
        state.finish_reason = FinishReason::from_wire(reason);
    }

    let delta = choice
        .pointer("/delta/content")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    if delta.is_empty() {
        SseOutcome::Continue
    } else {
        SseOutcome::Chunk(StreamChunk::Delta(delta.to_string()))
    }
}

fn parse_usage(usage: Option<&serde_json::Value>) -> TokenUsage {
    let Some(usage) = usage else {
        return TokenUsage::default();
    };
    TokenUsage {
        prompt_tokens: usage
            .get("prompt_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32,
        completion_tokens: usage
            .get("completion_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32,
    }
}

fn build_client(loopback_only: bool) -> CordonResult<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(16)
        .connect_timeout(Duration::from_secs(10));

    if loopback_only {
        // A loopback runtime must never be reached through a proxy — that would
        // route prompt plaintext off the machine.
        builder = builder.no_proxy();
    }

    builder
        .build()
        .map_err(|e| CordonError::Internal(format!("cannot build runtime HTTP client: {}", e)))
}

/// Whether a URL points at the local machine.
pub fn is_loopback_url(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    match parsed.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_loopback_urls() {
        assert!(is_loopback_url("http://127.0.0.1:8080"));
        assert!(is_loopback_url("http://localhost:8080/v1"));
        assert!(is_loopback_url("http://[::1]:8080"));
        assert!(!is_loopback_url("http://10.0.0.5:8080"));
        assert!(!is_loopback_url("https://api.example.com"));
        assert!(!is_loopback_url("not a url"));
    }

    #[test]
    fn splits_sse_records_on_blank_lines() {
        let mut buf = String::from("data: {\"a\":1}\n\ndata: [DONE]\n\n");
        assert_eq!(take_event(&mut buf).unwrap(), "data: {\"a\":1}");
        assert_eq!(take_event(&mut buf).unwrap(), "data: [DONE]");
        assert!(take_event(&mut buf).is_none());
    }

    #[test]
    fn holds_partial_records_until_complete() {
        let mut buf = String::from("data: {\"par");
        assert!(take_event(&mut buf).is_none());
        buf.push_str("tial\":true}\n\n");
        assert_eq!(take_event(&mut buf).unwrap(), "data: {\"partial\":true}");
    }

    #[test]
    fn extracts_deltas_and_finish_reason() {
        let mut state = SseState::default();
        let event = r#"data: {"choices":[{"delta":{"content":"hello"},"finish_reason":null}]}"#;
        match parse_sse_event(event, &mut state) {
            SseOutcome::Chunk(StreamChunk::Delta(d)) => assert_eq!(d, "hello"),
            _ => panic!("expected a delta"),
        }

        let event = r#"data: {"choices":[{"delta":{},"finish_reason":"length"}]}"#;
        assert!(matches!(
            parse_sse_event(event, &mut state),
            SseOutcome::Continue
        ));
        assert_eq!(state.finish_reason, FinishReason::Length);
    }

    #[test]
    fn records_usage_from_stream() {
        let mut state = SseState::default();
        let event = r#"data: {"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":11}}"#;
        let _ = parse_sse_event(event, &mut state);
        assert_eq!(state.usage.prompt_tokens, 7);
        assert_eq!(state.usage.completion_tokens, 11);
    }

    #[test]
    fn done_sentinel_terminates() {
        let mut state = SseState::default();
        assert!(matches!(
            parse_sse_event("data: [DONE]", &mut state),
            SseOutcome::Finished
        ));
        assert!(state.terminated);
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        let s = "aaaé";
        let out = truncate(s, 4);
        assert!(out.is_char_boundary(out.len() - '…'.len_utf8()));
    }
}
