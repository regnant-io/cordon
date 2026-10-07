//! An OpenAI-compatible door onto the same pipeline.
//!
//! Most software that can talk to a language model already speaks the OpenAI
//! chat-completions protocol: coding agents, workflow engines, research tools,
//! every SDK. These handlers let that software use Cordon by changing a base
//! URL, without a Cordon-specific client.
//!
//! They are a translation layer and nothing else. A request here passes through
//! exactly the admission, policy, audit, filtering and signing stages that
//! `POST /v1/inference` does, under the same client identity: under mTLS the
//! certificate, in Light mode the `x-client-id` header. The one addition is
//! for clients that cannot add a header: in Light mode only, with no
//! `x-client-id`, the bearer token an OpenAI client always sends is taken as
//! the client ID. That is exactly as strong as the development header, which is
//! to say not at all, and it is refused wherever the header would be.
//!
//! The Cordon-specific evidence, the request ID that keys the audit log, the
//! Ed25519 signature, the content-policy outcome, travels in a `cordon` object
//! on the response (on the final chunk of a stream) and in `x-cordon-*`
//! headers, where OpenAI clients ignore it and Cordon-aware ones can verify it.
//!
//! Routes, mounted under `/openai/v1` so the native `/v1/models` keeps its
//! shape, plus `/v1/chat/completions` for clients that hard-code that path:
//!
//! | Route | |
//! |---|---|
//! | `GET /openai/v1/models` | The served model, in OpenAI's list shape. |
//! | `POST /openai/v1/chat/completions` | Unary or `stream: true`. |
//! | `POST /v1/chat/completions` | The same handler. |

use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};

use cordon_core::{
    inference::{FinishReason, InferenceParams, Message},
    output_filter::StreamingFilter,
    CordonError,
};

use crate::{
    error::{map_err, ApiErrorResponse},
    handlers::{authenticated_client, resolve_timeout, sign_response, AppState},
    middleware::VerifiedIdentity,
};

/// The model a client gets when it names none, or names the generic `default`.
const DEFAULT_MODEL: &str = "default";

/// `POST /openai/v1/chat/completions` request body. Unknown fields (tools,
/// response_format, seed, user, …) are accepted and ignored rather than
/// refused, because SDKs send them by default.
#[derive(Debug, Deserialize)]
pub struct ChatCompletionRequest {
    #[serde(default)]
    model: String,
    messages: Vec<ChatMessage>,
    #[serde(default)]
    max_tokens: Option<u32>,
    #[serde(default)]
    max_completion_tokens: Option<u32>,
    #[serde(default)]
    temperature: Option<f32>,
    #[serde(default)]
    top_p: Option<f32>,
    #[serde(default)]
    stop: Option<Stop>,
    #[serde(default)]
    frequency_penalty: Option<f32>,
    #[serde(default)]
    stream: bool,
    #[serde(default)]
    response_format: Option<ResponseFormat>,
}

/// `response_format`. `json_object` and `json_schema` both ask for JSON; the
/// schema itself is not enforced, only that the output is an object.
#[derive(Debug, Deserialize)]
struct ResponseFormat {
    #[serde(rename = "type", default)]
    kind: String,
}

#[derive(Debug, Deserialize)]
struct ChatMessage {
    role: String,
    #[serde(default)]
    content: Option<Content>,
}

/// Message content: a string, or the array-of-parts form newer clients send.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Content {
    Text(String),
    Parts(Vec<ContentPart>),
}

#[derive(Debug, Deserialize)]
struct ContentPart {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Stop {
    One(String),
    Many(Vec<String>),
}

impl ChatCompletionRequest {
    fn model_id(&self) -> String {
        let m = self.model.trim();
        if m.is_empty() {
            DEFAULT_MODEL.to_string()
        } else {
            m.to_string()
        }
    }

    /// Translate to the core request. Non-text parts (images, audio) are
    /// refused rather than silently dropped: a model answering a question about
    /// an image it never saw is worse than an error.
    fn to_core(&self) -> Result<(Vec<Message>, InferenceParams), ApiErrorResponse> {
        let mut messages = Vec::with_capacity(self.messages.len());
        for m in &self.messages {
            let content = match &m.content {
                None => String::new(),
                Some(Content::Text(s)) => s.clone(),
                Some(Content::Parts(parts)) => {
                    let mut text = String::new();
                    for p in parts {
                        if p.kind != "text" && !p.kind.is_empty() {
                            return Err(bad_request(format!(
                                "content part type {:?} is not supported; Cordon serves text models",
                                p.kind
                            )));
                        }
                        text.push_str(p.text.as_deref().unwrap_or_default());
                    }
                    text
                }
            };
            // "developer" is OpenAI's newer name for the system role.
            let role = if m.role == "developer" {
                "system".to_string()
            } else {
                m.role.clone()
            };
            messages.push(Message { role, content });
        }

        let defaults = InferenceParams::default();
        let params = InferenceParams {
            max_tokens: self
                .max_completion_tokens
                .or(self.max_tokens)
                .unwrap_or(defaults.max_tokens),
            temperature: self.temperature.unwrap_or(defaults.temperature),
            top_p: self.top_p.unwrap_or(defaults.top_p),
            top_k: defaults.top_k,
            stop: match &self.stop {
                None => vec![],
                Some(Stop::One(s)) => vec![s.clone()],
                Some(Stop::Many(v)) => v.clone(),
            },
            // OpenAI's frequency penalty is additive around zero; the runtime's
            // repetition penalty is multiplicative around one.
            repetition_penalty: self
                .frequency_penalty
                .map(|p| 1.0 + p.clamp(0.0, 2.0) / 2.0)
                .unwrap_or(defaults.repetition_penalty),
            json_output: matches!(
                self.response_format.as_ref().map(|f| f.kind.as_str()),
                Some("json_object") | Some("json_schema")
            ),
        };
        Ok((messages, params))
    }
}

fn bad_request(message: String) -> ApiErrorResponse {
    map_err(CordonError::ValidationFailed(message))
}

/// Errors in OpenAI's shape, `{"error": {message, type, code}}`, with Cordon's
/// stable code kept as `code` so a caller can still branch on it.
pub struct OpenAiError(ApiErrorResponse);

impl From<ApiErrorResponse> for OpenAiError {
    fn from(e: ApiErrorResponse) -> Self {
        Self(e)
    }
}

impl IntoResponse for OpenAiError {
    fn into_response(self) -> Response {
        let status = self.0.status;
        let kind = match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => "authentication_error",
            StatusCode::TOO_MANY_REQUESTS => "rate_limit_error",
            StatusCode::BAD_REQUEST | StatusCode::PAYLOAD_TOO_LARGE | StatusCode::NOT_FOUND => {
                "invalid_request_error"
            }
            _ => "server_error",
        };
        let body = json!({
            "error": {
                "message": self.0.body.message,
                "type": kind,
                "code": self.0.body.error,
                "param": null,
                "request_id": self.0.body.request_id,
            }
        });
        let mut response = (status, Json(body)).into_response();
        if status == StatusCode::SERVICE_UNAVAILABLE || status == StatusCode::TOO_MANY_REQUESTS {
            response
                .headers_mut()
                .insert("retry-after", HeaderValue::from_static("1"));
        }
        response
    }
}

fn openai_finish_reason(fr: FinishReason) -> &'static str {
    match fr {
        FinishReason::Stop => "stop",
        FinishReason::Length => "length",
        FinishReason::ContentFilter => "content_filter",
        _ => "stop",
    }
}

/// `GET /openai/v1/models`.
pub async fn list_models(
    State(state): State<AppState>,
    Extension(vid): Extension<VerifiedIdentity>,
) -> Result<impl IntoResponse, OpenAiError> {
    authenticated_client(&state.node, vid)?;
    let created = Utc::now().timestamp();
    let mut ids: Vec<String> = Vec::new();
    if let Some(m) = state.node.inference.loaded_model().await {
        ids.push(m);
    }
    for b in state.node.model_store.list_bundles() {
        if !ids.contains(&b.bundle_id) {
            ids.push(b.bundle_id);
        }
    }
    ids.push(DEFAULT_MODEL.to_string());
    let data: Vec<Value> = ids
        .into_iter()
        .map(|id| json!({"id": id, "object": "model", "created": created, "owned_by": "cordon"}))
        .collect();
    Ok(Json(json!({"object": "list", "data": data})))
}

/// `POST /openai/v1/chat/completions` and `POST /v1/chat/completions`.
pub async fn chat_completions(
    State(state): State<AppState>,
    Extension(vid): Extension<VerifiedIdentity>,
    Json(req): Json<ChatCompletionRequest>,
) -> Result<Response, OpenAiError> {
    let client = authenticated_client(&state.node, vid)?;
    let (messages, params) = req.to_core()?;
    let model_id = req.model_id();
    let timeout = resolve_timeout(&state.node, None);

    if req.stream {
        return stream(state, client, model_id, messages, params, timeout).await;
    }

    let outcome = state
        .node
        .process_inference(&client, &model_id, messages, params, None, timeout)
        .await
        .map_err(map_err)?;

    let timestamp = Utc::now();
    let signature = sign_response(
        &state.node,
        outcome.request_id,
        &outcome.output_hash,
        &outcome.model_id,
        timestamp,
        &outcome.mrenclave,
    );
    let threshold = state
        .node
        .config
        .sustained_attack
        .covert_channel_score_threshold;
    let body = json!({
        "id": format!("chatcmpl-{}", outcome.request_id),
        "object": "chat.completion",
        "created": timestamp.timestamp(),
        "model": outcome.model_id,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": outcome.output},
            "finish_reason": openai_finish_reason(outcome.finish_reason),
        }],
        "usage": {
            "prompt_tokens": outcome.prompt_tokens,
            "completion_tokens": outcome.completion_tokens,
            "total_tokens": outcome.prompt_tokens + outcome.completion_tokens,
        },
        "cordon": {
            "request_id": outcome.request_id,
            "session_id": outcome.session_id,
            "client_id": outcome.client_id,
            "timestamp": timestamp,
            "output_hash": outcome.output_hash,
            "mrenclave": outcome.mrenclave,
            "content_policy": {
                "triggered": outcome.content_policy_triggered,
                "rules_matched": outcome.policy_rules_matched,
            },
            "covert_channel": {
                "anomaly_detected": outcome.covert_channel_score > threshold,
                "anomaly_score": outcome.covert_channel_score,
            },
            "signature": signature,
        },
    });

    let mut response = (StatusCode::OK, Json(body)).into_response();
    evidence_headers(
        response.headers_mut(),
        &signature.value,
        &signature.key_provenance,
    );
    Ok(response)
}

fn evidence_headers(headers: &mut HeaderMap, signature: &str, provenance: &str) {
    if let Ok(v) = HeaderValue::from_str(signature) {
        headers.insert("x-cordon-signature", v);
    }
    if let Ok(v) = HeaderValue::from_str(provenance) {
        headers.insert("x-cordon-key-provenance", v);
    }
}

/// Streaming in OpenAI's chunk format. The pipeline is the one
/// `POST /v1/inference/stream` runs, chunk for chunk: every delta passes the
/// client's streaming filter before release, and the node audits and signs
/// the released text when the stream ends.
async fn stream(
    state: AppState,
    client: cordon_core::identity::ClientIdentity,
    model_id: String,
    messages: Vec<Message>,
    params: InferenceParams,
    timeout: std::time::Duration,
) -> Result<Response, OpenAiError> {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures::StreamExt;

    let node = state.node.clone();
    let mut session = node
        .begin_streaming_inference(&client, &model_id, messages, params, None, timeout)
        .await
        .map_err(map_err)?;
    let meta = session.meta.clone();
    let id = format!("chatcmpl-{}", meta.request_id);
    let created = Utc::now().timestamp();

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, std::convert::Infallible>>(64);
    let chunk = move |delta: Value, finish: Option<&str>| -> Event {
        Event::default().data(
            json!({
                "id": id, "object": "chat.completion.chunk", "created": created,
                "model": meta.model_id,
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
            })
            .to_string(),
        )
    };
    let meta = session.meta.clone();

    tokio::spawn(async move {
        let mut filter = StreamingFilter::new(session.output_filter.clone());
        let mut usage = cordon_core::inference::TokenUsage::default();
        let mut finish_reason = FinishReason::Stop;
        let mut failed: Option<CordonError> = None;

        if tx
            .send(Ok(chunk(json!({"role": "assistant", "content": ""}), None)))
            .await
            .is_err()
        {
            return;
        }
        while let Some(next) = session.stream.next().await {
            match next {
                Ok(cordon_core::inference::StreamChunk::Delta(delta)) => {
                    match filter.push(&delta) {
                        Ok(released) if released.is_empty() => {}
                        Ok(released) => {
                            if tx
                                .send(Ok(chunk(json!({ "content": released }), None)))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        Err(e) => {
                            failed = Some(e);
                            break;
                        }
                    }
                }
                Ok(cordon_core::inference::StreamChunk::Done {
                    finish_reason: fr,
                    usage: u,
                }) => {
                    finish_reason = fr;
                    usage = u;
                }
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        if failed.is_none() {
            match filter.finish() {
                Ok((tail, _)) if !tail.is_empty() => {
                    if tx
                        .send(Ok(chunk(json!({ "content": tail }), None)))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                Ok(_) => {}
                Err(e) => failed = Some(e),
            }
        }
        let rules_matched: Vec<String> =
            filter.matches().iter().map(|m| m.rule_id.clone()).collect();

        let last = match failed {
            Some(error) => {
                let by_policy = matches!(error, CordonError::ContentPolicyViolation { .. });
                let recorded = if by_policy {
                    FinishReason::ContentFilter
                } else {
                    FinishReason::Error
                };
                let response = ApiErrorResponse::from(error);
                node.finish_streaming_inference(&meta, None, usage, recorded, rules_matched);
                Event::default().data(
                    json!({"error": {
                        "message": response.body.message,
                        "type": if by_policy { "content_filter" } else { "server_error" },
                        "code": response.body.error,
                    }})
                    .to_string(),
                )
            }
            None => {
                let text = filter.released_text().to_string();
                let record = node.finish_streaming_inference(
                    &meta,
                    Some(&text),
                    usage,
                    finish_reason,
                    rules_matched,
                );
                let timestamp = Utc::now();
                let signature = sign_response(
                    &node,
                    meta.request_id,
                    &record.output_hash,
                    &meta.model_id,
                    timestamp,
                    &meta.mrenclave,
                );
                Event::default().data(
                    json!({
                        "id": format!("chatcmpl-{}", meta.request_id),
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": meta.model_id,
                        "choices": [{"index": 0, "delta": {}, "finish_reason": openai_finish_reason(finish_reason)}],
                        "usage": {
                            "prompt_tokens": usage.prompt_tokens,
                            "completion_tokens": usage.completion_tokens,
                            "total_tokens": usage.prompt_tokens + usage.completion_tokens,
                        },
                        "cordon": {
                            "request_id": meta.request_id,
                            "session_id": meta.session_id,
                            "client_id": meta.client_id,
                            "timestamp": timestamp,
                            "output_hash": record.output_hash,
                            "mrenclave": meta.mrenclave,
                            "content_policy": {
                                "triggered": record.content_policy_triggered,
                                "rules_matched": record.policy_rules_matched,
                            },
                            "signature": signature,
                        },
                    })
                    .to_string(),
                )
            }
        };
        if tx.send(Ok(last)).await.is_ok() {
            let _ = tx.send(Ok(Event::default().data("[DONE]"))).await;
        }
    });

    let events = tokio_stream::wrappers::ReceiverStream::new(rx);
    Ok(Sse::new(events)
        .keep_alive(KeepAlive::default())
        .into_response())
}
