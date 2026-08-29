//! Deterministic backend for tests and offline configuration checks.
//!
//! This backend performs no inference. It echoes a fixed, clearly-labelled
//! response so the control plane — identity, policy, rate limiting, filtering,
//! auditing, signing — can be exercised end to end without a model runtime.
//!
//! It is refused outside [`DeploymentMode::Light`](crate::config::DeploymentMode::Light)
//! and every response it produces is prefixed so that output reaching a caller
//! can never be mistaken for model output.

use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use parking_lot::RwLock;

use crate::error::CordonResult;
use crate::inference::{
    FinishReason, InferenceBackend, InferenceRequest, RawInferenceOutput, TokenUsage,
};

/// Prefix stamped on every response so it is unmistakable in logs, transcripts,
/// and screenshots.
pub const ECHO_PREFIX: &str = "[cordon:no-model]";

/// A backend that returns deterministic, non-inferred text.
pub struct DeterministicBackend {
    last_model: RwLock<Option<String>>,
    calls: AtomicU64,
}

impl DeterministicBackend {
    /// Create a new deterministic backend.
    pub fn new() -> Self {
        Self {
            last_model: RwLock::new(None),
            calls: AtomicU64::new(0),
        }
    }

    /// Number of generations served since construction.
    pub fn call_count(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }
}

impl Default for DeterministicBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl InferenceBackend for DeterministicBackend {
    async fn infer(&self, request: &InferenceRequest) -> CordonResult<RawInferenceOutput> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        *self.last_model.write() = Some(request.model_id.clone());

        let last_user = request
            .messages
            .iter()
            .rev()
            .find(|m| m.role == "user")
            .map(|m| m.content.as_str())
            .unwrap_or("");

        // Echo a bounded, char-boundary-safe excerpt of the prompt so tests can
        // assert the request reached the backend intact.
        let excerpt = truncate_chars(last_user, 120);
        let text = format!(
            "{} No model runtime is attached to this node. The request for model \
             '{}' traversed the full Cordon pipeline and this placeholder was \
             returned in place of generated text. Prompt excerpt: {:?}",
            ECHO_PREFIX, request.model_id, excerpt
        );

        // Whitespace-delimited word counts, which is all this backend can offer
        // without a tokenizer. Reported as-is rather than dressed up as a real
        // token count.
        let prompt_tokens = request
            .messages
            .iter()
            .map(|m| m.content.split_whitespace().count() as u32)
            .sum();
        let completion_tokens = text.split_whitespace().count() as u32;

        Ok(RawInferenceOutput {
            text,
            usage: TokenUsage {
                prompt_tokens,
                completion_tokens,
            },
            finish_reason: FinishReason::Stop,
            latency_ms: 0,
        })
    }

    fn backend_name(&self) -> &'static str {
        "deterministic (no model)"
    }

    async fn loaded_model(&self) -> Option<String> {
        self.last_model.read().clone()
    }

    async fn is_ready(&self) -> bool {
        true
    }
}

/// Truncate to at most `max` characters without splitting a character.
fn truncate_chars(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::{InferenceParams, Message};
    use chrono::Utc;
    use std::time::Duration;
    use uuid::Uuid;

    fn request(content: &str) -> InferenceRequest {
        InferenceRequest {
            request_id: Uuid::new_v4(),
            client_id: "test".into(),
            session_id: None,
            model_id: "test-model".into(),
            messages: vec![Message {
                role: "user".into(),
                content: content.into(),
            }],
            params: InferenceParams::default(),
            timeout: Duration::from_secs(30),
            input_hash: "0".repeat(64),
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn output_is_labelled_as_non_inferred() {
        let backend = DeterministicBackend::new();
        let out = backend.infer(&request("hello")).await.unwrap();
        assert!(out.text.starts_with(ECHO_PREFIX));
        assert_eq!(backend.call_count(), 1);
    }

    #[tokio::test]
    async fn multibyte_prompts_do_not_panic() {
        let backend = DeterministicBackend::new();
        // 200 multi-byte characters: a naive byte slice at 120 would split one.
        let prompt = "é".repeat(200);
        let out = backend.infer(&request(&prompt)).await.unwrap();
        assert!(out.text.contains(ECHO_PREFIX));
    }

    #[test]
    fn truncation_is_char_safe() {
        assert_eq!(truncate_chars("héllo", 2), "hé");
        assert_eq!(truncate_chars("hi", 50), "hi");
    }
}
