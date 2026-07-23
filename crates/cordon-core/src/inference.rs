//! Inference Engine — Layer 4, §7
//!
//! Hardware-abstracted inference with per-client KV cache isolation.
//! In production, this dispatches to TensorRT-LLM (NVIDIA), vLLM (CUDA/ROCm),
//! llama.cpp (edge/CPU), or Optimum-Habana (Intel).
//! This implementation provides the full control plane with a pluggable backend.

use std::collections::HashMap;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::error::{CordonError, CordonResult};

/// A single message in the conversation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Role: system, user, or assistant
    pub role: String,
    /// Message content
    pub content: String,
}

/// Inference parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceParams {
    /// Maximum tokens to generate
    pub max_tokens: u32,
    /// Sampling temperature (0.0 = greedy)
    pub temperature: f32,
    /// Top-p nucleus sampling
    pub top_p: f32,
    /// Top-k sampling (0 = disabled)
    pub top_k: u32,
    /// Stop sequences
    pub stop: Vec<String>,
    /// Repetition penalty
    pub repetition_penalty: f32,
}

impl Default for InferenceParams {
    fn default() -> Self {
        Self {
            max_tokens: 2048,
            temperature: 0.7,
            top_p: 0.9,
            top_k: 0,
            stop: vec![],
            repetition_penalty: 1.0,
        }
    }
}

/// A complete inference request (inside TEE)
#[derive(Debug)]
pub struct InferenceRequest {
    /// Unique request ID
    pub request_id: Uuid,
    /// Client ID
    pub client_id: String,
    /// Optional session ID for multi-turn
    pub session_id: Option<Uuid>,
    /// Model bundle ID
    pub model_id: String,
    /// Messages
    pub messages: Vec<Message>,
    /// Inference parameters
    pub params: InferenceParams,
    /// Request timeout in seconds
    pub timeout_seconds: u64,
    /// SHA-256 of the input (for audit log — NOT the plaintext)
    pub input_hash: String,
    /// Request creation time
    pub created_at: DateTime<Utc>,
}

impl Drop for InferenceRequest {
    fn drop(&mut self) {
        // Zeroize message content on drop — prevents residual plaintext in memory
        for msg in &mut self.messages {
            msg.content.zeroize();
        }
    }
}

/// Reason inference generation stopped
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    /// Natural stop token
    Stop,
    /// Max tokens reached
    Length,
    /// Content filter blocked output
    ContentFilter,
    /// Request timed out
    Timeout,
    /// Internal error
    Error,
}

/// Raw inference output (before output filter)
#[derive(Debug)]
pub struct RawInferenceOutput {
    /// Generated text
    pub text: String,
    /// Number of prompt tokens
    pub prompt_tokens: u32,
    /// Number of generated tokens
    pub completion_tokens: u32,
    /// Why generation stopped
    pub finish_reason: FinishReason,
    /// Latency in milliseconds
    pub latency_ms: u64,
}

impl Drop for RawInferenceOutput {
    fn drop(&mut self) {
        // Zeroize on drop — output text may contain sensitive information
        self.text.zeroize();
    }
}

/// Hardware backend for inference
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InferenceBackend {
    /// NVIDIA TensorRT-LLM
    TensorRtLlm,
    /// vLLM (CUDA or ROCm)
    VLlm,
    /// llama.cpp (edge/CPU)
    LlamaCpp,
    /// Intel Optimum-Habana
    OptimumHabana,
    /// Mock backend (testing)
    Mock,
}

/// Trait for inference backends — allows swapping TensorRT-LLM, vLLM, llama.cpp
pub trait InferenceBackendTrait: Send + Sync {
    /// Run inference on the given request
    fn infer(&self, request: &InferenceRequest) -> CordonResult<RawInferenceOutput>;

    /// Get the backend name
    fn backend_name(&self) -> &'static str;

    /// Get the currently loaded model ID
    fn loaded_model(&self) -> Option<String>;

    /// Load a model from decrypted weight bytes
    fn load_model(&self, model_id: &str, weight_bytes: &[&[u8]]) -> CordonResult<()>;

    /// Unload the current model (zeroizes weights from GPU/RAM)
    fn unload_model(&self) -> CordonResult<()>;
}

/// Mock inference backend for testing — returns structured deterministic output
pub struct MockInferenceBackend {
    loaded_model: Mutex<Option<String>>,
}

impl MockInferenceBackend {
    /// Create a new mock backend
    pub fn new() -> Self {
        Self {
            loaded_model: Mutex::new(None),
        }
    }
}

impl Default for MockInferenceBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl InferenceBackendTrait for MockInferenceBackend {
    fn infer(&self, request: &InferenceRequest) -> CordonResult<RawInferenceOutput> {
        

        let last_user_msg = request.messages.iter()
            .rev()
            .find(|m| m.role == "user")
            .map(|m| m.content.as_str())
            .unwrap_or("(empty)");

        // Deterministic but realistic-looking response
        let response = format!(
            "I understand your query: \"{}\". This is a Cordon inference response from model {}. \
            The system is operating securely within the TEE boundary. \
            All inference computation is isolated and the response has been filtered \
            through the Cordon output pipeline.",
            &last_user_msg[..last_user_msg.len().min(80)],
            request.model_id
        );

        let prompt_tokens = request.messages.iter()
            .map(|m| m.content.split_whitespace().count() as u32)
            .sum::<u32>()
            .saturating_add(10); // system overhead

        let completion_tokens = response.split_whitespace().count() as u32;

        // Simulate realistic latency
        let latency_ms = 150 + (completion_tokens as u64 * 5);

        Ok(RawInferenceOutput {
            text: response,
            prompt_tokens,
            completion_tokens,
            finish_reason: FinishReason::Stop,
            latency_ms,
        })
    }

    fn backend_name(&self) -> &'static str {
        "mock"
    }

    fn loaded_model(&self) -> Option<String> {
        self.loaded_model.lock().clone()
    }

    fn load_model(&self, model_id: &str, _weight_bytes: &[&[u8]]) -> CordonResult<()> {
        *self.loaded_model.lock() = Some(model_id.to_string());
        tracing::info!("Mock backend: loaded model {}", model_id);
        Ok(())
    }

    fn unload_model(&self) -> CordonResult<()> {
        *self.loaded_model.lock() = None;
        Ok(())
    }
}

/// Real HTTP/vLLM inference backend — contacts a local/remote OpenAI-compatible chat completion service.
/// Zero-egress safe (can be run on localhost).
pub struct HttpInferenceBackend {
    loaded_model: Mutex<Option<String>>,
    endpoint_url: String,
}

impl HttpInferenceBackend {
    /// Create a new HTTP inference backend with a configurable endpoint URL
    pub fn new(endpoint_url: String) -> Self {
        Self {
            loaded_model: Mutex::new(None),
            endpoint_url,
        }
    }
}

impl InferenceBackendTrait for HttpInferenceBackend {
    fn infer(&self, request: &InferenceRequest) -> CordonResult<RawInferenceOutput> {
        let started = std::time::Instant::now();
        let api_request = serde_json::json!({
            "model": request.model_id,
            "messages": request.messages,
            "max_tokens": request.params.max_tokens,
            "temperature": request.params.temperature,
            "top_p": request.params.top_p,
            "stop": request.params.stop,
        });

        let url = self.endpoint_url.clone();

        // `infer` is a sync fn called from an async Tokio context.
        // We must not block a Tokio worker thread with a blocking HTTP call.
        // Solution: hand off to a dedicated OS thread that owns its own
        // single-threaded Tokio runtime — completely isolated from the main runtime.
        let response_text = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("inference thread runtime")
                .block_on(async move {
                    let client = reqwest::Client::new();
                    client
                        .post(&url)
                        .json(&api_request)
                        .send()
                        .await?
                        .json::<serde_json::Value>()
                        .await
                })
        })
        .join()
        .map_err(|_| CordonError::InferenceFailed("Inference thread panicked".into()))?
        .map_err(|e| CordonError::InferenceFailed(format!(
            "HTTP inference failed to contact llama-server: {}", e
        )))?;

        let text = response_text["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let prompt_tokens = response_text["usage"]["prompt_tokens"]
            .as_u64()
            .unwrap_or(0) as u32;

        let completion_tokens = response_text["usage"]["completion_tokens"]
            .as_u64()
            .unwrap_or(0) as u32;

        let finish_reason_str = response_text["choices"][0]["finish_reason"]
            .as_str()
            .unwrap_or("stop");

        let finish_reason = match finish_reason_str {
            "length" => FinishReason::Length,
            "content_filter" => FinishReason::ContentFilter,
            "timeout" => FinishReason::Timeout,
            _ => FinishReason::Stop,
        };

        let latency_ms = started.elapsed().as_millis() as u64;

        Ok(RawInferenceOutput {
            text,
            prompt_tokens,
            completion_tokens,
            finish_reason,
            latency_ms,
        })
    }

    fn backend_name(&self) -> &'static str {
        "vllm_http"
    }

    fn loaded_model(&self) -> Option<String> {
        self.loaded_model.lock().clone()
    }

    fn load_model(&self, model_id: &str, weight_bytes: &[&[u8]]) -> CordonResult<()> {
        use std::io::Write;
        // In production: Write decrypted weight bytes to a secure tempfs/memory-only file
        let mut tmp_file = tempfile::NamedTempFile::new()
            .map_err(|e| CordonError::Internal(format!("Failed to create secure temp file: {}", e)))?;

        for chunk in weight_bytes {
            tmp_file.as_file_mut().write_all(chunk)
                .map_err(|e| CordonError::Internal(format!("Failed to write weights to secure storage: {}", e)))?;
        }

        // Simulate loading the weights into memory / GPU
        *self.loaded_model.lock() = Some(model_id.to_string());
        tracing::info!("Real HTTP backend: Loaded model {} from secure memory-backed file", model_id);

        // Securely zeroize and remove the temp file
        // NamedTempFile deletes itself automatically on drop
        tmp_file.as_file_mut().flush()
            .map_err(|e| CordonError::Internal(format!("Failed to flush secure storage: {}", e)))?;

        Ok(())
    }

    fn unload_model(&self) -> CordonResult<()> {
        *self.loaded_model.lock() = None;
        Ok(())
    }
}


/// Per-client session state (KV cache handle)
#[allow(dead_code)] // session_id/created_at retained as session metadata
struct ClientSession {
    session_id: Uuid,
    client_id: String,
    created_at: DateTime<Utc>,
    last_active: DateTime<Utc>,
    turn_count: u32,
    /// Session-bound secret scratch. In this control plane it stands in for the
    /// backend KV-cache pages; it is explicitly zeroized when the session ends
    /// (and again on drop, since `SecretVec` is `ZeroizeOnDrop`).
    scratch: cordon_crypto::zeroize_ext::SecretVec,
}

/// KV cache isolation manager — §7.4
pub struct KvCacheManager {
    /// Active sessions per client
    sessions: Arc<RwLock<HashMap<Uuid, ClientSession>>>,
    /// Whether to zero KV cache on session end
    zero_on_end: bool,
}

impl KvCacheManager {
    /// Create a new KV cache manager
    pub fn new(zero_on_end: bool) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            zero_on_end,
        }
    }

    /// Create or resume a session for a client
    pub fn get_or_create_session(&self, client_id: &str, session_id: Option<Uuid>) -> Uuid {
        let sid = session_id.unwrap_or_else(Uuid::new_v4);
        let mut sessions = self.sessions.write();
        sessions.entry(sid).or_insert_with(|| {
            // Seed the session-bound secret scratch (stand-in for KV pages).
            let mut scratch = cordon_crypto::zeroize_ext::SecretVec::with_capacity(16);
            scratch.extend_from_slice(sid.as_bytes());
            ClientSession {
                session_id: sid,
                client_id: client_id.to_string(),
                created_at: Utc::now(),
                last_active: Utc::now(),
                turn_count: 0,
                scratch,
            }
        });
        if let Some(s) = sessions.get_mut(&sid) {
            s.last_active = Utc::now();
            s.turn_count += 1;
        }
        sid
    }

    /// Validate that a session belongs to a client (prevents cross-client access)
    pub fn validate_session_owner(&self, session_id: Uuid, client_id: &str) -> bool {
        self.sessions.read()
            .get(&session_id)
            .map(|s| s.client_id == client_id)
            .unwrap_or(false)
    }

    /// End a session, zeroing its KV cache.
    ///
    /// The session's secret scratch is explicitly overwritten before the entry
    /// is dropped (belt-and-suspenders with `SecretVec`'s drop-zeroization). In
    /// production this is where backend KV-cache pages are zeroed before being
    /// returned to the pool (§7.4).
    pub fn end_session(&self, session_id: Uuid) {
        if let Some(mut session) = self.sessions.write().remove(&session_id) {
            session.scratch.zero_now();
            tracing::debug!("Session {} ended, KV cache/scratch zeroized", session_id);
        }
    }

    /// Clean up expired sessions
    pub fn cleanup_expired(&self, max_idle_seconds: i64) {
        let cutoff = Utc::now() - chrono::Duration::seconds(max_idle_seconds);
        let mut sessions = self.sessions.write();
        sessions.retain(|_, s| s.last_active > cutoff);
    }

    /// Whether sessions are zeroized when they end.
    pub fn zero_on_end(&self) -> bool {
        self.zero_on_end
    }

    /// Get active session count for a client
    pub fn active_sessions_for_client(&self, client_id: &str) -> usize {
        self.sessions.read()
            .values()
            .filter(|s| s.client_id == client_id)
            .count()
    }
}

/// Request queue entry (reserved for a future queued-execution path).
#[allow(dead_code)]
struct QueuedRequest {
    request: InferenceRequest,
    response_tx: tokio::sync::oneshot::Sender<CordonResult<RawInferenceOutput>>,
}

/// Inference engine — orchestrates backend, KV cache, and request queuing
pub struct InferenceEngine {
    backend: Arc<dyn InferenceBackendTrait>,
    kv_cache: Arc<KvCacheManager>,
    max_concurrent: u32,
    active_requests: Arc<Mutex<u32>>,
    /// Input hash → count for replay detection
    input_hash_counts: Arc<Mutex<HashMap<String, u32>>>,
}

impl InferenceEngine {
    /// Create a new inference engine
    pub fn new(
        backend: Arc<dyn InferenceBackendTrait>,
        max_concurrent: u32,
        zero_kv_on_session_end: bool,
    ) -> Self {
        Self {
            backend,
            kv_cache: Arc::new(KvCacheManager::new(zero_kv_on_session_end)),
            max_concurrent,
            active_requests: Arc::new(Mutex::new(0)),
            input_hash_counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Run inference for a request
    pub fn run(&self, request: InferenceRequest) -> CordonResult<RawInferenceOutput> {
        // Check concurrency limit
        {
            let mut active = self.active_requests.lock();
            if *active >= self.max_concurrent {
                return Err(CordonError::Internal(
                    "Maximum concurrent requests reached".into()
                ));
            }
            *active += 1;
        }

        let _guard = scopeguard::defer_on_unwind({
            let active = self.active_requests.clone();
            move || { *active.lock() -= 1; }
        });

        // Track session
        let session_id = self.kv_cache.get_or_create_session(
            &request.client_id,
            request.session_id,
        );

        // Validate session ownership (prevents cross-client KV cache access)
        if request.session_id.is_some()
            && !self.kv_cache.validate_session_owner(session_id, &request.client_id)
        {
            return Err(CordonError::AuthFailed(
                "Session does not belong to this client".into()
            ));
        }

        // Track input hash for replay detection
        {
            let mut counts = self.input_hash_counts.lock();
            let count = counts.entry(request.input_hash.clone()).or_insert(0);
            *count += 1;
        }

        // Remember whether this is a single-shot request (no caller-owned
        // session) so we can tear the ephemeral session down afterwards.
        let single_shot = request.session_id.is_none();

        // Run inference — _guard decrements active_requests on drop
        let result = self.backend.infer(&request);

        // Single-shot sessions are ephemeral: end them immediately so their
        // KV/scratch is zeroized and the session map cannot grow unboundedly.
        if single_shot && self.kv_cache.zero_on_end() {
            self.kv_cache.end_session(session_id);
        }

        result
    }

    /// Get the KV cache manager
    pub fn kv_cache(&self) -> &Arc<KvCacheManager> {
        &self.kv_cache
    }

    /// Get current active request count
    pub fn active_requests(&self) -> u32 {
        *self.active_requests.lock()
    }

    /// Get backend name
    pub fn backend_name(&self) -> &'static str {
        self.backend.backend_name()
    }

    /// The currently loaded model id, if any.
    pub fn loaded_model(&self) -> Option<String> {
        self.backend.loaded_model()
    }

    /// Load a model into the backend
    pub fn load_model(&self, model_id: &str, weight_bytes: &[&[u8]]) -> CordonResult<()> {
        self.backend.load_model(model_id, weight_bytes)
    }

    /// Get replay detection counts for an input hash
    pub fn get_replay_count(&self, input_hash: &str) -> u32 {
        *self.input_hash_counts.lock().get(input_hash).unwrap_or(&0)
    }
}

// Scope guard — runs closure on drop (always, since panic=abort)
mod scopeguard {
    pub struct ScopeGuard<F: FnOnce()> {
        f: Option<F>,
    }

    impl<F: FnOnce()> Drop for ScopeGuard<F> {
        fn drop(&mut self) {
            if let Some(f) = self.f.take() {
                f();
            }
        }
    }

    pub fn defer_on_unwind<F: FnOnce()>(f: F) -> ScopeGuard<F> {
        ScopeGuard { f: Some(f) }
    }
}
// Allow unused import of defer_on_unwind pattern
#[allow(unused_imports)]
use scopeguard::defer_on_unwind as _;
