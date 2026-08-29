//! Inference engine (Layer 4).
//!
//! The engine owns concurrency admission, per-session KV-cache bookkeeping, and
//! request timeouts. The model runtime itself sits behind [`InferenceBackend`],
//! which has two implementations in `crate::runtime`: a supervised llama.cpp
//! server and a deterministic backend used by the test suite.
//!
//! Both a unary and a streaming entry point are provided. The streaming path
//! yields chunks as the runtime produces them; the caller is responsible for
//! passing those chunks through the output filter before releasing them.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::Stream;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::error::{CordonError, CordonResult};

/// Upper bound on distinct input hashes tracked for replay detection. Once
/// reached the map is cleared rather than grown, keeping memory constant under
/// adversarial input at the cost of forgetting old hashes.
const MAX_TRACKED_INPUT_HASHES: usize = 100_000;

/// A single message in the conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Role: `system`, `user`, or `assistant`.
    pub role: String,
    /// Message content.
    pub content: String,
}

/// Sampling and generation parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceParams {
    /// Maximum tokens to generate.
    pub max_tokens: u32,
    /// Sampling temperature (0.0 = greedy).
    pub temperature: f32,
    /// Top-p nucleus sampling.
    pub top_p: f32,
    /// Top-k sampling (0 = disabled).
    pub top_k: u32,
    /// Stop sequences.
    pub stop: Vec<String>,
    /// Repetition penalty.
    pub repetition_penalty: f32,
}

impl Default for InferenceParams {
    fn default() -> Self {
        Self {
            max_tokens: 512,
            temperature: 0.7,
            top_p: 0.9,
            top_k: 0,
            stop: vec![],
            repetition_penalty: 1.0,
        }
    }
}

/// A complete inference request.
#[derive(Debug)]
pub struct InferenceRequest {
    /// Unique request ID.
    pub request_id: Uuid,
    /// Authenticated client ID.
    pub client_id: String,
    /// Optional session ID for multi-turn conversations.
    pub session_id: Option<Uuid>,
    /// Model bundle ID.
    pub model_id: String,
    /// Conversation messages.
    pub messages: Vec<Message>,
    /// Sampling parameters.
    pub params: InferenceParams,
    /// Wall-clock deadline for the runtime call.
    pub timeout: Duration,
    /// SHA-256 of the input (recorded in the audit log in place of plaintext).
    pub input_hash: String,
    /// Request creation time.
    pub created_at: DateTime<Utc>,
}

impl Drop for InferenceRequest {
    fn drop(&mut self) {
        for msg in &mut self.messages {
            msg.content.zeroize();
        }
    }
}

/// Why generation stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    /// Natural stop token or stop sequence.
    #[default]
    Stop,
    /// Token budget exhausted.
    Length,
    /// Output filter blocked the response.
    ContentFilter,
    /// The request deadline elapsed.
    Timeout,
    /// The runtime reported an error.
    Error,
}

impl FinishReason {
    /// Wire representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            FinishReason::Stop => "stop",
            FinishReason::Length => "length",
            FinishReason::ContentFilter => "content_filter",
            FinishReason::Timeout => "timeout",
            FinishReason::Error => "error",
        }
    }

    /// Parse an OpenAI-style `finish_reason`.
    pub fn from_wire(s: &str) -> Self {
        match s {
            "length" => FinishReason::Length,
            "content_filter" => FinishReason::ContentFilter,
            "timeout" => FinishReason::Timeout,
            "error" => FinishReason::Error,
            _ => FinishReason::Stop,
        }
    }
}

/// Token accounting for one generation.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokenUsage {
    /// Tokens consumed by the prompt.
    pub prompt_tokens: u32,
    /// Tokens produced by the model.
    pub completion_tokens: u32,
}

/// Raw runtime output, before the output filter runs.
#[derive(Debug)]
pub struct RawInferenceOutput {
    /// Generated text.
    pub text: String,
    /// Token accounting.
    pub usage: TokenUsage,
    /// Why generation stopped.
    pub finish_reason: FinishReason,
    /// Time spent inside the runtime.
    pub latency_ms: u64,
}

impl RawInferenceOutput {
    /// Prompt tokens (convenience accessor).
    pub fn prompt_tokens(&self) -> u32 {
        self.usage.prompt_tokens
    }
    /// Completion tokens (convenience accessor).
    pub fn completion_tokens(&self) -> u32 {
        self.usage.completion_tokens
    }
}

impl Drop for RawInferenceOutput {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}

/// One increment of a streaming generation.
#[derive(Debug, Clone)]
pub enum StreamChunk {
    /// Newly generated text.
    Delta(String),
    /// Terminal event carrying final accounting.
    Done {
        /// Why generation stopped.
        finish_reason: FinishReason,
        /// Token accounting.
        usage: TokenUsage,
    },
}

/// A backend's streaming output.
pub type TokenStream = Pin<Box<dyn Stream<Item = CordonResult<StreamChunk>> + Send>>;

/// A model runtime Cordon can dispatch to.
///
/// Implementations must be cancel-safe: dropping the future returned by
/// [`InferenceBackend::infer`] or the stream from
/// [`InferenceBackend::infer_stream`] must abandon the underlying work without
/// leaking a connection or a child process.
#[async_trait]
pub trait InferenceBackend: Send + Sync {
    /// Run a generation to completion.
    async fn infer(&self, request: &InferenceRequest) -> CordonResult<RawInferenceOutput>;

    /// Run a generation, yielding chunks as the runtime produces them.
    ///
    /// The default implementation falls back to [`InferenceBackend::infer`] and
    /// emits the whole response as one chunk, so a backend without a native
    /// streaming API still satisfies the contract.
    async fn infer_stream(&self, request: &InferenceRequest) -> CordonResult<TokenStream> {
        let output = self.infer(request).await?;
        let text = output.text.clone();
        let usage = output.usage;
        let finish_reason = output.finish_reason;
        Ok(Box::pin(futures::stream::iter(vec![
            Ok(StreamChunk::Delta(text)),
            Ok(StreamChunk::Done {
                finish_reason,
                usage,
            }),
        ])))
    }

    /// Short name reported in health output.
    fn backend_name(&self) -> &'static str;

    /// Model identifier the runtime currently has resident, if any.
    async fn loaded_model(&self) -> Option<String>;

    /// Whether the runtime is reachable and ready to serve.
    async fn is_ready(&self) -> bool;

    /// Release runtime resources. Called during teardown.
    async fn shutdown(&self) -> CordonResult<()> {
        Ok(())
    }
}

/// Per-client session state.
struct ClientSession {
    client_id: String,
    created_at: DateTime<Utc>,
    last_active: DateTime<Utc>,
    turn_count: u32,
    /// Session-bound secret scratch, standing in for the runtime's KV-cache
    /// pages. Explicitly zeroized when the session ends and again on drop.
    scratch: cordon_crypto::zeroize_ext::SecretVec,
}

/// Metadata describing an active session.
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    /// Session identifier.
    pub session_id: Uuid,
    /// Owning client.
    pub client_id: String,
    /// When the session was opened.
    pub created_at: DateTime<Utc>,
    /// Most recent activity.
    pub last_active: DateTime<Utc>,
    /// Number of turns served.
    pub turn_count: u32,
}

/// Session and KV-cache isolation manager.
pub struct KvCacheManager {
    sessions: Arc<RwLock<HashMap<Uuid, ClientSession>>>,
    zero_on_end: bool,
    max_sessions: usize,
}

impl KvCacheManager {
    /// Create a manager holding at most `max_sessions` concurrent sessions.
    pub fn new(zero_on_end: bool, max_sessions: usize) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            zero_on_end,
            max_sessions,
        }
    }

    /// Open a new session, or resume one the client already owns.
    ///
    /// Resuming a session that belongs to a different client is refused before
    /// any session state is touched, so a caller cannot probe for, or disturb,
    /// another client's session by guessing its identifier.
    pub fn open_session(&self, client_id: &str, session_id: Option<Uuid>) -> CordonResult<Uuid> {
        let mut sessions = self.sessions.write();

        if let Some(sid) = session_id {
            return match sessions.get_mut(&sid) {
                Some(existing) if existing.client_id == client_id => {
                    existing.last_active = Utc::now();
                    existing.turn_count = existing.turn_count.saturating_add(1);
                    Ok(sid)
                }
                Some(_) => Err(CordonError::AuthFailed(
                    "session does not belong to this client".into(),
                )),
                None => {
                    // An unknown identifier is treated as a request to open that
                    // session for the caller, which is safe: it is not currently
                    // owned by anyone.
                    Self::insert_session(&mut sessions, sid, client_id, self.max_sessions)?;
                    Ok(sid)
                }
            };
        }

        let sid = Uuid::new_v4();
        Self::insert_session(&mut sessions, sid, client_id, self.max_sessions)?;
        Ok(sid)
    }

    fn insert_session(
        sessions: &mut HashMap<Uuid, ClientSession>,
        sid: Uuid,
        client_id: &str,
        max_sessions: usize,
    ) -> CordonResult<()> {
        if sessions.len() >= max_sessions {
            return Err(CordonError::Internal(format!(
                "session table is full ({} sessions)",
                max_sessions
            )));
        }
        let mut scratch = cordon_crypto::zeroize_ext::SecretVec::with_capacity(16);
        scratch.extend_from_slice(sid.as_bytes());
        let now = Utc::now();
        sessions.insert(
            sid,
            ClientSession {
                client_id: client_id.to_string(),
                created_at: now,
                last_active: now,
                turn_count: 1,
                scratch,
            },
        );
        Ok(())
    }

    /// Whether `client_id` owns `session_id`.
    pub fn validate_session_owner(&self, session_id: Uuid, client_id: &str) -> bool {
        self.sessions
            .read()
            .get(&session_id)
            .map(|s| s.client_id == client_id)
            .unwrap_or(false)
    }

    /// End a session, zeroizing its scratch before the entry is dropped.
    pub fn end_session(&self, session_id: Uuid) {
        if let Some(mut session) = self.sessions.write().remove(&session_id) {
            session.scratch.zero_now();
            tracing::debug!(%session_id, "Session ended, KV scratch zeroized");
        }
    }

    /// Drop sessions idle for longer than `max_idle_seconds`, zeroizing each.
    pub fn cleanup_expired(&self, max_idle_seconds: i64) -> usize {
        let cutoff = Utc::now() - chrono::Duration::seconds(max_idle_seconds);
        let mut sessions = self.sessions.write();
        let expired: Vec<Uuid> = sessions
            .iter()
            .filter(|(_, s)| s.last_active <= cutoff)
            .map(|(id, _)| *id)
            .collect();
        for id in &expired {
            if let Some(mut s) = sessions.remove(id) {
                s.scratch.zero_now();
            }
        }
        expired.len()
    }

    /// Whether sessions are zeroized when they end.
    pub fn zero_on_end(&self) -> bool {
        self.zero_on_end
    }

    /// Number of live sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.read().len()
    }

    /// Live sessions belonging to a client.
    pub fn active_sessions_for_client(&self, client_id: &str) -> usize {
        self.sessions
            .read()
            .values()
            .filter(|s| s.client_id == client_id)
            .count()
    }

    /// Snapshot of a session's metadata.
    pub fn session_info(&self, session_id: Uuid) -> Option<SessionInfo> {
        self.sessions.read().get(&session_id).map(|s| SessionInfo {
            session_id,
            client_id: s.client_id.clone(),
            created_at: s.created_at,
            last_active: s.last_active,
            turn_count: s.turn_count,
        })
    }
}

/// Admission control, session tracking, and timeout enforcement around a
/// [`InferenceBackend`].
pub struct InferenceEngine {
    backend: Arc<dyn InferenceBackend>,
    kv_cache: Arc<KvCacheManager>,
    /// Concurrency admission. A permit is held for the duration of a
    /// generation, so a slow runtime applies backpressure rather than queueing
    /// unbounded work.
    slots: Arc<Semaphore>,
    max_concurrent: u32,
    input_hash_counts: Arc<RwLock<HashMap<String, u32>>>,
}

/// A held concurrency slot plus the session it belongs to. Dropping this
/// releases the slot and, for single-shot requests, tears the session down.
pub struct InferenceLease {
    _permit: OwnedSemaphorePermit,
    kv_cache: Arc<KvCacheManager>,
    session_id: Uuid,
    end_on_drop: bool,
}

impl InferenceLease {
    /// The session this lease is bound to.
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }
}

impl Drop for InferenceLease {
    fn drop(&mut self) {
        if self.end_on_drop {
            self.kv_cache.end_session(self.session_id);
        }
    }
}

impl InferenceEngine {
    /// Create an engine over `backend`.
    pub fn new(
        backend: Arc<dyn InferenceBackend>,
        max_concurrent: u32,
        zero_kv_on_session_end: bool,
        max_sessions: usize,
    ) -> Self {
        let max_concurrent = max_concurrent.max(1);
        Self {
            backend,
            kv_cache: Arc::new(KvCacheManager::new(zero_kv_on_session_end, max_sessions)),
            slots: Arc::new(Semaphore::new(max_concurrent as usize)),
            max_concurrent,
            input_hash_counts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Acquire a concurrency slot and open the request's session.
    ///
    /// Returns [`CordonError::Overloaded`] immediately when every slot is busy
    /// rather than queueing, so callers see backpressure instead of unbounded
    /// latency.
    pub fn admit(&self, request: &InferenceRequest) -> CordonResult<InferenceLease> {
        let permit =
            self.slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| CordonError::Overloaded {
                    max_concurrent: self.max_concurrent,
                })?;

        let session_id = self
            .kv_cache
            .open_session(&request.client_id, request.session_id)?;

        self.record_input_hash(&request.input_hash);

        Ok(InferenceLease {
            _permit: permit,
            kv_cache: self.kv_cache.clone(),
            session_id,
            // A request that did not name a session gets an ephemeral one, torn
            // down as soon as the generation finishes.
            end_on_drop: request.session_id.is_none() && self.kv_cache.zero_on_end(),
        })
    }

    /// Run a generation to completion under the request's deadline.
    pub async fn run(&self, request: &InferenceRequest) -> CordonResult<RawInferenceOutput> {
        match tokio::time::timeout(request.timeout, self.backend.infer(request)).await {
            Ok(result) => result,
            Err(_) => Err(CordonError::Timeout {
                seconds: request.timeout.as_secs(),
            }),
        }
    }

    /// Begin a streaming generation. The deadline covers stream establishment;
    /// the caller is responsible for bounding the total stream duration.
    pub async fn run_stream(&self, request: &InferenceRequest) -> CordonResult<TokenStream> {
        match tokio::time::timeout(request.timeout, self.backend.infer_stream(request)).await {
            Ok(result) => result,
            Err(_) => Err(CordonError::Timeout {
                seconds: request.timeout.as_secs(),
            }),
        }
    }

    fn record_input_hash(&self, input_hash: &str) {
        let mut counts = self.input_hash_counts.write();
        if counts.len() >= MAX_TRACKED_INPUT_HASHES && !counts.contains_key(input_hash) {
            tracing::debug!("Replay-detection table full — resetting");
            counts.clear();
        }
        *counts.entry(input_hash.to_string()).or_insert(0) += 1;
    }

    /// The session and KV-cache manager.
    pub fn kv_cache(&self) -> &Arc<KvCacheManager> {
        &self.kv_cache
    }

    /// Generations currently in flight.
    pub fn active_requests(&self) -> u32 {
        self.max_concurrent
            .saturating_sub(self.slots.available_permits() as u32)
    }

    /// Configured concurrency ceiling.
    pub fn max_concurrent(&self) -> u32 {
        self.max_concurrent
    }

    /// Backend name for health output.
    pub fn backend_name(&self) -> &'static str {
        self.backend.backend_name()
    }

    /// Model currently resident in the runtime.
    pub async fn loaded_model(&self) -> Option<String> {
        self.backend.loaded_model().await
    }

    /// Whether the runtime is reachable.
    pub async fn is_ready(&self) -> bool {
        self.backend.is_ready().await
    }

    /// Shut the runtime down.
    pub async fn shutdown(&self) -> CordonResult<()> {
        self.backend.shutdown().await
    }

    /// How many times this exact input hash has been seen.
    pub fn replay_count(&self, input_hash: &str) -> u32 {
        *self.input_hash_counts.read().get(input_hash).unwrap_or(&0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_cannot_be_hijacked_by_another_client() {
        let kv = KvCacheManager::new(true, 128);
        let sid = kv.open_session("alice", None).unwrap();
        assert!(kv.validate_session_owner(sid, "alice"));

        let err = kv.open_session("mallory", Some(sid)).unwrap_err();
        assert!(matches!(err, CordonError::AuthFailed(_)));

        // Alice's session is untouched — turn count did not advance for Mallory.
        let info = kv.session_info(sid).unwrap();
        assert_eq!(info.client_id, "alice");
        assert_eq!(info.turn_count, 1);
    }

    #[test]
    fn resuming_own_session_advances_turn_count() {
        let kv = KvCacheManager::new(true, 128);
        let sid = kv.open_session("alice", None).unwrap();
        kv.open_session("alice", Some(sid)).unwrap();
        assert_eq!(kv.session_info(sid).unwrap().turn_count, 2);
    }

    #[test]
    fn session_table_is_bounded() {
        let kv = KvCacheManager::new(true, 2);
        kv.open_session("a", None).unwrap();
        kv.open_session("b", None).unwrap();
        assert!(kv.open_session("c", None).is_err());
    }

    #[test]
    fn expired_sessions_are_reclaimed() {
        let kv = KvCacheManager::new(true, 128);
        kv.open_session("a", None).unwrap();
        assert_eq!(kv.session_count(), 1);
        // A cutoff of -1 seconds puts every session in the past.
        assert_eq!(kv.cleanup_expired(-1), 1);
        assert_eq!(kv.session_count(), 0);
    }

    #[test]
    fn replay_table_stays_bounded() {
        let engine_counts: HashMap<String, u32> = HashMap::new();
        let counts = Arc::new(RwLock::new(engine_counts));
        // Mirror the engine's bounding rule directly.
        for i in 0..(MAX_TRACKED_INPUT_HASHES + 10) {
            let mut c = counts.write();
            if c.len() >= MAX_TRACKED_INPUT_HASHES {
                c.clear();
            }
            *c.entry(format!("hash-{}", i)).or_insert(0) += 1;
        }
        assert!(counts.read().len() <= MAX_TRACKED_INPUT_HASHES);
    }
}
