//! API endpoint handlers.
//!
//! Every handler that touches node state resolves an authenticated client
//! first. Under mTLS that means a verified certificate; under `--no-tls` it
//! means a header-derived development identity, which is accepted only because
//! the deployment explicitly disabled transport security.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use chrono::Utc;
use uuid::Uuid;

use cordon_core::{
    identity::ClientIdentity,
    inference::{FinishReason, InferenceParams, Message},
    node::CordonNode,
    output_filter::StreamingFilter,
    CordonError,
};

use crate::{
    error::{map_err, ApiErrorResponse},
    middleware::VerifiedIdentity,
    types::*,
};

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    /// The running node.
    pub node: Arc<CordonNode>,
    /// Cached audit-chain verdict, refreshed off the request path.
    pub chain_health: Arc<ChainHealth>,
}

/// A periodically refreshed audit-chain verdict.
///
/// Verifying the chain is linear in log size. Running it inline on every health
/// check turned a cheap endpoint into an unauthenticated way to make the node do
/// unbounded I/O, so the verdict is computed on a timer and read from here.
pub struct ChainHealth {
    inner: parking_lot::RwLock<Option<(bool, chrono::DateTime<Utc>)>>,
}

impl ChainHealth {
    /// Create an unpopulated verdict cache.
    pub fn new() -> Self {
        Self {
            inner: parking_lot::RwLock::new(None),
        }
    }

    /// The most recent verdict and when it was taken.
    pub fn get(&self) -> Option<(bool, chrono::DateTime<Utc>)> {
        *self.inner.read()
    }

    /// Record a fresh verdict.
    pub fn set(&self, valid: bool) {
        *self.inner.write() = Some((valid, Utc::now()));
    }

    /// Re-verify the chain on a timer, off the request path.
    pub fn spawn_refresher(self: Arc<Self>, node: Arc<CordonNode>, every: Duration) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(every);
            loop {
                ticker.tick().await;
                let node = node.clone();
                let verdict = tokio::task::spawn_blocking(move || node.audit_chain_valid()).await;
                match verdict {
                    Ok(valid) => {
                        if !valid {
                            tracing::error!(
                                "AUDIT CHAIN VERIFICATION FAILED — the log has been \
                                 altered or truncated"
                            );
                        }
                        self.set(valid);
                    }
                    Err(e) => tracing::error!("audit chain verification task failed: {}", e),
                }
            }
        });
    }
}

impl Default for ChainHealth {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve the authenticated client for a request.
///
/// When the deployment requires mTLS, only a certificate-derived identity is
/// accepted. A header-derived identity is refused, because accepting one would
/// make the whole mTLS configuration decorative.
fn authenticated_client(
    node: &CordonNode,
    vid: VerifiedIdentity,
) -> Result<ClientIdentity, ApiErrorResponse> {
    if node.config.requires_mtls() && !vid.is_verified() {
        return Err(map_err(CordonError::AuthFailed(
            "mTLS is required but no verified client certificate was presented".into(),
        )));
    }
    Ok(vid.identity)
}

// ─── Health ──────────────────────────────────────────────────────────────────

/// `GET /v1/health` — liveness. Unauthenticated by design; it reveals only that
/// a Cordon node is listening and whether it can serve.
pub async fn health_basic(State(state): State<AppState>) -> impl IntoResponse {
    let node_state = state.node.state.read();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": node_state.status.to_string(),
            "cordon_version": env!("CARGO_PKG_VERSION"),
            "serving": node_state.can_serve(),
        })),
    )
}

/// `GET /v1/health/detailed` — full posture. Requires an authenticated client:
/// it discloses key material identifiers, measurements, and traffic statistics.
pub async fn health_detailed(
    State(state): State<AppState>,
    Extension(vid): Extension<VerifiedIdentity>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    let _client = authenticated_client(&state.node, vid)?;
    let node = &state.node;

    let (chain_valid, chain_checked_at) = match state.chain_health.get() {
        Some((valid, at)) => (Some(valid), Some(at)),
        None => (None, None),
    };

    let node_state = node.state.read();

    let response = DetailedHealthResponse {
        status: node_state.status.to_string(),
        timestamp: Utc::now(),
        enclave: EnclaveHealth {
            status: format!("{:?}", node_state.enclave_state).to_lowercase(),
            tee_type: node.config.tee.preferred.to_string(),
            measurement_source: node.attestation.measurement_source().to_string(),
            hardware_measurements: node.attestation.has_hardware_measurements(),
            mrenclave: node.attestation.mrenclave(),
            last_attested: node.attestation.last_attestation_time(),
            verified_clients: node.attestation.verified_client_count(),
            key_provenance: node.key_provenance().as_str().to_string(),
        },
        boot_chain: BootChainStatus {
            tpm_required: node.config.boot.tpm_required,
            tpm_version: node.config.boot.tpm_version.clone(),
            secure_boot: node.config.boot.secure_boot,
            dm_verity: node.config.boot.dm_verity,
            last_pcr_verification: node.attestation.last_attestation_time(),
        },
        inference: InferenceHealth {
            runtime: node.inference.backend_name().to_string(),
            active_requests: node.inference.active_requests(),
            max_concurrent: node.inference.max_concurrent(),
            active_sessions: node.inference.kv_cache().session_count(),
            latency_ms_p50: node_state.stats.latency_ms_p50,
            latency_ms_p99: node_state.stats.latency_ms_p99,
        },
        audit: AuditHealth {
            entries_total: node.audit.sequence(),
            last_entry_hash: node.audit.tail_hash(),
            chain_valid,
            chain_checked_at,
        },
        integrity: IntegrityHealth {
            last_weight_check: node.integrity_monitor.last_check_time(),
            weight_check_result: if node.integrity_monitor.last_check_passed() {
                "valid".to_string()
            } else {
                "failed".to_string()
            },
            next_scheduled_check: node.integrity_monitor.last_check_time().map(|t| {
                t + chrono::Duration::minutes(
                    node.config.model_store.integrity_check_interval_minutes as i64,
                )
            }),
            tamper_detected: node.integrity_monitor.is_tamper_detected(),
        },
        security: SecurityHealth {
            enrolled_clients: node.identity.client_count(),
            suspended_clients: node.identity.suspended_count(),
            quarantine_mode: matches!(
                node_state.status,
                cordon_core::state::NodeStatus::Quarantine
            ),
        },
    };

    Ok((StatusCode::OK, Json(response)))
}

/// `GET /v1/health/runtime` — recent model-runtime output, for diagnosing a
/// runtime that will not start or has begun failing.
pub async fn health_runtime(
    State(state): State<AppState>,
    Extension(vid): Extension<VerifiedIdentity>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    let _client = authenticated_client(&state.node, vid)?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "backend": state.node.inference.backend_name(),
            "ready": state.node.inference.is_ready().await,
            "recent_output": state.node.runtime_logs(50),
        })),
    ))
}

// ─── Inference ───────────────────────────────────────────────────────────────

fn to_core_messages(messages: &[ApiMessage]) -> Vec<Message> {
    messages
        .iter()
        .map(|m| Message {
            role: m.role.clone(),
            content: m.content.clone(),
        })
        .collect()
}

fn to_core_params(params: &ApiInferenceParams) -> InferenceParams {
    InferenceParams {
        max_tokens: params.max_tokens,
        temperature: params.temperature,
        top_p: params.top_p,
        top_k: params.top_k,
        stop: params.stop.clone(),
        repetition_penalty: params.repetition_penalty,
    }
}

/// Clamp the caller's timeout to the configured ceiling so a request cannot pin
/// a concurrency slot indefinitely.
fn resolve_timeout(node: &CordonNode, requested: Option<u64>) -> Duration {
    let configured = node.config.inference.default_timeout_seconds;
    let seconds = requested.unwrap_or(configured).clamp(1, configured.max(1));
    Duration::from_secs(seconds)
}

/// `POST /v1/inference` — run a generation and return the signed result.
pub async fn inference(
    State(state): State<AppState>,
    Extension(vid): Extension<VerifiedIdentity>,
    Json(req): Json<InferenceRequest>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    let client = authenticated_client(&state.node, vid)?;

    let outcome = state
        .node
        .process_inference(
            &client,
            &req.model_id,
            to_core_messages(&req.messages),
            to_core_params(&req.inference_params),
            req.session_id,
            resolve_timeout(&state.node, req.timeout_seconds),
        )
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

    Ok((
        StatusCode::OK,
        Json(InferenceResponse {
            request_id: outcome.request_id,
            session_id: outcome.session_id,
            model_id: outcome.model_id.clone(),
            client_id: outcome.client_id,
            timestamp,
            usage: TokenUsage {
                prompt_tokens: outcome.prompt_tokens,
                completion_tokens: outcome.completion_tokens,
                total_tokens: outcome.prompt_tokens + outcome.completion_tokens,
            },
            choices: vec![Choice {
                index: 0,
                message: ApiMessage {
                    role: "assistant".to_string(),
                    content: outcome.output,
                },
                finish_reason: outcome.finish_reason.as_str().to_string(),
            }],
            content_policy: ContentPolicyStatus {
                triggered: outcome.content_policy_triggered,
                rules_matched: outcome.policy_rules_matched,
            },
            covert_channel: CovertChannelStatus {
                anomaly_detected: outcome.covert_channel_score
                    > state
                        .node
                        .config
                        .sustained_attack
                        .covert_channel_score_threshold,
                anomaly_score: outcome.covert_channel_score,
            },
            signature,
            enclave_info: EnclaveInfo {
                tee_type: state.node.config.tee.preferred.to_string(),
                measurement_source: state.node.attestation.measurement_source().to_string(),
                cordon_version: env!("CARGO_PKG_VERSION").to_string(),
                mrenclave: outcome.mrenclave,
            },
        }),
    ))
}

/// The bytes signed for an inference response.
///
/// The layout is fixed and documented so a client can reconstruct it from the
/// response body alone:
///
/// ```text
/// CORDON_RESPONSE_v1|{request_id}|{output_hash}|{model_id}|{timestamp_ms}|{mrenclave}
/// ```
///
/// `timestamp_ms` is the response `timestamp` as Unix epoch milliseconds, which
/// avoids any RFC 3339 formatting ambiguity.
fn response_signing_payload(
    request_id: Uuid,
    output_hash: &str,
    model_id: &str,
    timestamp: chrono::DateTime<Utc>,
    mrenclave: &str,
) -> String {
    format!(
        "CORDON_RESPONSE_v1|{}|{}|{}|{}|{}",
        request_id,
        output_hash,
        model_id,
        timestamp.timestamp_millis(),
        mrenclave
    )
}

fn sign_response(
    node: &CordonNode,
    request_id: Uuid,
    output_hash: &str,
    model_id: &str,
    timestamp: chrono::DateTime<Utc>,
    mrenclave: &str,
) -> ResponseSignature {
    let payload = response_signing_payload(request_id, output_hash, model_id, timestamp, mrenclave);
    ResponseSignature {
        enclave_key_id: node.enclave_key_id(),
        algorithm: "ed25519".to_string(),
        value: node.sign_enclave(payload.as_bytes()).to_hex(),
        key_provenance: node.key_provenance().as_str().to_string(),
        signed_fields: vec![
            "request_id".into(),
            "output_hash".into(),
            "model_id".into(),
            "timestamp_ms".into(),
            "mrenclave".into(),
        ],
    }
}

/// `POST /v1/inference/stream` — token-by-token generation over server-sent
/// events.
///
/// The full admission pipeline runs before the first byte is sent, and every
/// chunk passes through [`StreamingFilter`] before release, so no text the
/// policy would remove is ever transmitted. A blocking rule that fires mid-
/// generation terminates the stream with an `error` event.
///
/// Events:
///
/// ```text
/// event: delta  data: {"delta": "<text>"}
/// event: done   data: {request_id, finish_reason, usage, output_hash, signature, …}
/// event: error  data: {error, message}
/// ```
pub async fn inference_stream(
    State(state): State<AppState>,
    Extension(vid): Extension<VerifiedIdentity>,
    Json(req): Json<InferenceRequest>,
) -> Result<
    axum::response::Sse<
        impl futures::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>,
    >,
    ApiErrorResponse,
> {
    use axum::response::sse::{Event, KeepAlive};
    use futures::StreamExt;

    let client = authenticated_client(&state.node, vid)?;
    let node = state.node.clone();

    let messages = to_core_messages(&req.messages);
    let params = to_core_params(&req.inference_params);
    let timeout = resolve_timeout(&node, req.timeout_seconds);

    // Admission, auditing, and stream establishment all happen here. Any refusal
    // surfaces as an HTTP error before a single event is emitted.
    let mut session = node
        .begin_streaming_inference(
            &client,
            &req.model_id,
            messages,
            params,
            req.session_id,
            timeout,
        )
        .await
        .map_err(map_err)?;

    // The stream is `Send` but not `Sync`, so the metadata is cloned out before
    // the consuming task takes ownership of the session.
    let meta = session.meta.clone();

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, std::convert::Infallible>>(64);

    tokio::spawn(async move {
        let mut filter = StreamingFilter::new(node.output_filter.clone());
        let mut usage = cordon_core::inference::TokenUsage::default();
        let mut finish_reason = FinishReason::Stop;
        let mut failed: Option<CordonError> = None;

        while let Some(chunk) = session.stream.next().await {
            match chunk {
                Ok(cordon_core::inference::StreamChunk::Delta(delta)) => {
                    match filter.push(&delta) {
                        Ok(released) if released.is_empty() => {}
                        Ok(released) => {
                            let event = Event::default()
                                .event("delta")
                                .data(serde_json::json!({ "delta": released }).to_string());
                            // A closed receiver means the client hung up; stop
                            // generating rather than filling a dead channel.
                            if tx.send(Ok(event)).await.is_err() {
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
                    let event = Event::default()
                        .event("delta")
                        .data(serde_json::json!({ "delta": tail }).to_string());
                    if tx.send(Ok(event)).await.is_err() {
                        return;
                    }
                }
                Ok(_) => {}
                Err(e) => failed = Some(e),
            }
        }

        // Whatever happened, the node records the outcome and closes the stream
        // with a terminal event, so a client never has to infer completion from
        // a silent socket.
        let terminal = match failed {
            Some(error) => {
                let response = crate::error::ApiErrorResponse::from(error);
                node.finish_streaming_inference(&meta, None, usage, FinishReason::ContentFilter);
                Event::default().event("error").data(
                    serde_json::json!({
                        "error": response.body.error,
                        "message": response.body.message,
                    })
                    .to_string(),
                )
            }
            None => {
                let text = filter.released_text().to_string();
                let record =
                    node.finish_streaming_inference(&meta, Some(&text), usage, finish_reason);
                let timestamp = Utc::now();
                let signature = sign_response(
                    &node,
                    meta.request_id,
                    &record.output_hash,
                    &meta.model_id,
                    timestamp,
                    &meta.mrenclave,
                );
                Event::default().event("done").data(
                    serde_json::json!({
                        "request_id": meta.request_id,
                        "session_id": meta.session_id,
                        "model_id": meta.model_id,
                        "timestamp": timestamp,
                        "finish_reason": finish_reason.as_str(),
                        "usage": {
                            "prompt_tokens": usage.prompt_tokens,
                            "completion_tokens": usage.completion_tokens,
                            "total_tokens": usage.prompt_tokens + usage.completion_tokens,
                        },
                        "output_hash": record.output_hash,
                        "mrenclave": meta.mrenclave,
                        "content_policy": {
                            "triggered": record.content_policy_triggered,
                            "rules_matched": record.policy_rules_matched,
                        },
                        "covert_channel": { "anomaly_score": record.covert_channel_score },
                        "signature": signature,
                    })
                    .to_string(),
                )
            }
        };

        let _ = tx.send(Ok(terminal)).await;
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    Ok(axum::response::Sse::new(stream).keep_alive(KeepAlive::default()))
}

// ─── Attestation ─────────────────────────────────────────────────────────────

/// Sign an attestation report's combined hash so a client can confirm the report
/// came from the node holding the enclave key rather than from an intermediary.
fn sign_attestation(
    node: &CordonNode,
    report: &cordon_crypto::attestation::AttestationReport,
) -> serde_json::Value {
    let payload = format!(
        "CORDON_ATTESTATION_v1|{}|{}",
        report.combined.combined_hash, report.client_nonce
    );
    serde_json::json!({
        "algorithm": "ed25519",
        "value": node.sign_enclave(payload.as_bytes()).to_hex(),
        "enclave_signing_key": node.enclave_verifying_key_hex(),
        "key_provenance": node.key_provenance().as_str(),
        "signed": "CORDON_ATTESTATION_v1|<combined_hash>|<nonce>",
    })
}

/// `GET /v1/attestation` — a signed report bound to a fresh nonce.
///
/// The nonce is generated here, so this report proves freshness only to the node
/// itself. A client wanting evidence for its own challenge should post its own
/// nonce to `/v1/attestation/verify`.
pub async fn get_attestation(
    State(state): State<AppState>,
    Extension(vid): Extension<VerifiedIdentity>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    let client = authenticated_client(&state.node, vid)?;
    let nonce = Uuid::new_v4().to_string();

    let report = state
        .node
        .attestation
        .generate_attestation(&nonce, &state.node.config.node_id)
        .map_err(map_err)?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "verified_for_this_client": state.node.attestation.is_verified_by(&client.client_id),
            "measurement_source": state.node.attestation.measurement_source().to_string(),
            "hardware_measurements": state.node.attestation.has_hardware_measurements(),
            "measurements_are_pinned": state.node.attestation.pinned_measurements().is_some(),
            "report": report,
            "signature": sign_attestation(&state.node, &report),
            "generated_at": Utc::now(),
        })),
    ))
}

/// `POST /v1/attestation/verify` — check a report against the measurements the
/// **operator** pinned, and record that this client has attested the node.
///
/// The caller supplies only a nonce. It deliberately cannot supply expected
/// measurements: a node that verifies against caller-supplied values can always
/// be made to verify, because any caller can read the node's own measurements
/// from `GET /v1/attestation` and hand them straight back. A node with nothing
/// pinned returns `verified: false` and says so.
pub async fn verify_attestation(
    State(state): State<AppState>,
    Extension(vid): Extension<VerifiedIdentity>,
    Json(req): Json<AttestationVerifyRequest>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    let client = authenticated_client(&state.node, vid)?;

    let report = state
        .node
        .attestation
        .generate_attestation(&req.nonce, &state.node.config.node_id)
        .map_err(map_err)?;

    let signature = sign_attestation(&state.node, &report);

    match state
        .node
        .attestation
        .verify_for_client(&report, &req.nonce, &client.client_id)
    {
        Ok(()) => Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "verified": true,
                "client_id": client.client_id,
                "mrenclave": report.combined.tee_quote.mrenclave,
                "combined_hash": report.combined.combined_hash,
                "measurement_source": report.combined.tee_quote.measurement_source,
                "signature": signature,
                "timestamp": report.combined.generated_at,
            })),
        )),
        Err(e) => {
            tracing::warn!(client_id = %client.client_id, "Attestation verification failed: {}", e);
            Ok((
                StatusCode::OK,
                Json(serde_json::json!({
                    "verified": false,
                    "reason": e.to_string(),
                    "client_id": client.client_id,
                    "mrenclave": report.combined.tee_quote.mrenclave,
                    "combined_hash": report.combined.combined_hash,
                    "measurement_source": report.combined.tee_quote.measurement_source,
                    "report": report,
                    "signature": signature,
                    "timestamp": report.combined.generated_at,
                })),
            ))
        }
    }
}

// ─── Models ──────────────────────────────────────────────────────────────────

/// `GET /v1/models` — the bundles this node can serve.
pub async fn list_models(
    State(state): State<AppState>,
    Extension(vid): Extension<VerifiedIdentity>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    let _client = authenticated_client(&state.node, vid)?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "bundles": state.node.model_store.list_bundles(),
            "runtime_model": state.node.inference.loaded_model().await,
        })),
    ))
}

/// `POST /v1/models` — register an encrypted bundle already present on the node.
///
/// The caller names a directory **inside the configured model store**, not an
/// arbitrary path: an admin signature authorizes the action, it does not
/// authorize reading files elsewhere on the host.
pub async fn provision_model(
    State(state): State<AppState>,
    Extension(vid): Extension<VerifiedIdentity>,
    Json(req): Json<ProvisionModelRequest>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    use cordon_audit::events::AdminAction;

    let _client = authenticated_client(&state.node, vid)?;
    state
        .node
        .authorize_admin(
            "provision-model",
            &req.bundle_directory,
            &req.admin_signature,
        )
        .map_err(map_err)?;

    // A single path component, so nothing can escape the store root.
    if req.bundle_directory.is_empty()
        || std::path::Path::new(&req.bundle_directory)
            .components()
            .count()
            != 1
    {
        return Err(map_err(CordonError::ValidationFailed(
            "bundle_directory must be a single directory name inside the model store".into(),
        )));
    }

    let manifest: cordon_core::model_store::BundleManifest = serde_json::from_value(req.manifest)
        .map_err(|e| {
        map_err(CordonError::ValidationFailed(format!(
            "invalid manifest: {}",
            e
        )))
    })?;
    let bundle_id = manifest.bundle_id.clone();
    let bundle_dir = state
        .node
        .model_store
        .store_dir()
        .join(&req.bundle_directory);

    state
        .node
        .model_store
        .register_bundle(manifest, bundle_dir, None)
        .map_err(map_err)?;

    // Establish an integrity verdict now, so the bundle is servable without
    // waiting for the next monitor cycle.
    let store = state.node.model_store.clone();
    let id = bundle_id.clone();
    let integrity_ok = tokio::task::spawn_blocking(move || store.run_integrity_check(&id))
        .await
        .map_err(|e| map_err(CordonError::Internal(e.to_string())))?
        .map_err(map_err)?;

    record_admin_event(&state.node, AdminAction::ModelUpdate, &bundle_id, true);

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": if integrity_ok { "registered" } else { "registered_but_failing_integrity" },
            "bundle_id": bundle_id,
            "integrity_ok": integrity_ok,
        })),
    ))
}

// ─── Audit ───────────────────────────────────────────────────────────────────

/// `GET /v1/audit/verify` — recompute and check the whole chain.
///
/// Linear in log size, so it runs on a blocking thread and requires an
/// authenticated caller.
pub async fn audit_verify(
    State(state): State<AppState>,
    Extension(vid): Extension<VerifiedIdentity>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    let _client = authenticated_client(&state.node, vid)?;

    let log_dir = state.node.config.audit.log_path.clone();
    let vk = state.node.audit.verifying_key();
    let deployment_id = state.node.config.deployment_id.clone();

    let result = tokio::task::spawn_blocking(move || {
        cordon_audit::verify::verify_log_chain(&log_dir, &vk, &deployment_id)
    })
    .await
    .map_err(|e| map_err(CordonError::Internal(e.to_string())))?
    .map_err(|e| map_err(CordonError::Internal(e.to_string())))?;

    state.chain_health.set(result.valid);

    Ok((
        StatusCode::OK,
        Json(AuditVerifyResponse {
            valid: result.valid,
            entries_verified: result.entries_verified,
            first_entry: result.first_entry,
            last_entry: result.last_entry,
            log_tail_hash: result.log_tail_hash,
            violations: result.violations,
            log_verifying_key: state.node.log_verifying_key_hex(),
            key_provenance: state.node.key_provenance().as_str().to_string(),
        }),
    ))
}

/// `GET /v1/audit/tail` — the most recent entries.
pub async fn audit_tail(
    State(state): State<AppState>,
    Extension(vid): Extension<VerifiedIdentity>,
    Query(query): Query<AuditTailQuery>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    let _client = authenticated_client(&state.node, vid)?;

    let n = query.n.unwrap_or(10).clamp(1, 1000) as usize;
    let audit = state.node.audit.clone();

    let entries = tokio::task::spawn_blocking(move || audit.read_tail_entries(n))
        .await
        .map_err(|e| map_err(CordonError::Internal(e.to_string())))?
        .map_err(|e| map_err(CordonError::Internal(e.to_string())))?;

    let rendered: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "log_id": e.log_id,
                "sequence": e.sequence,
                "timestamp": e.timestamp,
                "event_type": e.payload.event_type_str(),
                "entry_hash": e.entry_hash,
                "signature": e.signature,
            })
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "entries": rendered,
            "sequence": state.node.audit.sequence(),
            "tail_hash": state.node.audit.tail_hash(),
        })),
    ))
}

/// `GET /v1/audit/anchor` — the current chain head, signed.
///
/// Publishing this value externally is what turns the tamper-evident chain into
/// a tamper-*proof* one for everything before the anchor point: an operator who
/// later rewrites history cannot also rewrite an anchor a third party holds.
pub async fn audit_anchor(
    State(state): State<AppState>,
    Extension(vid): Extension<VerifiedIdentity>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    let _client = authenticated_client(&state.node, vid)?;

    let sequence = state.node.audit.sequence();
    let tail_hash = state.node.audit.tail_hash().unwrap_or_default();
    let timestamp = Utc::now();

    let payload = format!(
        "CORDON_ANCHOR_v1|{}|{}|{}|{}",
        state.node.config.deployment_id,
        sequence,
        tail_hash,
        timestamp.timestamp_millis()
    );

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "deployment_id": state.node.config.deployment_id,
            "sequence": sequence,
            "chain_head": tail_hash,
            "timestamp": timestamp,
            "signature": {
                "algorithm": "ed25519",
                "value": state.node.sign_enclave(payload.as_bytes()).to_hex(),
                "enclave_signing_key": state.node.enclave_verifying_key_hex(),
                "signed": "CORDON_ANCHOR_v1|<deployment_id>|<sequence>|<chain_head>|<timestamp_ms>",
            },
            "guidance": "Record this anchor with a third party. Any later rewrite of \
                         the log before this sequence number becomes detectable.",
        })),
    ))
}

// ─── Admin ───────────────────────────────────────────────────────────────────

fn record_admin_event(
    node: &CordonNode,
    action: cordon_audit::events::AdminAction,
    params: &str,
    ok: bool,
) {
    use cordon_audit::events::{ActionResult, AdminEvent, AuditEvent};
    use sha2::{Digest, Sha256};

    let _ = node.audit.append(AuditEvent::Admin(AdminEvent {
        client_id: "operator".to_string(),
        actor_key_id: "k_admin".to_string(),
        action,
        authorization_sig_valid: ok,
        parameters_hash: hex::encode(Sha256::digest(params.as_bytes())),
        result: if ok {
            ActionResult::Success
        } else {
            ActionResult::Rejected
        },
        failure_reason: None,
    }));
}

/// `POST /v1/admin/teardown` — zeroize key material and stop serving.
pub async fn admin_teardown(
    State(state): State<AppState>,
    Extension(vid): Extension<VerifiedIdentity>,
    Json(req): Json<AdminReasonRequest>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    use cordon_audit::events::AdminAction;

    let _client = authenticated_client(&state.node, vid)?;
    if let Err(e) = state
        .node
        .authorize_admin("teardown", &req.reason, &req.admin_signature)
    {
        record_admin_event(&state.node, AdminAction::Teardown, &req.reason, false);
        return Err(map_err(e));
    }

    tracing::warn!(reason = %req.reason, "Teardown authorized");
    record_admin_event(&state.node, AdminAction::Teardown, &req.reason, true);
    state.node.state.write().enter_zeroized();
    state.node.shutdown().await;

    Ok((
        StatusCode::OK,
        Json(AdminResponse::ok(
            "Teardown complete — the node is no longer serving",
        )),
    ))
}

/// `POST /v1/admin/recover` — leave quarantine and resume serving.
pub async fn admin_recover(
    State(state): State<AppState>,
    Extension(vid): Extension<VerifiedIdentity>,
    Json(req): Json<AdminReasonRequest>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    use cordon_audit::events::AdminAction;

    let _client = authenticated_client(&state.node, vid)?;
    if let Err(e) = state
        .node
        .authorize_admin("recover", &req.reason, &req.admin_signature)
    {
        record_admin_event(&state.node, AdminAction::Recovery, &req.reason, false);
        return Err(map_err(e));
    }

    // Recovery must not resume a node whose weights are still failing integrity;
    // that would turn the tamper response into an inconvenience.
    let store = state.node.model_store.clone();
    let bundles = store.bundle_ids();
    let all_ok = tokio::task::spawn_blocking(move || {
        bundles
            .iter()
            .all(|id| store.run_integrity_check(id).unwrap_or(false))
    })
    .await
    .map_err(|e| map_err(CordonError::Internal(e.to_string())))?;

    if !all_ok {
        record_admin_event(&state.node, AdminAction::Recovery, &req.reason, false);
        return Err(map_err(CordonError::ModelIntegrityViolation {
            bundle_id: "one or more bundles still fail integrity; recovery refused".into(),
        }));
    }

    tracing::info!(reason = %req.reason, "Recovery authorized");
    record_admin_event(&state.node, AdminAction::Recovery, &req.reason, true);
    state.node.integrity_monitor.reset_tamper();
    state.node.state.write().go_operational();

    Ok((
        StatusCode::OK,
        Json(AdminResponse::ok("Node recovered and serving")),
    ))
}

/// `POST /v1/admin/quarantine` — stop serving until an operator recovers.
pub async fn admin_quarantine(
    State(state): State<AppState>,
    Extension(vid): Extension<VerifiedIdentity>,
    Json(req): Json<AdminReasonRequest>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    use cordon_audit::events::AdminAction;

    let _client = authenticated_client(&state.node, vid)?;
    if let Err(e) = state
        .node
        .authorize_admin("quarantine", &req.reason, &req.admin_signature)
    {
        record_admin_event(&state.node, AdminAction::ConfigChange, &req.reason, false);
        return Err(map_err(e));
    }

    state.node.state.enter_quarantine();
    tracing::warn!(reason = %req.reason, "Node quarantined by operator");
    record_admin_event(&state.node, AdminAction::ConfigChange, &req.reason, true);

    Ok((
        StatusCode::OK,
        Json(AdminResponse::ok(
            "Node is in quarantine; inference is refused",
        )),
    ))
}

/// `POST /v1/admin/suspend-client` — suspend a client for a period.
pub async fn admin_suspend_client(
    State(state): State<AppState>,
    Extension(vid): Extension<VerifiedIdentity>,
    Json(req): Json<SuspendClientRequest>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    use cordon_audit::events::AdminAction;

    let _client = authenticated_client(&state.node, vid)?;
    let params = format!("{}:{}", req.client_id, req.duration_seconds);
    state
        .node
        .authorize_admin("suspend-client", &params, &req.admin_signature)
        .map_err(map_err)?;

    state
        .node
        .identity
        .suspend(&req.client_id, req.duration_seconds, &req.reason);
    state.node.rate_limiter.remove_client(&req.client_id);
    record_admin_event(&state.node, AdminAction::ConfigChange, &params, true);

    Ok((
        StatusCode::OK,
        Json(AdminResponse::ok(format!(
            "Client {} suspended for {} seconds",
            req.client_id, req.duration_seconds
        ))),
    ))
}

/// `GET /metrics` — Prometheus exposition. Restricted to loopback by middleware.
pub async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.node.metrics.render(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_payload_is_stable_and_documented() {
        let id = Uuid::nil();
        let timestamp = chrono::DateTime::from_timestamp_millis(1_700_000_000_000).unwrap();
        let payload = response_signing_payload(id, "abc123", "model-x", timestamp, "mre");
        assert_eq!(
            payload,
            "CORDON_RESPONSE_v1|00000000-0000-0000-0000-000000000000|abc123|model-x|1700000000000|mre"
        );
    }

    #[test]
    fn signing_payload_distinguishes_every_field() {
        let id = Uuid::nil();
        let t = chrono::DateTime::from_timestamp_millis(1_700_000_000_000).unwrap();
        let base = response_signing_payload(id, "hash", "model", t, "mre");
        assert_ne!(
            base,
            response_signing_payload(id, "hash2", "model", t, "mre")
        );
        assert_ne!(
            base,
            response_signing_payload(id, "hash", "model2", t, "mre")
        );
        assert_ne!(
            base,
            response_signing_payload(id, "hash", "model", t, "mre2")
        );
        assert_ne!(
            base,
            response_signing_payload(Uuid::from_u128(1), "hash", "model", t, "mre")
        );
    }
}
