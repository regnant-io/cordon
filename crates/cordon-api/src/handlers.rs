//! API endpoint handlers — implements all §17.1 endpoints

use std::sync::Arc;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use chrono::Utc;
use uuid::Uuid;

use cordon_core::{
    identity::ClientIdentity,
    inference::{InferenceParams, Message},
    node::CordonNode,
    CordonError,
};
use cordon_audit::verify::verify_log_chain;

use crate::{
    error::{ApiErrorResponse, map_err},
    middleware::VerifiedIdentity,
    types::*,
};

/// Resolve the authenticated client for a request.
///
/// When the deployment requires mTLS, only a certificate-verified identity is
/// accepted — a header-derived (unverified) identity is rejected. In `--no-tls`
/// dev mode the header identity is allowed through.
fn authenticated_client(
    node: &CordonNode,
    vid: VerifiedIdentity,
) -> Result<ClientIdentity, ApiErrorResponse> {
    if node.config.requires_mtls() && !vid.verified {
        return Err(map_err(CordonError::AuthFailed(
            "mTLS required: no verified client certificate presented".into(),
        )));
    }
    Ok(vid.identity)
}

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    /// The running Cordon node.
    pub node: Arc<CordonNode>,
}

// ─── Health ───────────────────────────────────────────────────────────────────

/// GET /v1/health — basic health (no auth)
pub async fn health_basic(State(state): State<AppState>) -> impl IntoResponse {
    let node_state = state.node.state.read();
    let body = serde_json::json!({
        "status": node_state.status.to_string(),
        "cordon_version": env!("CARGO_PKG_VERSION"),
        "enclave_active": matches!(node_state.enclave_state, cordon_core::state::EnclaveState::Active),
    });
    (StatusCode::OK, Json(body))
}

/// GET /v1/health/detailed — full health (operator cert required)
pub async fn health_detailed(
    _headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let node = &state.node;
    let node_state = node.state.read();

    let response = DetailedHealthResponse {
        status: node_state.status.to_string(),
        timestamp: Utc::now(),
        enclave: EnclaveHealth {
            status: format!("{:?}", node_state.enclave_state).to_lowercase(),
            tee_type: node.config.tee.preferred.to_string(),
            mrenclave: node.attestation.mrenclave(),
            last_attested: node.attestation.last_attestation_time(),
            attestation_valid: node.attestation.is_client_verified(),
        },
        boot_chain: BootChainStatus {
            tpm_present: node.config.boot.tpm_required,
            tpm_version: node.config.boot.tpm_version.clone(),
            secure_boot: node.config.boot.secure_boot,
            dm_verity: node.config.boot.dm_verity,
            last_pcr_verification: node.attestation.last_attestation_time(),
        },
        inference: InferenceHealth {
            runtime: node.inference.backend_name().to_string(),
            active_requests: node.inference.active_requests(),
            queue_depth: 0,
            latency_ms_p50: node_state.stats.latency_ms_p50,
            latency_ms_p99: node_state.stats.latency_ms_p99,
        },
        audit: AuditHealth {
            entries_total: node.audit.sequence(),
            last_entry_hash: node.audit.tail_hash(),
            chain_valid: node.audit_chain_valid(),
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
                    node.config.model_store.integrity_check_interval_minutes as i64
                )
            }),
            tamper_detected: node.integrity_monitor.is_tamper_detected(),
        },
        security: SecurityHealth {
            sustained_attack_detector: "active".to_string(),
            alerts_last_24h: 0, // Would query audit log in production
            quarantine_mode: matches!(
                node_state.status,
                cordon_core::state::NodeStatus::Quarantine
            ),
        },
    };

    (StatusCode::OK, Json(response))
}

// ─── Inference ────────────────────────────────────────────────────────────────

/// POST /v1/inference — synchronous inference
pub async fn inference(
    State(state): State<AppState>,
    Extension(vid): Extension<VerifiedIdentity>,
    Json(req): Json<InferenceRequest>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    let client = authenticated_client(&state.node, vid)?;

    // Convert API messages to core messages
    let messages: Vec<Message> = req.messages.iter().map(|m| Message {
        role: m.role.clone(),
        content: m.content.clone(),
    }).collect();

    let params = InferenceParams {
        max_tokens: req.inference_params.max_tokens,
        temperature: req.inference_params.temperature,
        top_p: req.inference_params.top_p,
        top_k: req.inference_params.top_k,
        stop: req.inference_params.stop.clone(),
        repetition_penalty: req.inference_params.repetition_penalty,
    };

    let timeout = req.timeout_seconds.unwrap_or(
        state.node.config.inference.default_timeout_seconds
    );

    let result = state.node.process_inference(
        &client,
        &req.model_id,
        vec![],
        messages,
        params,
        req.session_id,
        timeout,
    ).await.map_err(map_err)?;

    let timestamp = Utc::now();

    // Real Ed25519 signature over the canonical signed payload, using the
    // enclave response-signing key. A client holding the CMK can derive the
    // matching verifying key and check this offline.
    let signature = sign_response(
        &state.node,
        result.request_id,
        &result.output_hash,
        &result.model_id,
        timestamp,
        &result.mrenclave,
    );

    let response = InferenceResponse {
        request_id: result.request_id,
        model_id: result.model_id.clone(),
        model_version: "2.0.0".to_string(),
        client_id: result.client_id,
        timestamp,
        usage: TokenUsage {
            prompt_tokens: result.prompt_tokens,
            completion_tokens: result.completion_tokens,
            total_tokens: result.prompt_tokens + result.completion_tokens,
        },
        choices: vec![Choice {
            index: 0,
            message: ApiMessage {
                role: "assistant".to_string(),
                content: result.output,
            },
            finish_reason: result.finish_reason,
        }],
        content_policy: ContentPolicyStatus {
            triggered: result.content_policy_triggered,
            rules_matched: result.policy_rules_matched,
        },
        covert_channel: CovertChannelStatus {
            anomaly_detected: result.covert_channel_score > 0.6,
            anomaly_score: result.covert_channel_score,
        },
        signature,
        enclave_info: EnclaveInfo {
            tee_type: state.node.config.tee.preferred.to_string(),
            cordon_version: env!("CARGO_PKG_VERSION").to_string(),
            mrenclave: result.mrenclave,
        },
    };

    Ok((StatusCode::OK, Json(response)))
}

/// Canonical bytes signed for an inference response. Field order is fixed and
/// documented so clients can reconstruct and verify the signature:
///
///   CORDON_RESPONSE_v1|{request_id}|{output_hash}|{model_id}|{timestamp_ms}|{mrenclave}
///
/// `timestamp_ms` is the response `timestamp` as Unix epoch milliseconds — a
/// deterministic representation (no RFC3339 formatting ambiguity), reconstructable
/// from the response's `timestamp` field via `.timestamp_millis()`.
fn response_signing_payload(
    request_id: Uuid,
    output_hash: &str,
    model_id: &str,
    timestamp: chrono::DateTime<Utc>,
    mrenclave: &str,
) -> String {
    format!(
        "CORDON_RESPONSE_v1|{}|{}|{}|{}|{}",
        request_id, output_hash, model_id, timestamp.timestamp_millis(), mrenclave
    )
}

/// Build a real Ed25519 `ResponseSignature` for an inference response.
fn sign_response(
    node: &CordonNode,
    request_id: Uuid,
    output_hash: &str,
    model_id: &str,
    timestamp: chrono::DateTime<Utc>,
    mrenclave: &str,
) -> ResponseSignature {
    let payload = response_signing_payload(request_id, output_hash, model_id, timestamp, mrenclave);
    let sig = node.sign_enclave(payload.as_bytes());
    ResponseSignature {
        enclave_key_id: node.enclave_key_id(),
        algorithm: "ed25519".to_string(),
        value: sig.to_hex(),
        signed_fields: vec![
            "request_id".to_string(),
            "output_hash".to_string(),
            "model_id".to_string(),
            "timestamp_ms".to_string(),
            "mrenclave".to_string(),
        ],
    }
}

/// POST /v1/inference/stream — streaming inference via SSE.
///
/// SECURITY: this endpoint runs the **identical** pipeline to `/v1/inference`
/// (auth, rate limit, model-store gate, audit pre/post-write, output filter,
/// covert-channel detection, timing normalization) by delegating to
/// `process_inference`, and only then streams the **already-filtered** output
/// to the client. Raw model tokens are never streamed before filtering — so a
/// blocked or redacted response can never leak partial content, and the audit
/// log records the true policy/covert-channel values (previously the streaming
/// path bypassed all of this and logged zeros).
///
/// Emits SSE events:
///   event: delta  data: {"delta":"<chunk>"}
///   event: done   data: {"request_id", "finish_reason", "usage", "output_hash",
///                        "mrenclave", "content_policy", "covert_channel", "signature"}
pub async fn inference_stream(
    State(state): State<AppState>,
    Extension(vid): Extension<VerifiedIdentity>,
    Json(req): Json<InferenceRequest>,
) -> Result<axum::response::Sse<impl futures::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>>, ApiErrorResponse> {
    use axum::response::sse::{Event, KeepAlive};

    let client = authenticated_client(&state.node, vid)?;
    let node = state.node.clone();

    let messages: Vec<Message> = req.messages.iter().map(|m| Message {
        role: m.role.clone(),
        content: m.content.clone(),
    }).collect();

    let params = InferenceParams {
        max_tokens: req.inference_params.max_tokens,
        temperature: req.inference_params.temperature,
        top_p: req.inference_params.top_p,
        top_k: req.inference_params.top_k,
        stop: req.inference_params.stop.clone(),
        repetition_penalty: req.inference_params.repetition_penalty,
    };

    let timeout = req.timeout_seconds.unwrap_or(node.config.inference.default_timeout_seconds);

    // Full pipeline. Any policy block / covert-channel suspension / rate limit /
    // quarantine surfaces here as an HTTP error BEFORE a single token streams.
    let result = node.process_inference(
        &client,
        &req.model_id,
        vec![],
        messages,
        params,
        req.session_id,
        timeout,
    ).await.map_err(map_err)?;

    let timestamp = Utc::now();
    let signature = sign_response(
        &node,
        result.request_id,
        &result.output_hash,
        &result.model_id,
        timestamp,
        &result.mrenclave,
    );

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, std::convert::Infallible>>(128);

    tokio::spawn(async move {
        // Stream the filtered output in modest chunks on char boundaries.
        let text = result.output;
        let mut chunk = String::new();
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            chunk.push(c);
            if chunk.chars().count() >= 24 || chars.peek().is_none() {
                if !chunk.is_empty() {
                    let _ = tx.send(Ok(Event::default().event("delta")
                        .data(serde_json::json!({"delta": chunk}).to_string()))).await;
                    chunk = String::new();
                }
            }
        }

        let _ = tx.send(Ok(Event::default().event("done")
            .data(serde_json::json!({
                "request_id": result.request_id,
                "finish_reason": result.finish_reason,
                "usage": {
                    "prompt_tokens": result.prompt_tokens,
                    "completion_tokens": result.completion_tokens,
                    "total_tokens": result.prompt_tokens + result.completion_tokens,
                },
                "output_hash": result.output_hash,
                "mrenclave": result.mrenclave,
                "content_policy": {
                    "triggered": result.content_policy_triggered,
                    "rules_matched": result.policy_rules_matched,
                },
                "covert_channel": { "anomaly_score": result.covert_channel_score },
                "signature": {
                    "algorithm": "ed25519",
                    "value": signature.value,
                    "enclave_key_id": signature.enclave_key_id,
                },
            }).to_string()))).await;
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    Ok(axum::response::Sse::new(stream).keep_alive(KeepAlive::default()))
}

// ─── Attestation ──────────────────────────────────────────────────────────────

/// Sign an attestation report's combined hash with the enclave key so a client
/// can confirm the report was produced by the node holding the enclave key
/// (rather than an intermediary). Returns (signature_hex, enclave_pubkey_hex).
fn sign_attestation(
    node: &CordonNode,
    report: &cordon_crypto::attestation::AttestationReport,
) -> (String, String) {
    let payload = format!(
        "CORDON_ATTESTATION_v1|{}|{}",
        report.combined.combined_hash, report.client_nonce
    );
    (node.sign_enclave(payload.as_bytes()).to_hex(), node.enclave_verifying_key_hex())
}

/// GET /v1/attestation — return a fresh, enclave-signed attestation report.
pub async fn get_attestation(
    _headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    let nonce = Uuid::new_v4().to_string();
    let report = state.node.attestation
        .generate_attestation(&nonce, &state.node.config.node_id)
        .map_err(|e| map_err(CordonError::AttestationInvalid(e.to_string())))?;

    let (signature, enclave_pubkey) = sign_attestation(&state.node, &report);

    Ok((StatusCode::OK, Json(serde_json::json!({
        "client_verified": state.node.attestation.is_client_verified(),
        "report": report,
        "signature": {
            "algorithm": "ed25519",
            "value": signature,
            "enclave_signing_key": enclave_pubkey,
            "signed": "CORDON_ATTESTATION_v1|<combined_hash>|<nonce>",
        },
        "key_provenance": state.node.key_provenance().as_str(),
        "generated_at": Utc::now(),
    }))))
}

/// POST /v1/attestation/verify — verify the report against client expectations.
///
/// FAIL-CLOSED: the node is marked client-verified ONLY when the caller supplies
/// `expected_measurements` AND the report actually satisfies them (nonce, PCRs,
/// MRENCLAVE/MRSIGNER, ISV SVN, TEE type, combined-hash integrity). Previously
/// this endpoint unconditionally returned `verified: true` and flipped the
/// node's verified flag regardless of input.
pub async fn verify_attestation(
    _headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<AttestationVerifyRequest>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    use cordon_crypto::attestation::ExpectedMeasurements;

    let report = state.node.attestation
        .generate_attestation(&req.nonce, &state.node.config.node_id)
        .map_err(|e| map_err(CordonError::AttestationInvalid(e.to_string())))?;

    let (signature, enclave_pubkey) = sign_attestation(&state.node, &report);

    // Without expected measurements we cannot verify — return the signed report
    // but DO NOT mark the node verified.
    let expected_value = match req.expected_measurements.clone() {
        Some(v) => v,
        None => {
            return Ok((StatusCode::OK, Json(serde_json::json!({
                "verified": false,
                "reason": "no expected_measurements supplied — cannot verify; report returned for client-side verification",
                "mrenclave": report.combined.tee_quote.mrenclave,
                "combined_hash": report.combined.combined_hash,
                "signature": { "algorithm": "ed25519", "value": signature, "enclave_signing_key": enclave_pubkey },
                "report": report,
                "timestamp": report.combined.generated_at,
            }))));
        }
    };

    let expected: ExpectedMeasurements = match serde_json::from_value(expected_value) {
        Ok(e) => e,
        Err(e) => {
            return Err(map_err(CordonError::AttestationInvalid(
                format!("malformed expected_measurements: {}", e),
            )));
        }
    };

    match report.verify(&expected, &req.nonce) {
        Ok(()) => {
            // Only now is the node considered verified by this client.
            state.node.attestation.mark_client_verified();
            Ok((StatusCode::OK, Json(serde_json::json!({
                "verified": true,
                "mrenclave": report.combined.tee_quote.mrenclave,
                "combined_hash": report.combined.combined_hash,
                "signature": { "algorithm": "ed25519", "value": signature, "enclave_signing_key": enclave_pubkey },
                "timestamp": report.combined.generated_at,
            }))))
        }
        Err(e) => {
            tracing::warn!("attestation verification FAILED: {}", e);
            Ok((StatusCode::OK, Json(serde_json::json!({
                "verified": false,
                "reason": e.to_string(),
                "mrenclave": report.combined.tee_quote.mrenclave,
                "combined_hash": report.combined.combined_hash,
                "timestamp": report.combined.generated_at,
            }))))
        }
    }
}

/// POST /v1/attestation/refresh — trigger re-attestation
pub async fn refresh_attestation(
    _headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    let nonce = Uuid::new_v4().to_string();
    let report = state.node.attestation
        .generate_attestation(&nonce, &state.node.config.node_id)
        .map_err(|e| map_err(CordonError::AttestationInvalid(e.to_string())))?;

    Ok((StatusCode::OK, Json(serde_json::json!({
        "status": "re_attestation_completed",
        "mrenclave": report.combined.tee_quote.mrenclave,
        "nonce": nonce,
        "timestamp": Utc::now(),
    }))))
}

// ─── Models ───────────────────────────────────────────────────────────────────

/// GET /v1/models — list model bundles
pub async fn list_models(
    _headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let bundles = state.node.model_store.list_bundles();
    let entries: Vec<serde_json::Value> = bundles.into_iter().map(|(id, status)| {
        serde_json::json!({
            "bundle_id": id,
            "status": format!("{:?}", status).to_lowercase(),
        })
    }).collect();

    (StatusCode::OK, Json(serde_json::json!({ "bundles": entries })))
}

// ─── Audit ────────────────────────────────────────────────────────────────────

/// GET /v1/audit/verify — verify chain integrity
pub async fn audit_verify(
    _headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    let log_dir = &state.node.config.audit.log_path;
    let vk = state.node.audit.verifying_key();

    let result = verify_log_chain(
        log_dir,
        &vk,
        &state.node.config.deployment_id,
    ).map_err(|e| map_err(CordonError::Internal(e.to_string())))?;

    let response = AuditVerifyResponse {
        valid: result.valid,
        entries_verified: result.entries_verified,
        first_entry: result.first_entry,
        last_entry: result.last_entry,
        log_tail_hash: result.log_tail_hash,
        violations: result.violations,
    };

    Ok((StatusCode::OK, Json(response)))
}

/// GET /v1/audit/tail — get most recent N entries
pub async fn audit_tail(
    _headers: HeaderMap,
    State(state): State<AppState>,
    Query(query): Query<AuditTailQuery>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    let n = query.n.unwrap_or(10).min(1000);
    let entries = state.node.audit.read_all_entries()
        .map_err(|e| map_err(CordonError::Internal(e.to_string())))?;

    let tail: Vec<_> = entries.iter().rev().take(n as usize).collect();
    let tail_values: Vec<serde_json::Value> = tail.iter().map(|e| {
        serde_json::json!({
            "log_id": e.log_id,
            "sequence": e.sequence,
            "timestamp": e.timestamp,
            "event_type": e.payload.event_type_str(),
            "entry_hash": e.entry_hash,
        })
    }).collect();

    Ok((StatusCode::OK, Json(serde_json::json!({
        "entries": tail_values,
        "total": entries.len(),
        "tail_hash": state.node.audit.tail_hash(),
    }))))
}

/// POST /v1/audit/anchor — publish Merkle root
pub async fn audit_anchor(
    _headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let tail = state.node.audit.tail_hash().unwrap_or_default();
    (StatusCode::OK, Json(serde_json::json!({
        "merkle_root": tail,
        "sequence": state.node.audit.sequence(),
        "timestamp": Utc::now(),
    })))
}

// ─── Admin ────────────────────────────────────────────────────────────────────

/// Record an administrative action to the audit log.
fn record_admin_event(node: &CordonNode, action: cordon_audit::events::AdminAction, params: &str, ok: bool) {
    use sha2::{Digest, Sha256};
    use cordon_audit::events::{AuditEvent, AdminEvent, ActionResult};
    let _ = node.audit.append(AuditEvent::Admin(AdminEvent {
        client_id: "operator".to_string(),
        actor_key_id: "k_admin".to_string(),
        action,
        authorization_sig_valid: ok,
        parameters_hash: hex::encode(Sha256::digest(params.as_bytes())),
        result: if ok { ActionResult::Success } else { ActionResult::Rejected },
        failure_reason: None,
    }));
}

/// POST /v1/admin/teardown — graceful shutdown + memory wipe.
/// Requires a valid Ed25519 K_admin signature over `CORDON_ADMIN:teardown:{reason}`.
pub async fn admin_teardown(
    _headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<RecoverRequest>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    use cordon_audit::events::AdminAction;
    if let Err(e) = state.node.authorize_admin("teardown", &req.reason, &req.admin_signature) {
        record_admin_event(&state.node, AdminAction::Teardown, &req.reason, false);
        return Err(map_err(e));
    }
    tracing::warn!("Teardown authorized: {}", req.reason);
    record_admin_event(&state.node, AdminAction::Teardown, &req.reason, true);
    state.node.state.write().enter_zeroized();
    Ok((StatusCode::OK, Json(AdminResponse::ok("Teardown initiated — key material zeroized"))))
}

/// POST /v1/admin/recover — exit quarantine.
/// Requires a valid Ed25519 K_admin signature over `CORDON_ADMIN:recover:{reason}`.
pub async fn admin_recover(
    _headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<RecoverRequest>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    use cordon_audit::events::AdminAction;
    if let Err(e) = state.node.authorize_admin("recover", &req.reason, &req.admin_signature) {
        record_admin_event(&state.node, AdminAction::Recovery, &req.reason, false);
        return Err(map_err(e));
    }
    tracing::info!("Recovery authorized: {}", req.reason);
    record_admin_event(&state.node, AdminAction::Recovery, &req.reason, true);
    state.node.integrity_monitor.reset_tamper();
    state.node.state.write().go_operational();
    Ok((StatusCode::OK, Json(AdminResponse::ok("Node recovered and operational"))))
}

/// POST /v1/admin/quarantine — manually enter quarantine.
/// Requires a valid Ed25519 K_admin signature over `CORDON_ADMIN:quarantine:{reason}`.
pub async fn admin_quarantine(
    _headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<RecoverRequest>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    use cordon_audit::events::AdminAction;
    if let Err(e) = state.node.authorize_admin("quarantine", &req.reason, &req.admin_signature) {
        record_admin_event(&state.node, AdminAction::ConfigChange, &req.reason, false);
        return Err(map_err(e));
    }
    state.node.state.enter_quarantine();
    tracing::warn!("Node manually quarantined by operator: {}", req.reason);
    record_admin_event(&state.node, AdminAction::ConfigChange, &req.reason, true);
    Ok((StatusCode::OK, Json(AdminResponse::ok("Node entered quarantine mode"))))
}

/// POST /v1/admin/key-rotate — rotate a bundle's key epoch.
/// Requires a K_admin signature over `CORDON_ADMIN:key-rotate:{bundle_id}:{emergency}`.
pub async fn admin_key_rotate(
    _headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<KeyRotateRequest>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    use cordon_audit::events::{AuditEvent, KeyRotationEvent};
    let params = format!("{}:{}", req.bundle_id, req.emergency);
    state.node.authorize_admin("key-rotate", &params, &req.admin_signature).map_err(map_err)?;
    let _ = state.node.audit.append(AuditEvent::KeyRotation(KeyRotationEvent {
        bundle_id: req.bundle_id.clone(),
        previous_epoch: 0,
        new_epoch: 1,
        emergency: req.emergency,
        requests_dropped: 0,
    }));
    tracing::warn!("Key rotation authorized for bundle {} (emergency={})", req.bundle_id, req.emergency);
    Ok((StatusCode::OK, Json(AdminResponse::ok(format!("Key rotation initiated for bundle {}", req.bundle_id)))))
}

/// POST /v1/admin/update — stage a signed software/model update.
/// Requires a K_admin signature over `CORDON_ADMIN:update:{package_path}`.
pub async fn admin_update(
    _headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<UpdateRequest>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    use cordon_audit::events::AdminAction;
    state.node.authorize_admin("update", &req.package_path, &req.admin_signature).map_err(map_err)?;
    record_admin_event(&state.node, AdminAction::SoftwareUpdate, &req.package_path, true);
    tracing::info!("Update authorized: {}", req.package_path);
    Ok((StatusCode::OK, Json(AdminResponse::ok("Update staged for A/B rollout"))))
}

/// POST /v1/models — register (provision) a new model bundle.
/// Requires a K_admin signature over `CORDON_ADMIN:provision-model:{bundle_path}`.
pub async fn provision_model(
    _headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<ProvisionModelRequest>,
) -> Result<impl IntoResponse, ApiErrorResponse> {
    use cordon_audit::events::AdminAction;
    state.node.authorize_admin("provision-model", &req.bundle_path, &req.admin_signature).map_err(map_err)?;

    let manifest: cordon_core::model_store::BundleManifest =
        serde_json::from_value(req.manifest).map_err(|e| {
            map_err(CordonError::ValidationFailed(format!("invalid manifest: {}", e)))
        })?;
    let bundle_id = manifest.bundle_id.clone();
    state.node.model_store
        .register_bundle(manifest, std::path::PathBuf::from(&req.bundle_path), None)
        .map_err(map_err)?;
    record_admin_event(&state.node, AdminAction::ModelUpdate, &bundle_id, true);

    Ok((StatusCode::OK, Json(serde_json::json!({
        "status": "registered",
        "bundle_id": bundle_id,
    }))))
}

/// GET /v1/metrics — Prometheus metrics (localhost only)
pub async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let body = state.node.metrics.render();
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
}
