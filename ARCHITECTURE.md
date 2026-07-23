# Cordon — Architecture & Trust Model

Cordon is a confidential-inference **control plane**: an HTTP service that fronts a
local LLM runtime (an OpenAI-compatible `/v1/chat/completions` server such as
llama.cpp/vLLM) and wraps every request in identity, policy, rate-limiting,
content filtering, covert-channel analysis, tamper-evident auditing, and
attestation. It is a Rust workspace of five crates.

This document describes what the system **actually does** — including an explicit
line between cryptography that is real and hardware roots of trust that are
**simulated** in this build.

---

## 1. Crates

| Crate | Responsibility |
|-------|----------------|
| `cordon-crypto` | AES‑256‑GCM, Ed25519, X25519, HKDF‑SHA256 key hierarchy, constant‑time compare, zeroizing secret types, attestation data types + client‑side verifier. |
| `cordon-audit` | Merkle‑chained (SHA‑256) + Ed25519‑signed append‑only JSONL audit log and an **offline** verifier. |
| `cordon-core` | Node orchestrator and every layer: config, state machine, identity/authorization, rate limiter, model store, inference engine, output filter, covert‑channel detector, timing normalizer, attestation service, integrity monitor, attack detector, metrics. |
| `cordon-api` | Axum HTTP server, routes, handlers, middleware, TLS/mTLS termination. |
| `cordon-cli` | `cordon` (serve/status/attest), `cordon-keygen`, `cordon-provision`, `cordon-verify-log`. |

`#![forbid(unsafe_code)]` is set workspace‑wide.

---

## 2. Key hierarchy (§6.2)

The **Client Master Key (CMK)** is the root of trust, held by the client (an HSM
in production; `CORDON_CMK` for dev). Everything else is HKDF‑SHA256‑derived with
domain separation, so keys for different purposes are cryptographically
independent and a client holding the CMK can independently derive the public
halves:

```
CMK ──HKDF──┬─ K_bundle (per bundle+client) ──HKDF──> per‑shard AES‑256‑GCM keys
            ├─ K_session (per deployment+client)
            ├─ K_log     (Ed25519)   → signs the audit log        (client verifies)
            ├─ K_admin   (Ed25519)   → authorizes admin commands  (node verifies)
            └─ K_enclave (Ed25519)   → signs inference responses + attestation reports
```

Domain strings live in `cordon-crypto/src/kdf.rs` (`CORDON_*_KEY_v1`). When no CMK
is provisioned the node generates **ephemeral** keys and marks its posture
`ephemeral` everywhere (health, attestation) — see the trust‑posture note in §6.

---

## 3. Request lifecycle (`process_inference`)

```
mTLS/identity → can_serve? → ATTESTATION GATE (hardware‑TEE modes)
  → IP‑block? → verify identity → suspension? → model permitted?
  → MODEL‑STORE GATE (registered + integrity + decrypt proof)
  → DECRYPT + LOAD weights (materialize plaintext in‑enclave, once)
  → rate limit (reserve output tokens) → input hash + replay probe
  → AUDIT PRE‑WRITE (log‑before‑process; fatal on failure)
  → inference (mock | HTTP backend) → SETTLE token reservation
  → output filter (block/redact/…) → covert‑channel score → timing normalization
  → output hash → AUDIT POST‑WRITE → Ed25519‑signed response
```

**Attestation gate.** In hardware‑TEE modes with `halt_on_attestation_failure`,
`process_inference` refuses to serve — and no bundle key is used — until a client
has successfully verified the node's attestation (`attestation_ready()`). Light/dev
skips this.

**Decrypt + load.** For a registered bundle with a CMK present, `ensure_model_loaded`
decrypts every shard (`materialize_plaintext`), verifies the full‑plaintext hash,
and hands the bytes to the backend in a zeroizing buffer — the real in‑enclave
decryption path. No‑op for dev passthrough / no‑CMK.

**Token reservation.** The rate limiter reserves `max_tokens` up front and
**settles** to the actual generated count after inference, refunding the unused
remainder.

The streaming endpoint (`/v1/inference/stream`) runs this **same** pipeline and
only streams the already‑filtered output, so it can never leak pre‑filter tokens
and its audit records carry true policy/covert‑channel values.

---

## 4. Endpoints

| Method / path | Auth | Notes |
|---|---|---|
| `GET /v1/health` | none | liveness |
| `GET /v1/health/detailed` | client | includes real `audit.chain_valid`, key provenance |
| `POST /v1/inference` | client (mTLS) | Ed25519‑signed response |
| `POST /v1/inference/stream` | client (mTLS) | full pipeline, then SSE of filtered output |
| `GET /v1/attestation` | client | signed report |
| `POST /v1/attestation/verify` | client | **fail‑closed** verification vs `expected_measurements` |
| `POST /v1/attestation/refresh` | client | |
| `GET /v1/models` | client | bundle list |
| `GET /v1/audit/verify` | client | runs the offline chain verifier |
| `GET /v1/audit/tail`, `POST /v1/audit/anchor` | client | |
| `POST /v1/admin/{teardown,recover,quarantine}` | **K_admin signature** | fail‑closed |
| `POST /v1/admin/{key-rotate,update}` | **K_admin signature** | audited |
| `POST /v1/models` | **K_admin signature** | register (provision) a bundle |
| `GET /metrics` | localhost | Prometheus |

---

## 5. Audit log (§9)

`entry_hash_n = SHA‑256(entry_hash_{n‑1} ‖ timestamp_n ‖ payload_hash_n)`,
`signature_n = Ed25519(K_log, entry_hash_n)`, genesis anchored to a deployment‑
specific constant. `cordon-verify-log` (and `GET /v1/audit/verify`) recompute the
whole chain and check every signature with **K_log’s public key** — which, when
the CMK is provisioned, is the key the *client* derives, so the vendor/operator
cannot rewrite history undetectably.

---

## 6. What is real vs simulated

**Real, exercised cryptography.** AES‑256‑GCM shard encryption with plaintext +
ciphertext hash checks; Ed25519 signing/verification (audit, admin, responses,
attestation reports); HKDF key hierarchy with domain separation; Merkle chaining;
constant‑time comparisons; drop‑zeroization of secret buffers; TLS 1.3 + mTLS.

**Hardware root of trust — real backend, simulated fallback.** `attestation_service.rs`
uses a **real TPM** backend (`tpm.rs`, shelling out to `tpm2-tools`) when the
operator sets `CORDON_TPM=1` and a TPM is reachable: PCR values are read from the
hardware and a signed quote can be produced from a provisioned AK. When the TPM
is absent it falls back to deterministic simulated PCRs/`MRENCLAVE`, and the mode
(`tpm2` vs `simulation`) is reported. The *verification path and its failure mode*
are real either way: the attestation report is Ed25519‑signed by the enclave key,
and `/v1/attestation/verify` runs the genuine `AttestationReport::verify` against
client‑supplied expected measurements and **only** marks the node verified on
success. (The TPM backend is wired against `tpm2-tools` output formats but not run
against physical TPM hardware in this repo's CI. Full SGX‑DCAP / SEV‑SNP quote
verification is the remaining source‑level step.)

**Key sourcing.** The CMK is read from `CORDON_CMK` (env; least safe),
`CORDON_CMK_FILE` (a file, e.g. tmpfs), or — the production path the `HsmConfig`
scaffolding describes — an HSM via PKCS#11, which plugs in at the `load_cmk_hex`
seam.

**Trust posture.** Every response advertises `key_provenance`:
`cmk_derived` (audit + response signatures are client‑verifiable) or `ephemeral`
(dev; self‑certified). This makes the guarantee level explicit rather than
implied.

---

## 7. Security fixes (relative to the pre‑Cordon baseline)

| # | Was | Now |
|---|-----|-----|
| 1 | Server logged a warning and ran **plain HTTP** even with TLS configured. | Real **TLS 1.3** termination via `tokio-rustls` + `hyper-util`. |
| 2 | Identity read from a spoofable `x-client-id` header. | Under mTLS, identity is bound to the **verified client certificate** (rustls `WebPkiClientVerifier`), injected via request extensions; the header is ignored. Header identity is accepted only under explicit `--no-tls` dev. |
| 3 | `/v1/admin/*` executed with **no authorization**. | Ed25519 **K_admin signature** required over a canonical command string; **fail‑closed** when no admin key is provisioned. `cordon-keygen admin-sign` produces signatures. |
| 4 | `/v1/attestation/verify` **always** returned `verified:true`. | Runs `AttestationReport::verify` vs client `expected_measurements`; **fail‑closed**; report is Ed25519‑signed. |
| 5 | Audit log signed with a **random per‑boot** key (non‑repudiation impossible). | K_log **derived from the CMK**; client verifies with the matching public key. Provenance surfaced; ephemeral only in dev. |
| 6 | "Response signature" was a **SHA‑256 hash** mislabeled `ed25519`; `chain_valid` hardcoded `true`. | Real **Ed25519** signature over a documented, reconstructable payload; `chain_valid` computed by the real verifier. |
| 7 | Encrypted model store **not wired** into serving. | Inference is **gated** on a registered bundle passing integrity **and** a decrypt‑with‑derived‑key proof; fail‑closed once bundles exist. |
| 8 | Streaming endpoint **bypassed** filter/covert/timing and logged zeros. | Streaming runs the **identical** pipeline via `process_inference`, then streams filtered output. |
| 9 | KV/session "zeroization" was a **log line**. | Session secret scratch is explicitly zeroized on end (plus `ZeroizeOnDrop`); single‑shot sessions are torn down so the map can't grow unbounded. |

---

## 8. Deployment modes

`Dark`, `Island`, `Vault`, `SovereignCloud`, `Light`. `validate()` enforces mode
invariants (e.g. Dark requires FIPS L4 HSM and forbids multi‑tenancy; non‑Light
modes forbid the Simulation TEE). `Light` is the dev/software‑isolation mode used
by the tests and the `--no-tls` path.
