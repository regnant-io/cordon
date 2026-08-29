# Cordon — architecture and trust model

Cordon is a confidential-inference **control plane**: an HTTP service that owns a
local model runtime and wraps every request in identity, policy, rate limiting,
content filtering, covert-channel analysis, tamper-evident auditing, and
attestation.

This document describes what the system does, and draws an explicit line between
the cryptography that is real and the hardware guarantees that are not.

---

## 1. Crates

| Crate | Responsibility |
|---|---|
| `cordon-crypto` | AES-256-GCM, Ed25519, HKDF-SHA256 key hierarchy, constant-time comparison, zeroizing secret types, attestation data types and the client-side verifier. |
| `cordon-audit` | Hash-chained, Ed25519-signed, append-only JSONL audit log, and an offline verifier. |
| `cordon-core` | The node and every layer: configuration, state machine, identity, rate limiting, model store, inference engine, model runtimes, output filter, covert-channel detector, timing normalizer, attestation service, integrity monitor, attack detector, metrics, Hub client. |
| `cordon-api` | Axum HTTP server, routes, handlers, middleware, TLS and mTLS termination, operator console. |
| `cordon-cli` | `cordon`, `cordon-keygen`, `cordon-provision`, `cordon-verify-log`. |

`#![forbid(unsafe_code)]` is set workspace-wide.

---

## 2. Key hierarchy

The **Client Master Key** is the root of trust, held by the client — an HSM in
production. Everything else is HKDF-SHA256-derived with domain separation, so
keys for different purposes are cryptographically independent and a client
holding the CMK can independently derive the public halves.

```text
CMK ──HKDF──┬─ K_bundle  (per bundle + principal) ──HKDF──> per-shard AES-256-GCM keys
            ├─ K_session (per deployment + principal)
            ├─ K_log     (Ed25519)  signs the audit log        — the client verifies
            ├─ K_admin   (Ed25519)  authorizes admin commands   — the node verifies
            └─ K_enclave (Ed25519)  signs responses and reports — the client verifies
```

Domain strings live in `cordon-crypto/src/kdf.rs` as `CORDON_*_KEY_v1`. They are
versioned: changing what a string derives without changing its version would
silently invalidate every existing deployment's keys.

The node needs the CMK to decrypt bundles and to sign. It never needs to own it,
and `CORDON_CMK_FILE` on a memory-backed filesystem is the recommended path
precisely because the environment is not a safe place for it.

When no CMK is provisioned the node generates **ephemeral** keys and reports
`key_provenance: "ephemeral"` in every response and health payload. Modes other
than Light refuse to start that way, because an audit log a node signs with a
key it generated itself carries no non-repudiation.

---

## 3. Request pipeline

```text
can serve?          the node is not quarantined, locked, or zeroized
attestation gate    hardware modes: THIS client has verified the node
source block        the peer's fingerprint is not blocked
identity            certificate validity, enrolment, policy lookup
suspension          the client is not serving a suspension
model permission    the policy admits this model
request limits      message count, prompt size, token budget, sampling ranges
model store gate    the bundle is registered and passed integrity recently
rate limit          a request slot and an output-token reservation
admission           a concurrency slot and a session
audit pre-write     log before processing; a failed write refuses the request
generate            the model runtime produces output
settle              unused output-token reservation is refunded
output filter       policy rules redact, truncate, or block
covert channel      statistical analysis of the released text
timing              latency normalised to a bucket or floor
audit post-write    the completed record, with true policy values
sign                Ed25519 over a canonical, reconstructable payload
```

Both `POST /v1/inference` and `POST /v1/inference/stream` run this pipeline
through the same `admit` function, so the two paths cannot diverge.

**Log before process.** The intake record is written before any model
computation, and a failed write refuses the request. A request that was
processed is always a request that was logged.

**Token reservation.** The rate limiter reserves `max_tokens` up front and
settles to the actual generated count afterwards, refunding the remainder. A
caller cannot exceed its budget by requesting a large ceiling and generating
little, nor be over-charged for asking for headroom it did not use.

**Attestation is per client.** `halt_until_verified` refuses a client until
*that client* has verified the node's measurements. One caller's acceptance says
nothing about whether another caller would accept, so it does not unlock the
node for everyone.

### Streaming

The streaming path applies the output filter incrementally through
`StreamingFilter`, which holds back a trailing window of characters and releases
only text far enough from the end that no rule could still match across the
boundary. A credit-card number whose final digits arrive in the next chunk is
caught before any part of it has left the node.

The contract is that nothing is released that the whole-response filter would
have removed. A blocking rule that fires mid-generation terminates the stream
with an `error` event.

---

## 4. Model runtime

Cordon owns the runtime rather than assuming an operator started one correctly.
`LlamaSupervisor` spawns `llama-server` as a child process and constrains it:

- **Loopback only.** The bind address is hard-coded to `127.0.0.1` and is not
  configurable. A runtime reachable from the network would let callers bypass
  identity, policy, filtering, and audit entirely.
- **Ephemeral port**, chosen at startup and never published.
- **Web UI removed.** `--no-webui` is passed when the binary accepts it, and
  after startup Cordon *asks the child for `/`* and refuses to run if it gets an
  HTML document back. The enforcement is the check, not the flag.
- **Per-boot API key**, 32 random bytes, required on every request.
- **Killed on drop and on exit**, and restarted automatically if it dies.

Three backends exist, selected by `runtime.backend`:

| Backend | Behaviour |
|---|---|
| `supervised` | The above. The recommended production posture. |
| `external` | Forwards to an endpoint the operator runs. Refused outside Light mode unless that endpoint is on loopback. |
| `none` | No runtime. Returns text prefixed `[cordon:no-model]`. Light mode only. |

Every backend is asynchronous. There is one pooled HTTP client, and no request
occupies a runtime worker thread waiting on I/O.

---

## 5. Model store

A bundle is a directory holding a plaintext `manifest.json` and AES-256-GCM
encrypted weight shards.

**Serving is gated on a cached integrity verdict.** The gate runs on every
request and performs no cryptography and no I/O: it consults the verdict
established at registration, at staging, and by the background monitor. A verdict
older than `integrity_check_interval_minutes` is refused, so a monitor that has
stopped running takes the node out of service rather than leaving it serving
unverified weights.

**Manifest validation is structural.** A manifest is refused if it declares an
algorithm other than AES-256-GCM, reuses a nonce across shards, uses an all-zero
nonce, has matching plaintext and ciphertext digests, or names a shard path that
escapes the bundle directory. Each of those describes plaintext weights wearing
a bundle's clothing.

**Staging.** `stage_plaintext` decrypts shard by shard, streaming to a mode-0600
file rather than reconstructing the model in memory, and verifies the
full-plaintext digest as it goes. The runtime is then started with memory mapping
disabled so it reads the weights fully into its own address space, and the staged
file is erased at once — and again on drop.

This is disk-backed staging, not enclave-resident decryption. It bounds the
window in which plaintext weights are readable; it does not eliminate it. Set
`model_store.staging_dir` to a `tmpfs` mount where that distinction matters.

---

## 6. What is real, and what is not

### Real, and exercised by tests

AES-256-GCM shard encryption with per-shard keys, fresh nonces, and digests
checked in both directions. The HKDF key hierarchy with domain separation.
Ed25519 signing and verification for responses, attestation reports, audit
entries, and anchors. The hash-chained audit log and its offline verifier.
Constant-time comparison. Drop-zeroization of secret buffers. TLS 1.3 and mutual
TLS with client identity parsed from the verified certificate.

### Real, but hardware-dependent

TPM 2.0 measurements and quotes come from `tpm2-tools`. The command wiring and
output parsing are unit-tested; this repository's CI has no TPM, so the path is
not exercised against hardware here. `cordon doctor` checks it on a real machine.

When `measurement_source = "tpm2"` and no TPM is reachable, the node **fails to
start**. It does not fall back to a software measurement — a node that quietly
downgrades is worse than one that refuses to boot, because operators believe the
stronger claim either way.

### Not a hardware root of trust

`measurement_source = "software_measurement"` derives measurements from Cordon's
build and configuration. It attests that the node is running the configuration
the operator expects. It attests nothing about the platform underneath it, and
an attacker with code execution on the host can reproduce it exactly.

It is confined to Light mode by `CordonConfig::validate`, and it is reported as
`software_measurement` in every attestation report, every response's
`enclave_info`, and the health endpoint, so no caller can mistake it for
hardware attestation.

Full SGX-DCAP and SEV-SNP quote verification are **not implemented**. The TEE
quote carries measurements and a type; it does not carry a hardware-signed
attestation verified against Intel's or AMD's roots. That is the remaining
source-level work for hardware modes.

### Why expectations are pinned

Attestation verification compares a report against measurements the **operator**
pinned in configuration. `POST /v1/attestation/verify` takes only a nonce.

An earlier design accepted expected measurements in the request body. That
verifier could always be satisfied: any caller could read the node's own
measurements from `GET /v1/attestation` and hand them straight back. Pinning is
what makes the check mean anything, and a node with nothing pinned reports
`verified: false` rather than verifying trivially.

### Bounded weaknesses, stated plainly

- Staged plaintext weights touch disk for the duration of a model load.
- Prompts and completions live in process memory. Buffers zeroize on drop, but
  an attacker with root can read them first.
- The operator console has no authentication; loopback binding is its access
  control.

---

## 7. Audit log

```text
entry_hash_n = SHA-256(entry_hash_{n-1} ‖ timestamp_n ‖ payload_hash_n)
signature_n  = Ed25519(K_log, entry_hash_n)
```

The genesis hash is anchored to a deployment-specific constant.
`cordon-verify-log` and `GET /v1/audit/verify` recompute the whole chain and
check every signature against **K_log's public key** — which, when a CMK is
provisioned, is the key the *client* derives. The operator cannot rewrite
history undetectably.

Chain verification is linear in log size, so it runs on a timer in the
background and health endpoints read the cached verdict. Running it inline would
make a cheap endpoint an unauthenticated way to force unbounded I/O.

`GET /v1/audit/anchor` returns a signed chain head. Recording it with a third
party makes any later rewrite before that point detectable.

The log records hashes, token counts, and policy outcomes. It never records
prompts or completions, and policy match summaries describe what matched without
reproducing it.

---

## 8. Deployment modes

| Mode | TEE | mTLS | Console | Egress | Notes |
|---|---|---|---|---|---|
| `light` | not required | optional | loopback | yes | Development. |
| `sovereign_cloud` | required | required | refused | yes | Client VPC. |
| `vault` | required | required | refused | no | Regulated enterprise. |
| `island` | required | required | refused | no | Private network. |
| `dark` | required | required | refused | no | FIPS L4 HSM, single tenant. |

`CordonConfig::validate` enforces every invariant at startup, and each check
fails closed. Notably, outside Light mode: a simulation TEE is refused, a
software measurement source is refused, unpinned measurements are refused, mTLS
without a client CA is refused, the console is refused, the placeholder runtime
is refused, and the `CORDON_INSECURE_ADMIN` and
`CORDON_ALLOW_UNREGISTERED_MODELS` development overrides are refused.

---

## 9. Threat model

### Defended

| Adversary | Defence |
|---|---|
| A network attacker | TLS 1.3, mutual TLS, certificate-bound identity. |
| An unauthorized client | Enrolment, per-client policy, certificate pinning. |
| A client exceeding its budget | Token-bucket limits with up-front reservation. |
| A client probing for other sessions | Session ownership checked before any state is touched. |
| A client extracting data through output | Content policy, covert-channel analysis, timing normalisation. |
| An operator rewriting the audit log | Hash chain plus signatures under a client-derived key. |
| An operator reading model weights | Bundle encryption under a client-held key. |
| An operator running unauthorized admin commands | Ed25519 signatures over canonical, non-replayable commands. |
| Weights modified at rest | Continuous integrity monitoring; a stale verdict removes the model from service. |
| Denial of service by resource exhaustion | Bounded bodies, sessions, connections, replay tables, and concurrency; handshake and request deadlines. |

### Not defended

| Adversary | Why |
|---|---|
| Root on the node, in a non-TEE mode | Can read process memory. Only a real TEE closes this. |
| An attacker holding the CMK | It is the root of trust by construction. |
| Physical attacks on the host | Out of scope; a hardware TEE is the mitigation. |
| A malicious model | Cordon controls access to a model, not what the model says. |
| A compromised llama.cpp | Cordon contains it to loopback; it does not sandbox it. |

---

## 10. Concurrency and resource bounds

Every structure an untrusted caller can grow is bounded:

| Structure | Bound |
|---|---|
| Request body | `limits.max_request_bytes`, enforced before buffering. |
| Messages and prompt size | `limits.max_messages`, `limits.max_prompt_chars`. |
| Concurrent generations | A semaphore; excess returns `503` rather than queueing. |
| Sessions | A capacity ceiling; idle sessions are reclaimed and zeroized. |
| Replay-detection hashes | A capacity ceiling; the table resets rather than growing. |
| Rate-limit buckets | Pruned when stale. |
| Client suspensions | Expired entries dropped on a timer. |
| TLS connections | A semaphore, plus a handshake deadline. |
| Audit tail reads | Newest-first, reading only as far as needed. |

Admission returns `Overloaded` immediately when full, so callers see
backpressure rather than unbounded latency.

---

## 11. Notes for reviewers

Places where a change is most likely to introduce a security regression:

- **String slicing.** `panic = "abort"` is set for release builds, so slicing a
  `String` at a non-character boundary is a remote crash. Use `char_indices` or
  the `floor_char_boundary` helper.
- **Lock guards across `await`.** `parking_lot` guards are not `Send`; holding
  one across an await makes a handler's future non-`Send` and will not compile,
  but restructuring to satisfy the compiler can accidentally widen a critical
  section.
- **New endpoints.** Every handler that touches node state must call
  `authenticated_client`.
- **`unwrap_or(true)`.** Almost always a fail-open in disguise.
- **Error messages.** Client faults may be specific. Node faults are generalised
  before they reach the wire; the detail belongs in the log.
