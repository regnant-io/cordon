# Cordon — architecture and trust model

Cordon is a confidential-inference **control plane**: an HTTP service that owns a
local model runtime and wraps every request in identity, policy, rate limiting,
content filtering, covert-channel analysis, tamper-evident auditing, and
attestation.

Whether it is also a trusted execution environment depends on where you run it.
On an ordinary host it is not: whoever has root can read prompts out of process
memory, and no amount of control plane changes that. Inside an AMD SEV-SNP
guest, Cordon and the model runtime and the weights are all on the private side
of the boundary and the hypervisor is outside it. §6 draws that line precisely,
and §6.1 explains the one mechanism that connects an attestation to an answer.

---

## 1. Crates

| Crate | Responsibility |
|---|---|
| `cordon-crypto` | AES-256-GCM, Ed25519, HKDF-SHA256 key hierarchy, constant-time comparison, zeroizing secret types, a canonical encoding for values a verifier must reproduce, TPM 2.0 and AMD SEV-SNP structure parsing and verification, and the client-side attestation verifier. |
| `cordon-audit` | Hash-chained, Ed25519-signed, append-only JSONL audit log, and an offline verifier. |
| `cordon-core` | The node and every layer: configuration, state machine, identity, rate limiting, model store, inference engine, model runtimes, output filter, covert-channel detector, timing normalizer, attestation service, confidential-VM report acquisition, integrity monitor, attack detector, metrics, Hub client. |
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

The re-scan is strided rather than run on every chunk. llama.cpp emits roughly a
token per chunk, so re-scanning the accumulated text each time made the work grow
with the square of the response length — seconds of CPU per stream at the
32,768-token ceiling. Release is still computed only from a completed scan of
the whole buffer, so nothing unscanned escapes; text simply arrives in slightly
larger pieces. `finish` always scans in full.

**Streaming is refused while timing normalisation is enabled.** Normalisation
holds a finished response until a bucket boundary; a stream releases text as it
is produced, so the intervals between chunks carry exactly the per-token timing
the setting removes. Delaying only the terminal event would normalise the total
and leave the signal intact. A caller told "no" can use the unary endpoint; a
caller silently served an unnormalised stream cannot.

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
- **Per-boot API key**, 32 random bytes, required on every request, handed over
  in an owner-only temporary file via `--api-key-file`. A command line is
  world-readable through `ps` and `/proc/<pid>/cmdline`, so passing the key as an
  argument would publish it to precisely the local process the key excludes.
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

**Staging.** `stage_plaintext` decrypts shard by shard, streaming to a file
rather than reconstructing the model in memory, and verifies the full-plaintext
digest as it goes. The runtime is then started with memory mapping disabled so it
reads the weights fully into its own address space, and the staged file is erased
at once — and again on drop.

The staging file is created carefully, because the recommended location is a
shared `tmpfs`. `mode(0o600)` applies only when a file is *created*, so a
pre-created world-readable file at the same path would be opened and filled with
the decrypted model; and `open` follows symlinks, so a planted link would choose
where the model went. The path is therefore unlinked first — `remove_file`
removes a symlink rather than following it — and recreated with `O_EXCL` and
`O_NOFOLLOW`, which fails outright if anything raced back in. The directory
itself is narrowed to 0700.

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
Per-client content policy. Constant-time comparison. Drop-zeroization of secret
buffers. TLS 1.3 and mutual TLS with client identity parsed from the verified
certificate.

Attestation reports that a client can verify from the wire, against measurements
it pinned itself, with replay, substituted measurements, a substituted
attestation key and a substituted signing key each rejected. See §6.1.

### Real, but hardware-dependent

**TPM 2.0.** Measurements and quotes come from `tpm2-tools`. A report carries the
`TPMS_ATTEST` structure the TPM signed, so a verifier can check the signature,
confirm `extraData` equals the challenge it issued, and confirm the PCR values
shown hash to the digest the TPM signed for. Parsing and verification are
unit-tested against real signatures; this repository's CI has no TPM, so the
acquisition path is not exercised against hardware here. `cordon doctor` checks
it on a real machine.

**AMD SEV-SNP.** The 1184-byte report, its ECDSA P-384 signature, and the VCEK
certificate chain to a root the verifier pins, all implemented against AMD's
specification and tested with synthetic keys — real signatures over genuinely
formatted structures, with every refusal path covered. Reports are read through
the kernel's `configfs-tsm` interface (Linux 6.7+) rather than an ioctl on
`/dev/sev-guest`, which keeps `#![forbid(unsafe_code)]` intact and costs no
dependency. **Not yet run against real silicon.**

When a hardware measurement source is configured and the hardware is not
reachable, the node **fails to start**. It does not fall back to a software
measurement — a node that quietly downgrades is worse than one that refuses to
boot, because operators believe the stronger claim either way.

### Not a hardware root of trust

`measurement_source = "software_measurement"` derives measurements from Cordon's
build and configuration. It attests that the node is running the configuration
the operator expects. It attests nothing about the platform underneath it, and
an attacker with code execution on the host can reproduce it exactly.

It is confined to Light mode by `CordonConfig::validate`, and it is reported as
`software_measurement` in every attestation report, every response's
`enclave_info`, and the health endpoint, so no caller can mistake it for
hardware attestation.

### What remains

- **Intel TDX and SGX-DCAP.** TDX is reachable through the same kernel interface
  as SEV-SNP; its report format is not yet parsed. SGX-DCAP is not implemented.
- **The AMD Key Distribution Service.** The VCEK request path is built; the fetch
  is left to the caller so an air-gapped node can verify from a cached chain.
- **Revocation.** Neither AMD's CRL nor a TPM vendor's is consulted.
- **Binding a TPM attestation key to genuine hardware.** The endorsement key
  certificate travels with the report and is not walked to a vendor root, so
  `TpmQuoteVerification::ak_is_trusted` is always false. A verified TPM quote
  proves the holder of that key produced it, not that the key is a real TPM's.
  SEV-SNP does chain to a pinned root, and reports `ak_is_trusted: true`.
- **Attestation-gated key release.** The CMK reaches the node from the operator;
  release is not conditioned on a verified quote. Attestation events record
  `key_released: false` rather than implying otherwise.

### 6.1 What binds an attestation to an answer

A quote proves something about a machine. A response signature proves something
about a key. Neither says anything about the other unless the platform's own
signature commits to that key.

Cordon puts a digest over **both** the client's nonce and the node's
response-signing public key into the field the platform signs — `extraData` in a
TPM quote, `REPORT_DATA` in a SEV-SNP report:

```text
challenge = SHA-256("CORDON_ATTEST_CHALLENGE_v1"
                    || len(key) || signing_key_hex
                    || len(nonce) || nonce)
```

A verifier recomputes it from the key the report declares and the nonce it chose
itself, so the node can substitute neither. `AttestationReport::verify` returns a
`VerifiedAttestation` rather than a boolean, because "the measurements matched",
"a platform signed for them" and "the quote binds the signing key" are three
different facts and a single flag reports the weakest while looking like the
strongest. `is_hardware_rooted()` requires the last two.

### 6.2 Canonical encoding

Digests a verifier must reproduce are built with an explicit, versioned,
length-prefixed encoding rather than `serde_json`, and PCR values live in a
`BTreeMap`.

This is not fastidiousness. `serde_json` over a `HashMap` serialises in iteration
order, which Rust randomises per map instance: the node hashed one order and a
client that deserialized the report hashed another, so verification failed on
genuine reports and passed on the node only because the node re-verified the map
it had just built. Struct field order has the same shape of problem more slowly —
reordering two fields in an unrelated refactor would invalidate every deployed
verifier, with no compile error and no failing test.

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
- On an ordinary host, prompts and completions live in process memory an
  attacker with root can read. Buffers zeroize on drop, but not before. This is
  the weakness a confidential VM closes and nothing else does.
- Response *length* is not padded. Timing is normalised; size is not.
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
reproducing it. Attestation events record a digest of the client's nonce rather
than the nonce, so the log does not become a place to look up which client
challenged when.

**What is recorded.** Inference intake and completion, administrative actions,
lifecycle transitions, attestation requests and failures, security events
(refused authorization, a model a client's policy does not admit, a client
suspended for repeated covert-channel detections), weight-integrity violations,
and every read of the audit log itself. That last one matters: the log records
which clients asked for what and how often, so a client that reads it and leaves
no trace turns an accountability record into a surveillance surface.

Two records deliberately state a negative rather than a plausible positive. A
tamper event reports `hsm_zeroized: false`, because Cordon holds no HSM and
withdraws the bundle instead; an attestation event reports `key_released:
false`, because key release is not gated on attestation.

**One writer per directory.** The log directory is claimed exclusively at
startup. Two nodes pointed at one directory both resume from the highest
sequence and both append, forking the chain: two entries claim the same
sequence, and the log then fails verification exactly as though it had been
tampered with. A tamper-evident log that cries tamper over an operational slip
trains people to disbelieve it, so the second writer is refused with a message
naming the holder.

---

## 8. Deployment modes

| Mode | Measurements | mTLS | Console | Egress | Notes |
|---|---|---|---|---|---|
| `light` | any | optional | loopback | permitted | Development. |
| `sovereign_cloud` | hardware | required | refused | permitted | Client VPC. |
| `vault` | hardware | required | refused | refused | Regulated enterprise. |
| `island` | hardware | required | refused | refused | Private network. |
| `dark` | hardware | required | refused | refused | FIPS L4 custody, single tenant. |

`CordonConfig::validate` enforces every invariant at startup, and each check
fails closed. Outside Light mode: a simulation TEE is refused, a software
measurement source is refused, unpinned measurements are refused, mTLS without a
client CA is refused, the console is refused, the placeholder runtime is
refused, and the `CORDON_INSECURE_ADMIN` and `CORDON_ALLOW_UNREGISTERED_MODELS`
development overrides are refused. Vault, Island and Dark additionally require
`outbound_policy = "zero_egress"`, and a SEV-SNP deployment requires a pinned
AMD root.

Egress is worth stating precisely. Cordon is a process and cannot stop packets
leaving a host; what `zero_egress` binds is Cordon's own behaviour — model
downloads are disabled and a non-loopback runtime endpoint is refused, so no
code path in Cordon opens a connection off the machine. The firewall is still
the firewall's job.

---

## 9. Threat model

### Defended

| Adversary | Defence |
|---|---|
| A network attacker | TLS 1.3, mutual TLS, certificate-bound identity. |
| An unauthorized client | Enrolment, per-client policy, certificate pinning. |
| A client exceeding its budget | Token-bucket limits with up-front reservation. |
| A client probing for other sessions | Session ownership checked before any state is touched. |
| A client extracting data through output | Per-client content policy, covert-channel analysis, timing normalisation. |
| An operator rewriting the audit log | Hash chain plus signatures under a client-derived key. |
| An operator reading model weights | Bundle encryption under a client-held key. |
| An operator running unauthorized admin commands | Ed25519 signatures over canonical, non-replayable commands. |
| Weights modified at rest | Continuous integrity monitoring; a stale verdict removes the model from service. |
| Denial of service by resource exhaustion | Bounded bodies, sessions, connections, replay tables, detector maps, and concurrency; handshake and request deadlines. |
| One client denying service to another | Per-client session share, per-client rate limits. |
| A client reading another's traffic pattern | `log_export_allowed`; audit reads are themselves audited. |

### Not defended

| Adversary | Why |
|---|---|
| Root on the node, outside a confidential VM | Can read process memory. `measurement_source = "sev_snp"` is what closes this; a TPM does not. |
| An attacker holding the CMK | It is the root of trust by construction. |
| Physical attacks on the host | Out of scope. SEV-SNP raises the cost considerably; it is not a claim of physical security. |
| A malicious model | Cordon controls access to a model, not what the model says. |
| A compromised llama.cpp | Cordon contains it to loopback; it does not sandbox it. |
| An operator substituting model weights and their manifest together | Bundle manifests carry vendor and client signature fields that nothing currently verifies. Integrity monitoring detects a shard changed under a fixed manifest, not both changed together. |
| Traffic analysis of response length | Timing is normalised; response size is not padded. |

---

## 10. Concurrency and resource bounds

Every structure an untrusted caller can grow is bounded:

| Structure | Bound |
|---|---|
| Request body | `limits.max_request_bytes`, enforced before buffering. |
| Messages and prompt size | `limits.max_messages`, `limits.max_prompt_chars`. |
| Concurrent generations | A semaphore; excess returns `503` rather than queueing. |
| Sessions, in total | A capacity ceiling; idle sessions are reclaimed and zeroized. |
| Sessions, per client | A share of that ceiling, so one caller cannot consume it. |
| Replay-detection hashes | A capacity ceiling; the table resets rather than growing. |
| Attack-detector maps | A capacity ceiling per map, evicting lapsed entries first; every map pruned on a timer. |
| Events inside one detector counter | A cap; a saturated counter still reports above every threshold. |
| Rate-limit buckets | Pruned when stale. |
| Client suspensions | Expired entries dropped on a timer. |
| TLS connections | A semaphore, plus a handshake deadline. |
| Audit tail reads | Newest-first, reading only as far as needed. |
| Streaming filter work | Strided re-scan, so cost is not quadratic in response length. |

Admission returns `Overloaded` immediately when full, so callers see
backpressure rather than unbounded latency.

Two of these read as bookkeeping and are not. The per-client session share
exists because a session is opened by naming any unused identifier and lives
until it goes idle, so without it one client could fill the table in a burst and
lock every other client out for the idle timeout. And the detector-map sweep is
rate-limited because sweeping on every insert once a map is full makes admission
quadratic in the number of distinct keys — a cheaper denial of service than the
memory growth the cap was added to prevent.

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
- **Blocking work on an async task.** Hashing a bundle, verifying the chain, and
  fsyncing all block. `spawn_blocking`, or a tokio worker stalls and every
  request scheduled behind it stalls with it.
- **Anything a verifier must reproduce.** It goes through
  `cordon_crypto::canonical`, never `serde_json`. A `HashMap` in a hashed
  structure is a latent, intermittent verification failure that passes on the
  node.
- **New configuration.** If nothing reads it, do not add it. A field an operator
  can set and Cordon ignores is a defence they believe they have.
- **New audit event types.** Write them from somewhere, or do not declare them.
  Six of the nine event types were declared and never emitted, which made
  `tracing` the only record of the events most worth having a durable one.
