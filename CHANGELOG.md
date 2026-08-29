# Changelog

All notable changes to Cordon are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] — 2026-08-30

First public release. This version replaced several mechanisms that reported
success without performing the work their names described, so the notes below
separate what became *real* from what became *stricter*.

### Made real

- **Client identity is parsed from the certificate.** `parse_client_identity_from_cert`
  previously hashed the certificate DER and synthesised a client ID, a subject
  DN, and validity dates from the clock. It now parses X.509 with
  `x509-parser`, taking the client ID from the subject CN or the first URI/DNS
  SAN, and the validity window from the certificate. A certificate that yields
  no usable name is refused rather than given an invented identity.

- **The client registry is loaded.** `IdentityRegistry` was constructed empty
  and never populated, so every client silently received the permissive default
  policy and the whole authorization layer was inert. It now loads from
  `client_registry_path`, and once any client is enrolled, unenrolled clients
  are denied.

- **The model runtime is supervised.** Cordon spawns `llama-server` itself on
  loopback with an ephemeral port, a per-boot API key, and `--no-webui`, then
  verifies after startup that the runtime does not serve HTML at `/` and refuses
  to run if it does. Previously Cordon proxied to a URL and had no way to know
  what else that endpoint exposed.

- **Model loading decrypts and erases.** `load_model` used to write decrypted
  weights to a temporary file, delete it, and set a boolean. Bundles are now
  decrypted shard by shard to a mode-0600 staging file, loaded with memory
  mapping disabled so the runtime reads them fully into its own memory, and the
  file is erased immediately afterwards.

- **Streaming streams.** The streaming endpoint ran inference to completion and
  then replayed the text in chunks. It now consumes the runtime's token stream
  and filters incrementally with a trailing holdback, so a pattern that
  completes in a later chunk is caught before any part of it is transmitted.

- **Backends are asynchronous.** The HTTP backend spawned an OS thread and a
  Tokio runtime per request and then joined it, which blocked the calling worker
  anyway, ignored the request timeout, and built a new client per call. It is
  now a pooled async client with deadlines and native streaming.

- **Audit anchoring is signed.** `POST /v1/audit/anchor` returned the tail hash
  labelled `merkle_root` and did nothing else. `GET /v1/audit/anchor` now returns
  a signed chain head with the payload layout it committed to.

### Removed

- `POST /v1/admin/key-rotate` and `POST /v1/admin/update` returned success and
  performed no rotation or update. Removed rather than left as stubs.
- Four duplicated UI pages, roughly a thousand lines of copied inline CSS,
  replaced by one operator console.
- An orphaned `tests/` directory at the workspace root that no crate compiled.

### Security

- **Attestation can no longer verify itself.** `POST /v1/attestation/verify`
  accepted expected measurements in the request body, so any caller could read
  the node's measurements from `GET /v1/attestation` and hand them back to be
  marked verified — unlocking the attestation gate. Expectations are now pinned
  by the operator in configuration; the endpoint takes only a nonce; a node with
  nothing pinned reports `verified: false`.

- **Verification is per client.** A single global flag meant one caller's
  verification unlocked the node for everyone, permanently. Verification is now
  recorded per client and expires with the re-attestation interval.

- **Every stateful endpoint authenticates.** `health/detailed`, `models`,
  `audit/*`, and `attestation/*` never resolved a client. Under `--no-tls` they
  were entirely open.

- **`/metrics` is enforced on loopback.** The router carried a comment claiming
  this was "enforced at the network layer"; nothing enforced it. Prometheus
  output names clients, models, and traffic volumes.

- **A remote crash in the output filter is fixed.** `MaxLength` truncation
  sliced a `String` at a byte offset derived from a character count. With
  `panic = "abort"`, any output containing a multi-byte character near the limit
  would abort the process.

- **Path traversal in model provisioning is fixed.** `POST /v1/models` took an
  arbitrary filesystem path. It now takes a single directory name inside the
  configured model store.

- **Unencrypted bundles are refused.** Manifests are validated structurally: an
  algorithm other than AES-256-GCM, an all-zero nonce, a nonce reused across
  shards, matching plaintext and ciphertext digests, or a shard path escaping
  the bundle directory are each grounds for refusal.

- **Error responses no longer leak internals.** Node faults are generalised
  before they reach the wire; filesystem paths, upstream endpoints, and key
  material identifiers stay in the log.

- **HSTS is not sent over plaintext.** It was, which would pin a development
  host into HTTPS-only in every browser that saw it.

- **The private key is written mode 0600.** Development certificate generation
  wrote it with default permissions.

- **Development overrides are refused outside Light mode.**
  `CORDON_INSECURE_ADMIN` and `CORDON_ALLOW_UNREGISTERED_MODELS` now fail
  startup in any mode that claims a security guarantee.

- **Sessions cannot be probed.** Resuming a session is refused before any state
  is touched, so a caller cannot disturb or detect another client's session by
  guessing its identifier.

- **Input hashing is prefix-free.** Message fields are length-prefixed, so two
  distinct conversations cannot produce the same audit-log input hash.

### Performance

- **The per-request integrity check is gone.** `ensure_servable` ran a full
  SHA-256 over sampled shards *and* an AES-GCM decryption of shard 0 on every
  inference request — roughly 450 MB of cryptography per request for a 229 MB
  model. It now consults a cached verdict maintained by the background monitor,
  and performs no I/O.

- **Integrity checks and provisioning stream.** Hashing, decryption, and
  encryption process a shard at a time, so memory is bounded by shard size
  rather than model size.

- **Audit tail reads are bounded.** `GET /v1/audit/tail` loaded every entry into
  memory and discarded all but the last few. It now reads newest-first, stopping
  once it has enough.

- **Chain verification moved off the request path.** `health/detailed` verified
  the whole chain inline on every call. It now reads a verdict refreshed on a
  timer.

- **Unbounded structures are bounded.** The replay-detection map, the session
  table, and the connection count all had no ceiling.

### Added

- `cordon pull` — fetch GGUF models from the Hugging Face Hub, with resumable
  downloads, quantisation selection, revision pinning, and verification against
  the digest the Hub publishes.
- `cordon run` — fetch-free single command to serve a pulled model.
- `cordon models` and `cordon remove`.
- `cordon doctor` — check the runtime, models, TPM, key material, and the
  security posture a configuration will actually deliver.
- `cordon attest --pin` — render a node's current measurements as a
  configuration block, ready to review and pin.
- `GET /v1/health/runtime` — recent model-runtime output, for diagnosing a
  runtime that will not start.
- `POST /v1/admin/suspend-client`.
- A rebuilt operator console: node posture, a chat console that exercises the
  real pipeline, and an endpoint reference. Loopback-only, opt-in, and refused
  outside Light mode.
- Graceful shutdown on `SIGINT` and `SIGTERM`.
- Apache-2.0 licence, contribution guide, security policy, and code of conduct.

### Changed

- Configuration gained `[runtime]`, `[ui]`, `[attestation]`, and `[limits]`
  sections; `TeeConfig.halt_on_attestation_failure` moved to
  `attestation.halt_until_verified`.
- `CordonNode::build` is now async, because it starts the model runtime.
- `MockInferenceBackend` became `DeterministicBackend`, and its output is
  prefixed `[cordon:no-model]` so it cannot be mistaken for generated text.
- `CORDON_CMK_FILE` is preferred over `CORDON_CMK`, which now warns.
- Test names state the property under test rather than the function called.
