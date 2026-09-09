# Changelog

All notable changes to Cordon are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The theme of this release is the distance between what the configuration and the
documentation described and what the code did. Some of that distance was a
missing feature; some of it was a defence that reported success without
performing the work its name described.

### Cordon can now be a trusted execution environment

`attestation.measurement_source = "sev_snp"` runs Cordon inside an AMD SEV-SNP
guest, where the model runtime, the weights and the prompts are all inside the
encrypted VM and the hypervisor is outside it. That closes the one adversary the
threat model has always had to concede: root on the node. A TPM never closed it
— a TPM attests how a machine booted and leaves the running machine to whoever
owns it.

- Report parsing, ECDSA P-384 signature verification, and a VCEK certificate
  chain walk to a root the verifier pins. A report is refused if the guest was
  launched debuggable (the hypervisor could then read its memory), if the
  platform is below the pinned TCB floor, or if no AMD root is pinned.
- Reports are read through the kernel's `configfs-tsm` interface (Linux 6.7+),
  so no ioctl and no `unsafe`. The same path reaches Intel TDX, whose report
  format is not yet parsed.
- Implemented against AMD's specification and tested with synthetic keys — real
  signatures over genuinely formatted structures, every refusal path covered.
  **Not yet run against real silicon.** See `SECURITY.md`.

### AWS Nitro Enclaves — the verifier, and an honest account of the rest

`attestation.expected.nitro` pins an AWS Nitro root and a set of PCRs, and
Cordon will verify an attestation document against them: the COSE_Sign1
envelope, the ES384 signature over the `Sig_structure` (not the payload — a
signature that did not cover the protected header would let an attacker rewrite
the algorithm after the fact), the certificate chain to the pinned root, the
PCRs, the challenge binding, and a freshness bound. Each is reported as a
separate fact, because "correctly signed by the wrong party" and "genuine
hardware running the wrong image" call for different responses.

The CBOR reader is written here rather than taken from a crate, for the same
reason the canonical encoder is: an attestation document is parsed *before* its
signature can be checked, which makes it the most hostile input Cordon accepts.
The reader refuses indefinite-length items, checks every declared length against
the bytes actually remaining before allocating, bounds depth and item count,
refuses trailing bytes and duplicate keys, and accepts only the shapes a Nitro
document uses. A general-purpose decoder is built to accept everything legal; a
verifier wants the opposite.

**Cordon cannot run inside a Nitro Enclave, and says so at startup.** An enclave
reaches the Nitro Security Module by `ioctl` on `/dev/nsm`, has no persistent
storage, and has no network interface but vsock. Cordon's audit log is a
hash-chained file `fsync`ed before each request is processed and its API is a
TLS listener; neither survives that without being redesigned around vsock and an
external log sink. A node configured with `measurement_source = "nitro_enclave"`
refuses to start rather than coming up announcing hardware attestation it would
fail to produce on the first request — which is the exact failure mode the rest
of this release is about. Not yet run against a real Nitro Security Module.

The chain walk SEV-SNP and Nitro both need now lives in one place, so the two
sources cannot drift apart on what "chains to a pinned root" means.

### Attestation reports are now verifiable at all

Three defects meant a client could not verify a report, which is the only thing
a report is for.

- **The report's digest was not reproducible.** It was computed with
  `serde_json` over a `HashMap`, whose iteration order Rust randomises per
  instance. The node hashed one order and a client that deserialized the report
  hashed another, so verification failed on genuine reports — and passed on the
  node only because the node re-verified the map it had just built. Digests a
  verifier must reproduce now use an explicit, versioned, length-prefixed
  encoding, and PCR values live in a `BTreeMap`.
- **The TPM quote was unverifiable as delivered.** `tpm2_quote` produces the
  signed `TPMS_ATTEST` structure and a signature over it; Cordon read both and
  discarded the message, shipping a signature with nothing to check it against.
  The message now travels with the report, and `cordon-crypto` parses the TPM
  wire structures and checks the signature, the challenge, and that the PCR
  values shown are the ones the TPM signed for.
- **Nothing connected an attestation to an answer.** The platform's signature
  now commits to a digest over both the client's nonce and the node's
  response-signing key, so verifying the quote establishes that the key signing
  your inference was resident on the platform you just measured.

`AttestationReport::verify` returns what was established rather than a boolean,
`GET /v1/attestation` accepts a `?nonce=`, and `cordon attest` verifies locally
instead of asking the node whether it approves of itself.

### Security fixes

- **The runtime API key was passed on a command line**, where `ps` and
  `/proc/<pid>/cmdline` publish it to every local user — the exact process the
  key exists to exclude. It now goes in an owner-only file via `--api-key-file`.
- **Staged plaintext weights could be redirected or exposed.** `mode(0o600)`
  applies only when a file is created, so a pre-created world-readable file at
  the staging path was opened and filled with the decrypted model; and `open`
  follows symlinks, so a planted link chose where the model went. The path is
  now unlinked first and recreated with `O_EXCL` and `O_NOFOLLOW`, in a 0700
  directory.
- **TPM helper output went to fixed names under `/tmp`**, allowing the same
  symlink and clobber attacks and making two concurrent attestation requests
  overwrite each other's files. Each invocation now gets a private 0700
  directory.
- **`fsync_on_write` did not fsync.** It flushed the `BufWriter` into the page
  cache and returned, so "log before process" did not survive a power loss.
- **Audit segments were created world-readable.**
- **Five attack-detector maps grew without limit.** They are keyed on a client
  ID, a peer fingerprint, or the digest of a prompt, and `cleanup` pruned only
  blocks and suspensions — so a client varying its prompt added an entry per
  request, for the life of the process. Each map is now capacity-bounded, the
  sweep is rate-limited so admission does not become quadratic, and all of them
  are pruned.
- **One client could consume the whole session table** and lock every other
  client out for the idle timeout, because a session is opened by naming any
  unused identifier. Clients now get a share of it.
- **`cordon run --bind 0.0.0.0` published unauthenticated inference.** Plain
  HTTP, identity from a header any caller can set, behind nothing but a log
  line. Refused unless `--insecure-bind` says otherwise.

### Correctness fixes

- **Log rotation scrambled the chain.** Segment filenames carried a
  whole-second timestamp and a random UUID, and every reader walked the
  directory in filename order — so two rotations inside the same second sorted
  at random, and the chain was reconstructed out of order and reported broken on
  a log nobody had touched. Segments now lead with a zero-padded sequence, and
  readers order by each entry's own sequence rather than by filename.
- **Two nodes on one audit directory forked the chain.** Both resumed from the
  highest sequence and both appended; the log then failed verification as though
  it had been tampered with. A tamper-evident log that cries tamper over an
  operational slip trains people to disbelieve it, so the directory is now
  claimed exclusively.
- **SSE decoding dropped bytes.** A multi-byte character split across TCP reads
  had its remainder discarded rather than carried into the next read, despite a
  comment saying otherwise.
- **The streaming filter was quadratic.** It re-scanned everything received so
  far on every chunk — at roughly a token per chunk, seconds of CPU per stream
  at the 32,768-token ceiling. The scan is now strided, and widens as the
  response grows.
- **The integrity monitor blocked a tokio worker,** calling a function
  documented "never directly from an async path" directly from one.
- **Streaming diverged from the unary path.** Timing normalisation was never
  applied to a stream, and the audit record logged an empty policy-rule list, so
  a redacted stream was recorded as though no policy had applied. Streaming is
  now refused while normalisation is enabled — a stream cannot honour it, since
  the intervals between chunks carry the signal — and the audit record carries
  what the filter actually did.

### Made real

- **Per-client content policy.** The filter engine — redact, truncate, block,
  PII categories, topic keywords — was fully implemented and unreachable from
  any configuration. Every client on every node got one built-in rule that
  flagged PII and changed nothing. There is now a `content_policy.default_path`
  and a per-client `content_policy_path` in the registry, compiled at startup.
- **`admin_allowed` and `log_export_allowed`.** Both appear in the documented
  client registry and neither was read, so any authenticated client could read
  the audit log — which records who asked for what and how often — and any
  client holding an admin signature could use it.
- **`outbound_policy`.** Vault, Island and Dark are documented as having no
  outbound access and nothing checked it. Those modes now require
  `zero_egress`, and declaring it disables model downloads and refuses a
  non-loopback runtime endpoint.
- **Six of the nine audit event types.** Attestation requests, security alerts,
  tamper findings and log reads went to `tracing` and nowhere else — not
  hash-chained, not signed, gone with the process. They are recorded now,
  including every read of the audit log itself.

### `cordon serve` ignored the configuration file it was given

Three settings an operator writes in a configuration file were overwritten
before the node read them, because the command-line flags that shadow them
carried clap `default_value`s — and a default is indistinguishable from a value
the operator typed.

- **`network.bind_address` and `network.api_port`.** `--bind` defaulted to
  `0.0.0.0:8443`, which always won. An operator who confined a node to loopback
  in the configuration got one listening on every interface. That is the same
  exposure `cordon run --bind 0.0.0.0` was hardened against in this release,
  arrived at from the opposite direction: there the operator asked for it, here
  they asked for the opposite and got it anyway.
- **`audit.log_path` and `model_store.path`**, overwritten from `--data-dir`,
  which defaulted to `/var/lib/cordon`. The configured audit directory was
  never created and the log went somewhere else.
- **`network.tls_cert_path` and `network.tls_key_path`**, likewise.

Each flag now takes no default. Given, it wins; absent, the configuration
stands; absent with no configuration file, the documented default applies. The
precedence lives in one function with tests, including that an IPv6
`bind_address` is bracketed before its port and that a `bind_address` which is
not an address to listen on is refused naming the values that caused it.

### Removed

Configuration Cordon did not act on, because a field an operator can set and
Cordon ignores is a defence they believe they have: `inbound_whitelist`,
`hardware_firewall`, `smartnic_acl`, `mgmt_channel`,
`constant_time_enforcement`, `memory_zeroize_on_completion`,
`response_size_padding` (and the `pad_response` helper it implied, which was
written, tested, and never called), `re_attestation_interval_hours`,
`halt_on_attestation_failure`, `cache_partitioning`, `boot.pcr_policy`,
`client_kv_cache_isolation`, `max_input_tokens`, `audit.log_format`,
`audit.export_method`, `audit.retention_days`, `signing_key_from_enclave`, the
whole `[updates]` section, and the HSM provider, slot and PIN fields that
together looked like PKCS#11 integration. Unknown keys are ignored, so an
existing configuration still loads — it simply no longer describes anything.

Also removed: `ui/landing_template.html`, `ui/chat.html`, `ui/docs.html`,
`ui/endpoints.html` and `ui/_shared.css`, which nothing referenced; and
`tests/integration_tests.rs` at the repository root, which the virtual workspace
manifest meant was never compiled — 541 lines that looked like coverage and were
not.

### The operator console

Gains an attestation panel that issues a nonce, requests a report bound to it,
and reports what that report does and does not establish as four separate facts
rather than one light — then renders the `[attestation.expected]` block ready to
paste. And an audit panel: chain head, verdict, recent entries, verify, anchor.
Both are the API's own handlers mounted on the console listener, so the console
cannot show an operator something a client would not receive, and its audit
reads are recorded like anyone's.

### Tests

`cordon-audit`, the crate implementing the tamper-evident chain, had no tests of
its own. It has seventeen, and one of them found the rotation bug above. The
workspace suite is 383 tests, up from 170.

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
