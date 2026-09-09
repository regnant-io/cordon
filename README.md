# Cordon

**A confidential inference control plane.**

Cordon sits in front of a local language model runtime and makes every request
accountable: identity bound to a client certificate, per-client policy and rate
limits, content filtering applied before a single token is released, a
tamper-evident audit log signed with a key the operator cannot forge, and an
Ed25519 signature over every response that a client can verify offline.

It runs the model itself. `cordon run` starts `llama-server` as a child process
bound to loopback on an ephemeral port with its own web UI unreachable, so
Cordon is the only way in. There is no second door.

```bash
cargo build --release
cordon pull HuggingFaceTB/SmolLM2-360M-Instruct-GGUF
cordon run smollm2-360m-instruct-gguf
```

---

## Contents

- [What Cordon actually does](#what-cordon-actually-does)
- [What is real, and what is not](#what-is-real-and-what-is-not)
- [Where the trust lives](#where-the-trust-lives)
- [Install](#install)
- [Getting a model](#getting-a-model)
- [Deployment modes](#deployment-modes)
  - [Light — development](#light--development)
  - [Sovereign Cloud — your VPC](#sovereign-cloud--your-vpc)
  - [Vault — regulated enterprise](#vault--regulated-enterprise)
  - [Island — private network](#island--private-network)
  - [Dark — air-gapped](#dark--air-gapped)
- [Provisioning keys](#provisioning-keys)
- [Encrypting a model bundle](#encrypting-a-model-bundle)
- [Verifying what a node tells you](#verifying-what-a-node-tells-you)
- [The API](#the-api)
- [The operator console](#the-operator-console)
- [Configuration reference](#configuration-reference)
- [Environment variables](#environment-variables)
- [Tools](#tools)
- [Troubleshooting](#troubleshooting)

---

## What Cordon actually does

A request arrives and passes through, in order:

| Stage | What it enforces |
|---|---|
| **State** | The node is not quarantined, locked, or zeroized. |
| **Attestation gate** | In hardware modes, *this client* has verified the node's measurements. |
| **Source block** | The peer is not blocked by the attack detector. |
| **Identity** | The certificate is within its validity window, and the client is enrolled. |
| **Suspension** | The client is not serving a suspension. |
| **Model permission** | The client's policy admits this model. |
| **Request limits** | Message count, prompt size, and token budget are within bounds. |
| **Model store gate** | The bundle is registered and passed an integrity check recently. |
| **Rate limit** | A request slot and an output-token reservation are available. |
| **Admission** | A concurrency slot and a session. |
| **Audit pre-write** | The request is logged *before* it is processed. A failed write refuses the request. |
| **Generate** | The model runtime produces output. |
| **Settle** | Unused output-token reservation is refunded. |
| **Output filter** | The policy enrolled *for this client* redacts, truncates, or blocks. |
| **Covert channel** | Statistical analysis of the text about to be released. |
| **Timing** | Latency is normalised to a bucket or floor. |
| **Audit post-write** | The completed record, with the true policy and covert-channel values. |
| **Sign** | Ed25519 over a canonical, reconstructable payload. |

The streaming endpoint runs the identical pipeline. Chunks pass through the
filter incrementally with a trailing holdback, so a pattern that only completes
in a later chunk — a card number whose last digits arrive next — is caught
before any part of it has left the node.

Streaming is refused while `side_channel.timing_normalization` is enabled. A
stream releases text as it is produced, so the intervals between chunks carry
exactly the per-token timing normalisation exists to remove; serving one under
that setting would be serving a guarantee the transport cannot keep. Use
`POST /v1/inference`, which is normalised.

---

## What is real, and what is not

Cordon is a control plane. On an ordinary host it is *only* a control plane, and
being precise about that line is the point of this section. Run it inside a
confidential VM and the line moves — see [Where the trust
lives](#where-the-trust-lives) below, which is the honest answer to "is this a
TEE?".

### Real, and exercised by the test suite

- **AES-256-GCM** shard encryption with per-shard keys, fresh nonces, and both
  plaintext and ciphertext digests checked on every decryption.
- **HKDF-SHA256 key hierarchy** with domain separation. A client holding the
  Client Master Key derives the same public halves and can verify the node's
  signatures without trusting the node.
- **Ed25519** signatures over inference responses, attestation reports, audit
  entries, and audit anchors.
- **A hash-chained, signed, append-only audit log** with an offline verifier.
  Rewriting, deleting, or renumbering an entry breaks the chain, and
  `cordon-verify-log` detects it without contacting the node.
- **Attestation reports a client can verify independently.** A report carries
  the structure the platform signed, the key that signed it, and the node's
  response-signing key, all bound to a nonce the *client* chose. Replay,
  substituted measurements, a substituted attestation key, and a substituted
  signing key are each rejected.
- **TLS 1.3 and mutual TLS**, with client identity parsed from the verified
  certificate's subject — not from a header.
- **Per-client content policy.** Redaction, truncation, blocking, PII
  categories and topic keywords, compiled at startup and applied per client on
  both the unary and the streaming path.
- **A supervised model runtime** on loopback with an ephemeral port, an API key
  passed by file rather than on a command line, and a startup check that refuses
  to run if the runtime serves a web UI.

### Real, but hardware-dependent

- **TPM 2.0 measurements and quotes,** through `tpm2-tools`. A report carries
  the `TPMS_ATTEST` structure the TPM signed, so a verifier can check the
  signature, confirm the quote answers their challenge, and confirm the PCR
  values shown are the ones the TPM signed for. The parsing and verification are
  unit-tested against real signatures; this repository's CI has no TPM, so
  confirm the acquisition path on your own hardware with `cordon doctor`.

- **AMD SEV-SNP attestation.** Report parsing, signature verification, and the
  VCEK certificate chain are implemented against AMD's specification and tested
  with synthetic keys — real signatures over genuinely formatted structures,
  with every refusal path covered. **They have not been run against real
  silicon.** Treat that exactly as you treat the TPM path.

### Not implemented

- **Full SGX-DCAP quote verification.** Intel TDX is reachable through the same
  kernel interface Cordon uses for SEV-SNP, and its report format is not yet
  parsed.
- **Fetching the VCEK from AMD's Key Distribution Service.** The request path is
  built; the fetch is left to the caller so an air-gapped node can verify from a
  cached chain.
- **Certificate revocation.** Neither AMD's CRL nor a TPM vendor's is consulted.
- **Binding a TPM attestation key to genuine hardware.** Cordon carries the
  endorsement key certificate and does not walk it to a vendor root, so a
  verified TPM quote proves the holder of that key produced it — not that the
  key belongs to a real TPM. SEV-SNP *does* chain to a root you pin.
- **HSM integration.** Cordon talks to no HSM. The Client Master Key arrives
  through `CORDON_CMK_FILE`; where that file comes from is your arrangement.
  `hsm.fips_level` is a declaration Cordon does not verify.

### Deliberate, bounded weaknesses

- **Staged plaintext weights touch disk.** An encrypted bundle is decrypted to a
  file created with `O_EXCL` and `O_NOFOLLOW` at mode 0600 in a 0700 directory,
  the runtime loads it with memory mapping disabled, and the file is erased
  immediately. The window is bounded and documented; it is not zero. Set
  `model_store.staging_dir` to a `tmpfs` mount where that matters.

- **Prompts live in process memory.** Buffers zeroize on drop, but on an
  ordinary host an attacker with root can read them first. This is the one a
  confidential VM closes, and nothing else does.

- **Response length is not padded.** Timing is normalised; size is not.

Everything above is stated the same way in `ARCHITECTURE.md` §6 and in the
`SECURITY.md` threat model. If you find a place where the code claims more than
this, that is a bug — please report it.

---

## Where the trust lives

The difference between the measurement sources is the whole subject. Choose
with `attestation.measurement_source`.

| | `software_measurement` | `tpm2` | `sev_snp` | `nitro_enclave` |
|---|---|---|---|---|
| Attests the configuration Cordon runs | yes | yes | yes | yes |
| Attests how the machine booted | no | yes | yes | yes |
| Signed by hardware you can check | no | yes | yes | yes |
| Chains to a vendor root you pinned | no | not yet | yes | yes |
| **Host root cannot read prompts** | **no** | **no** | **yes** | **yes** |
| Permitted outside Light mode | no | yes | yes | yes |
| **Cordon can run on it today** | **yes** | **yes** | **yes** | **no** |

The fifth row is the one that matters, and the last is the one that constrains
it. A TPM tells you a machine booted software you expect; it does not stop
whoever owns that machine from reading the memory of what is running on it.
Under SEV-SNP, Cordon, the model runtime, the weights and the prompts are all
inside an encrypted guest and the hypervisor is outside it — so "the operator
cannot read your prompts" stops being an aspiration.

**`nitro_enclave` is a verifier, not a deployment target.** Cordon parses and
checks AWS Nitro attestation documents — the COSE signature, the chain to a root
you pinned, the PCRs, the challenge binding, the freshness — so a client can
verify one, and a node relaying one can be held to it. Cordon cannot *run*
inside a Nitro Enclave: an enclave has no persistent storage for the audit log
and no network interface for the API, both of which Cordon's design rests on. A
node configured for it refuses to start and says so. See
[SECURITY.md](SECURITY.md) for the detail.

Whichever source you use, the platform's signature commits to a digest over
**both** the client's nonce and the node's response-signing key:

```text
report_data / extraData = SHA-256("CORDON_ATTEST_CHALLENGE_v1"
                                  || len(key) || signing_key_hex
                                  || len(nonce) || nonce)
```

That binding is what connects an attestation to an answer. Without it a quote
proves something about a machine, a response signature proves something about a
key, and nothing joins the two. Recompute it from
`report.combined.tee_quote.enclave_signing_key_hex` and the nonce you sent, and
check it against the quote.

### Running under SEV-SNP

```toml
[attestation]
measurement_source = "sev_snp"
halt_until_verified = true

[attestation.expected]
# The guest launch measurement, from `cordon attest --pin`.
mrenclave = "…96 hex characters…"

[attestation.expected.sev_snp]
# AMD's root, base64 DER. Pinned by you: a chain that ships its own root
# proves only that it is internally consistent.
amd_root_der_b64 = "…"
# Refuse a platform below the patch level you have reviewed.
min_bootloader_svn = 4
min_snp_svn        = 20
min_microcode_svn  = 210
# A debuggable guest's memory is readable by the hypervisor.
refuse_debuggable_guest = true
```

Cordon reads the report through the kernel's `configfs-tsm` interface (Linux
6.7+), so it needs no ioctl and keeps `#![forbid(unsafe_code)]`. A node
configured this way refuses to start if it is not in a confidential VM, if the
guest was launched debuggable, or if no AMD root is pinned.

### Verifying a Nitro Enclaves document

The pins a verifier needs, for the case where a Nitro attestation document
reaches Cordon from elsewhere:

```toml
[attestation.expected.nitro]
# AWS's Nitro Enclaves root CA, base64 DER. Download it once, check its
# fingerprint against AWS's published value, and commit it — the document
# carries its own copy of the root, which is exactly why you cannot use that one.
root_der_b64 = "…"
# How stale a document may be. The challenge nonce is the primary defence
# against replay; this bounds a document presented outside an exchange.
max_age_seconds = 300

[attestation.expected.nitro.pcr_values]
# PCR0 is the enclave image. Pinning the root establishes "some genuine Nitro
# enclave"; PCR0 is what makes it "the enclave you built", so it is required.
0 = "…96 hex characters…"
# PCR1 is the kernel and bootstrap, PCR2 the application. Optional.
1 = "…"
2 = "…"
```

PCR3 (IAM role) and PCR4 (parent instance ID) tie a deployment to one role or
one machine. That is occasionally what you want and usually not.

---

## Install

### From source

```bash
git clone https://github.com/cordon-project/cordon
cd cordon
cargo build --release
```

Binaries land in `target/release/`: `cordon`, `cordon-keygen`,
`cordon-provision`, `cordon-verify-log`.

### The model runtime

Cordon supervises [llama.cpp](https://github.com/ggml-org/llama.cpp)'s
`llama-server`. Install it and put it on `PATH`, or point Cordon at it:

```bash
export CORDON_LLAMA_SERVER=/opt/llama.cpp/llama-server
```

A build recent enough to accept `--no-webui` is strongly preferred: it removes
the runtime's web UI from the response path entirely. Without that flag Cordon
still binds the runtime to loopback on an ephemeral port behind a required API
key, and refuses to start if the runtime answers `/` with HTML.

### Check your machine

```bash
cordon doctor
```

`doctor` reports what is missing, what is weak, and the command that fixes each
one. It exits non-zero if the node would not start.

---

## Getting a model

Cordon serves GGUF models and fetches them from the Hugging Face Hub.

```bash
# Best available quantisation
cordon pull HuggingFaceTB/SmolLM2-360M-Instruct-GGUF

# A specific quantisation
cordon pull Qwen/Qwen2.5-7B-Instruct-GGUF:Q4_K_M

# Pinned to a commit, so a later pull is reproducible
cordon pull Qwen/Qwen2.5-7B-Instruct-GGUF@a1b2c3d:Q4_K_M

# The hf.co/ prefix is accepted and ignored
cordon pull hf.co/HuggingFaceTB/SmolLM2-360M-Instruct-GGUF
```

Downloads resume if interrupted — rerun the same command. The content digest the
Hub publishes for the file is verified before it is admitted, and a repository
that publishes none is reported as unverified rather than silently trusted.

```bash
cordon models             # what is available locally
cordon remove <id>        # delete one
```

Gated repositories need a token:

```bash
export HF_TOKEN=hf_...
```

Set `HF_ENDPOINT` to use a mirror or an enterprise Hub.

> Pulling reaches the public internet, so it is available only in Light and
> Sovereign Cloud modes. Air-gapped deployments acquire models from physical
> media through `cordon-provision`.

---

## Deployment modes

Five modes, from a laptop to an air-gapped rack. Each mode's invariants are
enforced at startup: a configuration that cannot deliver its mode's guarantees
is refused rather than degraded.

| Mode | Measurements | mTLS | Console | Egress | Runtime |
|---|---|---|---|---|---|
| `light` | any | optional | allowed, loopback | permitted | any |
| `sovereign_cloud` | `sev_snp` or `tpm2` | required | refused | permitted | local |
| `vault` | `sev_snp` or `tpm2` | required | refused | refused | local |
| `island` | `sev_snp` or `tpm2` | required | refused | refused | local |
| `dark` | `sev_snp` or `tpm2` | required | refused | refused | local |

Every mode above Light requires pinned measurements, a Client Master Key, and
`network.outbound_policy = "zero_egress"` where the table says egress is
refused. Which measurement source you choose decides whether the deployment can
also claim the operator cannot read prompts — see
[Where the trust lives](#where-the-trust-lives).

### Light — development

No hardware requirements. Client identity comes from a header, so **anyone who
can reach the port can claim any client ID**. Bind it to loopback.

```bash
cordon pull HuggingFaceTB/SmolLM2-360M-Instruct-GGUF
cordon run smollm2-360m-instruct-gguf
```

That is the whole setup. `cordon run` starts the supervised runtime, serves the
API on `127.0.0.1:8477`, and opens the operator console on `127.0.0.1:8478`.

```bash
curl -s localhost:8477/v1/health

curl -s -X POST localhost:8477/v1/inference \
  -H 'content-type: application/json' \
  -H 'x-client-id: demo' \
  -d '{"model_id":"smollm2","messages":[{"role":"user","content":"Hello"}]}'
```

Useful flags:

```bash
cordon run <model> \
  --bind 127.0.0.1:8477 \
  --gpu-layers 35 \      # offload to the GPU
  --ctx-size 8192 \      # context window
  --no-ui                # do not start the console
```

To make even Light mode meaningful, provision a Client Master Key so responses
and the audit log become independently verifiable — see
[Provisioning keys](#provisioning-keys).

### Sovereign Cloud — your VPC

Hardware TEE, mutual TLS, and pinned measurements, with outbound access for
pulling models.

```bash
# 1. Generate a configuration and edit it
cordon default-config --mode sovereign_cloud > /etc/cordon/cordon.toml

# 2. Provision a Client Master Key (keep it off the node in production)
cordon-keygen generate --deployment-id <id> --client-id operator

# 3. Enrol your clients
cat > /etc/cordon/clients.json <<'JSON'
[
  {
    "client_id": "analytics-cluster",
    "active": true,
    "permitted_models": ["qwen2.5-7b"],
    "max_tokens_per_request": 2048,
    "max_requests_per_minute": 600,
    "max_tokens_per_minute": 500000,
    "admin_allowed": false,
    "log_export_allowed": true,
    "policy_expires_at": null,
    "cert_pins": [],
    "content_policy_path": "/etc/cordon/policies/analytics.json"
  }
]
JSON

# 4. Capture the node's measurements and pin them
cordon attest --pin >> /etc/cordon/cordon.toml

# 5. Serve
CORDON_CMK_FILE=/run/cordon/cmk \
  cordon serve --config /etc/cordon/cordon.toml --bind 0.0.0.0:8443
```

Once `clients.json` enrols anyone, unenrolled clients are **denied**. Enrolling
is taken as intent to restrict, and the per-client privileges begin to apply
with it:

- `admin_allowed` — may carry an admin signature. The signature proves the
  operator authorized a command; this decides which clients may present one.
  Both apply.
- `log_export_allowed` — may read the audit log. The log records which clients
  asked for what and how often, which is exactly the traffic analysis one tenant
  should not be able to run against another, so reading it is a privilege rather
  than a consequence of being enrolled. Reads are themselves recorded.
- `content_policy_path` — the output policy applied to this client. Absent means
  the node's `content_policy.default_path`, and absent that, a built-in rule
  that flags PII and alters nothing.

Before anyone is enrolled none of these apply: a deployment that has enrolled
nobody is not running an access-control regime, and refusing a privilege nobody
could have been granted would only break the development path.

### Vault — regulated enterprise

As Sovereign Cloud, plus zero egress and timing normalisation. Models arrive as
encrypted bundles over the management channel, never by download.

```toml
mode = "vault"

[network]
outbound_policy = "zero_egress"
require_mtls = true
client_ca_path = "/etc/cordon/tls/client-ca.crt"

[side_channel.timing_normalization]
enabled = true
mode = "bucket"
bucket_ms = 100

[model_store]
staging_dir = "/dev/shm/cordon"   # plaintext weights never touch persistent storage

[attestation]
measurement_source = "tpm2"
halt_until_verified = true
```

`halt_until_verified` is the strong setting: a client is refused inference until
it has attested the node. Verification is per client — one caller's acceptance
does not unlock the node for anyone else.

Be precise about what that gate is. `POST /v1/attestation/verify` has the *node*
check its report against its own pinned configuration and record that the
calling client has attested it; the client contributes a nonce. It proves the
node is in the state its operator pinned, at a moment the client chose. A client
that wants its own answer fetches `GET /v1/attestation?nonce=…` and verifies the
report itself — everything needed for that is in the report.

With timing normalisation on, `POST /v1/inference/stream` is refused. See
[What Cordon actually does](#what-cordon-actually-does).

### Island — private network

As Vault, without a management channel. Everything arrives on physical media.
Use the fixed-floor timing mode where response latency itself is sensitive:

```toml
[side_channel.timing_normalization]
enabled = true
mode = "fixed_floor"
fixed_floor_ms = 500
```

### Dark — air-gapped

Maximum restriction: single tenant, no network beyond the client subnet, and key
custody at FIPS 140-2 Level 4.

```toml
mode = "dark"

[network]
outbound_policy = "zero_egress"

[hsm]
# A declaration, not an integration. Cordon talks to no HSM — the Client Master
# Key reaches it through CORDON_CMK_FILE, and where that file comes from is
# your arrangement. This value is used only to refuse a Dark configuration that
# contradicts its own mode.
fips_level = 4

[inference]
multi_tenant = false
```

Startup refuses a Dark configuration that declares a weaker level, enables
multi-tenancy, or permits egress.

---

## Provisioning keys

The **Client Master Key** is the root of trust. Everything else is derived from
it, and the node needs it only to decrypt bundles and sign — it never needs to
own it.

```bash
cordon-keygen generate --deployment-id <deployment-id> --client-id operator
```

This writes the CMK to `./cordon-keys/cmk.hex` with owner-only permissions and
prints the public halves — `K_log`, `K_admin`, and `K_enclave`. The CMK itself
is not printed unless you pass `--print-cmk`: a key echoed to a terminal
survives in scrollback and in CI logs.

Recover the public keys later with:

```bash
cordon-keygen public --cmk-file /run/cordon/cmk \
  --deployment-id <id> --client-id operator
```

Store the CMK in an HSM. Give the node access to it by file:

```bash
install -m 600 /dev/null /run/cordon/cmk       # on a tmpfs
echo -n "<cmk-hex>" > /run/cordon/cmk
export CORDON_CMK_FILE=/run/cordon/cmk
```

`CORDON_CMK` also works but reads the key from the environment, where it is
visible to every child process and in crash dumps. Cordon warns when you use it.

With a CMK provisioned:

- audit-log signatures verify against a key **you** derive, so the node cannot
  rewrite history undetectably;
- response signatures are verifiable offline;
- the admin API is enabled.

Without one, the node generates ephemeral keys, self-certifies, and reports
`key_provenance: "ephemeral"` in every response. Modes other than Light refuse
to start that way.

### Authorizing admin commands

Admin endpoints require an Ed25519 signature over
`CORDON_ADMIN:{action}:{params}`:

```bash
cordon-keygen admin-sign \
  --cmk-file /run/cordon/cmk \
  --deployment-id <id> --client-id operator \
  --action quarantine --params "incident-4471"

curl -X POST https://node:8443/v1/admin/quarantine \
  --cert client.crt --key client.key \
  -d '{"admin_signature":"<sig>","reason":"incident-4471"}'
```

A signature authorizes exactly one action with exactly those parameters. It
cannot be replayed against another command.

---

## Encrypting a model bundle

For deployments where the operator must not be able to read the weights:

```bash
cordon-provision encrypt \
  --weights ./qwen2.5-7b/ \
  --cmk-file /run/cordon/cmk \
  --bundle-id qwen2.5-7b \
  --client-id operator \
  --model-name "Qwen2.5 7B Instruct" \
  --output /var/lib/cordon/bundles/qwen2.5-7b
```

Weights are split into 256 MiB shards, each encrypted under its own derived key
with a fresh nonce. Memory stays bounded regardless of model size.

Verify a bundle on the node before serving it:

```bash
cordon-provision verify \
  --bundle /var/lib/cordon/bundles/qwen2.5-7b \
  --cmk-file /run/cordon/cmk --client-id operator

cordon-provision inspect --bundle /var/lib/cordon/bundles/qwen2.5-7b
```

Point the runtime at the bundle ID rather than a file, and Cordon decrypts it at
startup:

```toml
[runtime]
backend = "supervised"
model_path = "qwen2.5-7b"    # a registered bundle ID
```

A manifest that claims `encryption_algorithm = "NONE"`, reuses a nonce, uses an
all-zero nonce, or whose plaintext and ciphertext digests match is **refused**.
Those describe plaintext weights wearing a bundle's clothing.

---

## Verifying what a node tells you

The point of the audit log and the response signatures is that you do not have
to trust the node. Check them yourself.

### The audit chain, offline

```bash
cordon-verify-log \
  --log /var/lib/cordon/audit \
  --key <K_log, from `cordon-keygen public`> \
  --deployment-id <id>
```

This recomputes every hash and checks every signature against the key **you**
derived from the CMK. It does not contact the node.

It exits `0` when the chain verifies and `1` when it does not, and on failure it
names the entries that no longer match — so you learn what was altered, not
merely that something was.

### A response signature

Every response carries the payload layout it signed:

```text
CORDON_RESPONSE_v1|{request_id}|{output_hash}|{model_id}|{timestamp_ms}|{mrenclave}
```

`output_hash` is the SHA-256 of the message content you received, and
`timestamp_ms` is the response `timestamp` in epoch milliseconds. Reconstruct
the string, and verify the signature against `K_enclave_pub`.

Check `signature.key_provenance` first. If it says `ephemeral`, the node signed
with a key it generated itself and the signature proves only that the response
was not altered in transit.

### Anchoring the chain

```bash
curl -s https://node:8443/v1/audit/anchor --cert client.crt --key client.key
```

Returns the signed chain head. Record it somewhere the operator does not
control, and any later rewrite of the log before that point becomes detectable.

---

## The API

| Route | Auth | Purpose |
|---|---|---|
| `GET /v1/health` | none | Liveness. Reveals only that a node is listening. |
| `GET /v1/health/detailed` | client | Full posture: measurements, key provenance, audit state. |
| `GET /v1/health/runtime` | client | Recent model-runtime output. |
| `POST /v1/inference` | client | Generate. Ed25519-signed response. |
| `POST /v1/inference/stream` | client | Generate over SSE, filtered incrementally. |
| `GET /v1/attestation?nonce=` | client | A report bound to your challenge, and everything needed to verify it yourself. |
| `POST /v1/attestation/verify` | client | Have the node check its own report and record that you attested it. |
| `GET /v1/models` | client | Registered bundles and their integrity state. |
| `POST /v1/models` | K_admin + `admin_allowed` | Register a bundle present in the model store. |
| `GET /v1/audit/verify` | `log_export_allowed` | Recompute and check the whole chain. |
| `GET /v1/audit/tail` | `log_export_allowed` | The most recent entries. |
| `GET /v1/audit/anchor` | `log_export_allowed` | Signed chain head. |
| `POST /v1/admin/quarantine` | K_admin + `admin_allowed` | Stop serving until recovered. |
| `POST /v1/admin/recover` | K_admin + `admin_allowed` | Resume. Refused while any bundle fails integrity. |
| `POST /v1/admin/teardown` | K_admin + `admin_allowed` | Zeroize key material and stop. |
| `POST /v1/admin/suspend-client` | K_admin + `admin_allowed` | Suspend one client. |
| `GET /metrics` | loopback | Prometheus. Refused from any non-local peer. |

### Streaming

```text
event: delta   data: {"delta": "<text>"}
event: done    data: {request_id, finish_reason, usage, output_hash, signature, …}
event: error   data: {error, message}
```

The stream always terminates with `done` or `error`, so a client never has to
infer completion from a silent socket.

Refused while timing normalisation is enabled — see
[What Cordon actually does](#what-cordon-actually-does).

### Attestation

There are two ways to use these, and they are not equivalent.

**`POST /v1/attestation/verify`** takes only a nonce. Expected measurements are
pinned by the operator and cannot be supplied by the caller — a node that
verifies against caller-supplied values can always be made to verify, since
anyone can read its measurements from `GET /v1/attestation` and hand them
straight back. The response reports `platform_quote`, `binds_signing_key` and
`hardware_rooted` separately, so "the configuration matched" is never mistaken
for "a platform signed for it". A node with nothing pinned returns
`verified: false` and says why.

But note who is doing the checking: the node is, against its own configuration.
That is a useful gate and it is not evidence for you.

**`GET /v1/attestation?nonce=<yours>`** is what a client uses to reach its own
conclusion. The report carries the structure the platform signed, the key that
signed it, and the node's response-signing key. Verify it against measurements
*you* pinned:

```rust
use cordon_crypto::attestation::AttestationReport;

let established = report.verify(&my_pinned_measurements, &my_nonce)?;
assert!(established.is_hardware_rooted());
```

`is_hardware_rooted()` is true only when a platform quote verified *and* it
committed to the key that signs this node's responses. Anything less is worth
having and is not that.

---

## The operator console

A single page, five panels: node posture, an attestation challenger, the audit
chain, a chat console that exercises the real pipeline, and an endpoint
reference.

The attestation panel issues a fresh nonce, asks for a report bound to it, and
reports what that report does and does not establish as four separate facts
rather than one light — then renders the `[attestation.expected]` block ready to
paste. The audit panel shows the chain head, tails recent entries, verifies the
whole chain, and takes an anchor.

Both are the API's own handlers mounted on the console's listener, not a second
implementation, so the console cannot show you something a client would not
receive — and its audit reads are recorded like anyone's.

```bash
cordon run <model>              # console at http://127.0.0.1:8478
cordon run <model> --no-ui      # or not
```

The console has **no authentication of its own** — reachability is its access
control. It binds to loopback on its own listener, and Cordon refuses to enable
it outside Light mode or on a routable address. Reach a remote node's console
through an SSH tunnel:

```bash
ssh -L 8478:127.0.0.1:8478 operator@node
```

Requests from the console go through the full pipeline and are audited like any
other. Nothing there bypasses it.

---

## Configuration reference

`cordon default-config --mode <mode>` prints an annotated starting point.
Sections worth knowing:

```toml
[runtime]
backend = "supervised"          # supervised | external | none
binary = "/opt/llama.cpp/llama-server"
model_path = "/var/lib/cordon/models/model.gguf"   # or a registered bundle ID
context_size = 8192
gpu_layers = 35
parallel_slots = 8              # raised to max_concurrent_requests if lower
startup_timeout_seconds = 180

[attestation]
# sev_snp | tpm2 | software_measurement (Light only) | nitro_enclave (verify only)
measurement_source = "tpm2"
halt_until_verified = true
interval_hours = 24

[attestation.expected]          # pinned by the operator; capture with `cordon attest --pin`
mrenclave = "…"
mrsigner  = "…"
min_isv_svn = 0

[attestation.expected.pcr_values]
0 = "sha256:…"
4 = "sha256:…"

[attestation.expected.sev_snp]  # required when measurement_source = "sev_snp"
amd_root_der_b64        = "…"   # AMD's root, pinned by you
min_bootloader_svn      = 4
min_snp_svn             = 20
min_microcode_svn       = 210
refuse_debuggable_guest = true

[attestation.expected.nitro]    # for verifying AWS Nitro attestation documents
root_der_b64    = "…"           # AWS's Nitro root, pinned by you
max_age_seconds = 300

[attestation.expected.nitro.pcr_values]
0 = "…"                         # the enclave image; required
1 = "…"                         # kernel and bootstrap
2 = "…"                         # application

[content_policy]
# A JSON policy applied to every client that does not name its own. A client
# overrides it with `content_policy_path` in the registry. Compiled at startup,
# so a rule that does not parse stops the node rather than failing the request
# it was meant to filter.
default_path = "/etc/cordon/policy.json"

[network]
# zero_egress | restricted. Under zero_egress Cordon opens no outbound
# connections: model downloads are disabled and a non-loopback runtime endpoint
# is refused. It does not stop packets leaving the host — that is a firewall's
# job. Required in Vault, Island and Dark.
outbound_policy = "zero_egress"

[limits]
max_request_bytes = 1048576
max_messages = 256
max_prompt_chars = 262144
max_connections = 1024
tls_handshake_timeout_seconds = 15

[ui]
enabled = false                 # Light mode only, loopback only
bind_address = "127.0.0.1"
port = 8478

[model_store]
staging_dir = "/dev/shm/cordon" # where bundles are decrypted before loading
integrity_check_interval_minutes = 15
halt_on_tamper = true
```

`integrity_check_interval_minutes` is also the lifetime of an integrity verdict
on the serving path. A bundle whose last check is older than that is withdrawn
from service until the monitor confirms it again — so a monitor that has stopped
running takes the node out of service rather than leaving it serving unverified
weights.

### A note on what is not here

Configuration that Cordon does not act on has been removed rather than left to
imply a defence. Gone in this version: `inbound_whitelist`, `hardware_firewall`,
`smartnic_acl`, `mgmt_channel`, `constant_time_enforcement`,
`memory_zeroize_on_completion`, `response_size_padding`,
`re_attestation_interval_hours`, `halt_on_attestation_failure`,
`cache_partitioning`, `boot.pcr_policy`, `client_kv_cache_isolation`,
`max_input_tokens`, `audit.log_format`, `audit.export_method`,
`audit.retention_days`, `signing_key_from_enclave`, the whole `[updates]`
section, and the HSM provider, slot and PIN fields. Unknown keys are ignored, so
an existing file still loads; it simply no longer describes anything.

---

## Environment variables

| Variable | Effect |
|---|---|
| `CORDON_CMK_FILE` | Path to the Client Master Key. **Preferred.** |
| `CORDON_CMK` | The key itself, hex. Visible in the process environment; warns. |
| `CORDON_CLIENT_ID` | Key-derivation principal. Default `operator`. |
| `CORDON_LLAMA_SERVER` | Path to `llama-server`. |
| `CORDON_TPM_AK_CTX` | TPM attestation key context, for signed quotes. |
| `HF_TOKEN` | Hugging Face token, for gated repositories. |
| `HF_ENDPOINT` | Alternative Hub endpoint or mirror. |
| `RUST_LOG` | Log filter, e.g. `cordon_core=debug`. |
| `CORDON_INSECURE_ADMIN` | Dev only: admin without a signature. Refused outside Light mode. |
| `CORDON_ALLOW_UNREGISTERED_MODELS` | Dev only: bypass the model-store gate. Refused outside Light mode. |

The last two are refused at startup in any mode that claims a security
guarantee, so setting them cannot silently weaken a production node.

---

## Tools

| Binary | Purpose |
|---|---|
| `cordon` | `pull`, `run`, `serve`, `models`, `remove`, `doctor`, `status`, `attest`, `default-config` |
| `cordon-keygen` | Generate a CMK, derive public keys, sign admin commands |
| `cordon-provision` | `encrypt`, `verify`, `inspect` model bundles |
| `cordon-verify-log` | Offline audit-chain verification |

---

## Troubleshooting

**`no llama-server binary found`** — install llama.cpp and set
`CORDON_LLAMA_SERVER`, or put it on `PATH`. `cordon doctor` confirms.

**`the llama.cpp runtime is serving a web UI`** — your build lacks `--no-webui`
and serves HTML at `/`. Cordon refuses to run alongside a second, unaudited
inference surface. Upgrade llama.cpp.

**`integrity verdict is stale or absent`** — the integrity monitor has not
confirmed the bundle recently. Check the monitor is running and that the shard
files are readable.

**`this node has no pinned expected measurements`** — attestation verification
has nothing to check against. Run `cordon attest --pin >> cordon.toml`, review
the values, and restart.

**`another Cordon node is already writing to the audit log`** — two nodes
pointed at one audit directory fork the hash chain, and the log then fails
verification as though it had been tampered with, so the second is refused. Give
this node its own directory. If none is running, the previous one did not shut
down cleanly: verify the chain with `cordon-verify-log`, then delete
`.cordon-writer.lock`.

**`streaming is refused while side_channel.timing_normalization is enabled`** —
correct. Use `POST /v1/inference`, which is normalised.

**`this node is not running inside a confidential VM`** — `measurement_source =
"sev_snp"` needs an SEV-SNP guest and a kernel exposing `configfs-tsm` (Linux
6.7+). Cordon will not substitute a weaker measurement for one it was told to
produce.

**`nitro_enclave cannot be used to run a node`** — correct, and the message
says why: Cordon verifies Nitro attestation documents but cannot obtain one,
because an enclave has no persistent storage for the audit log and no network
interface for the API. Use `sev_snp` for a confidential VM, or `tpm2` for a
TPM-attested host. The `[attestation.expected.nitro]` pins remain useful for
verifying a document that reaches Cordon from elsewhere.

**`--bind <addr> is not a loopback address`** — `cordon run` serves plain HTTP
with header-derived identity, so a routable bind publishes an unauthenticated
inference endpoint. Use `cordon serve` with mTLS, forward the port over SSH, or
pass `--insecure-bind` if you understand the exposure.

**`--no-tls is refused in <mode> mode`** — correct. Client identity would come
from a header any caller can set. Provision certificates.

**Responses start with `[cordon:no-model]`** — no model runtime is attached.
Set `runtime.backend = "supervised"` and `runtime.model_path`.

**`Node is at capacity`** — every concurrency slot is busy. Raise
`inference.max_concurrent_requests` and `runtime.parallel_slots` together.

---

## Licence

[Apache License 2.0](LICENSE).

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Design and
threat model are in [ARCHITECTURE.md](ARCHITECTURE.md).
