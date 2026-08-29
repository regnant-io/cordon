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
| **Output filter** | Policy rules redact, truncate, or block. |
| **Covert channel** | Statistical analysis of the text about to be released. |
| **Timing** | Latency is normalised to a bucket or floor. |
| **Audit post-write** | The completed record, with the true policy and covert-channel values. |
| **Sign** | Ed25519 over a canonical, reconstructable payload. |

The streaming endpoint runs the identical pipeline. Chunks pass through the
filter incrementally with a trailing holdback, so a pattern that only completes
in a later chunk — a card number whose last digits arrive next — is caught
before any part of it has left the node.

---

## What is real, and what is not

Cordon is a control plane, not a trusted execution environment. Being precise
about that line is the point of this section.

### Real, and exercised by the test suite

- **AES-256-GCM** shard encryption with per-shard keys, fresh nonces, and both
  plaintext and ciphertext digests checked on every decryption.
- **HKDF-SHA256 key hierarchy** with domain separation. A client holding the
  Client Master Key derives the same public halves and can verify the node's
  signatures without trusting the node.
- **Ed25519** signatures over inference responses, attestation reports, audit
  entries, and audit anchors.
- **A hash-chained, signed, append-only audit log** with an offline verifier.
  Rewriting an entry breaks the chain, and `cordon-verify-log` detects it
  without contacting the node.
- **TLS 1.3 and mutual TLS**, with client identity parsed from the verified
  certificate's subject — not from a header.
- **A supervised model runtime** on loopback with an ephemeral port, a per-boot
  API key, and a startup check that refuses to run if the runtime serves a web UI.

### Real, but hardware-dependent

- **TPM 2.0 measurements.** PCR values and signed quotes come from `tpm2-tools`.
  The command wiring and parsing are unit-tested; this repository's CI has no
  TPM, so verify it on your own hardware with `cordon doctor`.

### Not a hardware root of trust

- **`measurement_source = "software_measurement"`** derives measurements from
  Cordon's build and configuration. It attests that the node is running the
  configuration you expect. It attests **nothing** about the platform underneath
  it, and an attacker with code execution on the host can reproduce it exactly.
  It is confined to Light mode, and every response says which source produced it.

- **Full SGX-DCAP and SEV-SNP quote verification** are not implemented. The TEE
  quote in a report carries measurements and a type; it does not carry a
  hardware-signed attestation Cordon verifies against Intel's or AMD's roots.

### Deliberate, bounded weaknesses

- **Staged plaintext weights touch disk.** An encrypted bundle is decrypted to a
  mode-0600 file, the runtime loads it with memory mapping disabled, and the
  file is erased immediately. The window is bounded and documented; it is not
  zero. Set `model_store.staging_dir` to a `tmpfs` mount where that matters.

- **Prompts live in process memory.** Buffers zeroize on drop, but an attacker
  with root on the node can read them before that. Cordon narrows the window; a
  real TEE is what closes it.

Everything above is stated the same way in `ARCHITECTURE.md` §6 and in the
`SECURITY.md` threat model. If you find a place where the code claims more than
this, that is a bug — please report it.

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

| Mode | TEE | mTLS | Console | Internet | Runtime |
|---|---|---|---|---|---|
| `light` | not required | optional | allowed, loopback | yes | any |
| `sovereign_cloud` | required | required | refused | yes | local |
| `vault` | required | required | refused | no | local |
| `island` | required | required | refused | no | local |
| `dark` | required | required | refused | no | local |

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
    "cert_pins": []
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
is taken as intent to restrict.

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
*it* has verified the node's attestation. Verification is per client — one
caller's acceptance does not unlock the node for anyone else.

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

Maximum restriction: a FIPS 140-2 Level 4 HSM, single tenant, no network beyond
the client subnet.

```toml
mode = "dark"

[hsm]
provider = "thales_luna"
fips_level = 4

[inference]
multi_tenant = false
```

Startup refuses a Dark configuration with a weaker HSM or multi-tenancy enabled.

---

## Provisioning keys

The **Client Master Key** is the root of trust. Everything else is derived from
it, and the node needs it only to decrypt bundles and sign — it never needs to
own it.

```bash
cordon-keygen generate --deployment-id <deployment-id> --client-id operator
```

This prints the CMK and the public halves of the derived keys. Store the CMK in
an HSM. Give the node access to it by file:

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
  --log-dir /var/lib/cordon/audit \
  --deployment-id <id> \
  --verifying-key <k_log_pub from cordon-keygen>
```

This recomputes every hash and checks every signature against the key **you**
derived from the CMK. It does not contact the node.

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
| `GET /v1/attestation` | client | A signed measurement report. |
| `POST /v1/attestation/verify` | client | Check a report against pinned measurements. |
| `GET /v1/models` | client | Registered bundles and their integrity state. |
| `POST /v1/models` | K_admin | Register a bundle present in the model store. |
| `GET /v1/audit/verify` | client | Recompute and check the whole chain. |
| `GET /v1/audit/tail` | client | The most recent entries. |
| `GET /v1/audit/anchor` | client | Signed chain head. |
| `POST /v1/admin/quarantine` | K_admin | Stop serving until recovered. |
| `POST /v1/admin/recover` | K_admin | Resume. Refused while any bundle fails integrity. |
| `POST /v1/admin/teardown` | K_admin | Zeroize key material and stop. |
| `POST /v1/admin/suspend-client` | K_admin | Suspend one client. |
| `GET /metrics` | loopback | Prometheus. Refused from any non-local peer. |

### Streaming

```text
event: delta   data: {"delta": "<text>"}
event: done    data: {request_id, finish_reason, usage, output_hash, signature, …}
event: error   data: {error, message}
```

The stream always terminates with `done` or `error`, so a client never has to
infer completion from a silent socket.

### Attestation verification

`POST /v1/attestation/verify` takes **only a nonce**. Expected measurements are
pinned by the operator in configuration and cannot be supplied by the caller —
a node that verifies against caller-supplied values can always be made to
verify, since anyone can read its measurements from `GET /v1/attestation` and
hand them straight back.

A node with nothing pinned returns `verified: false` and says why. Capture and
pin its measurements with `cordon attest --pin`.

---

## The operator console

A single page: node posture, a chat console that exercises the real pipeline,
and an endpoint reference.

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
measurement_source = "tpm2"     # tpm2 | software_measurement (Light only)
halt_until_verified = true
interval_hours = 24

[attestation.expected]          # pinned by the operator; capture with `cordon attest --pin`
mrenclave = "…"
mrsigner  = "…"
min_isv_svn = 0

[attestation.expected.pcr_values]
0 = "sha256:…"
4 = "sha256:…"

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
