# Cordon — Private Inference Engine v2.0

Cordon is a confidential‑inference control plane in Rust. It wraps a local
LLM runtime (any OpenAI‑compatible `/v1/chat/completions` server) with:

- **mTLS** identity bound to client certificates (not spoofable headers)
- a **CMK‑rooted key hierarchy** (HKDF‑SHA256) for bundle, session, log, admin, and response‑signing keys
- **Ed25519‑signed** inference responses and attestation reports (client‑verifiable offline)
- a **Merkle‑chained, signed, append‑only audit log** with an offline verifier
- output content filtering, covert‑channel detection, timing normalization
- rate limiting, sustained‑attack detection, and an encrypted **model store** gate
- **fail‑closed** admin authorization and attestation verification

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design and the real‑vs‑simulated trust model.

> **Note on hardware roots of trust:** this build **simulates** the TPM/TEE
> (PCRs and `MRENCLAVE` are derived from config). The cryptography, audit chain,
> TLS/mTLS, signatures, and the attestation *verification path* are real. See
> §6 of ARCHITECTURE.md.

---

## Build & test

```bash
cargo build
cargo test
```

## Quick start (dev, no TLS, mock inference)

```bash
CORDON_USE_MOCK_INFERENCE=true cargo run --bin cordon -- serve --no-tls --data-dir ./data --bind 127.0.0.1:8477
```

```bash
curl -s http://127.0.0.1:8477/v1/health
curl -s -X POST http://127.0.0.1:8477/v1/inference \
  -H 'content-type: application/json' -H 'x-client-id: demo' \
  -d '{"model_id":"m","messages":[{"role":"user","content":"hello"}]}'
```

## With a real model backend (llama.cpp / vLLM)

Run an OpenAI‑compatible server, then point Cordon at it:

```bash
CORDON_INFERENCE_URL="http://127.0.0.1:8000/v1/chat/completions" \
  cargo run --bin cordon -- serve --no-tls --data-dir ./data
```

## Production posture (CMK + TLS/mTLS)

Provision a Client Master Key so audit and response signatures become
client‑verifiable and the admin API is enabled:

```bash
# Generate a CMK and derived public keys (store CMK in an HSM in production)
cargo run --bin cordon-keygen -- generate --deployment-id <dep> --client-id operator

# Run with the CMK; identity comes from mTLS client certs
CORDON_CMK=<hex> CORDON_CLIENT_ID=operator \
  cargo run --bin cordon -- serve --config /etc/cordon/cordon.toml --bind 0.0.0.0:8443
```

mTLS requires `require_mtls = true` and a `client_ca_path` in the config's
`[network]` section. Connections without a CA‑issued client certificate are
rejected at the TLS handshake; the verified certificate — not any header —
determines the client identity.

## Authorizing admin commands

Admin endpoints require an Ed25519 signature from `K_admin`:

```bash
cargo run --bin cordon-keygen -- admin-sign \
  --cmk <hex> --deployment-id <dep> --client-id operator \
  --action quarantine --params "incident-123"
# → paste admin_signature into the POST body
```

## Environment variables

| Var | Effect |
|-----|--------|
| `CORDON_CMK` | Client Master Key (hex). Enables CMK‑derived keys + admin API. |
| `CORDON_CLIENT_ID` | Key‑derivation principal (default `operator`). |
| `CORDON_INFERENCE_URL` | Upstream OpenAI‑compatible endpoint. |
| `CORDON_USE_MOCK_INFERENCE=true` | Use the built‑in mock backend. |
| `CORDON_INSECURE_ADMIN=true` | Dev only: allow admin without a signature. |
| `CORDON_ALLOW_UNREGISTERED_MODELS=true` | Dev only: bypass the model‑store gate. |

## Tools

- `cordon` — node server (`serve`), `status`, `attest`, `default-config`
- `cordon-keygen` — CMK generation, key derivation, `admin-sign`
- `cordon-provision` — encrypt/verify/inspect model bundles
- `cordon-verify-log` — offline audit‑log verification
