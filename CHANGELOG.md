# Cordon Changelog

## v2.1.0 — Cordon (Current)

### Rebrand
- Project renamed **Sanctum → Cordon** across all crates (`cordon-*`), binaries
  (`cordon`, `cordon-keygen`, `cordon-provision`, `cordon-verify-log`), env vars
  (`CORDON_*`), key‑derivation domain strings, audit genesis constant, HTTP
  headers, config paths, and docs.

### Security fixes (see ARCHITECTURE.md §7)
- **TLS/mTLS is real.** TLS 1.3 termination via `tokio-rustls` + `hyper-util`.
  Client identity is bound to the **verified mTLS certificate**, not the
  `x-client-id` header (which is now trusted only under explicit `--no-tls` dev).
- **Admin API authenticated.** `/v1/admin/*` requires an Ed25519 `K_admin`
  signature over a canonical command and is **fail‑closed** without a key.
- **Attestation verification is fail‑closed.** `/v1/attestation/verify` runs the
  real verifier against client `expected_measurements`; reports are Ed25519‑signed.
- **Audit log key derived from the CMK** (not random per boot), making
  client‑side non‑repudiation meaningful. Key provenance is surfaced everywhere.
- **Real Ed25519 response signatures** over a documented, reconstructable payload
  (verified client‑side end‑to‑end); `chain_valid` now computed by the verifier.
- **Model‑store gate.** Inference requires a registered bundle that passes
  integrity and a decrypt‑with‑derived‑key proof; fail‑closed once bundles exist.
- **Streaming parity.** The streaming endpoint runs the identical filter /
  covert‑channel / timing / audit pipeline before emitting filtered output.
- **Real zeroization** of session/KV secret scratch; single‑shot sessions are
  torn down to bound memory.

### Fixes
- Rate limiter no longer starts clients at 2× their configured limit.
- Corrected the audit tamper‑detection test to actually mutate a payload.

---

## v2.0.0

### New in v2.0

**Layer 0 — Hardware Root of Trust** (was missing in v1.0)
- TPM 2.0 integration with PCR allocation map (PCR[0]–PCR[15])
- Full boot chain measurement: UEFI → bootloader → kernel → Cordon runtime → TEE
- dm-verity on root filesystem: any modification halts boot
- UEFI Secure Boot with vendor keys removed; client keys only
- Hardened kernel configuration (lockdown LSM, signed modules, KASLR)

**Layer 1 — Perimeter**
- Three-layer zero-egress: hardware appliance + SmartNIC ACLs + OS-level (defense in depth)
- Explicit SmartNIC hardware requirement note added (commodity NICs don't provide this)
- Optional unidirectional data diode for compliance attestation without data exposure

**Layer 2 — TEE**
- AMD SEV-SNP mandatory for ≥30B models (hypervisor memory protection)
- Combined TPM+TEE attestation report
- Cache partitioning via Intel CAT / AMD QoS
- Memory side-channel mitigations (ORAM, ECC, bank isolation)
- Timing side-channel: three modes (None, Bucket, FixedFloor) with streaming normalization
- TEMPEST / power side-channel mitigations documented (Dark mode physical controls)
- Formal security property proofs for key release, query confinement, log non-repudiation

**Layer 3 — Model Store**
- Shard-level AES-256-GCM encryption with per-shard HKDF keys
- Continuous integrity monitor: 5–10% ciphertext hash sampling every 15 minutes
- HSM integration documentation (Thales Luna, Entrust nShield, YubiHSM)
- Key rotation protocol with emergency rotation path

**Layer 4 — Inference**
- Performance overhead profile table (missing from v1.0)
- Runtime selection matrix: TensorRT-LLM, vLLM (CUDA/ROCm), llama.cpp, Optimum-Habana
- Per-client KV cache isolation with zeroed page reuse
- Multi-tenancy risk acknowledgment and mitigations documented

**Layer 5 — Response Pipeline**
- Covert channel detector: entropy analysis, pattern analysis, whitespace patterns
- Response signing with enclave ephemeral key (MRENCLAVE included)

**Layer 6 — Audit**
- Merkle-chained JSONL log (SHA-256 chain + Ed25519 signatures)
- Complete event catalog: inference, security alert, admin, attestation, key rotation, tamper, lifecycle
- Client-side verification tool (offline, no node connection required)
- Secure export methods table: operator pull, data diode, physical media, encrypted push

**Cross-cutting**
- Sustained Attack Detector (was missing in v1.0): auth flooding, replay probing, session flooding, covert channel accumulation, enclave exception rate
- Quarantine mode with sealed-storage persistence across reboots
- Light mode added (was missing in v1.0): software-only isolation for dev/low-sensitivity

**Deployment**
- Mode comparison matrix: Dark, Island, Vault, Sovereign Cloud, Light
- Physical security requirements by mode
- Tamper response protocol
- HA deployment architecture
- Update/patching pipeline with A/B staged rollout
- Ansible playbook, Kubernetes manifest, Terraform module

### v1.0 → v2.0 Breaking Changes
- Config file format changed significantly (new required fields per layer)
- API response schema extended with `signature`, `enclave_info`, `covert_channel` fields
- Key derivation paths updated to v1 strings (add `:v1` suffix)
- Audit log format updated (chain-linked, Ed25519 signed — not compatible with v1 logs)

---

## v1.0 (Previous)

Initial release. Layer 0 (Hardware Root of Trust), Light mode, and Sustained Attack
Detector were underspecified or missing. See v2.0 changes above.
