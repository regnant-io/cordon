# Research Programme: Cordon

**Title**: Cordon: Confidential Inference Control Plane for Sovereign AI Infrastructure  
**Status**: ACTIVE  
**Description**: Cordon is a confidential inference control plane that enforces containment at the hardware level, ensuring AI inference runs entirely within an institution's perimeter with cryptographic guarantees. The research programme investigates operator-independent audit verification, hardware attestation binding, per-client policy isolation, and architectural containment mechanisms for sovereign AI deployments. Core innovations include client-derived verification keys for tamper-evident logs, challenge-response protocols binding attestation to signing keys, streaming content filters with trailing holdback, and supervised model runtimes that prevent bypass. Research addresses institutions requiring air-gapped operation, classified data handling, and zero-trust deployment models where the infrastructure operator is outside the trust boundary.

**Tags**: confidential-computing, sovereign-ai, hardware-attestation, audit-verification, tpm, sev-snp, air-gap, operator-independent, merkle-chain, streaming-filters, supervised-runtime, multi-tenant-policy

**Published**: Yes

---

## Research Objectives

1. **Operator-Independent Audit**: Can audit logs be verified offline against keys the operator cannot forge?
2. **Attestation Binding**: How do we cryptographically bind platform quotes to response signing keys?
3. **Memory Confidentiality**: What distinguishes boot attestation (TPM) from runtime memory confidentiality (SEV-SNP)?
4. **Streaming Content Policy**: Can PII filters work on streaming responses without partial leakage?
5. **Architectural Containment**: How do we prevent model runtime bypass through supervised process management?
6. **Multi-Tenant Isolation**: Can per-client policies enforce in multi-tenant inference without cross-contamination?

---

## Published Research Papers

1. **Operator-Independent Audit Verification Through Client-Derived Keys** ([01-operator-independent-audit.md](01-operator-independent-audit.md))
   - Hash-chained logs signed with HKDF-derived keys from client-held CMK
   - Offline verification without node contact
   - Tamper-evidence through signature breaking on modifications

2. **Binding Attestation to Answers: Challenge-Response for Inference Verification** ([02-attestation-binding.md](02-attestation-binding.md))
   - Challenge = H(signing_key || nonce) embedded in platform quotes
   - Prevents attestation replay and signing key substitution
   - Implemented for TPM 2.0, SEV-SNP, AWS Nitro

3. **Streaming Content Policy with Incremental Filtering** ([03-streaming-filters.md](03-streaming-filters.md))
   - Trailing holdback window prevents partial PII leakage
   - Soundness proof for patterns ≤ window size
   - Performance optimization through re-scan strides

4. **Memory Confidentiality vs Boot Attestation** ([04-memory-confidentiality.md](04-memory-confidentiality.md))
   - TPM attests boot chain; operator can still read runtime memory
   - SEV-SNP/Nitro encrypt guest memory; hypervisor sees only ciphertext
   - Deployment mode validation enforces correct guarantees

5. **Supervised Runtime Architecture for Containment** ([05-supervised-runtime.md](05-supervised-runtime.md))
   - Loopback-only binding with ephemeral ports
   - Per-boot API keys, web UI disabled
   - Architectural prevention of control plane bypass

---

## Technical Architecture

**Core Pipeline**: 18-stage request processing with fail-closed validation at each layer:
1. Node state → 2. Attestation gate → 3. Source block → 4. Identity → 5. Suspension check → 6. Model permission → 7. Request limits → 8. Model store integrity → 9. Rate limiting → 10. Admission → 11. Audit pre-write → 12. Inference → 13. Token settlement → 14. Content policy → 15. Covert channel detection → 16. Timing normalization → 17. Audit post-write → 18. Response signature

**Key Hierarchy**: HKDF-SHA256 derivation from Client Master Key with domain separation:
- K_log (audit signatures)
- K_admin (admin command authorization)
- K_enclave (response signatures)
- K_bundle (per-shard AES-256-GCM for encrypted weights)

**Attestation Sources**: TPM 2.0, AMD SEV-SNP, Intel SGX v2, AWS Nitro, Software Measurement

**Deployment Modes**: Light (dev), Sovereign Cloud (VPC), Vault (zero-egress), Island (air-gap), Dark (FIPS L4)

---

## Implementation

- **Language**: Rust (100% safe code, `#![forbid(unsafe_code)]`)
- **Repository**: https://github.com/regnant-io/cordon
- **Version**: 2.0.0
- **Crates**: cordon-core, cordon-crypto, cordon-audit, cordon-api, cordon-cli
- **Test Coverage**: Unit + integration across all crates
- **LOC**: ~15,000 lines

---

## Current Status

**Production Ready**:
- TPM 2.0 attestation (tested on Dell R740, HP ProLiant)
- Hash-chained audit with offline verification
- Supervised llama.cpp runtime
- Per-client content policy engine
- Streaming with incremental filtering

**Research Phase**:
- AMD SEV-SNP (implemented, awaiting silicon validation)
- AWS Nitro verification (parser complete, deployment blocked by architectural constraints)
- Intel TDX support (planned)

---

## Open Research Questions

1. Can streaming be made compatible with timing normalization?
2. What is the optimal holdback window for a given policy rule set?
3. How do we verify model provenance cryptographically (vendor + client signatures)?
4. What are post-quantum migration paths for the key hierarchy?
5. Can audit chain properties be formally verified (Coq, Isabelle)?
6. Response-length padding: bandwidth-efficient strategies?
7. Certificate revocation for air-gapped deployments?

---

## Target Applications

- Government: Classified data processing, air-gapped networks
- Central banks: Financial intelligence, market surveillance
- Healthcare: HIPAA compliance, patient data confidentiality
- Critical infrastructure: Energy, utilities, telecommunications
- Defense: Operational planning, intelligence analysis

---

## Key Contributions

1. **First system** with operator-independent audit verification for AI inference
2. **Challenge-response binding** connecting hardware attestation to response signatures
3. **Streaming PII filtering** with formal soundness guarantees
4. **Supervised runtime model** preventing architectural bypass
5. **Fail-closed validation** refusing degraded security configurations
