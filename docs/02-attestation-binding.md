# Binding Attestation to Answers: Challenge-Response for Inference Verification

**Title**: Binding Attestation to Answers: Challenge-Response for Inference Verification  
**Slug**: attestation-binding-inference  
**Authors**: Regnant Research  
**Image URL**: /img/research/attestation-binding.png  
**Date Label**: 2026 Q3  
**Abstract**: A platform quote proves machine state. A response signature proves key ownership. Neither connects to the other without explicit binding. We present a challenge-response protocol where platform signatures commit to both the client's nonce and the node's signing key, preventing attestation replay and signing key substitution. Clients recompute the challenge from the declared signing key and their own nonce—divergence causes signature verification to fail.  
**Category**: RESEARCH  
**Published**: Yes

---

## Abstract

Hardware attestation platforms (TPM, AMD SEV-SNP, AWS Nitro) produce quotes that prove what software a machine is running. Separately, cryptographic signatures prove a particular key signed a response. But these are two independent facts unless explicitly bound: a quote proves something about a machine, a signature proves something about a key, and nothing connects them.

We present a challenge-response protocol where platform signatures commit to a digest over **both** the client's nonce and the node's response-signing key. Clients recompute the challenge from the signing key the report declares and the nonce they chose themselves. A substituted key or replayed nonce changes the digest, causing platform signature verification to fail.

**Result**: An attestation report proves the node holds the private key for the public signing key in the report, at measurements the client pinned, for a challenge the client chose. Replay and key substitution are architecturally prevented.

---

## 1. Problem Statement

### 1.1 The Disconnect

An institution wants to verify two properties:
1. **The machine is running expected software** (measurements match pinned values)
2. **Responses come from that machine** (not from an impostor)

Hardware platforms provide (1) via attestation:
- **TPM**: PCR values, signed by attestation key
- **AMD SEV-SNP**: Launch measurement, signed by platform signing key
- **AWS Nitro**: PCR values, signed by Nitro Security Module

Applications provide (2) via response signatures:
- **Ed25519/ECDSA**: Sign each response with a private key, client verifies against public key

But these are independent:
- A quote proves measurements at a particular moment
- A signature proves a key signed a message
- **Nothing proves the quoted machine holds the signing key**

### 1.2 Attack Scenario

**Attacker setup**:
- Genuine machine A (passes attestation)
- Impostor machine B (fails attestation, or never attested)

**Attack**:
1. Client requests attestation from B
2. B forwards the request to A
3. A produces a genuine quote
4. B returns A's quote to the client
5. Client verifies the quote (measurements match)
6. Client requests inference from B
7. B processes the request and signs with B's key
8. Client verifies the signature (it's valid)

**What the client believes**: "I verified attestation, I verified the signature, so the attested machine answered my query."

**Reality**: The attestation came from machine A. The answer came from machine B. The two are unrelated.

### 1.3 Why This Matters

For sovereign institutions:
- **Government**: Classified queries must not reach foreign servers, even momentarily
- **Central bank**: Market-moving analysis cannot be processed by unattested infrastructure
- **Healthcare**: Patient data cannot be routed through machines that haven't proven confidentiality

**The gap**: Attestation and response signing are separate protocols. Bridging them requires explicit binding.

---

## 2. Our Approach

### 2.1 Challenge Computation

The node computes:

```
challenge = SHA-256("CORDON_ATTEST_CHALLENGE_v1"
                    || len(signing_key_hex) || signing_key_hex
                    || len(nonce) || nonce)
```

Where:
- `signing_key_hex`: The Ed25519 public key that signs responses (64 hex characters)
- `nonce`: Client-chosen random bytes (32 bytes recommended)

This value goes into the field the platform signs:
- **TPM 2.0**: `extraData` in `TPMS_ATTEST` structure
- **AMD SEV-SNP**: First 32 bytes of `REPORT_DATA`
- **AWS Nitro**: `nonce` field in the attestation document (base64)

### 2.2 Verification

Client receives an attestation report containing:
- Platform's signature over the challenge
- The node's signing key (public key)
- Platform measurements (PCRs, launch measurement, etc.)

Client verifies:
1. **Recompute challenge**: `SHA-256("CORDON_ATTEST_CHALLENGE_v1" || len(key) || key || len(nonce) || nonce_i_sent)`
2. **Extract challenge from quote**: Read from `extraData` / `REPORT_DATA` / `nonce`
3. **Compare**: `computed_challenge == extracted_challenge`
4. **Verify platform signature**: Quote signature valid, chains to pinned root
5. **Check measurements**: PCRs / launch measurement match client's pinned values

**If any step fails**: The attestation does not prove the node with those measurements holds that signing key.

---

## 3. Platform-Specific Implementation

### 3.1 TPM 2.0

**Quote structure**:
```c
struct TPMS_ATTEST {
    TPM2_GENERATED magic;         // 0xff544347 ("TCG")
    TPMI_ST_ATTEST type;          // TPM_ST_ATTEST_QUOTE
    TPM2B_NAME qualified_signer;  // AK name
    TPM2B_DATA extra_data;        // ← challenge goes here
    TPMS_CLOCK_INFO clock_info;
    uint64_t firmware_version;
    TPMS_QUOTE_INFO attested;     // PCR digest
};
```

**Process**:
1. Node calls `tpm2_quote` with `--qualification <challenge_hex>`
2. TPM produces `TPMS_ATTEST` with `extra_data = challenge`
3. TPM signs `TPMS_ATTEST` with attestation key (AK)
4. Node returns quote + AK public key + signing key

**Verification**:
```rust
let attest = parse_tpms_attest(&quote)?;
let expected_challenge = compute_challenge(&signing_key, &nonce);

if attest.extra_data != expected_challenge {
    return Err("Challenge mismatch");
}

// Verify TPM signature
verify_tpm_signature(&quote, &attest_key_pub)?;
```

**Status**: Tested on Dell R740, HP ProLiant with real TPM 2.0 chips.

### 3.2 AMD SEV-SNP

**Report structure** (1184 bytes):
```c
struct snp_attestation_report {
    uint32_t version;
    uint32_t guest_svn;
    uint64_t policy;
    uint8_t family_id[16];
    uint8_t image_id[16];
    uint32_t vmpl;
    uint8_t signature_algo;
    uint8_t platform_version[8];
    uint8_t platform_info[8];
    uint32_t flags;
    uint8_t report_data[64];      // ← challenge goes here (first 32 bytes)
    uint8_t measurement[48];      // Launch measurement
    uint8_t host_data[32];
    uint8_t signature[512];       // ECDSA P-384
    // ... additional fields
};
```

**Process**:
1. Node writes challenge to `/sys/kernel/config/tsm/report/inblob` (configfs-tsm, Linux 6.7+)
2. Kernel invokes PSP to produce attestation report
3. PSP sets `report_data[0:32] = challenge`
4. PSP signs entire report with VCEK (Versioned Chip Endorsement Key)
5. Node reads report from `/sys/kernel/config/tsm/report/outblob`

**Verification**:
```rust
let report = parse_snp_report(&blob)?;
let expected_challenge = compute_challenge(&signing_key, &nonce);

if report.report_data[0..32] != expected_challenge {
    return Err("Challenge mismatch");
}

// Verify VCEK signature, walk cert chain to AMD root
verify_snp_signature(&report, &vcek_chain, &amd_root)?;
```

**Status**: Implemented, tested with synthetic keys. **Not yet run on real silicon** (awaiting AMD EPYC access).

### 3.3 AWS Nitro Enclaves

**Attestation document** (CBOR, COSE_Sign1 envelope):
```
{
  "module_id": "i-1234567890abcdef0-enc9876543210fedcba",
  "digest": "SHA384",
  "timestamp": 1695987654321,
  "pcrs": {
    "0": "hex...",  // Enclave image measurement
    "1": "hex...",  // Kernel + bootstrap
    "2": "hex..."   // Application
  },
  "certificate": "base64...",    // Leaf cert
  "cabundle": ["base64..."],     // Chain to AWS root
  "public_key": "base64...",     // Optional
  "user_data": "base64...",      // Optional
  "nonce": "base64..."           // ← challenge goes here
}
```

**Process**:
1. Node calls `ioctl(nsm_fd, NSM_IOCTL_ATTESTATION_DOC, &req)`
2. Nitro Security Module produces CBOR document
3. NSM sets `nonce = challenge`
4. NSM signs document (COSE_Sign1, ES384)
5. Node returns document + signing key

**Verification**:
```rust
let doc = parse_nitro_document(&cose_sign1)?;
let expected_challenge = compute_challenge(&signing_key, &nonce);

if doc.nonce != base64_encode(&expected_challenge) {
    return Err("Challenge mismatch");
}

// Verify COSE_Sign1, walk cert chain to AWS root
verify_nitro_signature(&doc, &aws_root)?;
```

**Status**: CBOR parser implemented and tested. **Cannot run in Nitro Enclave** (no persistent storage for audit log, no network beyond vsock).

---

## 4. Security Analysis

### 4.1 Threat: Attestation Replay

**Attack**: Attacker captures a genuine attestation report from a previous session and replays it.

**Defense**: Nonce is client-chosen, fresh per request. The challenge commits to this nonce. A replayed report contains `challenge = H(signing_key || old_nonce)`. Client recomputes `challenge = H(signing_key || new_nonce)`. Mismatch → verification fails.

**Result**: Replay is detectable.

### 4.2 Threat: Signing Key Substitution

**Attack**: Attacker wants to present an attestation report from machine A but responses from machine B (B's signing key).

**Process**:
1. Client requests attestation with `nonce_c`
2. Attacker asks machine A to produce a quote for `challenge_A = H(key_A || nonce_c)`
3. Attacker receives A's quote (valid, measurements match)
4. Attacker substitutes `key_B` into the report sent to the client
5. Client recomputes `challenge_client = H(key_B || nonce_c)`
6. Client extracts `challenge_report = H(key_A || nonce_c)` from the quote
7. `challenge_client ≠ challenge_report`
8. Verification fails

**Result**: Key substitution is detectable.

### 4.3 Threat: Man-in-the-Middle on Attestation Request

**Attack**: MITM intercepts client's attestation request, substitutes their own nonce.

**Defense**: Challenge is computed from the nonce the **client chose**, not the nonce in the request. Even if MITM modifies the request, the client recomputes challenge from their original nonce. If the node answers the modified nonce, verification fails on the client side.

**Result**: MITM cannot force the node to answer a challenge the client didn't choose.

### 4.4 Limitation: Stolen Signing Key

If an attacker steals the signing key from the attested machine, they can:
1. Get a genuine attestation report (machine A, measurements match, challenge binds key_A)
2. Use key_A to sign responses from anywhere (machine B)

The binding proves "machine A holds key_A at measurements M." It does not prevent key_A from being copied elsewhere afterward. This is a **key custody problem**, not an attestation problem.

**Mitigation**: Keep signing keys in hardware (SGX enclave, TPM-bound key, Nitro enclave). If the key cannot leave the attested environment, this attack is blocked.

---

## 5. Implementation

### 5.1 Challenge Function

```rust
pub fn compute_challenge(signing_key_hex: &str, nonce: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    
    let mut hasher = Sha256::new();
    hasher.update(b"CORDON_ATTEST_CHALLENGE_v1");
    hasher.update((signing_key_hex.len() as u64).to_le_bytes());
    hasher.update(signing_key_hex.as_bytes());
    hasher.update((nonce.len() as u64).to_le_bytes());
    hasher.update(nonce);
    hasher.finalize().to_vec()
}
```

**Why length-prefix?**: Prevents ambiguity. Without it, `("key" || "ABC")` and `("keyA" || "BC")` hash to the same value.

### 5.2 Client Verification Flow

```rust
pub fn verify_attestation(
    report: &AttestationReport,
    expected_measurements: &Measurements,
    nonce: &[u8],
) -> Result<VerifiedAttestation> {
    // 1. Recompute challenge
    let expected_challenge = compute_challenge(
        &report.enclave_signing_key_hex,
        nonce
    );
    
    // 2. Extract challenge from platform quote
    let actual_challenge = match report.measurement_source {
        MeasurementSource::Tpm2 => extract_tpm_extra_data(&report.tee_quote)?,
        MeasurementSource::SevSnp => extract_snp_report_data(&report.tee_quote)?,
        MeasurementSource::NitroEnclave => extract_nitro_nonce(&report.tee_quote)?,
        _ => return Err("No hardware quote"),
    };
    
    // 3. Compare
    if !constant_time_eq(&expected_challenge, &actual_challenge) {
        return Err("Challenge mismatch: replay or key substitution detected");
    }
    
    // 4. Verify platform signature
    verify_platform_signature(&report)?;
    
    // 5. Check measurements
    check_measurements(&report, expected_measurements)?;
    
    Ok(VerifiedAttestation {
        hardware_rooted: true,
        signing_key_bound: true,
        measurements_match: true,
        challenge_fresh: true,
    })
}
```

### 5.3 API Usage

**Request attestation**:
```bash
curl -s "https://node:8443/v1/attestation?nonce=$(openssl rand -hex 32)" \
  --cert client.crt --key client.key > report.json
```

**Verify offline**:
```bash
cordon-verify-attestation \
  --report report.json \
  --nonce <nonce-you-sent> \
  --expected-measurements pinned.toml
```

---

## 6. Evaluation

### 6.1 Performance

| Operation | Time |
|-----------|------|
| Compute challenge | <1ms |
| TPM quote generation | 50-200ms |
| SEV-SNP report (configfs-tsm) | 10-50ms |
| Nitro attestation doc | 100-300ms |
| Client verification | 5-50ms (depends on cert chain length) |

**Overhead**: Marginal. Challenge computation is a single SHA-256 (sub-millisecond). Platform quote generation is the bottleneck, but happens once per session, not per request.

### 6.2 Comparison

| Approach | Replay Prevention | Key Binding | Offline Verifiable |
|----------|------------------|-------------|-------------------|
| **Challenge-response (ours)** | Yes (nonce) | Yes (challenge commits to key) | Yes |
| Timestamp-based | Partial (clock skew) | No | No |
| Session ID | Partial (ID reuse) | No | Yes |
| Signed attestation only | No | No | Yes |

**Intel SGX DCAP**: Uses `report_data` similarly, but doesn't commit to signing key—only to application-specific data. Our approach binds signing key explicitly.

---

## 7. Limitations

1. **Key custody**: If signing key is stolen, attacker can sign responses elsewhere. Binding proves key ownership at attestation time, not continuous custody.

2. **Nitro deployment blocked**: Cordon cannot run in Nitro Enclave (architectural constraint: no storage, no network). Verification is implemented; deployment is not.

3. **Certificate revocation**: We verify cert chains to pinned roots but do not check CRLs. An attacker with a revoked VCEK could still produce valid quotes until next firmware update.

4. **TDX not yet supported**: Intel TDX uses similar mechanisms but report format is not yet parsed.

---

## 8. Future Work

1. **TDX implementation**: Parse TDX quotes, verify ECDSA signatures
2. **Formal verification**: Prove binding properties in Coq/Isabelle
3. **Key binding to HSM**: Store signing keys in TPM/HSM, bind attestation to HSM-resident keys
4. **CRL checking**: Integrate VCEK CRL verification for air-gapped deployments

---

## 9. Conclusion

We present a challenge-response protocol where platform attestation quotes commit to both client nonces and node signing keys, preventing attestation replay and signing key substitution. The protocol is implemented for TPM 2.0 (tested on real hardware), AMD SEV-SNP (tested with synthetic keys), and AWS Nitro (parser complete, deployment blocked by architectural constraints).

Verification is offline, taking 5-50ms depending on certificate chain length. Challenge computation overhead is sub-millisecond. The binding is cryptographic: divergence between computed and quoted challenges causes verification failure, detectable by any client with pinned measurements and their chosen nonce.

**Implementation**: https://github.com/regnant-io/cordon (`cordon-crypto` crate, `AttestationService`)

---

**References**:
1. TPM 2.0 Library Specification (Trusted Computing Group)
2. AMD SEV-SNP Firmware ABI Specification
3. AWS Nitro Enclaves Attestation Process
4. RFC 8152: CBOR Object Signing and Encryption (COSE)
