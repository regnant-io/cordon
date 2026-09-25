# Dispatch Entry

**Title**: Binding Attestation to Answers  
**Slug**: binding-attestation-to-answers  
**Image URL**: /img/dispatch/attestation-binding.png  
**Excerpt**: Hardware attestation proves what software a machine is running. Response signatures prove key ownership. But these are two separate facts unless you explicitly connect them. We use challenge-response to bind them cryptographically.

---

## Body

Hardware attestation (TPM, SEV-SNP, Nitro) proves what software a machine is running. Cryptographic signatures prove a particular key signed a response. But these are two separate facts unless you explicitly connect them.

**The problem**: A genuine attestation quote from machine A doesn't prove the response you just received came from machine A. An impostor (machine B) could forward A's quote to you, then process your query and sign with B's key. You verified both—attestation and signature—but they weren't from the same machine.

### The Fix

The platform's signature must commit to **both**:
1. The client's nonce (prevents replay)
2. The node's response-signing key (prevents key substitution)

We do this with a challenge:

```
challenge = SHA-256("CORDON_ATTEST_CHALLENGE_v1"
                    || signing_key || nonce)
```

This value goes into the field the platform signs:
- **TPM**: `extraData` in the quote
- **SEV-SNP**: First 32 bytes of `REPORT_DATA`
- **Nitro**: `nonce` field in the attestation document

When you verify, you recompute the challenge from:
- The signing key the report declares
- The nonce **you chose**

If an attacker substitutes the key or replays an old quote, the challenge won't match. The platform's signature verification fails.

### Why This Matters

For institutions running classified workloads or handling sensitive data, you need proof that:
- The machine you're talking to passed attestation
- The responses you're getting come from **that specific machine**
- Not from an impostor in the middle

Without binding, attestation is decorative. With binding, it's cryptographic proof.

### Attack Prevention

**Replay attack**: Client chooses a fresh nonce every session. Old quotes have old nonces; the challenge recomputation fails.

**Key substitution**: Attacker can't get machine A to sign `challenge = H(key_B || nonce)` without knowing key_B in advance. And if they did, machine A would be signing for B's key, which B doesn't hold.

**MITM on request**: Even if an attacker intercepts your attestation request and modifies the nonce, you recompute the challenge from **your** original nonce. The node's answer won't match.

### In Production

- **TPM 2.0**: Tested on Dell R740, HP ProLiant with real TPM chips
- **AMD SEV-SNP**: Implemented, tested with synthetic keys, awaiting production silicon
- **AWS Nitro**: Verification implemented (parser complete), deployment blocked by architectural constraints

**Performance**: Challenge computation is <1ms. Platform quote generation (50-300ms depending on hardware) is the bottleneck, but it happens once per session, not per request.

**Read the full paper**: [Binding Attestation to Answers: Challenge-Response for Inference Verification](../02-attestation-binding.md)

**Implementation**: https://github.com/regnant-io/cordon (`cordon-crypto` crate, `AttestationService`)
