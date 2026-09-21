# Security policy

Cordon is a security control plane. A defect in it can silently weaken every
guarantee a deployment depends on, so please report problems privately before
disclosing them.

## Reporting a vulnerability

Open a [private security advisory](https://github.com/cordon-project/cordon/security/advisories/new)
on GitHub. Please do not open a public issue for a suspected vulnerability.

Include, as far as you can:

- the version or commit affected,
- the deployment mode and configuration that exhibits the problem,
- what an attacker gains, and what they need in order to get it,
- a reproduction, ideally as a failing test.

You should get an acknowledgement within three working days and an assessment
within ten. If a fix is warranted we will agree a disclosure date with you and
credit you in the release notes unless you prefer otherwise.

## Scope

In scope, and treated as security defects:

- Any way to obtain inference without satisfying identity, policy, rate limits,
  or the model-store gate.
- Any way to make the audit log incomplete, reorderable, or rewritable without
  detection by `cordon-verify-log`.
- Any way to make a node report itself attested, or its keys CMK-derived, when
  it is not.
- Any way to make an attestation report verify when it should not: a replay, a
  substituted attestation key, measurements the platform did not sign for, or a
  signing key the quote does not commit to.
- Any way to reach the model runtime other than through Cordon.
- Any way for one client to read, exhaust, or degrade another's service;
including reading the audit log without `log_export_allowed`.
- Plaintext prompts, completions, or key material reaching disk, logs, or the
  network outside the paths documented in `ARCHITECTURE.md`.
- Remote crashes, unbounded memory growth, or unbounded work triggered by an
  unauthenticated or minimally authenticated request.
- Configuration that describes a defence Cordon does not implement. A field an
  operator can set and Cordon ignores is a belief they hold and cannot act on,
  and we treat that as a defect rather than a documentation gap.

Out of scope:

- The absence of hardware attestation in Light mode. This is documented
  behaviour: Light mode does not claim a hardware root of trust, and
  `MeasurementSource::SoftwareMeasurement` is reported as such in every response.
- Attacks that require the Client Master Key. It is the root of trust by
  construction.
- Root on the node **outside a confidential VM**. Documented as undefended.
  Inside one it is in scope: if root on the *host* can reach guest memory
  through something Cordon does, we want to know.
- Physical attacks on the host.
- Weaknesses in a model runtime Cordon supervises but does not ship. Report
  those upstream; tell us if Cordon's supervision fails to contain them.
- Findings that depend on a configuration Cordon refuses to start with.
- The unimplemented items listed under "What is not implemented" below. They are
  known gaps, not findings.

## Threat model

`ARCHITECTURE.md` states what Cordon defends against and what it does not.
A report is most useful when it identifies a property that document claims and
shows it does not hold.

## What Cordon does not claim

On an ordinary host Cordon is a control plane and not a trusted execution
environment. Inside an AMD SEV-SNP guest, `measurement_source = "sev_snp"`,
the model runtime, the weights and the prompts are inside the encrypted guest
and the hypervisor is outside it, and the claim changes accordingly. Which of
those you are running decides which of the following applies.

In particular:

- **Outside a confidential VM**, an attacker with root on the node can read
  prompts and completions from process memory. Cordon narrows that window; it
  does not close it. A TPM does not close it either; it attests how a machine
  booted, not that its memory is private from whoever owns it.
- Staged plaintext weights exist on disk for the duration of a model load. The
  window is bounded, the file is created with `O_EXCL` and `O_NOFOLLOW` at mode
  0600, and it is erased; on a host where that is unacceptable, stage onto a
  memory-backed filesystem.
- A software measurement attests configuration, not platform.
- Response *length* is not padded. Timing is normalised; size is not.
- `zero_egress` means Cordon opens no outbound connections. It does not mean
  packets cannot leave the host, which remains a firewall's job.
- `hsm.fips_level` is a declaration Cordon does not verify. Cordon talks to no
  HSM.

## What is not implemented

Stated here so a report about one is not mistaken for a finding, and so an
operator does not read a capability into silence:

- Intel TDX and SGX-DCAP quote verification.
- Fetching the VCEK from AMD's Key Distribution Service. The request path is
  built; the fetch is left to the caller so an air-gapped node can verify from a
  cached chain.
- Certificate revocation, for AMD's chain or a TPM vendor's.
- Walking a TPM endorsement key certificate to a vendor root. A verified TPM
  quote proves the holder of the attestation key produced it, not that the key
  belongs to genuine hardware. SEV-SNP does chain to a root you pin.
- Attestation-gated key release. The Client Master Key reaches the node from the
  operator; release is not conditioned on a verified quote.
- Verification of the vendor and client signature fields on a bundle manifest.
  Integrity monitoring detects a shard changed under a fixed manifest, not a
  manifest and its shards replaced together.
- Certificate revocation checking for client certificates. Revoking a client
  means removing it from the registry (which needs a restart) or suspending it
  through the admin API.
- The SEV-SNP path has not been exercised against real silicon. It is
  implemented against AMD's specification and tested with synthetic keys.
- **Running Cordon inside an AWS Nitro Enclave.** The verifier is implemented:
  Cordon parses the COSE_Sign1 envelope and the CBOR attestation document, checks
  the ES384 signature, walks the certificate chain to a root you pinned, compares
  the PCRs, and enforces the challenge binding and a freshness bound. Every
  refusal path is tested. What is missing is not a binding but a fit: an enclave
  reaches the Nitro Security Module by `ioctl` on `/dev/nsm`, has no persistent
  storage, and has no network interface other than vsock. Cordon's audit log is a
  hash-chained file that must be `fsync`ed before a request is processed, and its
  API is a TLS listener; neither survives that environment without being
  redesigned around vsock and an external log sink. A node configured with
  `measurement_source = "nitro_enclave"` refuses to start rather than coming up
  and failing on the first attestation request. The Nitro document path has not
  been exercised against a real Nitro Security Module.
