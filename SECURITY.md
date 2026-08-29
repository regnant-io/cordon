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
- Any way to reach the model runtime other than through Cordon.
- Plaintext prompts, completions, or key material reaching disk, logs, or the
  network outside the paths documented in `ARCHITECTURE.md`.
- Remote crashes, unbounded memory growth, or unbounded work triggered by an
  unauthenticated or minimally authenticated request.

Out of scope:

- The absence of hardware attestation in Light mode. This is documented
  behaviour: Light mode does not claim a hardware root of trust, and
  `MeasurementSource::SoftwareMeasurement` is reported as such in every response.
- Attacks that require the Client Master Key, root on the node, or physical
  access. Those are outside Cordon's threat model by construction.
- Weaknesses in a model runtime Cordon supervises but does not ship. Report
  those upstream; tell us if Cordon's supervision fails to contain them.
- Findings that depend on a configuration Cordon refuses to start with.

## Threat model

`ARCHITECTURE.md` states what Cordon defends against and what it does not.
A report is most useful when it identifies a property that document claims and
shows it does not hold.

## What Cordon does not claim

Cordon is a control plane, not a trusted execution environment. In particular:

- Outside a hardware-TEE deployment, an attacker with root on the node can read
  prompts and completions from process memory. Cordon narrows that window; it
  does not close it.
- Staged plaintext weights exist on disk for the duration of a model load. The
  window is bounded and the file is erased; on a host where that is
  unacceptable, stage onto a memory-backed filesystem.
- A software measurement attests configuration, not platform.
