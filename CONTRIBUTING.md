# Contributing to Cordon

Cordon is a security control plane. That shapes what a good contribution looks
like here more than most projects: a change that makes the system faster or
tidier but weakens a guarantee is a regression, and a change that adds a
guarantee the code cannot actually deliver is worse than no change at all.

## Before you start

For anything beyond a bug fix or a documentation correction, open an issue
first. Design discussion is cheaper than a rejected pull request.

## Building

```bash
cargo build --workspace
cargo test --workspace
```

The workspace builds with zero warnings, and CI enforces that. Run
`cargo clippy --all-targets` before you push.

To exercise a real model runtime you need `llama-server` on `PATH`. Without it
the test suite still passes in full — it uses the deterministic backend, which
performs no inference and labels its output as such.

```bash
cargo run --bin cordon -- doctor
```

## What a change should look like

**Fail closed.** When a check cannot be performed, refuse. A node that cannot
verify its model's integrity should stop serving, not serve and hope. Every
`unwrap_or(true)`, every `if let Ok(..)` that silently skips a check, and every
fallback to a weaker mode is a place where this can go wrong.

**Say what is true.** If a function cannot deliver what its name promises, give
it a name it can keep. Cordon previously had a `load_model` that wrote weights
to a temporary file, deleted it, and set a boolean; the name was the bug. The
same applies to responses: `measurement_source` exists so that no caller can
mistake a configuration digest for a hardware attestation.

**Bound everything an untrusted caller can influence.** Request sizes, session
tables, replay-detection maps, connection counts, work per request. An
unbounded anything reachable from the network is a denial of service.

**Never slice a `String` at an arbitrary byte offset.** `panic = "abort"` is set
for release builds, so a mid-character slice is a remote crash. Use
`char_indices`, or the `floor_char_boundary` helper in `output_filter`.

**Do not put client content in logs.** The audit log records hashes, token
counts, and policy outcomes. The tracing log records paths and statuses. Neither
records prompts or completions.

## Tests

New behaviour needs a test. Prefer tests that state a property an attacker would
want to violate, and name them after that property:

```rust
#[test]
fn a_node_without_pinned_measurements_cannot_be_verified() { … }

#[test]
fn multibyte_output_does_not_panic_on_length_truncation() { … }
```

A test named `test_filter` tells a future reader nothing about what breaks if it
fails.

Security-relevant changes should come with a test that fails before the change.
If you cannot write one, say so in the pull request and explain why.

## Cryptography

Do not add a cryptographic primitive, construction, or protocol without
discussion. The existing set — AES-256-GCM, Ed25519, HKDF-SHA256, SHA-256 — is
deliberately small.

If you touch the key hierarchy, the domain-separation strings in
`cordon-crypto/src/kdf.rs` are versioned (`CORDON_*_KEY_v1`). Changing what a
string derives without changing its version silently invalidates every existing
deployment's keys. Add a new version instead.

## Commits and pull requests

Write commit messages that explain why, not what — the diff already says what.
Keep unrelated changes in separate commits.

A pull request should say:

- what problem it solves,
- what an attacker could do before the change and cannot after,
- anything you considered and rejected.

## Licence

Contributions are accepted under the [Apache License 2.0](LICENSE). By opening a
pull request you confirm you have the right to submit the work under that
licence.
