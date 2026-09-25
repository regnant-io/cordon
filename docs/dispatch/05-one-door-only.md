# Dispatch Entry

**Title**: One Door Only  
**Slug**: one-door-only  
**Image URL**: /img/dispatch/supervised-runtime.png  
**Excerpt**: Control planes enforce identity, policy, audit. But if the model runtime is reachable from the network, callers bypass everything. We spawn the runtime as a child process: loopback-only, ephemeral port, per-boot API key. Startup validation refuses non-compliance.

---

## Body

Control planes for AI inference enforce identity, authorization, content policy, rate limits, and audit. But enforcement means nothing if callers can bypass it.

**Traditional deployment**:
```
Client → [Control Plane] → Model Runtime (0.0.0.0:8080)
Client → Model Runtime (direct access, bypass everything)
```

If the model runtime is reachable from the network, **every control is advisory**.

### The Bypass Problem

An operator deploys:
```bash
# Model runtime
llama-server --model /weights/model.gguf --host 0.0.0.0 --port 8080

# Control plane
cordon --runtime-url http://127.0.0.1:8080
```

**Problem**: Runtime binds to `0.0.0.0` (all interfaces). Anyone who knows the IP can reach it directly:

```bash
curl http://inference-node:8080/v1/completions \
  -d '{"prompt": "Sensitive query"}'
```

Result:
- ❌ No identity check
- ❌ No authorization
- ❌ No content filtering
- ❌ No rate limiting
- ❌ No audit

**The control plane is advisory, not mandatory.**

### The Fix: Supervised Runtime

**Cordon spawns and owns the runtime** as a child process:

1. **Loopback only**: `--host 127.0.0.1`, never `0.0.0.0`
2. **Ephemeral port**: OS-assigned, unpredictable, never published
3. **Per-boot API key**: 32 random bytes, rotates every restart
4. **Web UI disabled**: `--no-webui` (many runtimes include a debug UI—a second bypass)
5. **Killed on exit**: Runtime dies when Cordon stops

**Startup validation** refuses:
- Non-loopback binding (if logs show `0.0.0.0`, startup fails)
- HTML at `/` (indicates web UI is active)
- Health check failure

### Why This Works

**External attacker**: Runtime is loopback-only. Cannot reach it from the network.

**Port scanning**: Ephemeral port is unpredictable. Scanning finds nothing.

**Local attacker**: API key is required (32 random bytes, stored in a file with mode 0600). Even with shell access, you need Cordon's UID to read the key.

**Operator starts a second runtime**: Clients don't know about it. They were enrolled with `https://cordon-node:8443/v1/inference` as the endpoint. A second runtime on port 9000 doesn't help unless the operator also redistributes the endpoint—and then clients would see attestation reports that don't match.

**Combined with bundle encryption**: An operator could start a second runtime, but it can't decrypt the weights without the Client Master Key. They could serve a *different* model, but attestation verification (which includes model hash in measurements) would fail.

### Architectural, Not Operational

**Other approaches** (network policies, firewall rules, container isolation) are **operational**: they depend on correct configuration. Misconfigure once, and the runtime is exposed.

**Supervised runtime** is **architectural**: The runtime literally cannot bind to a public interface. Cordon controls the process lifecycle. There is no configuration knob to bypass it.

**Fail-closed**: A runtime that won't comply (e.g., refuses `--host 127.0.0.1`) is refused at startup. You don't discover the issue when an attacker bypasses your controls.

### Performance

- **Overhead**: Marginal. Proxying adds <1ms per request.
- **Restart on crash**: Detected within 10 seconds, runtime restarted with exponential backoff.
- **Log capture**: Runtime stdout/stderr captured for diagnostics (`GET /v1/health/runtime`).

### Limitations

1. **Same-user compromise**: If attacker gains access as Cordon's user, they can read the API key file. But at that point they already have access to everything Cordon protects (audit log, config, CMK).

2. **No sandboxing yet**: Runtime runs as the same UID as Cordon. Future work: user namespaces, seccomp filters.

3. **llama.cpp specific**: Current implementation is llama.cpp-aware. Generalizing to vLLM, TGI, etc. requires adapting command-line args and log parsing.

### In Production

Used with llama.cpp in government, healthcare, and finance deployments. Zero bypasses detected over 6 months.

**Key insight**: Process supervision with constrained spawning makes control plane enforcement mandatory, not advisory.

**Read the full paper**: [Supervised Runtime Architecture: Architectural Containment for Sovereign AI](../05-supervised-runtime.md)

**Implementation**: https://github.com/regnant-io/cordon (`cordon-core/src/runtime/supervisor.rs`)
