# Supervised Runtime Architecture for Containment

**Title**: Supervised Runtime Architecture: Architectural Containment for Sovereign AI  
**Slug**: supervised-runtime-architecture  
**Authors**: Regnant Research  
**Image URL**: /img/research/supervised-runtime.png  
**Date Label**: 2026 Q3  
**Abstract**: A model runtime reachable from the network lets callers bypass identity, policy, rate limits, and audit—the control plane becomes advisory rather than mandatory. We present the supervised runtime architecture where Cordon spawns and owns the model process, binding it to loopback with an ephemeral port and per-boot API key. Startup validation refuses non-compliant configurations. Result: "Cordon is the only door" becomes an architectural property, not an operational policy. Tested with llama.cpp; generalizes to any OpenAI-compatible runtime.  
**Category**: RESEARCH  
**Published**: Yes

---

## Abstract

Control planes for AI inference enforce identity, authorization, content policy, rate limits, and audit. But enforcement is meaningless if the model runtime is directly reachable: callers bypass all controls.

Traditional deployment:
```
Client → [Control Plane] → Model Runtime (on 0.0.0.0:8080)
Client → Model Runtime (direct, bypasses control plane)
```

We present the **supervised runtime** architecture where Cordon spawns and owns the model process:
1. **Loopback only**: `--host 127.0.0.1`, never `0.0.0.0`
2. **Ephemeral port**: OS-assigned, never published
3. **Per-boot API key**: 32 random bytes, passed via file (not CLI arg)
4. **Web UI disabled**: `--no-webui` when supported
5. **Killed on exit**: Process dies when Cordon stops

**Startup validation** refuses:
- Non-loopback binding
- HTML at `/` (indicates web UI active)
- Health check failure

**Result**: "Cordon is the only door" is an architectural property. An operator who starts a second runtime bypasses nothing—clients never learn the endpoint.

---

## 1. Problem Statement

### 1.1 The Bypass Problem

Control planes implement:
- **Identity**: mTLS client certificates, enrollment checks
- **Authorization**: Per-client model permissions
- **Content policy**: PII filtering, redaction, blocking
- **Rate limits**: Requests/minute, tokens/minute
- **Audit**: Tamper-evident logs of every request

**But** if the model runtime is accessible:
```bash
# Direct call, bypassing Cordon
curl http://inference-node:8080/v1/completions \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Sensitive query"}'
```

All controls are circumvented:
- ❌ No identity check (runtime doesn't verify certificates)
- ❌ No authorization (runtime doesn't know about policies)
- ❌ No content filtering (runtime returns raw output)
- ❌ No rate limiting (runtime processes every request)
- ❌ No audit (runtime doesn't log to Cordon's chain)

**The control plane is advisory, not mandatory.**

### 1.2 Why This Happens

Operators deploy:
```bash
# Model runtime (llama-server, vLLM, etc.)
llama-server --model /weights/model.gguf --host 0.0.0.0 --port 8080

# Control plane
cordon --runtime-url http://127.0.0.1:8080
```

**Problem 1**: Runtime binds to `0.0.0.0` (all interfaces). Anyone who knows the IP can reach it.

**Problem 2**: Port is fixed and documented. Scanning finds it.

**Problem 3**: No authentication on runtime endpoint. It accepts any request.

### 1.3 Existing Mitigations (Inadequate)

**Network policies**: "Use a firewall to block port 8080."
- Requires correct configuration
- Operator error exposes runtime
- Internal threats still reach it

**API keys on runtime**: Some runtimes support `--api-key`.
- Cordon must know the key
- If an operator also knows it, they can call directly
- Key rotation is manual

**Containerization**: "Run runtime in a separate container with no exposed ports."
- Requires orchestration (Docker Compose, Kubernetes)
- Misconfiguration exposes ports
- Still depends on network policy

**None of these are architectural.** They are policies an operator can misconfigure or bypass.

---

## 2. Our Approach: Supervised Runtime

### 2.1 Ownership Model

**Cordon spawns the runtime** as a child process:
```rust
pub struct LlamaSupervisor {
    process: Child,               // std::process::Child
    endpoint: String,             // "http://127.0.0.1:52341"
    api_key: String,              // 32 random bytes, per-boot
    log_buffer: RingBuffer<String>,
}
```

**Lifecycle**:
1. Cordon starts
2. Cordon generates random API key
3. Cordon spawns runtime with constraints
4. Cordon polls runtime health
5. Cordon forwards requests to runtime
6. Cordon stops → runtime is killed

### 2.2 Constraints Enforced

#### Constraint 1: Loopback Only

```rust
let mut cmd = Command::new("llama-server");
cmd.arg("--host").arg("127.0.0.1");  // Never 0.0.0.0
cmd.arg("--port").arg("0");           // Ephemeral (OS-assigned)
```

**Validation**: After spawn, read runtime's stdout for the line:
```
llama_server: listening on 127.0.0.1:52341
```

If the log contains `0.0.0.0`, startup fails:
```rust
if log_line.contains("0.0.0.0") {
    process.kill()?;
    return Err("Runtime bound to 0.0.0.0, refusing");
}
```

#### Constraint 2: Ephemeral Port

`--port 0` tells the OS to assign an unused port. The port number is unpredictable and never published outside Cordon.

**Benefit**: An attacker scanning ports finds nothing. The runtime is listening, but on a port only Cordon knows.

#### Constraint 3: Per-Boot API Key

```rust
let api_key = generate_api_key();  // 32 random bytes, base64
let key_file = temp_dir.path().join("api_key.txt");
fs::write(&key_file, &api_key)?;

cmd.arg("--api-key-file").arg(&key_file);
```

**Why not `--api-key <value>`?**
- CLI args are visible in `ps aux`
- Any user on the system can read them
- File with mode 0600 is readable only by Cordon's user

**Key rotation**: Every boot. An attacker who steals the key has until next restart.

#### Constraint 4: Web UI Disabled

Many runtimes include a web UI for debugging. This is a **second interface** to the model, bypassing Cordon.

```rust
cmd.arg("--no-webui");  // If supported
```

**Validation**: After startup, HTTP GET to `/`:
```rust
let response = reqwest::get(&format!("{}/", endpoint)).await?;
let content_type = response.headers().get("content-type");

if content_type.map_or(false, |v| v.to_str().unwrap_or("").contains("text/html")) {
    process.kill()?;
    return Err("Runtime serves HTML at /, web UI is active");
}
```

Expected: `404 Not Found` or `{"error": "Not Found"}`. If HTML is returned, startup fails.

#### Constraint 5: Killed on Exit

```rust
impl Drop for LlamaSupervisor {
    fn drop(&mut self) {
        let _ = self.process.kill();
    }
}
```

When Cordon stops (graceful shutdown, SIGTERM, crash), the runtime process is killed. It does not outlive the control plane.

---

## 3. Startup Validation

### 3.1 The Validation Sequence

```rust
pub async fn start_supervised_runtime(config: &RuntimeConfig) -> Result<LlamaSupervisor> {
    // 1. Generate ephemeral credentials
    let api_key = generate_api_key();
    let key_file = write_api_key_file(&api_key)?;
    
    // 2. Spawn process
    let mut cmd = build_command(config, &key_file)?;
    let mut process = cmd.spawn()?;
    
    // 3. Parse logs for endpoint
    let endpoint = wait_for_endpoint(&mut process, Duration::from_secs(30))?;
    
    // 4. Validate loopback binding
    if !endpoint.contains("127.0.0.1") && !endpoint.contains("localhost") {
        process.kill()?;
        return Err("Runtime did not bind to loopback");
    }
    
    // 5. Check web UI is disabled
    validate_no_web_ui(&endpoint).await?;
    
    // 6. Health check
    health_check(&endpoint, &api_key).await?;
    
    Ok(LlamaSupervisor {
        process,
        endpoint,
        api_key,
        log_buffer: RingBuffer::new(1000),
    })
}
```

**Timeout**: 30 seconds. If validation doesn't complete, the process is killed and startup fails.

**Fail-closed**: A runtime that won't comply is refused, not tolerated.

### 3.2 Health Monitoring

Background task pings every 10 seconds:
```rust
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    loop {
        interval.tick().await;
        match health_check(&endpoint, &api_key).await {
            Ok(_) => {}
            Err(e) => {
                warn!("Runtime health check failed: {}", e);
                // Mark as degraded, attempt restart
                restart_runtime().await;
            }
        }
    }
});
```

If the runtime crashes, Cordon detects it within 10 seconds and restarts.

---

## 4. Request Forwarding

### 4.1 Proxying

Clients call Cordon:
```
POST https://cordon-node:8443/v1/inference
```

Cordon validates (identity, policy, rate limits, audit), then forwards to runtime:
```rust
pub async fn forward_to_runtime(
    req: InferenceRequest,
    supervisor: &LlamaSupervisor,
) -> Result<InferenceResponse> {
    let client = reqwest::Client::new();
    let response = client
        .post(&format!("{}/v1/completions", supervisor.endpoint))
        .header("Authorization", format!("Bearer {}", supervisor.api_key))
        .json(&req)
        .timeout(Duration::from_secs(req.timeout_seconds))
        .send()
        .await?;
    
    let completion: InferenceResponse = response.json().await?;
    Ok(completion)
}
```

**Key point**: The runtime endpoint is **never** exposed to clients. They don't know it exists.

### 4.2 Streaming

For streaming:
```rust
let response = client
    .post(&format!("{}/v1/completions", supervisor.endpoint))
    .header("Authorization", format!("Bearer {}", supervisor.api_key))
    .json(&req)
    .send()
    .await?;

let mut stream = response.bytes_stream();
while let Some(chunk) = stream.next().await {
    let chunk = chunk?;
    // Apply content policy incrementally
    let filtered = streaming_filter.push_chunk(&chunk)?;
    // Send to client
    send_sse_chunk(&filtered).await?;
}
```

Content policy is applied **before** chunks reach the client, not after.

---

## 5. Security Analysis

### 5.1 Threat: Direct Runtime Access

**Attack**: Attacker scans network for runtime endpoint.

**Defense**:
- Loopback binding: Only reachable from localhost
- Ephemeral port: Unpredictable
- Firewall: Default deny on ingress (operational layer)

**Result**: External attacker cannot reach runtime.

### 5.2 Threat: Local Attacker

**Attack**: Attacker with shell access on the node tries to call runtime directly.

**Defense**:
- API key required (32 random bytes)
- Key stored in file with mode 0600 (readable only by Cordon's user)
- Key rotates on every boot

**Limitation**: If attacker gains access as Cordon's user, they can read the key file. At that point, they already have access to all Cordon resources (audit log, config, CMK). The supervised runtime does not defend against same-user compromise.

### 5.3 Threat: Operator Starts Second Runtime

**Attack**: Operator starts a second instance of `llama-server` on a public port with the same weights.

**Scenario**:
```bash
# Operator's shell
llama-server --model /weights/model.gguf --host 0.0.0.0 --port 9000
```

**What this achieves**:
- Clients who know about port 9000 can call it
- Bypasses Cordon entirely

**What it doesn't achieve**:
- Clients enrolled in Cordon don't know about port 9000
- They were given `https://cordon-node:8443/v1/inference` as the endpoint
- The operator gained nothing unless they also distribute the new endpoint

**Mitigation (operational)**:
- Audit processes: `ps aux | grep llama-server` should show only one
- Network monitoring: Flag unexpected listeners
- Container isolation: Runtime runs in a container with no bind-mount of weights

**Mitigation (architectural)**:
- Bundle encryption: Operator cannot decrypt weights without CMK
- Integrity monitoring: Weights on disk are ciphertext; serving plaintext requires decryption, which requires staging through Cordon

**Combined**: An operator can start a second runtime, but it cannot decrypt the weights. They could serve a different model, but clients verify attestation reports that commit to measurements (including the model hash). A substituted model fails verification.

### 5.4 Threat: Runtime Vulnerability

**Attack**: Runtime has an RCE vulnerability (e.g., buffer overflow in prompt parsing).

**Impact**:
- Attacker gains code execution inside the runtime process
- Runtime runs as the same user as Cordon (typically)
- Attacker can read audit log, config, CMK

**Mitigation (current)**:
- Runtime is confined to loopback (external attacker must compromise Cordon first)
- Supervised: Restart on crash (attacker's foothold is temporary)

**Mitigation (future work)**:
- Run runtime in a separate user namespace
- Apply seccomp filters (allow only networking, file I/O to specific paths)
- Use a purpose-built inference runtime with smaller attack surface

**Status**: Containment exists; sandboxing does not. Future research direction.

---

## 6. Comparison to Alternatives

| Approach | Bypass Prevention | Key Rotation | Operator Error Resilience |
|----------|------------------|--------------|--------------------------|
| **Supervised (ours)** | Architectural (loopback + ephemeral) | Per-boot | High (fail-closed validation) |
| Network policy | Operational (firewall rules) | N/A | Low (misconfiguration exposes) |
| Static API key | Weak (key may leak) | Manual | Low (key in logs, config) |
| Separate container | Operational (orchestration config) | N/A | Medium (depends on k8s/compose) |
| No enforcement | None | N/A | None |

**Unique advantage**: Fail-closed validation. A runtime that won't comply is refused at startup, not discovered in production.

---

## 7. Implementation Details

### 7.1 Command Building

```rust
fn build_command(config: &RuntimeConfig, key_file: &Path) -> Result<Command> {
    let mut cmd = Command::new(&config.binary_path);
    
    // Required args
    cmd.arg("--host").arg("127.0.0.1");
    cmd.arg("--port").arg("0");
    cmd.arg("--model").arg(&config.model_path);
    cmd.arg("--api-key-file").arg(key_file);
    
    // Optional args
    if config.context_size > 0 {
        cmd.arg("--ctx-size").arg(config.context_size.to_string());
    }
    
    if config.threads > 0 {
        cmd.arg("--threads").arg(config.threads.to_string());
    }
    
    // Disable web UI
    cmd.arg("--no-webui");
    
    // Capture stdout/stderr
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    
    Ok(cmd)
}
```

### 7.2 Endpoint Parsing

Runtime prints:
```
llama_server: listening on 127.0.0.1:52341
```

Parser:
```rust
fn parse_endpoint(line: &str) -> Option<String> {
    let re = Regex::new(r"listening on (127\.0\.0\.1:\d+|localhost:\d+)").unwrap();
    re.captures(line).and_then(|caps| caps.get(1)).map(|m| m.as_str().to_string())
}
```

### 7.3 Log Capture

```rust
impl LlamaSupervisor {
    pub fn capture_logs(&mut self) {
        let stdout = self.process.stdout.take().unwrap();
        let stderr = self.process.stderr.take().unwrap();
        
        let log_buffer = self.log_buffer.clone();
        
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            while reader.read_line(&mut line).await.is_ok() {
                log_buffer.push(line.clone());
                line.clear();
            }
        });
        
        // Same for stderr
    }
}
```

Logs are available via `GET /v1/health/runtime` for diagnostics.

---

## 8. Limitations

1. **Same-user compromise**: If attacker gains access as Cordon's user, they can read the API key file.

2. **No sandboxing**: Runtime runs in the same process context as Cordon (same UID, same filesystem view).

3. **llama.cpp specific**: Current implementation is llama.cpp-aware. Generalization to other runtimes requires adapting command-line args and log parsing.

4. **No multi-runtime support**: One runtime per Cordon instance. Multi-model scenarios require multiple Cordon nodes.

---

## 9. Future Work

1. **Seccomp sandboxing**: Restrict runtime to a minimal syscall set
2. **User namespaces**: Run runtime as a separate UID
3. **cgroups limits**: Bound CPU, memory, I/O
4. **Runtime-agnostic abstraction**: Support vLLM, TGI, etc.
5. **Multi-runtime pooling**: Route requests to a pool of runtimes by model_id

---

## 10. Conclusion

We present a supervised runtime architecture where Cordon spawns and owns the model process, enforcing loopback binding, ephemeral ports, per-boot API keys, and startup validation. Result: "Cordon is the only door" is an architectural property, not an operational policy.

The approach is in production use with llama.cpp, preventing bypass through misconfiguration or operator error. Fail-closed validation refuses non-compliant runtimes at startup rather than discovering the issue when a caller bypasses controls.

**Key insight**: Process supervision with constrained spawning makes control plane enforcement mandatory. Combined with bundle encryption and attestation, the supervised runtime completes the containment architecture.

**Implementation**: https://github.com/regnant-io/cordon (`cordon-core/src/runtime/supervisor.rs`)

---

**References**:
1. llama.cpp server documentation
2. OpenAI API specification
3. POSIX process management (`fork`, `exec`, `kill`)
4. Linux namespaces and cgroups (future work)
