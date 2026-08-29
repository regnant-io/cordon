//! Supervised llama.cpp runtime.
//!
//! Cordon owns the model runtime rather than assuming an operator has started
//! one correctly. [`LlamaSupervisor`] spawns `llama-server` as a child process
//! and constrains it so that Cordon is the only reachable surface:
//!
//! * **Loopback only.** The child is bound to `127.0.0.1`. The bind address is
//!   not configurable — a runtime reachable from the network would let callers
//!   bypass Cordon's identity, policy, filtering, and audit layers entirely.
//! * **Ephemeral port.** The port is chosen at startup from the kernel's
//!   ephemeral range and is never published, so the runtime is not sitting on a
//!   guessable port.
//! * **Web UI compiled out of the response path.** `--no-webui` is passed when
//!   the binary supports it, and after startup Cordon *verifies* that the child
//!   does not serve an HTML document at `/`. If it does, startup fails closed.
//! * **Per-boot API key.** A 32-byte random key is generated for each launch and
//!   required on every request, so another local process cannot drive the
//!   runtime even if it discovers the port.
//!
//! The child is terminated when the supervisor is dropped and when the process
//! exits, and it is restarted automatically if it dies while Cordon is running.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

use crate::error::{CordonError, CordonResult};

/// Lines of child stderr retained for diagnostics.
const LOG_RING_CAPACITY: usize = 200;

/// How long to wait for the runtime to report healthy before giving up.
const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(180);

/// Interval between health probes during startup.
const HEALTH_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Configuration for a supervised llama.cpp runtime.
#[derive(Debug, Clone)]
pub struct LlamaRuntimeConfig {
    /// Path to the `llama-server` binary.
    pub binary: PathBuf,
    /// Path to the GGUF model file.
    pub model_path: PathBuf,
    /// Context window size passed to the runtime.
    pub ctx_size: u32,
    /// Layers to offload to the GPU. Zero keeps the model on the CPU.
    pub gpu_layers: u32,
    /// Generation threads. `None` lets llama.cpp choose.
    pub threads: Option<u32>,
    /// Parallel decoding slots. Should be at least Cordon's concurrency limit.
    pub parallel_slots: u32,
    /// How long to wait for the runtime to become healthy.
    pub startup_timeout: Duration,
    /// Additional arguments appended verbatim.
    pub extra_args: Vec<String>,
}

impl LlamaRuntimeConfig {
    /// Build a configuration with defaults suited to a small local model.
    pub fn new(binary: PathBuf, model_path: PathBuf) -> Self {
        Self {
            binary,
            model_path,
            ctx_size: 4096,
            gpu_layers: 0,
            threads: None,
            parallel_slots: 4,
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
            extra_args: Vec::new(),
        }
    }
}

/// A running, supervised llama.cpp server.
pub struct LlamaSupervisor {
    config: LlamaRuntimeConfig,
    endpoint: SocketAddr,
    api_key: String,
    child: Arc<Mutex<Option<Child>>>,
    stderr_ring: Arc<Mutex<Vec<String>>>,
    supports_no_webui: bool,
    http: reqwest::Client,
}

impl LlamaSupervisor {
    /// Spawn the runtime and block until it reports healthy.
    ///
    /// Fails closed on any of: a missing binary, a missing model file, a
    /// startup timeout, or a child that serves an HTML web UI at `/`.
    pub async fn start(config: LlamaRuntimeConfig) -> CordonResult<Self> {
        Self::validate_paths(&config)?;

        let supports_no_webui = probe_no_webui_support(&config.binary).await;
        if !supports_no_webui {
            tracing::warn!(
                binary = %config.binary.display(),
                "llama-server does not accept --no-webui; the runtime UI is suppressed \
                 by loopback binding, an ephemeral port, and a required API key. Consider \
                 upgrading llama.cpp so the UI is removed from the response path entirely."
            );
        }

        let endpoint = reserve_loopback_port()?;
        let api_key = generate_api_key();

        let http = reqwest::Client::builder()
            // The runtime is on loopback; no proxy should ever be consulted.
            .no_proxy()
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .map_err(|e| {
                CordonError::Internal(format!("cannot build runtime HTTP client: {}", e))
            })?;

        let supervisor = Self {
            config,
            endpoint,
            api_key,
            child: Arc::new(Mutex::new(None)),
            stderr_ring: Arc::new(Mutex::new(Vec::new())),
            supports_no_webui,
            http,
        };

        supervisor.spawn_child().await?;
        supervisor.await_healthy().await?;
        supervisor.assert_web_ui_unreachable().await?;

        tracing::info!(
            endpoint = %supervisor.endpoint,
            model = %supervisor.config.model_path.display(),
            "llama.cpp runtime supervised on loopback; web UI unreachable"
        );

        Ok(supervisor)
    }

    fn validate_paths(config: &LlamaRuntimeConfig) -> CordonResult<()> {
        if !config.binary.exists() {
            return Err(CordonError::RuntimeUnavailable(format!(
                "llama-server binary not found at {}. Install llama.cpp and set \
                 runtime.binary in the config (or CORDON_LLAMA_SERVER).",
                config.binary.display()
            )));
        }
        if !config.model_path.exists() {
            return Err(CordonError::RuntimeUnavailable(format!(
                "model file not found at {}. Fetch one with `cordon pull <repo>`.",
                config.model_path.display()
            )));
        }
        Ok(())
    }

    async fn spawn_child(&self) -> CordonResult<()> {
        let mut cmd = Command::new(&self.config.binary);
        cmd.arg("--model")
            .arg(&self.config.model_path)
            // Loopback is deliberately hard-coded. See the module docs.
            .arg("--host")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(self.endpoint.port().to_string())
            .arg("--api-key")
            .arg(&self.api_key)
            .arg("--ctx-size")
            .arg(self.config.ctx_size.to_string())
            .arg("--n-gpu-layers")
            .arg(self.config.gpu_layers.to_string())
            .arg("--parallel")
            .arg(self.config.parallel_slots.to_string());

        if let Some(threads) = self.config.threads {
            cmd.arg("--threads").arg(threads.to_string());
        }
        if self.supports_no_webui {
            cmd.arg("--no-webui");
        }
        for arg in &self.config.extra_args {
            cmd.arg(arg);
        }

        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            // If Cordon dies, the runtime must not outlive it holding the model
            // and the port.
            .kill_on_drop(true);

        let mut child = cmd.spawn().map_err(|e| {
            CordonError::RuntimeUnavailable(format!(
                "cannot launch {}: {}",
                self.config.binary.display(),
                e
            ))
        })?;

        if let Some(stderr) = child.stderr.take() {
            let ring = self.stderr_ring.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::debug!(target: "llama", "{}", line);
                    let mut ring = ring.lock();
                    if ring.len() >= LOG_RING_CAPACITY {
                        ring.remove(0);
                    }
                    ring.push(line);
                }
            });
        }

        *self.child.lock() = Some(child);
        Ok(())
    }

    async fn await_healthy(&self) -> CordonResult<()> {
        let deadline = tokio::time::Instant::now() + self.config.startup_timeout;
        let url = format!("http://{}/health", self.endpoint);

        loop {
            if tokio::time::Instant::now() >= deadline {
                let tail = self.recent_logs(20).join("\n");
                return Err(CordonError::RuntimeUnavailable(format!(
                    "llama-server did not become healthy within {}s. Recent output:\n{}",
                    self.config.startup_timeout.as_secs(),
                    tail
                )));
            }

            if let Some(status) = self.child_exit_status() {
                let tail = self.recent_logs(20).join("\n");
                return Err(CordonError::RuntimeUnavailable(format!(
                    "llama-server exited during startup with {}. Recent output:\n{}",
                    status, tail
                )));
            }

            let responded = self
                .http
                .get(&url)
                .bearer_auth(&self.api_key)
                .timeout(Duration::from_secs(2))
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false);

            if responded {
                return Ok(());
            }

            tokio::time::sleep(HEALTH_POLL_INTERVAL).await;
        }
    }

    /// Confirm the runtime does not serve a browsable UI.
    ///
    /// This is the enforcement behind the `--no-webui` flag rather than a
    /// restatement of it: Cordon asks the child for `/` and refuses to run if it
    /// gets an HTML document back.
    async fn assert_web_ui_unreachable(&self) -> CordonResult<()> {
        let url = format!("http://{}/", self.endpoint);
        let response = match self
            .http
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(r) => r,
            // A refused or erroring root is exactly what we want.
            Err(_) => return Ok(()),
        };

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();

        let status = response.status();
        let serves_html = status.is_success() && content_type.contains("text/html");

        if serves_html {
            return Err(CordonError::RuntimeUnavailable(format!(
                "the llama.cpp runtime is serving a web UI at {} (HTTP {}, {}). Cordon \
                 will not run alongside a second, unaudited inference surface. Upgrade \
                 llama.cpp to a build that supports --no-webui, or rebuild it with the \
                 server UI disabled.",
                url, status, content_type
            )));
        }

        tracing::debug!(status = %status, content_type = %content_type, "Runtime root is not a web UI");
        Ok(())
    }

    fn child_exit_status(&self) -> Option<std::process::ExitStatus> {
        let mut guard = self.child.lock();
        match guard.as_mut() {
            Some(child) => child.try_wait().ok().flatten(),
            None => None,
        }
    }

    /// Whether the child process is still running.
    pub fn is_running(&self) -> bool {
        self.child.lock().is_some() && self.child_exit_status().is_none()
    }

    /// The loopback endpoint the runtime is listening on.
    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// Base URL for the runtime's OpenAI-compatible API.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.endpoint)
    }

    /// The per-boot API key required on every runtime request.
    pub fn api_key(&self) -> &str {
        &self.api_key
    }

    /// The model file this runtime was launched with.
    pub fn model_path(&self) -> &Path {
        &self.config.model_path
    }

    /// The most recent `n` lines of runtime stderr.
    pub fn recent_logs(&self, n: usize) -> Vec<String> {
        let ring = self.stderr_ring.lock();
        let start = ring.len().saturating_sub(n);
        ring[start..].to_vec()
    }

    /// Restart the child after an unexpected exit.
    pub async fn restart(&self) -> CordonResult<()> {
        tracing::warn!("Restarting llama.cpp runtime");
        self.terminate().await;
        self.spawn_child().await?;
        self.await_healthy().await?;
        self.assert_web_ui_unreachable().await
    }

    /// Stop the child process, waiting briefly for it to exit.
    pub async fn terminate(&self) {
        let child = self.child.lock().take();
        if let Some(mut child) = child {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
            tracing::info!("llama.cpp runtime stopped");
        }
    }
}

impl Drop for LlamaSupervisor {
    fn drop(&mut self) {
        // `kill_on_drop` on the Command handles the common case; this makes the
        // intent explicit and covers a child taken out of the mutex.
        if let Some(mut child) = self.child.lock().take() {
            let _ = child.start_kill();
        }
    }
}

/// Reserve a free loopback port by binding to port 0 and reading back the
/// assignment. The listener is closed before the child binds, which is the
/// standard approach; the window is small and confined to loopback.
fn reserve_loopback_port() -> CordonResult<SocketAddr> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).map_err(|e| {
        CordonError::RuntimeUnavailable(format!("cannot reserve a loopback port: {}", e))
    })?;
    let addr = listener.local_addr().map_err(|e| {
        CordonError::RuntimeUnavailable(format!("cannot read reserved port: {}", e))
    })?;
    drop(listener);
    Ok(addr)
}

/// Generate a 32-byte random API key, hex encoded.
fn generate_api_key() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Ask the binary whether it accepts `--no-webui`.
async fn probe_no_webui_support(binary: &Path) -> bool {
    let output = Command::new(binary)
        .arg("--help")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output()
        .await;

    match output {
        Ok(out) => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            text.contains("--no-webui")
        }
        Err(_) => false,
    }
}

/// Locate a `llama-server` binary: the explicit override first, then `PATH`,
/// then the conventional install locations.
pub fn discover_llama_server(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return path.exists().then(|| path.to_path_buf());
    }

    if let Ok(from_env) = std::env::var("CORDON_LLAMA_SERVER") {
        let p = PathBuf::from(from_env);
        if p.exists() {
            return Some(p);
        }
    }

    let exe = if cfg!(windows) {
        "llama-server.exe"
    } else {
        "llama-server"
    };

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(exe);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    let conventional: &[&str] = if cfg!(windows) {
        &[r"C:\Program Files\llama.cpp\llama-server.exe"]
    } else {
        &[
            "/usr/local/bin/llama-server",
            "/usr/bin/llama-server",
            "/opt/llama.cpp/llama-server",
        ]
    };
    conventional.iter().map(PathBuf::from).find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_port_is_loopback_and_nonzero() {
        let addr = reserve_loopback_port().unwrap();
        assert!(addr.ip().is_loopback());
        assert_ne!(addr.port(), 0);
    }

    #[test]
    fn api_keys_are_unique_and_full_entropy() {
        let a = generate_api_key();
        let b = generate_api_key();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn missing_binary_fails_closed() {
        let config = LlamaRuntimeConfig::new(
            PathBuf::from("/nonexistent/llama-server"),
            PathBuf::from("/nonexistent/model.gguf"),
        );
        match LlamaSupervisor::start(config).await {
            Err(CordonError::RuntimeUnavailable(_)) => {}
            Err(other) => panic!("expected RuntimeUnavailable, got {}", other),
            Ok(_) => panic!("a missing binary must not start a runtime"),
        }
    }

    #[test]
    fn discovery_honours_explicit_missing_path() {
        assert!(discover_llama_server(Some(Path::new("/definitely/not/here"))).is_none());
    }
}
