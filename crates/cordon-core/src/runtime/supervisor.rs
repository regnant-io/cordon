//! Supervised llama.cpp runtime.
//!
//! Cordon owns the model runtime rather than assuming an operator has started
//! one correctly. [`LlamaSupervisor`] spawns `llama-server` as a child process
//! and constrains it so that Cordon is the only reachable surface:
//!
//! * **Loopback only.** The child is bound to `127.0.0.1`. The bind address is
//!   not configurable, a runtime reachable from the network would let callers
//!   bypass Cordon's identity, policy, filtering, and audit layers entirely.
//! * **Ephemeral port.** The port is chosen at startup from the kernel's
//!   ephemeral range and is never published, so the runtime is not sitting on a
//!   guessable port.
//! * **Web UI compiled out of the response path.** `--no-webui` is passed when
//!   the binary supports it, and after startup Cordon *verifies* that the child
//!   does not serve an HTML document at `/`. If it does, startup fails closed.
//! * **Per-boot API key, passed by file.** A 32-byte random key is generated for
//!   each launch and required on every request, so another local process cannot
//!   drive the runtime even if it discovers the port. The key is handed over in
//!   an owner-only temporary file rather than on the command line, because a
//!   command line is world-readable through `ps` and `/proc/<pid>/cmdline`,
//!   which would hand the key to exactly the local process this is meant to
//!   exclude.
//!
//! The child is terminated when the supervisor is dropped and when the process
//! exits, and it is restarted automatically if it dies while Cordon is running.
//! On Windows it is also placed in a job object that kills it when the job
//! handle closes, so it cannot outlive a Cordon that crashed or was killed
//! outright, and it is started without a console window, so a desktop build
//! does not flash one on screen.
//!
//! Slots share one KV cache (`--kv-unified`) when the binary supports it.
//! Without that, llama.cpp divides `--ctx-size` evenly between `--parallel`
//! slots, and a 4096-token context split 32 ways leaves each request 128
//! tokens: long conversations would fail on a node that looked healthy.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

use crate::config::GpuLayers;
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
    pub gpu_layers: GpuLayers,
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
            gpu_layers: GpuLayers::Count(0),
            threads: None,
            parallel_slots: 4,
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
            extra_args: Vec::new(),
        }
    }
}

/// Command-line flags this `llama-server` build accepts, probed once at startup.
#[derive(Debug, Clone, Copy)]
struct SupportedFlags {
    /// `--no-webui` removes the runtime's browsable UI from the response path.
    no_webui: bool,
    /// `--api-key-file` reads the key from a file instead of the command line.
    api_key_file: bool,
    /// `--kv-unified` lets every slot draw on the whole context window.
    kv_unified: bool,
    /// `--no-slots` removes the slot-inspection endpoint, which reports the
    /// prompts currently being processed.
    no_slots: bool,
    /// `--n-gpu-layers` accepts `auto` and `all` as well as a count.
    gpu_layer_words: bool,
}

/// A running, supervised llama.cpp server.
pub struct LlamaSupervisor {
    config: LlamaRuntimeConfig,
    endpoint: SocketAddr,
    api_key: String,
    /// The API key on disk, owner-only, deleted when the supervisor drops.
    ///
    /// Held for the supervisor's whole life rather than only across the spawn,
    /// because a restart re-launches the child against the same file.
    api_key_file: Option<tempfile::NamedTempFile>,
    child: Arc<Mutex<Option<Child>>>,
    stderr_ring: Arc<Mutex<VecDeque<String>>>,
    flags: SupportedFlags,
    http: reqwest::Client,
    /// Job object every child is assigned to. Closing it, which happens when
    /// this process exits by any route, terminates the child.
    #[cfg(windows)]
    job: Option<win32job::Job>,
}

impl LlamaSupervisor {
    /// Spawn the runtime and block until it reports healthy.
    ///
    /// Fails closed on any of: a missing binary, a missing model file, a
    /// startup timeout, or a child that serves an HTML web UI at `/`.
    pub async fn start(config: LlamaRuntimeConfig) -> CordonResult<Self> {
        Self::validate_paths(&config)?;

        let flags = probe_supported_flags(&config.binary).await;
        if !flags.no_webui {
            tracing::warn!(
                binary = %config.binary.display(),
                "llama-server does not accept --no-webui; the runtime UI is suppressed \
                 by loopback binding, an ephemeral port, and a required API key. Consider \
                 upgrading llama.cpp so the UI is removed from the response path entirely."
            );
        }

        let endpoint = reserve_loopback_port()?;
        let api_key = generate_api_key();

        // Prefer handing the key over in a file. A command line is readable by
        // every local user through `ps` and `/proc/<pid>/cmdline`, so passing
        // the key as an argument would publish it to precisely the local
        // process the key exists to keep out.
        let api_key_file = if flags.api_key_file {
            Some(write_api_key_file(&api_key)?)
        } else {
            tracing::warn!(
                binary = %config.binary.display(),
                "llama-server does not accept --api-key-file, so the runtime's \
                 per-boot API key must be passed on its command line, where any \
                 local user can read it from the process table. The runtime is \
                 still bound to loopback on an ephemeral port. Upgrade llama.cpp \
                 to remove this exposure."
            );
            None
        };

        let http = reqwest::Client::builder()
            // The runtime is on loopback; no proxy should ever be consulted.
            .no_proxy()
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .map_err(|e| {
                CordonError::Internal(format!("cannot build runtime HTTP client: {}", e))
            })?;

        if !flags.kv_unified && config.parallel_slots > 1 {
            tracing::warn!(
                ctx_size = config.ctx_size,
                parallel = config.parallel_slots,
                per_slot = config.ctx_size / config.parallel_slots.max(1),
                "llama-server does not accept --kv-unified, so the context window is \
                 divided between slots. Raise runtime.context_size or lower \
                 inference.max_concurrent_requests if requests are cut short."
            );
        }

        let supervisor = Self {
            config,
            endpoint,
            api_key,
            api_key_file,
            child: Arc::new(Mutex::new(None)),
            stderr_ring: Arc::new(Mutex::new(VecDeque::with_capacity(LOG_RING_CAPACITY))),
            flags,
            http,
            #[cfg(windows)]
            job: kill_on_close_job(),
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

    /// A supervisor with no child process, for tests that exercise what the
    /// supervisor reports rather than what the runtime does. Nothing is
    /// spawned, so `is_running` is false and no request will succeed.
    #[cfg(test)]
    pub(crate) fn detached(config: LlamaRuntimeConfig) -> Self {
        Self {
            config,
            endpoint: SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
            api_key: generate_api_key(),
            api_key_file: None,
            child: Arc::new(Mutex::new(None)),
            stderr_ring: Arc::new(Mutex::new(VecDeque::new())),
            flags: SupportedFlags {
                no_webui: true,
                api_key_file: true,
                kv_unified: true,
                no_slots: true,
                gpu_layer_words: true,
            },
            http: reqwest::Client::new(),
            #[cfg(windows)]
            job: None,
        }
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
            .arg("--ctx-size")
            .arg(self.config.ctx_size.to_string())
            .arg("--parallel")
            .arg(self.config.parallel_slots.to_string());

        if let Some(layers) = gpu_layers_arg(self.config.gpu_layers, self.flags.gpu_layer_words) {
            cmd.arg("--n-gpu-layers").arg(layers);
        }
        if self.flags.kv_unified {
            cmd.arg("--kv-unified");
        }
        if self.flags.no_slots {
            cmd.arg("--no-slots");
        }

        match &self.api_key_file {
            Some(file) => {
                cmd.arg("--api-key-file").arg(file.path());
            }
            None => {
                cmd.arg("--api-key").arg(&self.api_key);
            }
        }

        if let Some(threads) = self.config.threads {
            cmd.arg("--threads").arg(threads.to_string());
        }
        if self.flags.no_webui {
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
        hide_console_window(&mut cmd);

        let mut child = cmd.spawn().map_err(|e| {
            CordonError::RuntimeUnavailable(format!(
                "cannot launch {}: {}",
                self.config.binary.display(),
                e
            ))
        })?;

        #[cfg(windows)]
        if let (Some(job), Some(handle)) = (&self.job, child.raw_handle()) {
            if let Err(e) = job.assign_process(handle as isize) {
                tracing::warn!(
                    "cannot place llama-server in a job object ({}); it may outlive \
                     Cordon if Cordon is killed rather than stopped",
                    e
                );
            }
        }

        if let Some(stderr) = child.stderr.take() {
            let ring = self.stderr_ring.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::debug!(target: "llama", "{}", line);
                    let mut ring = ring.lock();
                    if ring.len() >= LOG_RING_CAPACITY {
                        ring.pop_front();
                    }
                    ring.push_back(line);
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

    /// The identifier for the model this runtime has loaded.
    ///
    /// Cordon launched the child against exactly one file, so this is known
    /// before any request arrives and does not change while the runtime lives.
    pub fn model_id(&self) -> String {
        model_id_from_path(&self.config.model_path)
    }

    /// The most recent `n` lines of runtime stderr.
    pub fn recent_logs(&self, n: usize) -> Vec<String> {
        let ring = self.stderr_ring.lock();
        let start = ring.len().saturating_sub(n);
        ring.iter().skip(start).cloned().collect()
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

/// The `--n-gpu-layers` value for a setting, or `None` to leave the flag off.
///
/// A binary too old to understand `auto` gets no flag at all for it, which is
/// its own default, rather than a word it would refuse to start with. `all`
/// becomes a count larger than any model's layer count, which every build
/// accepts.
fn gpu_layers_arg(layers: GpuLayers, words_supported: bool) -> Option<String> {
    match (layers, words_supported) {
        (GpuLayers::Count(n), _) => Some(n.to_string()),
        (GpuLayers::Auto, true) => Some("auto".into()),
        (GpuLayers::Auto, false) => None,
        (GpuLayers::All, true) => Some("all".into()),
        (GpuLayers::All, false) => Some("999".into()),
    }
}

/// Start a child without a console window of its own.
///
/// `llama-server` is a console program. Launched from a process that has no
/// console, which is every desktop build, Windows would otherwise open a
/// window for it and for every `--help` probe.
fn hide_console_window(cmd: &mut Command) {
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    let _ = cmd;
}

/// A job object that terminates its processes when its last handle closes.
#[cfg(windows)]
fn kill_on_close_job() -> Option<win32job::Job> {
    let mut info = win32job::ExtendedLimitInfo::new();
    info.limit_kill_on_job_close();
    match win32job::Job::create_with_limit_info(&info) {
        Ok(job) => Some(job),
        Err(e) => {
            tracing::warn!("cannot create a job object for the runtime: {}", e);
            None
        }
    }
}

/// Name a model file the way an operator names it.
///
/// The file stem is the identifier. `cordon pull` writes each model as
/// `<local id>.gguf`, so for a pulled model this is the same name `cordon
/// models` lists and `cordon run` accepts. For a file the operator placed
/// themselves it is the name on disk, which is the only name that file has.
/// A path with no stem at all falls back to the path, because reporting
/// something the operator can act on beats reporting nothing.
fn model_id_from_path(path: &Path) -> String {
    path.file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .filter(|stem| !stem.is_empty())
        .unwrap_or_else(|| path.to_string_lossy().into_owned())
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

/// Write the per-boot API key to an owner-only temporary file.
///
/// `NamedTempFile` creates with `O_EXCL` and mode 0600 on Unix, so the file
/// cannot be pre-created or raced by another local user, and it is removed when
/// the supervisor drops.
fn write_api_key_file(api_key: &str) -> CordonResult<tempfile::NamedTempFile> {
    use std::io::Write as _;

    let mut file = tempfile::Builder::new()
        .prefix("cordon-runtime-key-")
        .tempfile()
        .map_err(|e| {
            CordonError::RuntimeUnavailable(format!("cannot create the runtime key file: {}", e))
        })?;

    // llama.cpp reads the whole file and trims it; no trailing newline is
    // written so there is nothing to disagree about.
    file.write_all(api_key.as_bytes())
        .and_then(|_| file.as_file().sync_all())
        .map_err(|e| {
            CordonError::RuntimeUnavailable(format!("cannot write the runtime key file: {}", e))
        })?;

    Ok(file)
}

/// Ask the binary which of the flags Cordon depends on it accepts.
///
/// The help text is read once and searched for every flag, rather than
/// launching the binary again per flag.
async fn probe_supported_flags(binary: &Path) -> SupportedFlags {
    let mut cmd = Command::new(binary);
    cmd.arg("--help")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    hide_console_window(&mut cmd);
    let output = cmd.output().await;

    match output {
        Ok(out) => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            SupportedFlags::from_help(&text)
        }
        // A binary whose help cannot be read is assumed to support none, so
        // the failure is a loud warning rather than a flag the child rejects.
        Err(_) => SupportedFlags::from_help(""),
    }
}

impl SupportedFlags {
    fn from_help(text: &str) -> Self {
        SupportedFlags {
            no_webui: text.contains("--no-webui"),
            api_key_file: text.contains("--api-key-file"),
            kv_unified: text.contains("--kv-unified"),
            no_slots: text.contains("--no-slots"),
            gpu_layer_words: text.contains("'auto', or 'all'"),
        }
    }
}

/// The runtime's executable name on this platform.
pub const LLAMA_SERVER_EXE: &str = if cfg!(windows) {
    "llama-server.exe"
} else {
    "llama-server"
};

/// Locate a `llama-server` binary: the explicit override first, then
/// `CORDON_LLAMA_SERVER`, then a copy shipped alongside Cordon itself, then
/// `PATH`, then the conventional install locations.
///
/// A bundled copy wins over `PATH` because a distribution that ships one has
/// tested Cordon against that build; a different llama.cpp that happens to be
/// installed system-wide has not been.
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

    let exe = LLAMA_SERVER_EXE;

    if let Some(bundled) = std::env::current_exe()
        .ok()
        .and_then(|me| me.parent().map(Path::to_path_buf))
        .and_then(|dir| bundled_candidates(&dir).into_iter().find(|p| p.is_file()))
    {
        return Some(bundled);
    }

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

/// Where a distribution places `llama-server` relative to the directory
/// holding the Cordon executable.
fn bundled_candidates(exe_dir: &Path) -> Vec<PathBuf> {
    vec![
        exe_dir.join(LLAMA_SERVER_EXE),
        exe_dir.join("llama").join(LLAMA_SERVER_EXE),
        // A macOS application bundle keeps resources beside, not inside,
        // `Contents/MacOS`.
        exe_dir
            .join("..")
            .join("Resources")
            .join("llama")
            .join(LLAMA_SERVER_EXE),
        // Linux packages install resources under `/usr/lib/<product>`.
        exe_dir
            .join("..")
            .join("lib")
            .join("cordon")
            .join("llama")
            .join(LLAMA_SERVER_EXE),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_layer_settings_become_flags_the_binary_accepts() {
        assert_eq!(
            gpu_layers_arg(GpuLayers::Count(0), false).as_deref(),
            Some("0")
        );
        assert_eq!(
            gpu_layers_arg(GpuLayers::Count(20), true).as_deref(),
            Some("20")
        );
        assert_eq!(
            gpu_layers_arg(GpuLayers::Auto, true).as_deref(),
            Some("auto")
        );
        assert_eq!(gpu_layers_arg(GpuLayers::Auto, false), None);
        assert_eq!(gpu_layers_arg(GpuLayers::All, true).as_deref(), Some("all"));
        assert_eq!(
            gpu_layers_arg(GpuLayers::All, false).as_deref(),
            Some("999")
        );
    }

    #[test]
    fn flags_are_read_from_the_help_text() {
        let flags = SupportedFlags::from_help(
            "-ngl, --n-gpu-layers N  either an exact number, 'auto', or 'all'\n\
             -kvu, --kv-unified, -no-kvu\n--slots, --no-slots\n--no-webui\n--api-key-file FNAME",
        );
        assert!(flags.no_webui && flags.api_key_file && flags.kv_unified);
        assert!(flags.no_slots && flags.gpu_layer_words);

        let none = SupportedFlags::from_help("usage: llama-server [options]");
        assert!(!none.no_webui && !none.api_key_file && !none.kv_unified);
        assert!(!none.no_slots && !none.gpu_layer_words);
    }

    #[test]
    fn a_bundled_runtime_is_looked_for_beside_the_executable() {
        let dir = Path::new("/opt/cordon/bin");
        let candidates = bundled_candidates(dir);
        assert_eq!(candidates[0], dir.join(LLAMA_SERVER_EXE));
        assert!(candidates
            .iter()
            .any(|p| p.ends_with(Path::new("llama").join(LLAMA_SERVER_EXE))));
    }

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

    /// The key must reach the child through a file the owner alone can read.
    /// Passing it as an argument would publish it through `ps` to the very
    /// local process the key exists to keep out.
    #[test]
    fn the_api_key_file_holds_the_key_and_nothing_else() {
        let key = generate_api_key();
        let file = write_api_key_file(&key).unwrap();
        assert_eq!(std::fs::read_to_string(file.path()).unwrap(), key);
    }

    #[cfg(unix)]
    #[test]
    fn the_api_key_file_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let file = write_api_key_file(&generate_api_key()).unwrap();
        let mode = std::fs::metadata(file.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "runtime key file mode was {:o}", mode);
    }

    #[test]
    fn the_api_key_file_is_removed_with_the_supervisor() {
        let path = {
            let file = write_api_key_file(&generate_api_key()).unwrap();
            file.path().to_path_buf()
        };
        assert!(!path.exists(), "the runtime key file outlived its owner");
    }

    /// A pulled model is stored as `<local id>.gguf`, so the stem is the name
    /// the operator already knows it by. A quantisation suffix separated by
    /// dots must survive, which rules out cutting at the first dot.
    #[test]
    fn a_model_is_named_by_its_file_stem() {
        let cases = [
            (
                "data/models/huggingfacetb--smollm2-360m-instruct-gguf--q8_0.gguf",
                "huggingfacetb--smollm2-360m-instruct-gguf--q8_0",
            ),
            ("/opt/models/mistral-7b.Q4_K_M.gguf", "mistral-7b.Q4_K_M"),
            ("model.gguf", "model"),
            ("/srv/weights/no-extension", "no-extension"),
        ];
        for (path, expected) in cases {
            assert_eq!(
                model_id_from_path(Path::new(path)),
                expected,
                "for {}",
                path
            );
        }
    }

    #[test]
    fn the_supervisor_names_the_model_it_was_launched_with() {
        let supervisor = LlamaSupervisor::detached(LlamaRuntimeConfig::new(
            PathBuf::from("/usr/bin/llama-server"),
            PathBuf::from("data/models/smollm2-360m-instruct-q8_0.gguf"),
        ));
        assert_eq!(supervisor.model_id(), "smollm2-360m-instruct-q8_0");
        assert!(
            !supervisor.is_running(),
            "a detached supervisor must not claim a running child"
        );
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
