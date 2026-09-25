//! The node, run inside the desktop process.
//!
//! This is `cordon run` without a terminal: a Light-mode node, the supervised
//! llama.cpp runtime the app ships with, the API and the operator console on
//! loopback. The difference is that it can be stopped and started again in
//! the same process when settings change, which takes some care: every
//! background task and every open connection holds the node, and a node that
//! is still held keeps its audit log claimed, so a restart waits for the old
//! node to be released before building the next one.

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use parking_lot::Mutex;
use serde::Serialize;
use tokio::sync::oneshot;

use cordon_api::server::ApiServer;
use cordon_core::{
    config::{CordonConfig, RuntimeBackend},
    node::CordonNode,
};

use crate::models;
use crate::settings::{stable_deployment_id, Paths, Settings};

/// How long a model may take to load before startup is abandoned. Large
/// models on a cold disk are slow; a progress screen makes the wait visible.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(600);

/// How long a stopping node gets to finish in-flight requests and let go.
const STOP_TIMEOUT: Duration = Duration::from_secs(20);

/// What the engine is doing, as the launcher shows it.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum Phase {
    /// Nothing running.
    Idle,
    /// Starting: `step` says which part.
    Starting {
        /// Current step, in words.
        step: String,
        /// Milliseconds since startup began.
        elapsed_ms: u64,
    },
    /// Serving.
    Running {
        /// API base URL.
        api: String,
        /// Console URL, as the desktop window loads it.
        console: String,
        /// The model being served.
        model: String,
    },
    /// Stopping.
    Stopping,
    /// Startup failed, or the node stopped on its own.
    Failed {
        /// What went wrong, in full.
        error: String,
    },
}

struct Running {
    node: Arc<CordonNode>,
    stop: oneshot::Sender<()>,
    server: tokio::task::JoinHandle<Result<()>>,
}

/// Owns the node's lifecycle.
pub struct Engine {
    paths: Paths,
    llama: Option<PathBuf>,
    phase: Mutex<(Phase, Option<Instant>)>,
    /// Held across start and stop, so two of them never interleave.
    slot: tokio::sync::Mutex<Option<Running>>,
    console_port: std::sync::atomic::AtomicU16,
    /// Wakes a startup in progress so it can be abandoned. Loading a large
    /// model takes minutes, and quitting must not wait for it.
    abandon: tokio::sync::Notify,
}

impl Engine {
    /// An engine that runs `llama` (when found) against models under `paths`.
    pub fn new(paths: Paths, llama: Option<PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            paths,
            llama,
            phase: Mutex::new((Phase::Idle, None)),
            slot: tokio::sync::Mutex::new(None),
            console_port: std::sync::atomic::AtomicU16::new(0),
            abandon: tokio::sync::Notify::new(),
        })
    }

    /// The current phase.
    pub fn phase(&self) -> Phase {
        let guard = self.phase.lock();
        match (&guard.0, guard.1) {
            (Phase::Starting { step, .. }, Some(since)) => Phase::Starting {
                step: step.clone(),
                elapsed_ms: since.elapsed().as_millis() as u64,
            },
            (phase, _) => phase.clone(),
        }
    }

    /// The port the console is on while running, else 0.
    pub fn console_port(&self) -> u16 {
        self.console_port.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn set_phase(&self, phase: Phase) {
        let mut guard = self.phase.lock();
        let since = match (&phase, guard.1) {
            (Phase::Starting { .. }, Some(since)) if matches!(guard.0, Phase::Starting { .. }) => {
                Some(since)
            }
            (Phase::Starting { .. }, _) => Some(Instant::now()),
            _ => None,
        };
        *guard = (phase, since);
    }

    fn step(&self, step: &str) {
        tracing::info!("{}", step);
        self.set_phase(Phase::Starting {
            step: step.to_string(),
            elapsed_ms: 0,
        });
    }

    /// Start, or restart, the node with `settings`. Progress and failure are
    /// reported through [`phase`](Self::phase); the error is also returned.
    pub async fn start(self: &Arc<Self>, settings: Settings) -> Result<()> {
        let mut slot = self.slot.lock().await;
        if let Some(running) = slot.take() {
            self.set_phase(Phase::Stopping);
            self.stop_running(running).await;
        }

        self.step("Preparing");
        // Dropping the boot future part-way is safe: a runtime that was being
        // started is killed with its supervisor, and nothing is published
        // until boot returns.
        let booted = tokio::select! {
            booted = self.boot(&settings) => booted,
            _ = self.abandon.notified() => Err(anyhow!("Startup was cancelled.")),
        };
        match booted {
            Ok((running, phase)) => {
                *slot = Some(running);
                self.set_phase(phase);
                Ok(())
            }
            Err(e) => {
                let error = format!("{:#}", e);
                tracing::error!("Startup failed: {}", error);
                self.console_port
                    .store(0, std::sync::atomic::Ordering::SeqCst);
                self.set_phase(Phase::Failed { error });
                Err(e)
            }
        }
    }

    /// Stop the node, if one is running, abandoning a startup in progress.
    pub async fn stop(&self) {
        self.abandon.notify_waiters();
        let mut slot = self.slot.lock().await;
        if let Some(running) = slot.take() {
            self.set_phase(Phase::Stopping);
            self.stop_running(running).await;
        }
        self.console_port
            .store(0, std::sync::atomic::Ordering::SeqCst);
        self.set_phase(Phase::Idle);
    }

    async fn boot(&self, settings: &Settings) -> Result<(Running, Phase)> {
        settings.validate()?;

        let key = settings.model.as_deref().ok_or_else(|| {
            anyhow!("No model is selected. Choose one to download, or open a GGUF file.")
        })?;
        let model_path = models::resolve(&self.paths.model_dir, key).ok_or_else(|| {
            anyhow!(
                "The selected model is no longer on disk ({}). Choose another one.",
                key
            )
        })?;
        let binary = self.llama.clone().ok_or_else(|| {
            anyhow!(
                "llama.cpp was not found. This build of Cordon should include it; \
                 reinstall, or set CORDON_LLAMA_SERVER to a llama-server binary."
            )
        })?;

        let api_port = free_port(settings.api_port, None)?;
        let console_port = free_port(settings.console_port, Some(api_port))?;
        let config = self.config(settings, model_path.clone(), binary, console_port)?;
        let api_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, api_port));

        self.step("Loading the model");
        let node = build_node(config).await?;
        node.start_background_services();
        node.go_operational()
            .context("the node could not go operational")?;

        self.step("Opening the console");
        let (stop, stopped) = oneshot::channel::<()>();
        let server = tokio::spawn(
            ApiServer::new(node.clone(), api_addr, None).run(async move {
                let _ = stopped.await;
            }),
        );

        let running = Running { node, stop, server };
        if let Err(e) = wait_for_console(console_port, &running.server).await {
            self.stop_running(running).await;
            return Err(e);
        }
        self.console_port
            .store(console_port, std::sync::atomic::Ordering::SeqCst);

        let model = model_path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        tracing::info!(%api_addr, console_port, %model, "Cordon is serving");
        Ok((
            running,
            Phase::Running {
                api: format!("http://{}", api_addr),
                console: console_url(console_port),
                model,
            },
        ))
    }

    fn config(
        &self,
        settings: &Settings,
        model_path: PathBuf,
        binary: PathBuf,
        console_port: u16,
    ) -> Result<CordonConfig> {
        let data = &self.paths.data_dir;
        let deployment_id = stable_deployment_id(data)?;
        let node_id = format!("desktop-{}", &deployment_id[..8.min(deployment_id.len())]);

        let mut config = CordonConfig::default_light(node_id, deployment_id);
        config.deployment_name = "cordon-desktop".into();
        config.audit.log_path = data.join("audit");
        config.model_store.path = data.join("bundles");
        config.local_key_path = Some(data.join("node.key"));

        config.runtime.backend = RuntimeBackend::Supervised;
        config.runtime.binary = Some(binary);
        config.runtime.model_path = Some(model_path);
        config.runtime.model_dir = self.paths.model_dir.clone();
        config.runtime.gpu_layers = settings.gpu_layers()?;
        config.runtime.context_size = settings.context_size;
        config.runtime.threads = settings.threads;
        config.runtime.parallel_slots = settings.parallel;
        config.runtime.startup_timeout_seconds = STARTUP_TIMEOUT.as_secs();
        config.inference.max_concurrent_requests = settings.parallel;

        config.network.bind_address = "127.0.0.1".into();
        config.network.api_port = settings.api_port;
        config.ui.enabled = true;
        config.ui.bind_address = "127.0.0.1".into();
        config.ui.port = console_port;

        std::fs::create_dir_all(&config.audit.log_path)
            .context("cannot create the audit log directory")?;
        std::fs::create_dir_all(&config.model_store.path)
            .context("cannot create the model store directory")?;
        config.validate()?;
        Ok(config)
    }

    /// Stop a node and wait until nothing holds it any more.
    async fn stop_running(&self, running: Running) {
        let Running { node, stop, server } = running;
        let _ = stop.send(());
        match tokio::time::timeout(STOP_TIMEOUT, server).await {
            Ok(Ok(Err(e))) => tracing::warn!("The server stopped with an error: {:#}", e),
            Ok(Err(e)) => tracing::warn!("The server task failed: {}", e),
            Err(_) => tracing::warn!("The server did not stop in time"),
            Ok(Ok(Ok(()))) => {}
        }
        // `run` shuts the node down on its way out; this covers a server that
        // never got that far.
        node.shutdown().await;

        let deadline = Instant::now() + STOP_TIMEOUT;
        while Arc::strong_count(&node) > 1 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if Arc::strong_count(&node) > 1 {
            tracing::warn!(
                holders = Arc::strong_count(&node) - 1,
                "The previous node is still referenced; its audit log may stay claimed"
            );
        }
        drop(node);
        tracing::info!("Node stopped");
    }
}

/// Build the node, retrying briefly if the previous one in this process is
/// still releasing the audit log.
async fn build_node(config: CordonConfig) -> Result<Arc<CordonNode>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match CordonNode::build(config.clone()).await {
            Ok(node) => return Ok(Arc::new(node)),
            Err(e) if e.to_string().contains("already writing") && Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(e) => return Err(anyhow!(e).context("the node could not start")),
        }
    }
}

/// Wait until the console answers, or the server has failed.
async fn wait_for_console(port: u16, server: &tokio::task::JoinHandle<Result<()>>) -> Result<()> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()?;
    let url = format!("http://127.0.0.1:{}/api/status", port);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if server.is_finished() {
            bail!("the server stopped while starting; see the log for the reason");
        }
        if let Ok(response) = client.get(&url).send().await {
            if response.status().is_success() {
                return Ok(());
            }
        }
        if Instant::now() > deadline {
            bail!("the console did not answer on port {}", port);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The console URL the desktop window loads.
pub fn console_url(port: u16) -> String {
    format!("http://127.0.0.1:{}/?shell=desktop#overview", port)
}

/// `preferred` if it is free on loopback, otherwise one the OS picks.
fn free_port(preferred: u16, avoid: Option<u16>) -> Result<u16> {
    if Some(preferred) != avoid && TcpListener::bind((Ipv4Addr::LOCALHOST, preferred)).is_ok() {
        return Ok(preferred);
    }
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).context("cannot find a free loopback port")?;
    let port = listener.local_addr()?.port();
    tracing::info!(
        preferred,
        chosen = port,
        "Preferred port is taken; using another"
    );
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_taken_port_is_replaced_with_a_free_one() {
        let holder = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let taken = holder.local_addr().unwrap().port();
        let chosen = free_port(taken, None).unwrap();
        assert_ne!(chosen, taken);
        assert_ne!(free_port(chosen, Some(chosen)).unwrap(), chosen);
    }

    #[test]
    fn the_console_is_loaded_in_desktop_mode() {
        assert_eq!(
            console_url(8478),
            "http://127.0.0.1:8478/?shell=desktop#overview"
        );
    }
}
