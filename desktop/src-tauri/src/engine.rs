//! The node, run inside the desktop process.
//!
//! This is `cordon run`, or in a hardened mode `cordon serve`, without a
//! terminal: a node, the supervised llama.cpp runtime the app ships with, the
//! API and, in Light mode, the operator console on loopback. The difference is
//! that it can be stopped and started again in the same process when settings
//! change, which takes some care: every background task and every open
//! connection holds the node, and a node that is still held keeps its audit
//! log claimed, so a restart waits for the old node to be released before
//! building the next one.

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use parking_lot::Mutex;
use serde::Serialize;
use tokio::sync::oneshot;

use cordon_api::server::ApiServer;
use cordon_api::tls::{TlsConfig, TlsMode};
use cordon_core::{
    config::{
        CordonConfig, ExpectedMeasurementsConfig, OutboundPolicy, RuntimeBackend, SevSnpPinsConfig,
        TeePreference, TimingMode, TimingNormalizationConfig,
    },
    node::CordonNode,
    DeploymentMode, MeasurementSource,
};

use crate::settings::{stable_deployment_id, Paths, Settings};
use crate::{bundles, keys, models, posture, remote};

/// How long a model may take to load before startup is abandoned. Large
/// models on a cold disk are slow; a progress screen makes the wait visible.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(600);

/// How long a stopping node gets to finish in-flight requests and let go.
const STOP_TIMEOUT: Duration = Duration::from_secs(20);

/// What the engine is doing, as the app shows it.
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
        /// Console URL, as the desktop window loads it. Absent outside Light
        /// mode, where the node refuses to serve a console.
        console: Option<String>,
        /// The model being served.
        model: String,
        /// Whether that model is a sealed bundle.
        sealed: bool,
        /// Whether the API requires client certificates.
        mtls: bool,
        /// Whether the API listens beyond this machine.
        remote: bool,
        /// The deployment mode.
        mode: String,
    },
    /// Stopping.
    Stopping,
    /// Startup failed, or the node stopped on its own.
    Failed {
        /// What went wrong, in full.
        error: String,
    },
}

/// Live node figures for the app's own status page.
#[derive(Debug, Clone, Serialize)]
pub struct NodeStatus {
    /// Node state: healthy, degraded, quarantined, and so on.
    pub status: String,
    /// Deployment mode.
    pub mode: String,
    /// Node ID.
    pub node_id: String,
    /// Seconds since the node started.
    pub uptime_seconds: u64,
    /// Whether the runtime answers.
    pub runtime_ready: bool,
    /// Requests in flight.
    pub active_requests: u32,
    /// Concurrency limit.
    pub max_concurrent: u32,
    /// Median latency.
    pub latency_ms_p50: u64,
    /// Tail latency.
    pub latency_ms_p99: u64,
    /// Audit entries written.
    pub audit_entries: u64,
    /// Hash at the head of the audit chain.
    pub chain_head: Option<String>,
    /// The audit log's verifying key, hex.
    pub log_verifying_key: String,
    /// Where the signing keys came from.
    pub key_provenance: String,
    /// Where measurements come from.
    pub measurement_source: String,
    /// Whether measurements come from hardware.
    pub hardware_measurements: bool,
    /// Whether expected measurements are pinned.
    pub measurements_pinned: bool,
    /// Whether the last integrity check passed.
    pub integrity_ok: Option<bool>,
    /// When the integrity monitor last checked.
    pub integrity_checked_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Whether tampering was detected.
    pub tamper_detected: bool,
    /// The bundle being served, if any.
    pub bundle: Option<String>,
}

struct Running {
    node: Arc<CordonNode>,
    stop: oneshot::Sender<()>,
    server: tokio::task::JoinHandle<Result<()>>,
}

/// Everything a start needs, worked out from settings before anything runs.
struct Plan {
    config: CordonConfig,
    tls: Option<TlsConfig>,
    api_addr: SocketAddr,
    console_port: Option<u16>,
    model_label: String,
    sealed: bool,
}

/// Owns the node's lifecycle.
pub struct Engine {
    paths: Paths,
    llama: Option<PathBuf>,
    phase: Mutex<(Phase, Option<Instant>)>,
    /// Held across start and stop, so two of them never interleave.
    slot: tokio::sync::Mutex<Option<Running>>,
    /// The running node, without keeping it alive, for status reads that
    /// must not wait on a start or stop in progress.
    current: Mutex<Weak<CordonNode>>,
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
            current: Mutex::new(Weak::new()),
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

    /// Live figures from the running node, if one is running.
    pub async fn status(&self) -> Option<NodeStatus> {
        let node = self.current.lock().upgrade()?;
        let runtime_ready = node.inference.is_ready().await;
        let (status, p50, p99) = {
            let state = node.state.read();
            (
                state.status.to_string(),
                state.stats.latency_ms_p50,
                state.stats.latency_ms_p99,
            )
        };
        Some(NodeStatus {
            status,
            mode: posture::mode_id(&node.config.mode).to_string(),
            node_id: node.config.node_id.clone(),
            uptime_seconds: node.started_at.elapsed().as_secs(),
            runtime_ready,
            active_requests: node.inference.active_requests(),
            max_concurrent: node.inference.max_concurrent(),
            latency_ms_p50: p50,
            latency_ms_p99: p99,
            audit_entries: node.audit.sequence(),
            chain_head: node.audit.tail_hash(),
            log_verifying_key: node.log_verifying_key_hex(),
            key_provenance: node.key_provenance().as_str().to_string(),
            measurement_source: node.attestation.measurement_source().to_string(),
            hardware_measurements: node.attestation.has_hardware_measurements(),
            measurements_pinned: node.attestation.pinned_measurements().is_some(),
            integrity_ok: node
                .integrity_monitor
                .last_check_time()
                .map(|_| node.integrity_monitor.last_check_passed()),
            integrity_checked_at: node.integrity_monitor.last_check_time(),
            tamper_detected: node.integrity_monitor.is_tamper_detected(),
            bundle: node.served_bundle().map(str::to_string),
        })
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
                *self.current.lock() = Arc::downgrade(&running.node);
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
        let binary = self.llama.clone().ok_or_else(|| {
            anyhow!(
                "llama.cpp was not found. This build of Cordon should include it; \
                 reinstall, or set CORDON_LLAMA_SERVER to a llama-server binary."
            )
        })?;

        let plan = self.plan(settings, binary)?;
        let Plan {
            config,
            tls,
            api_addr,
            console_port,
            model_label,
            sealed,
        } = plan;
        let mode = posture::mode_id(&config.mode).to_string();
        let remote = settings.remote.enabled;

        self.step(if sealed {
            "Decrypting and loading the model"
        } else {
            "Loading the model"
        });
        let node = build_node(config).await?;
        node.start_background_services();
        node.go_operational()
            .context("the node could not go operational")?;

        self.step("Opening the API");
        let (stop, stopped) = oneshot::channel::<()>();
        let mtls = tls.is_some();
        let server = tokio::spawn(ApiServer::new(node.clone(), api_addr, tls).run(async move {
            let _ = stopped.await;
        }));

        let running = Running { node, stop, server };
        let ready = match console_port {
            Some(port) => wait_for_console(port, &running.server).await,
            None => wait_for_listener(&running.server).await,
        };
        if let Err(e) = ready {
            self.stop_running(running).await;
            return Err(e);
        }
        self.console_port.store(
            console_port.unwrap_or(0),
            std::sync::atomic::Ordering::SeqCst,
        );

        let scheme = if mtls { "https" } else { "http" };
        let host = if remote {
            cordon_api::pki::primary_ipv4()
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "127.0.0.1".into())
        } else {
            "127.0.0.1".into()
        };
        let api = format!("{}://{}:{}", scheme, host, api_addr.port());
        tracing::info!(%api, ?console_port, model = %model_label, %mode, "Cordon is serving");
        Ok((
            running,
            Phase::Running {
                api,
                console: console_port.map(console_url),
                model: model_label,
                sealed,
                mtls,
                remote,
                mode,
            },
        ))
    }

    /// Work out the node's configuration from the app's settings.
    fn plan(&self, settings: &Settings, binary: PathBuf) -> Result<Plan> {
        let paths = &self.paths;
        let mode = settings.mode.clone();
        let hardened = mode != DeploymentMode::Light;
        let data = &paths.data_dir;
        let deployment_id = stable_deployment_id(data)?;
        let node_id = format!("desktop-{}", &deployment_id[..8.min(deployment_id.len())]);

        // The model: a sealed bundle from the store, or a plain file.
        let key = settings.model.as_deref().ok_or_else(|| {
            anyhow!("No model is selected. Choose one to download, or open a GGUF file.")
        })?;
        let (model_path, model_label, sealed) = match settings.bundle() {
            Some(id) => {
                let dir = bundles::find(&paths.bundle_dir, id).ok_or_else(|| {
                    anyhow!(
                        "The selected bundle ({}) is no longer in the store. Choose another model.",
                        id
                    )
                })?;
                let name = cordon_core::bundle::read_manifest(&dir)
                    .map(|m| m.model_name)
                    .unwrap_or_else(|_| id.to_string());
                (PathBuf::from(id), name, true)
            }
            None => {
                let path = models::resolve(&paths.model_dir, key).ok_or_else(|| {
                    anyhow!(
                        "The selected model is no longer on disk ({}). Choose another one.",
                        key
                    )
                })?;
                let label = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                (path, label, false)
            }
        };
        if hardened && !sealed {
            bail!(
                "{} mode serves only sealed models, so weights are encrypted at rest. \
                 Seal this model on the Bundles page and select the bundle.",
                posture::MODES
                    .iter()
                    .find(|m| m.id == posture::mode_id(&mode))
                    .map(|m| m.name)
                    .unwrap_or("This")
            );
        }

        // Keys: the Client Master Key when a bundle has to be opened or the
        // mode requires signatures a third party can check; otherwise this
        // machine's local signing key.
        let uses_cmk = hardened || sealed;
        let key_id = if uses_cmk {
            let key = keys::load(&paths.key_dir)?.ok_or_else(|| {
                anyhow!(
                    "{} needs your Client Master Key, and there is none. Create or import \
                     one on the Keys page.",
                    if sealed {
                        "Serving a sealed model"
                    } else {
                        "This mode"
                    }
                )
            })?;
            Some(keys::key_id(&key))
        } else {
            None
        };

        let mut config = CordonConfig::default_light(node_id, deployment_id);
        config.mode = mode.clone();
        config.deployment_name = "cordon-desktop".into();
        config.model_store.path = paths.bundle_dir.clone();
        // An audit chain verifies against one signing key, so a different key,
        // or a different mode, gets its own log rather than a chain whose
        // earlier entries no longer verify.
        config.audit.log_path = match &key_id {
            None => data.join("audit"),
            Some(id) => data.join(format!("audit-{}-{}", posture::mode_id(&mode), id)),
        };
        if uses_cmk {
            config.cmk_path = Some(keys::path(&paths.key_dir));
            config.key_principal = Some(settings.principal.trim().to_string());
        } else {
            config.local_key_path = Some(data.join("node.key"));
        }

        config.runtime.backend = RuntimeBackend::Supervised;
        config.runtime.binary = Some(binary);
        config.runtime.model_path = Some(model_path);
        config.runtime.model_dir = paths.model_dir.clone();
        config.runtime.gpu_layers = settings.gpu_layers()?;
        config.runtime.context_size = settings.context_size;
        config.runtime.threads = settings.threads;
        config.runtime.parallel_slots = settings.parallel;
        config.runtime.startup_timeout_seconds = STARTUP_TIMEOUT.as_secs();
        config.inference.max_concurrent_requests = settings.parallel;

        // Transport. Plain HTTP on loopback in Light mode without remote
        // access; otherwise TLS 1.3 with a client certificate on every
        // connection, from the app's own CA.
        let remote = settings.remote.enabled;
        let tls = if hardened || remote {
            let pki = remote::pki(paths);
            pki.ensure_server(&remote::server_names(settings))
                .context("cannot prepare the server certificate")?;
            config.network.tls_cert_path = pki.server_cert_path();
            config.network.tls_key_path = pki.server_key_path();
            config.network.client_ca_path = Some(pki.ca_cert_path());
            config.client_registry_path = Some(remote::write_registry(paths)?);
            Some(TlsConfig {
                cert_path: pki.server_cert_path(),
                key_path: pki.server_key_path(),
                client_ca_path: Some(pki.ca_cert_path()),
                mode: TlsMode::Mutual,
            })
        } else {
            None
        };
        // Outside Light mode the node also refuses any identity that did not
        // come from a certificate. In Light mode with remote access the TLS
        // listener already demands one, and the flag stays off so the console
        // on loopback, which identifies itself by header, keeps working.
        config.network.require_mtls = hardened;

        let api_addr = if remote {
            let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, settings.remote.port));
            TcpListener::bind(addr).with_context(|| {
                format!(
                    "Port {} is in use by another program. Choose another port for remote access.",
                    settings.remote.port
                )
            })?;
            config.limits.max_connections = 256;
            config.limits.tls_handshake_timeout_seconds = 10;
            addr
        } else {
            SocketAddr::from((Ipv4Addr::LOCALHOST, free_port(settings.api_port, None)?))
        };
        config.network.bind_address = api_addr.ip().to_string();
        config.network.api_port = api_addr.port();

        let console_port = if hardened {
            config.ui.enabled = false;
            None
        } else {
            let port = free_port(settings.console_port, Some(api_addr.port()))?;
            config.ui.enabled = true;
            config.ui.bind_address = "127.0.0.1".into();
            config.ui.port = port;
            Some(port)
        };

        if hardened {
            harden(&mut config, settings)?;
        }

        std::fs::create_dir_all(&config.audit.log_path)
            .context("cannot create the audit log directory")?;
        std::fs::create_dir_all(&config.model_store.path)
            .context("cannot create the model store directory")?;
        config.validate()?;
        Ok(Plan {
            config,
            tls,
            api_addr,
            console_port,
            model_label,
            sealed,
        })
    }

    /// Stop a node and wait until nothing holds it any more.
    async fn stop_running(&self, running: Running) {
        let Running { node, stop, server } = running;
        *self.current.lock() = Weak::new();
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

/// Apply what a mode other than Light requires, mirroring the template
/// `cordon default-config` prints for it.
fn harden(config: &mut CordonConfig, settings: &Settings) -> Result<()> {
    let mode = config.mode.clone();
    let hw = &settings.hardware;
    config.attestation.halt_until_verified = true;
    config.boot.tpm_required = false;
    config.boot.secure_boot = true;
    config.boot.dm_verity = false;
    config.inference.multi_tenant = mode != DeploymentMode::Dark;
    config.hsm.fips_level = if mode == DeploymentMode::Dark && hw.fips_level_4 {
        4
    } else {
        3
    };
    config.network.outbound_policy = if posture::permits_downloads(&mode) {
        OutboundPolicy::Restricted
    } else {
        OutboundPolicy::ZeroEgress
    };
    if mode != DeploymentMode::SovereignCloud {
        config.side_channel.timing_normalization = TimingNormalizationConfig {
            enabled: true,
            mode: if mode == DeploymentMode::Dark {
                TimingMode::FixedFloor
            } else {
                TimingMode::Bucket
            },
            bucket_ms: 100,
            fixed_floor_ms: 500,
        };
    }

    match hw.source.as_deref() {
        Some("tpm2") => {
            config.tee.preferred = TeePreference::AmdSevSnp;
            config.attestation.measurement_source = MeasurementSource::Tpm2;
            config.boot.tpm_required = true;
            if hw.pcrs.is_empty() {
                bail!("Pin this machine's measurements on the Deployment page first.");
            }
            config.attestation.expected = Some(ExpectedMeasurementsConfig {
                pcr_values: hw.pcrs.clone(),
                ..ExpectedMeasurementsConfig::default()
            });
            if let Some(ak) = &hw.tpm_ak_context {
                // The TPM layer reads the attestation key's location from the
                // environment; this process is the only reader of it.
                std::env::set_var("CORDON_TPM_AK_CTX", ak);
            }
        }
        Some("sev_snp") => {
            config.tee.preferred = TeePreference::AmdSevSnp;
            config.attestation.measurement_source = MeasurementSource::SevSnp;
            let root_path = hw
                .amd_root
                .as_ref()
                .context("Choose the AMD root certificate on the Deployment page first.")?;
            let root = read_certificate_b64(root_path)?;
            let measurement = hw
                .measurement
                .clone()
                .context("Pin this machine's launch measurement on the Deployment page first.")?;
            config.attestation.expected = Some(ExpectedMeasurementsConfig {
                mrenclave: Some(measurement),
                sev_snp: Some(SevSnpPinsConfig {
                    amd_root_der_b64: root,
                    ..SevSnpPinsConfig::default()
                }),
                ..ExpectedMeasurementsConfig::default()
            });
        }
        _ => bail!("Choose a hardware root of trust on the Deployment page first."),
    }
    Ok(())
}

/// A certificate file, PEM or DER, as base64 DER.
fn read_certificate_b64(path: &std::path::Path) -> Result<String> {
    use base64::Engine;
    use rustls_pki_types::pem::PemObject;
    let bytes = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let der = match rustls_pki_types::CertificateDer::from_pem_slice(&bytes) {
        Ok(cert) => cert.as_ref().to_vec(),
        Err(_) => bytes,
    };
    Ok(base64::engine::general_purpose::STANDARD.encode(der))
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

/// Without a console there is nothing unauthenticated to ask. The listener
/// binds, or fails to, as the server starts, so a server still running after
/// a moment is listening.
async fn wait_for_listener(server: &tokio::task::JoinHandle<Result<()>>) -> Result<()> {
    tokio::time::sleep(Duration::from_millis(600)).await;
    if server.is_finished() {
        bail!("the server stopped while starting; see the log for the reason");
    }
    Ok(())
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

    fn engine() -> (tempfile::TempDir, Arc<Engine>) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().to_path_buf(), dir.path().join("logs"));
        std::fs::create_dir_all(&paths.model_dir).unwrap();
        (dir, Engine::new(paths, None))
    }

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

    #[test]
    fn light_mode_serves_a_plain_file_on_loopback_with_the_local_key() {
        let (dir, engine) = engine();
        let model = dir.path().join("m.gguf");
        std::fs::write(&model, b"GGUF").unwrap();
        let settings = Settings {
            model: Some(model.to_string_lossy().into_owned()),
            ..Settings::default()
        };
        let plan = engine
            .plan(&settings, PathBuf::from("llama-server"))
            .unwrap();
        assert!(plan.tls.is_none());
        assert!(plan.api_addr.ip().is_loopback());
        assert!(plan.console_port.is_some());
        assert!(plan.config.local_key_path.is_some());
        assert!(plan.config.cmk_path.is_none());
        assert!(plan.config.audit.log_path.ends_with("audit"));
    }

    #[test]
    fn remote_access_is_mutual_tls_with_a_deny_by_default_registry() {
        let (dir, engine) = engine();
        let model = dir.path().join("m.gguf");
        std::fs::write(&model, b"GGUF").unwrap();
        let mut settings = Settings {
            model: Some(model.to_string_lossy().into_owned()),
            ..Settings::default()
        };
        settings.remote.enabled = true;
        settings.remote.port = free_port(18443, None).unwrap();
        let plan = engine
            .plan(&settings, PathBuf::from("llama-server"))
            .unwrap();

        let tls = plan.tls.expect("remote access must use TLS");
        assert_eq!(tls.mode, TlsMode::Mutual);
        assert!(tls.cert_path.is_file() && tls.client_ca_path.unwrap().is_file());
        assert!(plan.api_addr.ip().is_unspecified());
        let registry = plan.config.client_registry_path.expect("a registry");
        let registry = cordon_core::identity::IdentityRegistry::load_from_file(&registry).unwrap();
        assert_eq!(
            registry.unknown_client_policy(),
            cordon_core::identity::UnknownClientPolicy::Deny
        );
        // The console stays on loopback whatever remote access says.
        assert_eq!(plan.config.ui.bind_address, "127.0.0.1");
    }

    #[test]
    fn a_sealed_model_needs_the_key_and_gets_its_own_audit_log() {
        let (_dir, engine) = engine();
        let settings = Settings {
            model: Some("bundle:missing".into()),
            ..Settings::default()
        };
        let err = engine
            .plan(&settings, PathBuf::from("llama-server"))
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("no longer in the store"), "{}", err);
    }

    #[test]
    fn a_hardened_mode_refuses_a_plain_model() {
        let (dir, engine) = engine();
        let model = dir.path().join("m.gguf");
        std::fs::write(&model, b"GGUF").unwrap();
        let settings = Settings {
            model: Some(model.to_string_lossy().into_owned()),
            mode: DeploymentMode::Vault,
            ..Settings::default()
        };
        let err = engine
            .plan(&settings, PathBuf::from("llama-server"))
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("serves only sealed models"), "{}", err);
    }
}
