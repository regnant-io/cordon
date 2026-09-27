//! Cordon for the desktop.
//!
//! One window. The app's own pages (`shell/`, bundled with the app) cover
//! models, sealed bundles, keys, deployment mode, remote access and settings.
//! Once a Light-mode node is serving, the operator console is loaded from the
//! node itself, the same page and the same requests a browser gets from
//! `cordon run`, with `?shell=desktop` so it draws the app's title bar and
//! sidebar. Outside Light mode the node serves no console, and the app's own
//! status page takes its place.
//!
//! The app's pages can call the commands below. The console cannot: it is
//! served from a loopback origin whose only grant is moving and sizing the
//! window, so a page the node serves has no more reach into the app than it
//! would in a browser. It asks for an app page by navigating to
//! `/desktop/<page>`, which the navigation guard intercepts.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod bundles;
mod cli;
mod engine;
mod hardware;
mod keys;
mod logs;
mod models;
mod posture;
mod remote;
mod settings;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use serde::Serialize;
use tauri::webview::PageLoadEvent;
use tauri::{AppHandle, Manager, RunEvent, State, Url, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_opener::OpenerExt;

use engine::{Engine, NodeStatus, Phase};
use hardware::RuntimeInfo;
use models::{CatalogEntry, DownloadState, Downloads, LocalModel};
use settings::{Paths, Settings, BUNDLE_PREFIX};

/// Everything the commands share.
struct Desktop {
    paths: Paths,
    engine: Arc<Engine>,
    settings: Mutex<Settings>,
    runtime: Mutex<RuntimeInfo>,
    hardware: Mutex<posture::HardwareProbe>,
    downloads: Downloads,
    jobs: bundles::Jobs,
    logs: logs::LogBuffer,
    exiting: AtomicBool,
}

type Shared<'a> = State<'a, Arc<Desktop>>;
type Reply<T = ()> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    format!("{:#}", e).trim_end_matches('.').to_string() + "."
}

impl Desktop {
    fn settings(&self) -> Settings {
        self.settings.lock().clone()
    }

    fn save(&self, settings: Settings) -> Reply {
        settings.validate().map_err(err)?;
        settings
            .save(&self.paths)
            .map_err(|e| format!("Cannot save settings: {}", e))?;
        *self.settings.lock() = settings;
        Ok(())
    }

    /// Start (or restart) the node in the background with the saved settings.
    fn start(self: &Arc<Self>) {
        let engine = self.engine.clone();
        let settings = self.settings();
        tauri::async_runtime::spawn(async move {
            let _ = engine.start(settings).await;
        });
    }

    /// Restart the node if it is running, so a change it reads at start
    /// takes effect.
    fn restart_if_running(self: &Arc<Self>) -> bool {
        let running = matches!(
            self.engine.phase(),
            Phase::Running { .. } | Phase::Starting { .. }
        );
        if running {
            self.start();
        }
        running
    }

    fn key(&self) -> Reply<cordon_crypto::hierarchy::MasterKey> {
        keys::load(&self.paths.key_dir)
            .map_err(err)?
            .ok_or_else(|| "Create or import a Client Master Key first.".to_string())
    }
}

/// The app's view of everything, polled by its pages.
#[derive(Serialize)]
struct Snapshot {
    version: &'static str,
    platform: &'static str,
    phase: Phase,
    settings: Settings,
    models: Vec<LocalModel>,
    catalog: Vec<CatalogView>,
    runtime: RuntimeInfo,
    download: Option<DownloadState>,
    bundles: Vec<bundles::BundleView>,
    job: Option<bundles::JobState>,
    key: keys::KeyStatus,
    remote: remote::RemoteView,
    modes: &'static [posture::ModeInfo],
    readiness: Vec<posture::Readiness>,
    hardware: posture::HardwareProbe,
    downloads_allowed: bool,
    cli: cli::CliStatus,
    paths: Paths,
    log_mark: u64,
    logs: Vec<String>,
}

#[derive(Serialize)]
struct CatalogView {
    #[serde(flatten)]
    entry: CatalogEntry,
    local_id: String,
    on_disk: bool,
}

// ── Overview ────────────────────────────────────────────────────────────────

#[tauri::command]
fn snapshot(state: Shared<'_>, log_after: Option<u64>) -> Snapshot {
    let settings = state.settings();
    let models = models::list(&state.paths.model_dir, settings.model.as_deref());
    let catalog = models::CATALOG
        .iter()
        .map(|entry| {
            let local_id = models::local_id_of(entry.reference).unwrap_or_default();
            CatalogView {
                on_disk: models.iter().any(|m| m.key == local_id),
                local_id,
                entry: entry.clone(),
            }
        })
        .collect();
    let key = keys::status(&state.paths.key_dir);
    let hardware = state.hardware.lock().clone();
    let readiness = posture::MODES
        .iter()
        .filter_map(|m| posture::parse_mode(m.id))
        .map(|mode| posture::readiness(&mode, &settings, &state.paths, &hardware, key.present))
        .collect();
    let (log_mark, logs) = state.logs.since(log_after.unwrap_or(0));
    Snapshot {
        version: env!("CARGO_PKG_VERSION"),
        platform: std::env::consts::OS,
        phase: state.engine.phase(),
        downloads_allowed: posture::permits_downloads(&settings.mode),
        remote: remote::view(&state.paths, &settings),
        bundles: bundles::list(&state.paths.bundle_dir),
        job: state.jobs.snapshot(),
        settings,
        models,
        catalog,
        runtime: state.runtime.lock().clone(),
        download: state.downloads.snapshot(),
        key,
        modes: posture::MODES,
        readiness,
        hardware,
        cli: cli::status(state.paths.cli.as_deref()),
        paths: state.paths.clone(),
        log_mark,
        logs,
    }
}

/// Live figures from the running node.
#[tauri::command]
async fn node_status(state: Shared<'_>) -> Reply<Option<NodeStatus>> {
    Ok(state.engine.status().await)
}

/// Save settings; restart the node if asked and a model is selected.
#[tauri::command]
fn save_settings(state: Shared<'_>, settings: Settings, restart: bool) -> Reply {
    state.save(settings)?;
    if restart && state.settings().model.is_some() {
        state.start();
    }
    Ok(())
}

#[tauri::command]
fn start(state: Shared<'_>) -> Reply {
    if state.settings().model.is_none() {
        return Err("Choose a model first.".into());
    }
    state.start();
    Ok(())
}

#[tauri::command]
async fn stop(state: Shared<'_>) -> Reply {
    state.engine.stop().await;
    Ok(())
}

// ── Models ──────────────────────────────────────────────────────────────────

/// Serve a model or bundle that is already on disk.
#[tauri::command]
fn select_model(state: Shared<'_>, key: String) -> Reply {
    let exists = match key.strip_prefix(BUNDLE_PREFIX) {
        Some(id) => bundles::find(&state.paths.bundle_dir, id).is_some(),
        None => models::resolve(&state.paths.model_dir, &key).is_some(),
    };
    if !exists {
        return Err("That model is no longer on disk.".into());
    }
    let mut settings = state.settings();
    settings.model = Some(key);
    state.save(settings)?;
    state.start();
    Ok(())
}

/// Fetch a model from the Hub. When nothing is selected yet, which is the
/// first-run case, the new model is selected and started when it arrives.
#[tauri::command]
fn download(state: Shared<'_>, reference: String) -> Reply {
    if !posture::permits_downloads(&state.settings().mode) {
        return Err(
            "This deployment mode makes no outbound connections. Bring models in as sealed bundles."
                .into(),
        );
    }
    let desktop: Arc<Desktop> = state.inner().clone();
    state
        .downloads
        .start(reference, state.paths.model_dir.clone(), move |local_id| {
            let mut settings = desktop.settings();
            if settings.model.is_none() {
                settings.model = Some(local_id);
                if desktop.save(settings).is_ok() {
                    desktop.start();
                }
            }
        })
        .map_err(err)
}

#[tauri::command]
fn cancel_download(state: Shared<'_>) {
    state.downloads.cancel();
}

async fn pick_file(
    app: &AppHandle,
    title: &str,
    filter: Option<(&str, &[&str])>,
) -> Option<PathBuf> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut dialog = app.dialog().file().set_title(title);
    if let Some((name, extensions)) = filter {
        dialog = dialog.add_filter(name, extensions);
    }
    dialog.pick_file(move |picked| {
        let _ = tx.send(picked);
    });
    rx.await.ok().flatten().and_then(|p| p.into_path().ok())
}

async fn pick_folder(app: &AppHandle, title: &str) -> Option<PathBuf> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title(title)
        .pick_folder(move |picked| {
            let _ = tx.send(picked);
        });
    rx.await.ok().flatten().and_then(|p| p.into_path().ok())
}

/// Pick a GGUF file from disk and serve it where it is.
#[tauri::command]
async fn import_model(app: AppHandle, state: Shared<'_>) -> Reply<Option<LocalModel>> {
    let Some(path) = pick_file(&app, "Open a GGUF model", Some(("GGUF model", &["gguf"]))).await
    else {
        return Ok(None);
    };
    let model = models::imported(&path);
    let mut settings = state.settings();
    settings.model = Some(model.key.clone());
    state.save(settings)?;
    state.start();
    Ok(Some(model))
}

/// Delete a downloaded model. Imported files are never deleted, only
/// forgotten: they belong to wherever they came from.
#[tauri::command]
async fn remove_model(state: Shared<'_>, key: String) -> Reply {
    let mut settings = state.settings();
    if settings.model.as_deref() == Some(key.as_str()) {
        state.engine.stop().await;
        settings.model = None;
        state.save(settings)?;
    }
    if !PathBuf::from(&key).is_file() {
        cordon_core::hub::remove_local_model(&state.paths.model_dir, &key).map_err(err)?;
    }
    Ok(())
}

// ── Keys ────────────────────────────────────────────────────────────────────

#[tauri::command]
fn key_create(state: Shared<'_>) -> Reply<keys::KeyStatus> {
    keys::create(&state.paths.key_dir).map_err(err)
}

#[tauri::command]
async fn key_import(app: AppHandle, state: Shared<'_>) -> Reply<Option<keys::KeyStatus>> {
    let Some(from) = pick_file(&app, "Import a Client Master Key", None).await else {
        return Ok(None);
    };
    keys::import(&state.paths.key_dir, &from)
        .map(Some)
        .map_err(err)
}

#[tauri::command]
async fn key_backup(app: AppHandle, state: Shared<'_>) -> Reply<Option<String>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title("Back up the Client Master Key")
        .set_file_name("cordon-cmk.hex")
        .save_file(move |picked| {
            let _ = tx.send(picked);
        });
    let Some(to) = rx.await.ok().flatten().and_then(|p| p.into_path().ok()) else {
        return Ok(None);
    };
    keys::backup(&state.paths.key_dir, &to).map_err(err)?;
    Ok(Some(to.to_string_lossy().into_owned()))
}

#[tauri::command]
async fn key_remove(state: Shared<'_>) -> Reply {
    let settings = state.settings();
    if settings.bundle().is_some() || settings.mode != cordon_core::DeploymentMode::Light {
        state.engine.stop().await;
    }
    keys::remove(&state.paths.key_dir).map_err(err)
}

// ── Bundles ─────────────────────────────────────────────────────────────────

/// Seal a model. `source` is a model key from the local list; without one, a
/// file is picked. `to_folder` writes the bundle to a chosen folder instead of
/// this computer's store, for another node.
#[tauri::command]
async fn bundle_seal(
    app: AppHandle,
    state: Shared<'_>,
    source: Option<String>,
    name: String,
    version: String,
    to_folder: bool,
) -> Reply<bool> {
    let key = state.key()?;
    let source = match source {
        Some(key) => models::resolve(&state.paths.model_dir, &key)
            .ok_or_else(|| "That model is no longer on disk.".to_string())?,
        None => match pick_file(
            &app,
            "Choose model weights to seal",
            Some(("Model weights", cordon_core::bundle::WEIGHT_EXTENSIONS)),
        )
        .await
        {
            Some(path) => path,
            None => return Ok(false),
        },
    };
    let destination = if to_folder {
        match pick_folder(&app, "Choose where to save the bundle").await {
            Some(folder) => Some(folder),
            None => return Ok(false),
        }
    } else {
        None
    };
    let name = if name.trim().is_empty() {
        cordon_core::bundle::model_name_from_path(&source)
    } else {
        name.trim().to_string()
    };
    let version = if version.trim().is_empty() {
        "1.0.0".to_string()
    } else {
        version.trim().to_string()
    };
    state
        .jobs
        .seal(
            state.paths.bundle_dir.clone(),
            key,
            bundles::SealJob {
                source,
                model_name: name,
                model_version: version,
                principal: state.settings().principal,
                destination,
            },
        )
        .map_err(err)?;
    Ok(true)
}

#[tauri::command]
fn bundle_verify(state: Shared<'_>, id: String) -> Reply {
    let dir = bundles::find(&state.paths.bundle_dir, &id)
        .ok_or_else(|| "That bundle is not in the store.".to_string())?;
    let key = keys::load(&state.paths.key_dir)
        .map_err(err)?
        .map(|k| (k, state.settings().principal));
    state.jobs.verify(dir, key).map_err(err)
}

#[tauri::command]
async fn bundle_import(app: AppHandle, state: Shared<'_>) -> Reply<bool> {
    let Some(from) = pick_folder(&app, "Choose a bundle folder to import").await else {
        return Ok(false);
    };
    state
        .jobs
        .import(state.paths.bundle_dir.clone(), from)
        .map_err(err)?;
    Ok(true)
}

#[tauri::command]
async fn bundle_export(app: AppHandle, state: Shared<'_>, id: String) -> Reply<bool> {
    let dir = bundles::find(&state.paths.bundle_dir, &id)
        .ok_or_else(|| "That bundle is not in the store.".to_string())?;
    let Some(folder) = pick_folder(&app, "Choose where to export the bundle").await else {
        return Ok(false);
    };
    state.jobs.export(dir, folder).map_err(err)?;
    Ok(true)
}

#[tauri::command]
async fn bundle_remove(state: Shared<'_>, id: String) -> Reply {
    let mut settings = state.settings();
    if settings.bundle() == Some(id.as_str()) {
        state.engine.stop().await;
        settings.model = None;
        state.save(settings)?;
    }
    bundles::remove(&state.paths.bundle_dir, &id).map_err(err)
}

#[tauri::command]
fn bundle_cancel(state: Shared<'_>) {
    state.jobs.cancel();
}

#[tauri::command]
fn bundle_dismiss(state: Shared<'_>) {
    state.jobs.dismiss();
}

// ── Remote access ───────────────────────────────────────────────────────────

/// Issue a client certificate and save its files to a folder the operator
/// picks first, so a key is never issued with nowhere to go.
#[tauri::command]
async fn remote_issue(
    app: AppHandle,
    state: Shared<'_>,
    name: String,
    days: u32,
) -> Reply<Option<String>> {
    cordon_api::pki::validate_client_id(&name).map_err(err)?;
    let Some(folder) = pick_folder(&app, "Choose where to save the client's files").await else {
        return Ok(None);
    };
    let settings = state.settings();
    let issued = remote::issue(&state.paths, &name, days).map_err(err)?;
    let view = remote::view(&state.paths, &settings);
    let url = view
        .addresses
        .first()
        .cloned()
        .unwrap_or_else(|| format!("https://127.0.0.1:{}", settings.remote.port));
    let saved = remote::save_client_files(&folder, &issued, &url).map_err(err)?;
    if settings.remote.enabled || settings.mode != cordon_core::DeploymentMode::Light {
        state.restart_if_running();
    }
    let _ = app.opener().reveal_item_in_dir(&saved);
    Ok(Some(saved.to_string_lossy().into_owned()))
}

#[tauri::command]
fn remote_revoke(state: Shared<'_>, fingerprint: String) -> Reply<bool> {
    remote::revoke(&state.paths, &fingerprint).map_err(err)?;
    let settings = state.settings();
    Ok(
        (settings.remote.enabled || settings.mode != cordon_core::DeploymentMode::Light)
            && state.restart_if_running(),
    )
}

#[tauri::command]
fn remote_clear_revoked(state: Shared<'_>) -> Reply {
    remote::clear_revoked(&state.paths).map_err(err)
}

// ── Deployment mode and hardware ────────────────────────────────────────────

/// Look for a TPM or confidential VM again.
#[tauri::command]
async fn hardware_probe(state: Shared<'_>) -> Reply<posture::HardwareProbe> {
    let probe = tauri::async_runtime::spawn_blocking(posture::probe)
        .await
        .map_err(err)?;
    *state.hardware.lock() = probe.clone();
    Ok(probe)
}

/// Choose a file the hardware root of trust needs: the TPM attestation key
/// context, or the AMD root certificate.
#[tauri::command]
async fn hardware_pick(app: AppHandle, state: Shared<'_>, what: String) -> Reply<bool> {
    let title = match what.as_str() {
        "ak" => "Choose the TPM attestation key context",
        "amd_root" => "Choose the AMD root certificate (ARK)",
        _ => return Err("Unknown file.".into()),
    };
    let Some(path) = pick_file(&app, title, None).await else {
        return Ok(false);
    };
    let mut settings = state.settings();
    if what == "ak" {
        settings.hardware.tpm_ak_context = Some(path);
    } else {
        settings.hardware.amd_root = Some(path);
    }
    state.save(settings)?;
    Ok(true)
}

/// Record this machine's current measurements as the expected ones.
#[tauri::command]
async fn hardware_capture(state: Shared<'_>) -> Reply {
    let settings = state.settings();
    let captured = {
        let settings = settings.clone();
        tauri::async_runtime::spawn_blocking(move || posture::capture(&settings))
            .await
            .map_err(err)?
            .map_err(err)?
    };
    let mut settings = settings;
    settings.hardware.pcrs = captured.0;
    settings.hardware.measurement = captured.1;
    state.save(settings)
}

// ── Command line ────────────────────────────────────────────────────────────

#[tauri::command]
fn cli_install(state: Shared<'_>, install: bool) -> Reply<cli::CliStatus> {
    let path = state
        .paths
        .cli
        .clone()
        .ok_or_else(|| "This build does not include the command line.".to_string())?;
    if install {
        cli::install(&path).map_err(err)?;
    } else {
        cli::uninstall(&path).map_err(err)?;
    }
    Ok(cli::status(Some(&path)))
}

// ── Window and links ────────────────────────────────────────────────────────

/// Show a folder or file in the system file manager.
#[tauri::command]
fn reveal(app: AppHandle, state: Shared<'_>, what: String) -> Reply {
    let path = match what.as_str() {
        "logs" => state.paths.log_file.clone(),
        "models" => state.paths.model_dir.clone(),
        "bundles" => state.paths.bundle_dir.clone(),
        "cli" => state.paths.cli.clone().unwrap_or_default(),
        _ => state.paths.data_dir.join("settings.json"),
    };
    let target = if path.exists() {
        path
    } else {
        path.parent().map(PathBuf::from).unwrap_or(path)
    };
    app.opener().reveal_item_in_dir(&target).map_err(err)
}

/// Load the operator console in the window, at a view.
#[tauri::command]
fn open_console(app: AppHandle, state: Shared<'_>, view: Option<String>) -> Reply {
    let port = state.engine.console_port();
    if port == 0 {
        return Err("The console is not running.".into());
    }
    let mut url = engine::console_url(port);
    url.push_str(&format!("&theme={}", state.settings().theme));
    if let Some(view) = view.filter(|v| v.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')) {
        if let Some(i) = url.find('#') {
            url.truncate(i);
        }
        url.push('#');
        url.push_str(&view);
    }
    navigate(&app, &url);
    Ok(())
}

/// Open a link in the system browser.
#[tauri::command]
fn open_external(app: AppHandle, url: String) -> Reply {
    let parsed = Url::parse(&url).map_err(err)?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err("Only web links can be opened.".into());
    }
    app.opener()
        .open_url(parsed.as_str(), None::<&str>)
        .map_err(err)
}

/// The app's origin, which Tauri serves the bundled `shell/` from.
fn app_url(fragment: &str) -> String {
    let origin = if cfg!(windows) {
        "http://tauri.localhost"
    } else {
        "tauri://localhost"
    };
    format!("{}/index.html#{}", origin, fragment)
}

fn navigate(app: &AppHandle, url: &str) {
    let (Some(window), Ok(url)) = (app.get_webview_window("main"), Url::parse(url)) else {
        return;
    };
    if let Err(e) = window.navigate(url) {
        tracing::warn!("cannot navigate the window: {}", e);
    }
}

/// App pages the console may ask for.
const APP_PAGES: &[&str] = &[
    "home",
    "models",
    "bundles",
    "keys",
    "deployment",
    "remote",
    "settings",
];

/// Decide whether the window may go to `url`.
///
/// The app's own origin and the running console are allowed. The console's
/// requests for app pages are turned into navigations back to them. Any other
/// web link goes to the system browser, so nothing a model writes into a
/// transcript can take over the application window.
fn allow_navigation(app: &AppHandle, desktop: &Desktop, url: &Url) -> bool {
    let host = url.host_str().unwrap_or_default();
    match url.scheme() {
        "tauri" => true,
        "http" | "https" if host == "tauri.localhost" => true,
        "http" if host == "127.0.0.1" && url.port() == Some(desktop.engine.console_port()) => {
            match url.path().strip_prefix("/desktop/") {
                // The console's title bar stops the node the way the app's
                // does. Stopping is the one action it can ask for, and the
                // worst a page could do with it is what the button says.
                Some("stop") => {
                    let app = app.clone();
                    let engine = desktop.engine.clone();
                    tauri::async_runtime::spawn(async move {
                        navigate(&app, &app_url("home"));
                        engine.stop().await;
                    });
                    false
                }
                Some(page) => {
                    let page = if APP_PAGES.contains(&page) {
                        page
                    } else {
                        "home"
                    };
                    let app = app.clone();
                    let target = app_url(page);
                    tauri::async_runtime::spawn(async move {
                        navigate(&app, &target);
                    });
                    false
                }
                None => true,
            }
        }
        "about" => true,
        "http" | "https" => {
            let _ = app.opener().open_url(url.as_str(), None::<&str>);
            false
        }
        _ => false,
    }
}

fn main() {
    // The uninstaller asks the app to take the command line off PATH before
    // the files go. No window, no node: undo the one change and exit.
    if std::env::args().any(|a| a == "--uninstall-cli") {
        let cli = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(PathBuf::from))
            .and_then(|dir| cli::locate(&dir));
        if let Some(cli) = cli {
            let _ = cli::uninstall(&cli);
        }
        return;
    }

    tauri::Builder::default()
        // First, so a second launch hands over to the first before anything
        // else in it starts.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        // Size and position are the operator's to keep. Decorations and
        // visibility are the app's: the pages draw the title bar, and the
        // window is shown once they have painted. A state file from a version
        // with a system title bar would otherwise bring it back.
        .plugin(
            tauri_plugin_window_state::Builder::default()
                .with_state_flags(
                    tauri_plugin_window_state::StateFlags::all()
                        - tauri_plugin_window_state::StateFlags::DECORATIONS
                        - tauri_plugin_window_state::StateFlags::VISIBLE,
                )
                .build(),
        )
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let data_dir = app.path().app_local_data_dir()?;
            let log_dir = app.path().app_log_dir()?;
            let mut paths = Paths::new(data_dir, log_dir);
            std::fs::create_dir_all(&paths.model_dir)?;
            std::fs::create_dir_all(&paths.bundle_dir)?;
            let logs = logs::init(&paths.log_file);
            tracing::info!(
                version = env!("CARGO_PKG_VERSION"),
                "Cordon desktop starting"
            );

            let resources = app.path().resource_dir().ok();
            paths.cli = resources.as_deref().and_then(cli::locate);
            let bundled = resources.map(|dir| {
                dir.join("llama")
                    .join(cordon_core::runtime::LLAMA_SERVER_EXE)
            });
            let runtime = tauri::async_runtime::block_on(hardware::probe(bundled));
            match &runtime.binary {
                Some(path) => tracing::info!(
                    path = %path.display(),
                    bundled = runtime.bundled,
                    version = runtime.version.as_deref().unwrap_or("unknown"),
                    devices = runtime.devices.len(),
                    "llama.cpp runtime found"
                ),
                None => tracing::error!("No llama.cpp runtime found"),
            }

            let settings = Settings::load(&paths);
            let desktop = Arc::new(Desktop {
                engine: Engine::new(paths.clone(), runtime.binary.clone()),
                settings: Mutex::new(settings.clone()),
                runtime: Mutex::new(runtime),
                hardware: Mutex::new(posture::HardwareProbe::default()),
                downloads: Downloads::default(),
                jobs: bundles::Jobs::default(),
                logs,
                exiting: AtomicBool::new(false),
                paths,
            });
            app.manage(desktop.clone());

            // Probing runs tpm2-tools when it is installed; keep it off the
            // path to the first frame.
            {
                let desktop = desktop.clone();
                tauri::async_runtime::spawn_blocking(move || {
                    *desktop.hardware.lock() = posture::probe();
                });
            }

            let handle = app.handle().clone();
            let guard = desktop.clone();
            let builder =
                WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                    .title("Cordon")
                    .inner_size(1280.0, 820.0)
                    .min_inner_size(1000.0, 660.0)
                    .center()
                    .theme(match settings.theme.as_str() {
                        "light" => Some(tauri::Theme::Light),
                        "dark" => Some(tauri::Theme::Dark),
                        _ => None,
                    })
                    // Shown once the first page has painted, so the first frame is
                    // the app rather than a blank white rectangle.
                    .visible(false)
                    .on_navigation(move |url| allow_navigation(&handle, &guard, url))
                    .on_page_load(|webview, payload| {
                        if payload.event() == PageLoadEvent::Finished {
                            let _ = webview.show();
                        }
                    });
            // The pages draw the title bar. macOS keeps its own traffic
            // lights over the page; elsewhere the pages draw the controls.
            #[cfg(target_os = "macos")]
            let builder = builder
                .title_bar_style(tauri::TitleBarStyle::Overlay)
                .hidden_title(true);
            #[cfg(not(target_os = "macos"))]
            let builder = builder.decorations(false);
            builder.build()?;

            if settings.start_on_launch && settings.model.is_some() {
                desktop.start();
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            snapshot,
            node_status,
            save_settings,
            start,
            stop,
            select_model,
            download,
            cancel_download,
            import_model,
            remove_model,
            key_create,
            key_import,
            key_backup,
            key_remove,
            bundle_seal,
            bundle_verify,
            bundle_import,
            bundle_export,
            bundle_remove,
            bundle_cancel,
            bundle_dismiss,
            remote_issue,
            remote_revoke,
            remote_clear_revoked,
            hardware_probe,
            hardware_pick,
            hardware_capture,
            cli_install,
            reveal,
            open_console,
            open_external,
        ])
        .build(tauri::generate_context!())
        .expect("the Cordon desktop app could not start")
        .run(|app, event| {
            // Closing the last window asks to exit. The node is stopped first,
            // so llama.cpp is shut down and the audit log records a clean
            // shutdown; the exit then proceeds.
            if let RunEvent::ExitRequested { api, .. } = event {
                let desktop = app.state::<Arc<Desktop>>().inner().clone();
                if desktop.exiting.swap(true, Ordering::SeqCst) {
                    return;
                }
                api.prevent_exit();
                desktop.downloads.cancel();
                desktop.jobs.cancel();
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let stopped = tokio::time::timeout(
                        std::time::Duration::from_secs(30),
                        desktop.engine.stop(),
                    )
                    .await;
                    if stopped.is_err() {
                        // The runtime is in a job object (Windows) or dies
                        // with its pipe; exiting now does not orphan it.
                        tracing::warn!("The node did not stop in time; exiting anyway");
                    }
                    app.exit(0);
                });
            }
        });
}
