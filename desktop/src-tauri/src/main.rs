//! Cordon for the desktop.
//!
//! One window, two pages. The launcher (`shell/`, bundled with the app) picks
//! a model, tunes the runtime and shows startup progress. Once the node is
//! serving, the window loads the operator console from the node itself, the
//! same page and the same requests a browser gets from `cordon run`, with
//! `?shell=desktop` so it drops the browser-only affordances.
//!
//! The launcher can call the commands below. The console cannot: it is served
//! from a loopback origin that no capability grants anything to, so a page
//! the node serves has no more reach into the app than it would in a browser.
//! It asks for the launcher back by navigating to `/desktop/settings`, which
//! the navigation guard intercepts.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod engine;
mod hardware;
mod logs;
mod models;
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

use engine::{Engine, Phase};
use hardware::RuntimeInfo;
use models::{CatalogEntry, DownloadState, Downloads, LocalModel};
use settings::{Paths, Settings};

/// Everything the commands share.
struct Desktop {
    paths: Paths,
    engine: Arc<Engine>,
    settings: Mutex<Settings>,
    runtime: Mutex<RuntimeInfo>,
    downloads: Downloads,
    logs: logs::LogBuffer,
    exiting: AtomicBool,
}

type Shared<'a> = State<'a, Arc<Desktop>>;

impl Desktop {
    fn settings(&self) -> Settings {
        self.settings.lock().clone()
    }

    fn save(&self, settings: Settings) -> Result<(), String> {
        settings.validate().map_err(|e| e.to_string())?;
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
}

/// The launcher page's view of the app.
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

// ── Commands ────────────────────────────────────────────────────────────────

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
    let (log_mark, logs) = state.logs.since(log_after.unwrap_or(0));
    Snapshot {
        version: env!("CARGO_PKG_VERSION"),
        platform: std::env::consts::OS,
        phase: state.engine.phase(),
        settings,
        models,
        catalog,
        runtime: state.runtime.lock().clone(),
        download: state.downloads.snapshot(),
        paths: state.paths.clone(),
        log_mark,
        logs,
    }
}

/// Save settings; restart the node if asked and a model is selected.
#[tauri::command]
fn save_settings(state: Shared<'_>, settings: Settings, restart: bool) -> Result<(), String> {
    state.save(settings)?;
    if restart && state.settings().model.is_some() {
        state.start();
    }
    Ok(())
}

#[tauri::command]
fn start(state: Shared<'_>) -> Result<(), String> {
    if state.settings().model.is_none() {
        return Err("Choose a model first.".into());
    }
    state.start();
    Ok(())
}

#[tauri::command]
async fn stop(state: Shared<'_>) -> Result<(), String> {
    state.engine.stop().await;
    Ok(())
}

/// Serve a model that is already on disk.
#[tauri::command]
fn select_model(state: Shared<'_>, key: String) -> Result<(), String> {
    if models::resolve(&state.paths.model_dir, &key).is_none() {
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
fn download(state: Shared<'_>, reference: String) -> Result<(), String> {
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
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn cancel_download(state: Shared<'_>) {
    state.downloads.cancel();
}

/// Pick a GGUF file from disk and serve it where it is.
#[tauri::command]
async fn import_model(app: AppHandle, state: Shared<'_>) -> Result<Option<LocalModel>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title("Open a GGUF model")
        .add_filter("GGUF model", &["gguf"])
        .pick_file(move |picked| {
            let _ = tx.send(picked);
        });
    let Some(picked) = rx.await.map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    let path: PathBuf = picked.into_path().map_err(|e| e.to_string())?;
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
async fn remove_model(state: Shared<'_>, key: String) -> Result<(), String> {
    let mut settings = state.settings();
    let selected = settings.model.as_deref() == Some(key.as_str());
    if selected {
        state.engine.stop().await;
        settings.model = None;
        state.save(settings)?;
    }
    if !PathBuf::from(&key).is_file() {
        cordon_core::hub::remove_local_model(&state.paths.model_dir, &key)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Show the data or log folder in the system file manager.
#[tauri::command]
fn reveal(app: AppHandle, state: Shared<'_>, what: String) -> Result<(), String> {
    let path = match what.as_str() {
        "logs" => state.paths.log_file.clone(),
        "models" => state.paths.model_dir.clone(),
        _ => state.paths.data_dir.join("settings.json"),
    };
    let target = if path.exists() {
        path
    } else {
        path.parent().map(PathBuf::from).unwrap_or(path)
    };
    app.opener()
        .reveal_item_in_dir(&target)
        .map_err(|e| e.to_string())
}

/// Load the operator console in the window.
#[tauri::command]
fn open_console(app: AppHandle, state: Shared<'_>) -> Result<(), String> {
    let port = state.engine.console_port();
    if port == 0 {
        return Err("Cordon is not running.".into());
    }
    navigate(&app, &engine::console_url(port));
    Ok(())
}

/// Open a link in the system browser.
#[tauri::command]
fn open_external(app: AppHandle, url: String) -> Result<(), String> {
    let parsed = Url::parse(&url).map_err(|e| e.to_string())?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err("Only web links can be opened.".into());
    }
    app.opener()
        .open_url(parsed.as_str(), None::<&str>)
        .map_err(|e| e.to_string())
}

// ── Window ──────────────────────────────────────────────────────────────────

/// The launcher's origin, which Tauri serves the bundled `shell/` from.
fn launcher_url(fragment: &str) -> String {
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

/// Decide whether the window may go to `url`.
///
/// The launcher's own origin and the running console are allowed. The
/// console's request for the launcher is turned into a navigation back to it.
/// Any other web link goes to the system browser, so nothing a model writes
/// into a transcript can take over the application window.
fn allow_navigation(app: &AppHandle, desktop: &Desktop, url: &Url) -> bool {
    let host = url.host_str().unwrap_or_default();
    match url.scheme() {
        "tauri" => true,
        "http" | "https" if host == "tauri.localhost" => true,
        "http" if host == "127.0.0.1" && url.port() == Some(desktop.engine.console_port()) => {
            if url.path() == "/desktop/settings" {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    navigate(&app, &launcher_url("settings"));
                });
                false
            } else {
                true
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
        .plugin(tauri_plugin_window_state::Builder::default().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let data_dir = app.path().app_local_data_dir()?;
            let log_dir = app.path().app_log_dir()?;
            let paths = Paths::new(data_dir, log_dir);
            std::fs::create_dir_all(&paths.model_dir)?;
            let logs = logs::init(&paths.log_file);
            tracing::info!(
                version = env!("CARGO_PKG_VERSION"),
                "Cordon desktop starting"
            );

            let bundled = app.path().resource_dir().ok().map(|dir| {
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
                downloads: Downloads::default(),
                logs,
                exiting: AtomicBool::new(false),
                paths,
            });
            app.manage(desktop.clone());

            let handle = app.handle().clone();
            let guard = desktop.clone();
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("Cordon")
                .inner_size(1280.0, 820.0)
                .min_inner_size(980.0, 640.0)
                .center()
                // Shown once the launcher has painted, so the first frame is
                // the app rather than a blank white rectangle.
                .visible(false)
                .on_navigation(move |url| allow_navigation(&handle, &guard, url))
                .on_page_load(|webview, payload| {
                    if payload.event() == PageLoadEvent::Finished {
                        let _ = webview.show();
                    }
                })
                .build()?;

            if settings.start_on_launch && settings.model.is_some() {
                desktop.start();
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            snapshot,
            save_settings,
            start,
            stop,
            select_model,
            download,
            cancel_download,
            import_model,
            remove_model,
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
