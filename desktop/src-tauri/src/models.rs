//! Models: a short list worth starting with, the ones already on disk, and
//! downloads from the Hugging Face Hub.
//!
//! Downloads go through the same [`HubClient`] as `cordon pull`, so a model
//! fetched here is resumable, digest-checked against what the Hub publishes,
//! and recorded in the same format `cordon models` reads.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use serde::Serialize;

use cordon_core::hub::{self, DownloadedModel, HubClient, ModelRef};

/// A model offered on the first-run screen.
#[derive(Debug, Clone, Serialize)]
pub struct CatalogEntry {
    /// Reference passed to the Hub client, `owner/repo:QUANT`.
    pub reference: &'static str,
    /// Display name.
    pub name: &'static str,
    /// One line on what it is good for.
    pub summary: &'static str,
    /// Download size, in bytes, as published.
    pub size_bytes: u64,
    /// Memory it wants to run comfortably, in GiB.
    pub memory_gib: u32,
    /// Licence, as the model card states it.
    pub license: &'static str,
    /// Suggested first choice.
    pub recommended: bool,
}

/// Small, instruction-tuned, single-file GGUF models whose repositories are
/// public, checked against the Hub when this list was written. Sizes are the
/// published file sizes.
pub const CATALOG: &[CatalogEntry] = &[
    CatalogEntry {
        reference: "HuggingFaceTB/SmolLM2-360M-Instruct-GGUF:Q8_0",
        name: "SmolLM2 360M",
        summary: "Tiny and quick to load. Good for trying Cordon out, not for real work.",
        size_bytes: 386_000_000,
        memory_gib: 1,
        license: "Apache 2.0",
        recommended: false,
    },
    CatalogEntry {
        reference: "Qwen/Qwen2.5-1.5B-Instruct-GGUF:Q4_K_M",
        name: "Qwen2.5 1.5B Instruct",
        summary: "Small and capable. Runs well on most laptops without a GPU.",
        size_bytes: 1_117_000_000,
        memory_gib: 3,
        license: "Apache 2.0",
        recommended: true,
    },
    CatalogEntry {
        reference: "bartowski/Llama-3.2-3B-Instruct-GGUF:Q4_K_M",
        name: "Llama 3.2 3B Instruct",
        summary: "Stronger general assistant. Comfortable with 8 GB of memory.",
        size_bytes: 2_019_000_000,
        memory_gib: 5,
        license: "Llama 3.2 Community",
        recommended: false,
    },
    CatalogEntry {
        reference: "unsloth/gemma-3-4b-it-GGUF:Q4_K_M",
        name: "Gemma 3 4B Instruct",
        summary: "Good writing and multilingual quality for its size.",
        size_bytes: 2_490_000_000,
        memory_gib: 6,
        license: "Gemma Terms of Use",
        recommended: false,
    },
    CatalogEntry {
        reference: "bartowski/Qwen2.5-7B-Instruct-GGUF:Q4_K_M",
        name: "Qwen2.5 7B Instruct",
        summary: "The most capable here. Wants 16 GB of memory or a GPU with 6 GB.",
        size_bytes: 4_683_000_000,
        memory_gib: 10,
        license: "Apache 2.0",
        recommended: false,
    },
];

/// The local ID a catalog reference is stored under.
pub fn local_id_of(reference: &str) -> Option<String> {
    ModelRef::parse(reference).ok().map(|m| m.local_id())
}

/// A model on disk that can be served.
#[derive(Debug, Clone, Serialize)]
pub struct LocalModel {
    /// What the settings store to select it: a local ID, or a path.
    pub key: String,
    /// Display name.
    pub name: String,
    /// File on disk.
    pub path: PathBuf,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Quantisation, when known.
    pub quant: Option<String>,
    /// Hub repository it came from, when it came from the Hub.
    pub source: Option<String>,
    /// Whether its digest was checked against one the publisher released.
    pub digest_verified: bool,
    /// Imported from elsewhere on disk rather than downloaded.
    pub imported: bool,
}

impl From<DownloadedModel> for LocalModel {
    fn from(m: DownloadedModel) -> Self {
        let name = CATALOG
            .iter()
            .find(|c| local_id_of(c.reference).as_deref() == Some(m.id.as_str()))
            .map(|c| c.name.to_string())
            .unwrap_or_else(|| m.filename.trim_end_matches(".gguf").to_string());
        Self {
            key: m.id,
            name,
            path: m.path,
            size_bytes: m.size_bytes,
            quant: m.quant,
            source: Some(m.repo_id),
            digest_verified: m.digest_verified,
            imported: false,
        }
    }
}

/// Models in the models directory, plus the selected one if it is a file
/// imported from elsewhere.
pub fn list(model_dir: &Path, selected: Option<&str>) -> Vec<LocalModel> {
    let mut models: Vec<LocalModel> = hub::list_local_models(model_dir)
        .unwrap_or_default()
        .into_iter()
        .map(LocalModel::from)
        .collect();
    if let Some(path) = selected.map(PathBuf::from).filter(|p| p.is_file()) {
        if !models.iter().any(|m| m.path == path) {
            models.push(imported(&path));
        }
    }
    models
}

/// Describe a GGUF file chosen from disk.
pub fn imported(path: &Path) -> LocalModel {
    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    LocalModel {
        key: path.to_string_lossy().into_owned(),
        name: filename.trim_end_matches(".gguf").to_string(),
        size_bytes: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
        quant: hub::quant_of(&filename),
        path: path.to_path_buf(),
        source: None,
        digest_verified: false,
        imported: true,
    }
}

/// Resolve a settings value to a file: an existing path, or a local ID.
pub fn resolve(model_dir: &Path, key: &str) -> Option<PathBuf> {
    let as_path = PathBuf::from(key);
    if as_path.is_file() {
        return Some(as_path);
    }
    hub::find_local_model(model_dir, key)
        .ok()
        .flatten()
        .map(|m| m.path)
}

/// A download in progress, or the last one to finish.
#[derive(Debug, Clone, Serialize, Default)]
pub struct DownloadState {
    /// What is being fetched.
    pub reference: String,
    /// Where it will be stored.
    pub local_id: Option<String>,
    /// Bytes on disk so far, including a resumed prefix.
    pub downloaded: u64,
    /// Total, when known.
    pub total: Option<u64>,
    /// Recent throughput.
    pub bytes_per_second: u64,
    /// `resolving`, `downloading`, `verifying`, `done`, `failed`, `cancelled`.
    pub stage: String,
    /// Failure detail.
    pub error: Option<String>,
    /// Whether the digest was checked against the publisher's.
    pub digest_verified: Option<bool>,
}

/// Runs one download at a time and reports on it.
#[derive(Default)]
pub struct Downloads {
    state: Arc<Mutex<Option<DownloadState>>>,
    task: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
}

impl Downloads {
    /// The current or most recent download.
    pub fn snapshot(&self) -> Option<DownloadState> {
        self.state.lock().clone()
    }

    fn busy(&self) -> bool {
        matches!(
            self.state.lock().as_ref().map(|s| s.stage.as_str()),
            Some("resolving" | "downloading" | "verifying")
        )
    }

    /// Start fetching `reference` into `model_dir`. `on_done` runs with the
    /// local ID once the file is on disk and recorded.
    pub fn start<F>(&self, reference: String, model_dir: PathBuf, on_done: F) -> anyhow::Result<()>
    where
        F: FnOnce(String) + Send + 'static,
    {
        if self.busy() {
            anyhow::bail!("A download is already in progress.");
        }
        let model = ModelRef::parse(reference.trim()).map_err(|e| anyhow::anyhow!("{}", e))?;
        let local_id = model.local_id();

        *self.state.lock() = Some(DownloadState {
            reference: reference.clone(),
            local_id: Some(local_id.clone()),
            stage: "resolving".into(),
            ..DownloadState::default()
        });

        let state = self.state.clone();
        let handle = tauri::async_runtime::spawn(async move {
            let update = |f: &dyn Fn(&mut DownloadState)| {
                if let Some(s) = state.lock().as_mut() {
                    f(s);
                }
            };
            let result: anyhow::Result<DownloadedModel> = async {
                let client = HubClient::new()?;
                let resolved = client.resolve(&model).await?;
                update(&|s| s.stage = "downloading".into());

                let mut window_start = Instant::now();
                let mut window_bytes = 0u64;
                let downloaded = client
                    .download(&resolved, &local_id, &model_dir, |p| {
                        let elapsed = window_start.elapsed().as_secs_f64();
                        let rate = if elapsed >= 1.0 {
                            let r = ((p.downloaded.saturating_sub(window_bytes)) as f64 / elapsed)
                                as u64;
                            window_start = Instant::now();
                            window_bytes = p.downloaded;
                            Some(r)
                        } else {
                            None
                        };
                        update(&|s| {
                            s.downloaded = p.downloaded;
                            s.total = p.total;
                            if let Some(r) = rate {
                                s.bytes_per_second = r;
                            }
                            if p.total.is_some_and(|t| p.downloaded >= t) {
                                s.stage = "verifying".into();
                            }
                        });
                    })
                    .await?;
                Ok(downloaded)
            }
            .await;

            match result {
                Ok(model) => {
                    update(&|s| {
                        s.stage = "done".into();
                        s.downloaded = model.size_bytes;
                        s.total = Some(model.size_bytes);
                        s.digest_verified = Some(model.digest_verified);
                    });
                    tracing::info!(id = %model.id, "Model downloaded");
                    on_done(model.id);
                }
                Err(e) => {
                    let message = format!("{:#}", e);
                    tracing::warn!("Model download failed: {}", message);
                    update(&|s| {
                        s.stage = "failed".into();
                        s.error = Some(message.clone());
                    });
                }
            }
        });
        *self.task.lock() = Some(handle);
        Ok(())
    }

    /// Stop the current download. The partial file stays, so starting the
    /// same download again resumes it.
    pub fn cancel(&self) {
        if let Some(task) = self.task.lock().take() {
            task.abort();
        }
        if let Some(s) = self.state.lock().as_mut() {
            if matches!(s.stage.as_str(), "resolving" | "downloading" | "verifying") {
                s.stage = "cancelled".into();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_catalog_reference_parses_and_has_a_distinct_local_id() {
        let mut ids: Vec<String> = CATALOG
            .iter()
            .map(|c| local_id_of(c.reference).unwrap_or_else(|| panic!("{}", c.reference)))
            .collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), CATALOG.len());
        assert_eq!(CATALOG.iter().filter(|c| c.recommended).count(), 1);
    }

    #[test]
    fn a_catalog_model_is_stored_under_the_id_cordon_pull_uses() {
        assert_eq!(
            local_id_of("HuggingFaceTB/SmolLM2-360M-Instruct-GGUF:Q8_0").as_deref(),
            Some("huggingfacetb--smollm2-360m-instruct-gguf--q8_0")
        );
    }
}
