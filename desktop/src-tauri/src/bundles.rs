//! Encrypted bundles: the store, and sealing, verifying, importing and
//! exporting them.
//!
//! The store is the node's own model store directory, so a bundle sealed or
//! imported here is one the node finds at its next start. The work is
//! [`cordon_core::bundle`], the same code as `cordon bundle`, run one job at a
//! time on a blocking thread and reported through [`Jobs::snapshot`].

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use parking_lot::Mutex;
use serde::Serialize;

use cordon_core::bundle::{self, BundleEvent, SealRequest, DEFAULT_SHARD_SIZE};
use cordon_crypto::hierarchy::MasterKey;

/// A bundle in the store, as the app lists it.
#[derive(Debug, Clone, Serialize)]
pub struct BundleView {
    /// Bundle ID; the node serves it by this.
    pub id: String,
    /// Model name from the manifest.
    pub model_name: String,
    /// Model version from the manifest.
    pub model_version: String,
    /// When it was sealed.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Plaintext size.
    pub size_bytes: u64,
    /// Number of shards.
    pub shards: usize,
    /// The principal it was sealed for.
    pub principal: String,
    /// Its directory.
    pub path: PathBuf,
    /// Why the node would refuse it, if it would.
    pub problem: Option<String>,
}

/// Bundles in `store`, newest first. A directory whose manifest is unreadable
/// or invalid is listed with the reason, rather than hidden, so an operator
/// can see why the node will not serve it.
pub fn list(store: &Path) -> Vec<BundleView> {
    let Ok(entries) = std::fs::read_dir(store) else {
        return Vec::new();
    };
    let mut out: Vec<BundleView> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir() && p.join("manifest.json").is_file())
        .map(|dir| match bundle::read_manifest(&dir) {
            Ok(m) => BundleView {
                problem: m.validate_structure().err().map(|e| e.to_string()),
                size_bytes: m.shards.iter().map(|s| s.size_bytes).sum(),
                shards: m.shards.len(),
                id: m.bundle_id,
                model_name: m.model_name,
                model_version: m.model_version,
                created_at: m.created_at,
                principal: m.client_key_id,
                path: dir,
            },
            Err(e) => BundleView {
                id: dir
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                model_name: String::new(),
                model_version: String::new(),
                created_at: chrono::Utc::now(),
                size_bytes: 0,
                shards: 0,
                principal: String::new(),
                problem: Some(e.to_string()),
                path: dir,
            },
        })
        .collect();
    out.sort_by_key(|b| std::cmp::Reverse(b.created_at));
    out
}

/// Find a bundle's directory in the store by its ID.
pub fn find(store: &Path, id: &str) -> Option<PathBuf> {
    list(store)
        .into_iter()
        .find(|b| b.id == id && b.problem.is_none())
        .map(|b| b.path)
}

/// Delete a bundle from the store.
pub fn remove(store: &Path, id: &str) -> Result<()> {
    let dir = list(store)
        .into_iter()
        .find(|b| b.id == id)
        .map(|b| b.path)
        .context("That bundle is not in the store.")?;
    // The directory came from listing the store, but check once more that it
    // is inside it before deleting anything recursively.
    let canonical_store = store.canonicalize()?;
    if !dir.canonicalize()?.starts_with(&canonical_store) {
        bail!("Refusing to delete a folder outside the bundle store.");
    }
    std::fs::remove_dir_all(&dir).with_context(|| format!("cannot remove {}", dir.display()))?;
    tracing::info!(bundle_id = id, "Bundle removed");
    Ok(())
}

/// A job in progress, or the last one to finish.
#[derive(Debug, Clone, Serialize, Default)]
pub struct JobState {
    /// `seal`, `verify`, `import` or `export`.
    pub kind: String,
    /// What it is working on, in words.
    pub label: String,
    /// The bundle, once known.
    pub bundle_id: Option<String>,
    /// Bytes processed.
    pub done: u64,
    /// Bytes in total.
    pub total: u64,
    /// `running`, `done`, `failed` or `cancelled`.
    pub stage: String,
    /// What went wrong.
    pub error: Option<String>,
    /// The outcome, in words.
    pub result: Option<String>,
    /// Where the result was written.
    pub output: Option<PathBuf>,
}

/// What to seal.
pub struct SealJob {
    /// The weight file.
    pub source: PathBuf,
    /// Model name for the manifest.
    pub model_name: String,
    /// Model version for the manifest.
    pub model_version: String,
    /// The principal to seal for.
    pub principal: String,
    /// A folder to write the bundle into, instead of the store.
    pub destination: Option<PathBuf>,
}

/// Runs one bundle job at a time.
#[derive(Default)]
pub struct Jobs {
    state: Arc<Mutex<Option<JobState>>>,
    cancel: Arc<AtomicBool>,
}

impl Jobs {
    /// The current or most recent job.
    pub fn snapshot(&self) -> Option<JobState> {
        self.state.lock().clone()
    }

    /// Ask the running job to stop.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    /// Clear a finished job from view.
    pub fn dismiss(&self) {
        let mut state = self.state.lock();
        if state.as_ref().is_some_and(|s| s.stage != "running") {
            *state = None;
        }
    }

    fn begin(&self, kind: &str, label: String) -> Result<()> {
        let mut state = self.state.lock();
        if state.as_ref().is_some_and(|s| s.stage == "running") {
            bail!("Another bundle task is still running.");
        }
        self.cancel.store(false, Ordering::SeqCst);
        *state = Some(JobState {
            kind: kind.into(),
            label,
            stage: "running".into(),
            ..JobState::default()
        });
        Ok(())
    }

    /// Run `work` on a blocking thread, recording its outcome. `work` gets a
    /// progress reporter and the cancel flag.
    fn run<F>(&self, work: F)
    where
        F: FnOnce(&dyn Fn(BundleEvent), &AtomicBool) -> Result<(String, Option<PathBuf>)>
            + Send
            + 'static,
    {
        let state = self.state.clone();
        let cancel = self.cancel.clone();
        tauri::async_runtime::spawn_blocking(move || {
            let report = |event: BundleEvent| {
                if let Some(s) = state.lock().as_mut() {
                    match event {
                        BundleEvent::Started {
                            bundle_id,
                            total_bytes,
                            ..
                        } => {
                            s.bundle_id = Some(bundle_id);
                            s.total = total_bytes;
                        }
                        BundleEvent::Progress {
                            done_bytes,
                            total_bytes,
                        } => {
                            s.done = done_bytes;
                            s.total = total_bytes;
                        }
                        BundleEvent::Shard { .. } => {}
                    }
                }
            };
            let outcome = work(&report, &cancel);
            let mut guard = state.lock();
            let Some(s) = guard.as_mut() else { return };
            match outcome {
                Ok((result, output)) => {
                    s.stage = "done".into();
                    s.result = Some(result);
                    s.output = output;
                }
                Err(_) if cancel.load(Ordering::SeqCst) => {
                    s.stage = "cancelled".into();
                }
                Err(e) => {
                    let message = format!("{:#}", e);
                    tracing::warn!(kind = %s.kind, "Bundle task failed: {}", message);
                    s.stage = "failed".into();
                    s.error = Some(message);
                }
            }
        });
    }

    /// Seal a weight file under `key`.
    pub fn seal(&self, store: PathBuf, key: MasterKey, job: SealJob) -> Result<()> {
        if !job.source.is_file() {
            bail!("The model file is no longer there.");
        }
        self.begin("seal", format!("Sealing {}", job.model_name))?;
        self.run(move |report, cancel| {
            let bundle_id = bundle::suggest_bundle_id(&job.model_name);
            let output = match &job.destination {
                Some(folder) => folder.join(format!("{}.bundle", bundle_id)),
                None => store.join(&bundle_id),
            };
            let manifest = bundle::seal(
                &SealRequest {
                    weights: &job.source,
                    master: &key,
                    principal: &job.principal,
                    bundle_id: Some(bundle_id),
                    model_name: &job.model_name,
                    model_version: &job.model_version,
                    output: &output,
                    shard_size: DEFAULT_SHARD_SIZE,
                },
                cancel,
                report,
            )?;
            tracing::info!(bundle_id = %manifest.bundle_id, output = %output.display(), "Bundle sealed");
            Ok((
                format!("Sealed into {} shard(s)", manifest.shards.len()),
                Some(output),
            ))
        });
        Ok(())
    }

    /// Verify a bundle in the store; with a key, decrypt it too.
    pub fn verify(&self, dir: PathBuf, key: Option<(MasterKey, String)>) -> Result<()> {
        let id = bundle::read_manifest(&dir)?.bundle_id;
        self.begin("verify", format!("Verifying {}", id))?;
        self.run(move |report, cancel| {
            let result = bundle::verify(
                &dir,
                key.as_ref().map(|(k, p)| (k, p.as_str())),
                cancel,
                report,
            )?;
            if !result.passed() {
                bail!("{}", result.failures.join("\n"));
            }
            Ok((
                if result.decrypted {
                    format!("All {} shard(s) decrypted and matched", result.shards)
                } else {
                    format!(
                        "All {} shard(s) match; add a key to check decryption",
                        result.shards
                    )
                },
                None,
            ))
        });
        Ok(())
    }

    /// Copy a bundle folder into the store after checking its manifest.
    pub fn import(&self, store: PathBuf, from: PathBuf) -> Result<()> {
        let manifest = bundle::read_manifest(&from)
            .context("That folder is not a Cordon bundle: it has no readable manifest.json.")?;
        manifest.validate_structure()?;
        let target = store.join(&manifest.bundle_id);
        if target.exists() || find(&store, &manifest.bundle_id).is_some() {
            bail!("A bundle with this ID is already in the store.");
        }
        self.begin("import", format!("Importing {}", manifest.model_name))?;
        self.run(move |report, cancel| {
            let copied = copy_bundle(&from, &target, &manifest, report, cancel);
            if copied.is_err() {
                let _ = std::fs::remove_dir_all(&target);
            }
            copied?;
            Ok(("Imported into the store".into(), Some(target)))
        });
        Ok(())
    }

    /// Copy a bundle out of the store into `folder`.
    pub fn export(&self, dir: PathBuf, folder: PathBuf) -> Result<()> {
        let manifest = bundle::read_manifest(&dir)?;
        let target = folder.join(format!("{}.bundle", manifest.bundle_id));
        if target.exists() {
            bail!("{} already exists.", target.display());
        }
        self.begin("export", format!("Exporting {}", manifest.model_name))?;
        self.run(move |report, cancel| {
            let copied = copy_bundle(&dir, &target, &manifest, report, cancel);
            if copied.is_err() {
                let _ = std::fs::remove_dir_all(&target);
            }
            copied?;
            Ok(("Exported".into(), Some(target)))
        });
        Ok(())
    }
}

/// Copy the files a manifest names, then the manifest, so the copy only looks
/// like a bundle once it is complete.
fn copy_bundle(
    from: &Path,
    to: &Path,
    manifest: &cordon_core::model_store::BundleManifest,
    report: &dyn Fn(BundleEvent),
    cancel: &AtomicBool,
) -> Result<()> {
    let total: u64 = manifest.shards.iter().map(|s| s.size_bytes + 16).sum();
    report(BundleEvent::Started {
        bundle_id: manifest.bundle_id.clone(),
        total_bytes: total,
        items: manifest.shards.len(),
    });
    std::fs::create_dir_all(to.join("shards"))?;
    let mut done = 0;
    for shard in &manifest.shards {
        if cancel.load(Ordering::SeqCst) {
            bail!("cancelled");
        }
        // `validate_structure` has already refused absolute paths and `..`.
        let source = from.join(&shard.path);
        let target = to.join(&shard.path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        done += std::fs::copy(&source, &target)
            .with_context(|| format!("cannot copy {}", source.display()))?;
        report(BundleEvent::Progress {
            done_bytes: done,
            total_bytes: total,
        });
    }
    std::fs::copy(from.join("manifest.json"), to.join("manifest.json"))
        .context("cannot copy the manifest")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal_into_store(store: &Path) -> String {
        let dir = tempfile::tempdir().unwrap();
        let weights = dir.path().join("m.gguf");
        std::fs::write(&weights, vec![5u8; 3000]).unwrap();
        let key = MasterKey::from_hex(&"11".repeat(32)).unwrap();
        let manifest = bundle::seal(
            &SealRequest {
                weights: &weights,
                master: &key,
                principal: "operator",
                bundle_id: Some("m-1".into()),
                model_name: "M",
                model_version: "1",
                output: &store.join("m-1"),
                shard_size: 1024,
            },
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap();
        manifest.bundle_id
    }

    #[test]
    fn the_store_lists_bundles_and_explains_broken_ones() {
        let store = tempfile::tempdir().unwrap();
        let id = seal_into_store(store.path());
        let broken = store.path().join("broken");
        std::fs::create_dir_all(&broken).unwrap();
        std::fs::write(broken.join("manifest.json"), "{}").unwrap();

        let listed = list(store.path());
        assert_eq!(listed.len(), 2);
        let good = listed.iter().find(|b| b.id == id).unwrap();
        assert!(good.problem.is_none());
        assert_eq!(good.shards, 3);
        assert!(listed
            .iter()
            .any(|b| b.id == "broken" && b.problem.is_some()));
        assert_eq!(find(store.path(), &id), Some(store.path().join("m-1")));
        assert_eq!(find(store.path(), "broken"), None);
    }

    #[test]
    fn a_copied_bundle_is_complete_and_removable() {
        let store = tempfile::tempdir().unwrap();
        let id = seal_into_store(store.path());
        let other = tempfile::tempdir().unwrap();
        let manifest = bundle::read_manifest(&store.path().join("m-1")).unwrap();
        let target = other.path().join("copy");
        copy_bundle(
            &store.path().join("m-1"),
            &target,
            &manifest,
            &|_| {},
            &AtomicBool::new(false),
        )
        .unwrap();
        let report = bundle::verify(&target, None, &AtomicBool::new(false), |_| {}).unwrap();
        assert!(report.passed());

        remove(store.path(), &id).unwrap();
        assert!(list(store.path()).is_empty());
    }
}
