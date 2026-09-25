//! Where the desktop app keeps things, and the settings it remembers.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use cordon_core::GpuLayers;

/// The app's directories, resolved once at startup.
#[derive(Debug, Clone, Serialize)]
pub struct Paths {
    /// Models, audit log, keys and settings. Local rather than roaming: model
    /// files are gigabytes, and an audit log belongs to one machine.
    pub data_dir: PathBuf,
    /// Pulled GGUF models and their records.
    pub model_dir: PathBuf,
    /// Log files.
    pub log_dir: PathBuf,
    /// This session's log.
    pub log_file: PathBuf,
}

impl Paths {
    /// Lay the directories out under `data_dir` and `log_dir`.
    pub fn new(data_dir: PathBuf, log_dir: PathBuf) -> Self {
        Self {
            model_dir: data_dir.join("models"),
            log_file: log_dir.join("cordon-desktop.log"),
            data_dir,
            log_dir,
        }
    }

    fn settings_file(&self) -> PathBuf {
        self.data_dir.join("settings.json")
    }
}

/// Settings the launcher edits.
///
/// Every field has a default, so a settings file written by an older version,
/// or edited by hand and missing a field, still loads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Settings {
    /// The model to serve: a local model ID from the models directory, or an
    /// absolute path to a GGUF file somewhere else on disk.
    pub model: Option<String>,
    /// GPU offload: `"auto"`, `"all"`, or a layer count (`"0"` is CPU only).
    pub gpu_layers: String,
    /// Context window, in tokens, shared by every request in flight.
    pub context_size: u32,
    /// Generation threads. `None` lets llama.cpp choose.
    pub threads: Option<u32>,
    /// Requests served at once.
    pub parallel: u32,
    /// Preferred API port. Another is chosen if this one is taken.
    pub api_port: u16,
    /// Preferred console port. Another is chosen if this one is taken.
    pub console_port: u16,
    /// Start the model when the app opens, if one is chosen.
    pub start_on_launch: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            model: None,
            gpu_layers: "auto".into(),
            context_size: 8192,
            threads: None,
            parallel: 4,
            api_port: 8477,
            console_port: 8478,
            start_on_launch: true,
        }
    }
}

impl Settings {
    /// Load settings, falling back to defaults when there are none yet or the
    /// file cannot be read.
    pub fn load(paths: &Paths) -> Self {
        match std::fs::read_to_string(paths.settings_file()) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|e| {
                tracing::warn!("settings.json is unreadable ({}); using defaults", e);
                Settings::default()
            }),
            Err(_) => Settings::default(),
        }
    }

    /// Persist settings, via a temporary file so a crash mid-write cannot
    /// leave a truncated file behind.
    pub fn save(&self, paths: &Paths) -> anyhow::Result<()> {
        std::fs::create_dir_all(&paths.data_dir)?;
        let target = paths.settings_file();
        let tmp = target.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, &target)?;
        Ok(())
    }

    /// Check values a person typed before anything acts on them.
    pub fn validate(&self) -> anyhow::Result<()> {
        self.gpu_layers()?;
        if !(512..=262_144).contains(&self.context_size) {
            anyhow::bail!("Context length must be between 512 and 262,144 tokens.");
        }
        if !(1..=32).contains(&self.parallel) {
            anyhow::bail!("Parallel requests must be between 1 and 32.");
        }
        if let Some(threads) = self.threads {
            if !(1..=256).contains(&threads) {
                anyhow::bail!("Threads must be between 1 and 256.");
            }
        }
        if self.api_port == 0 || self.console_port == 0 || self.api_port == self.console_port {
            anyhow::bail!("The API and console need two different, non-zero ports.");
        }
        Ok(())
    }

    /// The GPU offload setting as the runtime takes it.
    pub fn gpu_layers(&self) -> anyhow::Result<GpuLayers> {
        self.gpu_layers
            .parse()
            .map_err(|e: String| anyhow::anyhow!("GPU offload: {}", e))
    }
}

/// Read, or create, the deployment ID kept in the data directory. It feeds
/// every derived key, so it must not change between runs.
pub fn stable_deployment_id(data_dir: &Path) -> anyhow::Result<String> {
    let path = data_dir.join("deployment-id");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    std::fs::create_dir_all(data_dir)?;
    let id = uuid::Uuid::new_v4().to_string();
    std::fs::write(&path, &id)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        Settings::default().validate().unwrap();
    }

    #[test]
    fn a_partial_file_takes_defaults_for_what_it_omits() {
        let parsed: Settings = serde_json::from_str(r#"{ "context_size": 4096 }"#).unwrap();
        assert_eq!(parsed.context_size, 4096);
        assert_eq!(parsed.parallel, Settings::default().parallel);
    }

    #[test]
    fn nonsense_is_refused_with_a_reason() {
        let bad = Settings {
            gpu_layers: "lots".into(),
            ..Settings::default()
        };
        assert!(bad.validate().unwrap_err().to_string().contains("GPU"));

        let clash = Settings {
            console_port: 8477,
            ..Settings::default()
        };
        assert!(clash.validate().is_err());
    }

    #[test]
    fn settings_round_trip_through_disk() {
        let dir = std::env::temp_dir().join(format!("cordon-settings-{}", uuid::Uuid::new_v4()));
        let paths = Paths::new(dir.clone(), dir.join("logs"));
        let settings = Settings {
            model: Some("some-model".into()),
            gpu_layers: "12".into(),
            ..Settings::default()
        };
        settings.save(&paths).unwrap();
        assert_eq!(Settings::load(&paths), settings);
        let _ = std::fs::remove_dir_all(dir);
    }
}
