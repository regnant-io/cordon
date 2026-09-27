//! Where the desktop app keeps things, and the settings it remembers.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use cordon_core::{DeploymentMode, GpuLayers};

/// The app's directories, resolved once at startup.
#[derive(Debug, Clone, Serialize)]
pub struct Paths {
    /// Models, audit log, keys and settings. Local rather than roaming: model
    /// files are gigabytes, and an audit log belongs to one machine.
    pub data_dir: PathBuf,
    /// Pulled GGUF models and their records.
    pub model_dir: PathBuf,
    /// Encrypted bundles, which is also the node's model store.
    pub bundle_dir: PathBuf,
    /// The Client Master Key.
    pub key_dir: PathBuf,
    /// The certificate authority for remote access.
    pub pki_dir: PathBuf,
    /// Log files.
    pub log_dir: PathBuf,
    /// This session's log.
    pub log_file: PathBuf,
    /// The `cordon` command line shipped with the app, when it is.
    pub cli: Option<PathBuf>,
}

impl Paths {
    /// Lay the directories out under `data_dir` and `log_dir`.
    pub fn new(data_dir: PathBuf, log_dir: PathBuf) -> Self {
        Self {
            model_dir: data_dir.join("models"),
            bundle_dir: data_dir.join("bundles"),
            key_dir: data_dir.join("keys"),
            pki_dir: data_dir.join("pki"),
            log_file: log_dir.join("cordon-desktop.log"),
            data_dir,
            log_dir,
            cli: None,
        }
    }

    fn settings_file(&self) -> PathBuf {
        self.data_dir.join("settings.json")
    }
}

/// Settings the app edits.
///
/// Every field has a default, so a settings file written by an older version,
/// or edited by hand and missing a field, still loads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Settings {
    /// The model to serve: a local model ID from the models directory, an
    /// absolute path to a GGUF file somewhere else on disk, or
    /// `bundle:<id>` for an encrypted bundle in the store.
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
    /// The deployment mode the node runs in.
    #[serde(with = "mode_serde")]
    pub mode: DeploymentMode,
    /// The key-derivation principal bundles are sealed for.
    pub principal: String,
    /// Access from other machines.
    pub remote: Remote,
    /// Hardware root of trust, for every mode but Light.
    pub hardware: Hardware,
    /// Appearance: `system`, `light` or `dark`.
    pub theme: String,
}

/// Access from other machines. Always mutual TLS.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Remote {
    /// Listen on every interface, not only loopback.
    pub enabled: bool,
    /// The port other machines connect to.
    pub port: u16,
    /// Extra host names and addresses clients use to reach this machine, such
    /// as a public DNS name or a router's address. The server certificate
    /// covers these as well as the local ones.
    pub names: Vec<String>,
}

impl Default for Remote {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 8443,
            names: Vec::new(),
        }
    }
}

/// Hardware root of trust for the modes that need one.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Hardware {
    /// `tpm2` or `sev_snp`. `None` until chosen.
    pub source: Option<String>,
    /// TPM attestation key context, for `tpm2`.
    pub tpm_ak_context: Option<PathBuf>,
    /// The AMD root certificate, for `sev_snp`.
    pub amd_root: Option<PathBuf>,
    /// Pinned PCR values, for `tpm2`.
    pub pcrs: BTreeMap<u8, String>,
    /// Pinned launch measurement, for `sev_snp`.
    pub measurement: Option<String>,
    /// The operator's declaration that key custody meets FIPS 140-2 Level 4,
    /// which Dark mode claims. Cordon cannot check this; it records it.
    pub fips_level_4: bool,
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
            mode: DeploymentMode::Light,
            principal: "operator".into(),
            remote: Remote::default(),
            hardware: Hardware::default(),
            theme: "system".into(),
        }
    }
}

/// The prefix a bundle carries in [`Settings::model`].
pub const BUNDLE_PREFIX: &str = "bundle:";

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
        let ports = [self.api_port, self.console_port, self.remote.port];
        if ports.contains(&0) {
            anyhow::bail!("Ports must be between 1 and 65535.");
        }
        if self.api_port == self.console_port
            || (self.remote.enabled
                && (self.remote.port == self.api_port || self.remote.port == self.console_port))
        {
            anyhow::bail!("The API, console and remote access need different ports.");
        }
        let principal = self.principal.trim();
        if principal.is_empty()
            || principal.len() > 64
            || !principal
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'))
        {
            anyhow::bail!(
                "The key principal must be 1 to 64 letters, digits, '-', '_', '.' or '@'."
            );
        }
        if !matches!(self.theme.as_str(), "system" | "light" | "dark") {
            anyhow::bail!("Appearance must be system, light or dark.");
        }
        Ok(())
    }

    /// The GPU offload setting as the runtime takes it.
    pub fn gpu_layers(&self) -> anyhow::Result<GpuLayers> {
        self.gpu_layers
            .parse()
            .map_err(|e: String| anyhow::anyhow!("GPU offload: {}", e))
    }

    /// The selected bundle's ID, when the selected model is a bundle.
    pub fn bundle(&self) -> Option<&str> {
        self.model.as_deref()?.strip_prefix(BUNDLE_PREFIX)
    }
}

/// Deployment modes as the settings file spells them.
mod mode_serde {
    use cordon_core::DeploymentMode;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(mode: &DeploymentMode, s: S) -> Result<S::Ok, S::Error> {
        mode.serialize(s)
    }

    /// An unknown mode reads as Light rather than failing the whole file: the
    /// app then starts in the mode with the fewest requirements, and the
    /// operator sees which one it is.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DeploymentMode, D::Error> {
        Ok(DeploymentMode::deserialize(d).unwrap_or(DeploymentMode::Light))
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
        assert_eq!(parsed.mode, DeploymentMode::Light);
        assert_eq!(parsed.remote.port, 8443);
    }

    /// A file from before modes existed, or naming one this build does not
    /// know, still loads.
    #[test]
    fn an_unknown_mode_reads_as_light() {
        let parsed: Settings = serde_json::from_str(r#"{ "mode": "orbital" }"#).unwrap();
        assert_eq!(parsed.mode, DeploymentMode::Light);
        let parsed: Settings = serde_json::from_str(r#"{ "mode": "vault" }"#).unwrap();
        assert_eq!(parsed.mode, DeploymentMode::Vault);
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

        let mut remote_clash = Settings::default();
        remote_clash.remote.enabled = true;
        remote_clash.remote.port = remote_clash.api_port;
        assert!(remote_clash.validate().is_err());

        let principal = Settings {
            principal: "a b".into(),
            ..Settings::default()
        };
        assert!(principal.validate().is_err());
    }

    #[test]
    fn a_bundle_selection_is_recognised() {
        let s = Settings {
            model: Some("bundle:qwen-1234".into()),
            ..Settings::default()
        };
        assert_eq!(s.bundle(), Some("qwen-1234"));
        assert_eq!(Settings::default().bundle(), None);
    }

    #[test]
    fn settings_round_trip_through_disk() {
        let dir = std::env::temp_dir().join(format!("cordon-settings-{}", uuid::Uuid::new_v4()));
        let paths = Paths::new(dir.clone(), dir.join("logs"));
        let mut settings = Settings {
            model: Some("some-model".into()),
            gpu_layers: "12".into(),
            mode: DeploymentMode::Vault,
            ..Settings::default()
        };
        settings.hardware.pcrs.insert(7, "sha256:00".into());
        settings.save(&paths).unwrap();
        assert_eq!(Settings::load(&paths), settings);
        let _ = std::fs::remove_dir_all(dir);
    }
}
