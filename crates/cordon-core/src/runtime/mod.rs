//! Model runtimes.
//!
//! Cordon dispatches generation to one of three backends, selected by
//! [`RuntimeConfig::backend`](crate::config::RuntimeBackend):
//!
//! | Backend | Behaviour |
//! |---|---|
//! | `supervised` | Cordon spawns and owns a `llama-server` child on loopback with its web UI unreachable. The recommended production posture. |
//! | `external` | Cordon forwards to an OpenAI-compatible endpoint the operator runs. Cordon cannot vouch for that endpoint's exposure. |
//! | `none` | No model runtime. The control plane runs and returns clearly-labelled placeholder text. Light mode only. |
//!
//! Selection happens once at startup in [`build_backend`], which fails closed
//! rather than silently degrading to a weaker backend.

pub mod deterministic;
pub mod openai;
pub mod supervisor;

use std::sync::Arc;

pub use deterministic::DeterministicBackend;
pub use openai::{is_loopback_url, OpenAiBackend};
pub use supervisor::{discover_llama_server, LlamaRuntimeConfig, LlamaSupervisor};

use crate::config::{CordonConfig, DeploymentMode, RuntimeBackend};
use crate::error::{CordonError, CordonResult};
use crate::inference::InferenceBackend;

/// A constructed backend together with the supervisor that owns its child
/// process, if any. The supervisor must be kept alive for as long as the
/// backend is in use — dropping it terminates the runtime.
pub struct BuiltRuntime {
    /// The backend the inference engine dispatches to.
    pub backend: Arc<dyn InferenceBackend>,
    /// The supervised child process, when the `supervised` backend is in use.
    pub supervisor: Option<Arc<LlamaSupervisor>>,
}

/// Construct the configured backend, failing closed on any misconfiguration.
pub async fn build_backend(config: &CordonConfig) -> CordonResult<BuiltRuntime> {
    match config.runtime.backend {
        RuntimeBackend::Supervised => build_supervised(config).await,
        RuntimeBackend::External => build_external(config),
        RuntimeBackend::None => build_none(config),
    }
}

async fn build_supervised(config: &CordonConfig) -> CordonResult<BuiltRuntime> {
    let binary = discover_llama_server(config.runtime.binary.as_deref()).ok_or_else(|| {
        CordonError::RuntimeUnavailable(
            "no llama-server binary found. Install llama.cpp, then set \
             `runtime.binary` in the config or the CORDON_LLAMA_SERVER environment \
             variable. Run `cordon doctor` to check your setup."
                .into(),
        )
    })?;

    let model_path = config.runtime.model_path.clone().ok_or_else(|| {
        CordonError::RuntimeUnavailable(
            "the supervised runtime needs a model file. Fetch one with \
             `cordon pull <repo>` and set `runtime.model_path`."
                .into(),
        )
    })?;

    let mut runtime_config = LlamaRuntimeConfig::new(binary, model_path);
    runtime_config.ctx_size = config.runtime.context_size;
    runtime_config.gpu_layers = config.runtime.gpu_layers;
    runtime_config.threads = config.runtime.threads;
    // Give llama.cpp at least as many decode slots as Cordon will admit
    // concurrently, otherwise Cordon's admission control is not the binding
    // constraint and requests queue invisibly inside the runtime.
    runtime_config.parallel_slots = config
        .runtime
        .parallel_slots
        .max(config.inference.max_concurrent_requests);
    runtime_config.startup_timeout =
        std::time::Duration::from_secs(config.runtime.startup_timeout_seconds);
    runtime_config.extra_args = config.runtime.extra_args.clone();

    let supervisor = Arc::new(LlamaSupervisor::start(runtime_config).await?);
    let backend = Arc::new(OpenAiBackend::supervised(supervisor.clone())?);

    Ok(BuiltRuntime {
        backend,
        supervisor: Some(supervisor),
    })
}

fn build_external(config: &CordonConfig) -> CordonResult<BuiltRuntime> {
    let url = config.runtime.endpoint_url.clone().ok_or_else(|| {
        CordonError::ConfigError(
            "runtime.backend = \"external\" requires runtime.endpoint_url".into(),
        )
    })?;

    // A non-loopback runtime means prompt plaintext crosses a network Cordon
    // does not control. That is a deliberate operator decision in Light mode and
    // is refused outright everywhere else.
    if !is_loopback_url(&url) {
        if config.mode == DeploymentMode::Light {
            tracing::warn!(
                endpoint = %url,
                "External model runtime is not on loopback — prompt and completion \
                 plaintext will leave this host in the clear unless the endpoint is \
                 itself TLS-protected."
            );
        } else {
            return Err(CordonError::ConfigError(format!(
                "runtime.endpoint_url {} is not on loopback. In {} mode the model \
                 runtime must be local, or prompt plaintext leaves the trust boundary. \
                 Use runtime.backend = \"supervised\", or point at a loopback address.",
                url, config.mode
            )));
        }
    }

    let api_key = config
        .runtime
        .endpoint_api_key_env
        .as_ref()
        .and_then(|var| std::env::var(var).ok())
        .filter(|k| !k.is_empty());

    Ok(BuiltRuntime {
        backend: Arc::new(OpenAiBackend::external(url, api_key)?),
        supervisor: None,
    })
}

fn build_none(config: &CordonConfig) -> CordonResult<BuiltRuntime> {
    if config.mode != DeploymentMode::Light {
        return Err(CordonError::ConfigError(format!(
            "runtime.backend = \"none\" returns placeholder text instead of model \
             output and is permitted only in Light mode, not {}. Configure a real \
             runtime before deploying in this mode.",
            config.mode
        )));
    }
    tracing::warn!(
        "No model runtime configured — responses are clearly-labelled placeholders, \
         not generated text. Set runtime.backend = \"supervised\" to serve a model."
    );
    Ok(BuiltRuntime {
        backend: Arc::new(DeterministicBackend::new()),
        supervisor: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CordonConfig;

    fn light() -> CordonConfig {
        CordonConfig::default_light("node".into(), "deployment".into())
    }

    #[test]
    fn none_backend_is_refused_outside_light_mode() {
        let mut config = light();
        config.mode = DeploymentMode::Vault;
        config.runtime.backend = RuntimeBackend::None;
        assert!(build_none(&config).is_err());
    }

    #[test]
    fn none_backend_is_allowed_in_light_mode() {
        let mut config = light();
        config.runtime.backend = RuntimeBackend::None;
        assert!(build_none(&config).is_ok());
    }

    #[test]
    fn external_runtime_must_be_local_outside_light_mode() {
        let mut config = light();
        config.mode = DeploymentMode::Island;
        config.runtime.backend = RuntimeBackend::External;
        config.runtime.endpoint_url = Some("http://10.1.2.3:8000".into());
        assert!(build_external(&config).is_err());

        config.runtime.endpoint_url = Some("http://127.0.0.1:8000".into());
        assert!(build_external(&config).is_ok());
    }

    #[test]
    fn external_runtime_requires_a_url() {
        let mut config = light();
        config.runtime.backend = RuntimeBackend::External;
        config.runtime.endpoint_url = None;
        assert!(build_external(&config).is_err());
    }
}
