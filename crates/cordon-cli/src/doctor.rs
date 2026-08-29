//! `cordon doctor` — check that this machine can run Cordon, and that the
//! configuration in front of it means what the operator thinks it means.
//!
//! The checks are ordered from "will it start at all" to "is the security
//! posture what you intended", and each failure carries the command that fixes
//! it. A node that will not start is easy to diagnose; a node that starts with a
//! weaker posture than intended is not, which is why posture warnings are
//! reported here rather than buried in a log line at boot.

use std::path::Path;

use anyhow::Result;

use cordon_core::{
    config::{CordonConfig, DeploymentMode, MeasurementSource, RuntimeBackend},
    hub,
    runtime::discover_llama_server,
    tpm,
};

/// Outcome of one check.
enum Verdict {
    Pass(String),
    Warn(String, String),
    Fail(String, String),
}

struct Report {
    checks: Vec<(String, Verdict)>,
}

impl Report {
    fn new() -> Self {
        Self { checks: Vec::new() }
    }

    fn pass(&mut self, name: &str, detail: impl Into<String>) {
        self.checks
            .push((name.to_string(), Verdict::Pass(detail.into())));
    }

    fn warn(&mut self, name: &str, detail: impl Into<String>, fix: impl Into<String>) {
        self.checks
            .push((name.to_string(), Verdict::Warn(detail.into(), fix.into())));
    }

    fn fail(&mut self, name: &str, detail: impl Into<String>, fix: impl Into<String>) {
        self.checks
            .push((name.to_string(), Verdict::Fail(detail.into(), fix.into())));
    }

    fn render(&self) -> (usize, usize) {
        let width = self
            .checks
            .iter()
            .map(|(name, _)| name.len())
            .max()
            .unwrap_or(0);

        let mut warnings = 0;
        let mut failures = 0;

        for (name, verdict) in &self.checks {
            match verdict {
                Verdict::Pass(detail) => {
                    println!("  ok    {:<width$}  {}", name, detail, width = width);
                }
                Verdict::Warn(detail, fix) => {
                    warnings += 1;
                    println!("  warn  {:<width$}  {}", name, detail, width = width);
                    println!("        {:<width$}  → {}", "", fix, width = width);
                }
                Verdict::Fail(detail, fix) => {
                    failures += 1;
                    println!("  FAIL  {:<width$}  {}", name, detail, width = width);
                    println!("        {:<width$}  → {}", "", fix, width = width);
                }
            }
        }
        (warnings, failures)
    }
}

/// Run every check and print a report.
pub async fn run(config_path: Option<&Path>, model_dir: &Path) -> Result<()> {
    let mut report = Report::new();

    println!();
    println!("Cordon {} — environment check", env!("CARGO_PKG_VERSION"));
    println!();

    check_runtime(&mut report).await;
    check_models(&mut report, model_dir);
    check_tpm(&mut report);

    let config = match config_path {
        Some(path) => match CordonConfig::from_file(path) {
            Ok(config) => {
                report.pass("config", format!("{} — valid", path.display()));
                Some(config)
            }
            Err(e) => {
                report.fail(
                    "config",
                    format!("{} — {}", path.display(), e),
                    "fix the configuration, or regenerate one with `cordon default-config`",
                );
                None
            }
        },
        None => None,
    };

    if let Some(config) = &config {
        check_posture(&mut report, config);
    } else if config_path.is_none() {
        check_key_material(&mut report);
    }

    let (warnings, failures) = report.render();

    println!();
    if failures > 0 {
        println!(
            "  {} check(s) failed, {} warning(s). Cordon will not start as configured.",
            failures, warnings
        );
        std::process::exit(1);
    } else if warnings > 0 {
        println!("  Ready, with {} warning(s).", warnings);
    } else {
        println!("  Ready.");
    }
    println!();
    Ok(())
}

async fn check_runtime(report: &mut Report) {
    let Some(binary) = discover_llama_server(None) else {
        report.fail(
            "llama-server",
            "not found on PATH or in the usual install locations",
            "install llama.cpp, then set CORDON_LLAMA_SERVER=/path/to/llama-server",
        );
        return;
    };

    // Reading `--help` tells us both that the binary runs and whether it can
    // remove its own web UI, which is the property Cordon depends on.
    let output = tokio::process::Command::new(&binary)
        .arg("--help")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .output()
        .await;

    match output {
        Ok(out) => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            report.pass("llama-server", binary.display().to_string());

            if text.contains("--no-webui") {
                report.pass("runtime web UI", "can be disabled with --no-webui");
            } else {
                report.warn(
                    "runtime web UI",
                    "this build does not accept --no-webui",
                    "Cordon still binds the runtime to loopback on an ephemeral port \
                     behind a required API key, and refuses to start if the runtime \
                     serves HTML. Upgrading llama.cpp removes the UI entirely.",
                );
            }
        }
        Err(e) => report.fail(
            "llama-server",
            format!("{} is not runnable: {}", binary.display(), e),
            "check the file is executable and matches this machine's architecture",
        ),
    }
}

fn check_models(report: &mut Report, model_dir: &Path) {
    match hub::list_local_models(model_dir) {
        Ok(models) if models.is_empty() => report.warn(
            "models",
            format!("none in {}", model_dir.display()),
            "cordon pull HuggingFaceTB/SmolLM2-360M-Instruct-GGUF",
        ),
        Ok(models) => {
            let unverified = models.iter().filter(|m| !m.digest_verified).count();
            report.pass("models", format!("{} available", models.len()));
            if unverified > 0 {
                report.warn(
                    "model integrity",
                    format!("{} downloaded without a publisher digest", unverified),
                    "re-pull them, or verify the files against the publisher out of band",
                );
            }
        }
        Err(e) => report.warn(
            "models",
            format!("cannot read {}: {}", model_dir.display(), e),
            "check the directory exists and is readable",
        ),
    }
}

fn check_tpm(report: &mut Report) {
    if tpm::is_available() {
        report.pass("TPM 2.0", "reachable via tpm2-tools");
        if tpm::ak_context_path().is_some() {
            report.pass("TPM attestation key", "provisioned");
        } else {
            report.warn(
                "TPM attestation key",
                "no attestation key is provisioned",
                "run tpm2_createek and tpm2_createak, then set CORDON_TPM_AK_CTX; \
                 without one the TPM cannot sign a quote",
            );
        }
    } else {
        report.warn(
            "TPM 2.0",
            "not reachable",
            "Light mode runs without one. Every other mode requires a TPM and will \
             refuse to start.",
        );
    }
}

fn check_key_material(report: &mut Report) {
    if std::env::var("CORDON_CMK_FILE").is_ok() {
        report.pass("client master key", "sourced from CORDON_CMK_FILE");
    } else if std::env::var("CORDON_CMK").is_ok() {
        report.warn(
            "client master key",
            "sourced from the CORDON_CMK environment variable",
            "prefer CORDON_CMK_FILE on a tmpfs — an environment variable is visible \
             to child processes and in crash dumps",
        );
    } else {
        report.warn(
            "client master key",
            "not provisioned; signing keys will be generated at boot",
            "generate one with `cordon-keygen generate`; without it the node \
             self-certifies and its audit log carries no non-repudiation",
        );
    }
}

/// Check that a configuration's posture matches what its mode claims.
fn check_posture(report: &mut Report, config: &CordonConfig) {
    let is_light = config.mode == DeploymentMode::Light;
    report.pass("mode", config.mode.to_string());

    check_key_material(report);

    match config.attestation.measurement_source {
        MeasurementSource::Tpm2 if tpm::is_available() => {
            report.pass("measurements", "read from TPM hardware")
        }
        MeasurementSource::Tpm2 => report.fail(
            "measurements",
            "configured for TPM but no TPM is reachable",
            "Cordon will not fall back to a software measurement — connect a TPM, or \
             switch to Light mode",
        ),
        MeasurementSource::SoftwareMeasurement => report.warn(
            "measurements",
            "derived from configuration, not hardware",
            "this attests the software Cordon is running and nothing about the \
             platform underneath it",
        ),
    }

    if config
        .attestation
        .expected
        .as_ref()
        .is_some_and(|e| !e.is_empty())
    {
        report.pass("pinned measurements", "configured");
    } else if is_light {
        report.warn(
            "pinned measurements",
            "none configured",
            "attestation verification will refuse every report until measurements \
             are pinned; capture them with `cordon attest --pin`",
        );
    }

    if config.network.require_mtls {
        match &config.network.client_ca_path {
            Some(path) if path.exists() => {
                report.pass("mTLS", format!("client CA at {}", path.display()))
            }
            Some(path) => report.fail(
                "mTLS",
                format!("client CA {} does not exist", path.display()),
                "provision the CA certificate that issued your client certificates",
            ),
            None => report.fail(
                "mTLS",
                "enabled with no client CA",
                "set network.client_ca_path",
            ),
        }
    } else if is_light {
        report.warn(
            "mTLS",
            "disabled — client identity comes from a header",
            "any caller can claim any client ID; enable mTLS before exposing this node",
        );
    }

    match config.runtime.backend {
        RuntimeBackend::Supervised => report.pass("runtime", "supervised (loopback, no web UI)"),
        RuntimeBackend::External => report.warn(
            "runtime",
            "external endpoint",
            "Cordon cannot vouch for that endpoint's exposure; confirm it is not \
             reachable from anywhere but this host",
        ),
        RuntimeBackend::None => report.warn(
            "runtime",
            "no model attached — responses are labelled placeholders",
            "set runtime.backend = \"supervised\" and runtime.model_path to serve a model",
        ),
    }

    if config.ui.enabled {
        report.warn(
            "operator console",
            format!("enabled on {}", config.ui.bind_address),
            "the console has no authentication of its own; keep it on loopback and \
             reach it over an SSH tunnel",
        );
    }

    match &config.client_registry_path {
        Some(path) if path.exists() => report.pass("client registry", path.display().to_string()),
        Some(path) => report.fail(
            "client registry",
            format!("{} does not exist", path.display()),
            "create the registry, or clear client_registry_path",
        ),
        None => report.warn(
            "client registry",
            "not configured — every client gets default limits",
            "enrol clients in a registry file and set client_registry_path",
        ),
    }
}
