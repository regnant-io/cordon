//! Deployment modes, and whether this machine is ready for one.
//!
//! Light is what the app has always run. The other four are the modes a
//! server deployment runs, and each claims more: a hardware root of trust,
//! keys the operator cannot forge, client identity bound to certificates, and
//! for three of them no outbound connections at all. The node refuses a
//! configuration that cannot back its claims, so the app does not guess: it
//! lists what a mode needs, marks what this machine already has, offers to
//! set up what it can, and only then lets the mode start.

use serde::Serialize;

use cordon_core::DeploymentMode;

use crate::settings::{Paths, Settings};

/// PCRs pinned for a TPM-attested node: firmware, boot loader and Secure
/// Boot state.
pub const PINNED_PCRS: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7];

/// A mode as the app presents it.
#[derive(Debug, Clone, Serialize)]
pub struct ModeInfo {
    /// Settings value.
    pub id: &'static str,
    /// Display name.
    pub name: &'static str,
    /// Who it is for.
    pub summary: &'static str,
    /// Whether Cordon may reach the network, to download models.
    pub egress: bool,
}

/// Every mode, weakest first.
pub const MODES: &[ModeInfo] = &[
    ModeInfo {
        id: "light",
        name: "Light",
        summary: "Development and evaluation. Software isolation, local signing key, no hardware requirements.",
        egress: true,
    },
    ModeInfo {
        id: "sovereign_cloud",
        name: "Sovereign Cloud",
        summary: "A node in your own cloud account. Hardware attestation and mutual TLS; models may be downloaded.",
        egress: true,
    },
    ModeInfo {
        id: "vault",
        name: "Vault",
        summary: "Regulated enterprise. Hardware attestation, mutual TLS, and no outbound connections.",
        egress: false,
    },
    ModeInfo {
        id: "island",
        name: "Island",
        summary: "Private networks and critical infrastructure. As Vault, for isolated sites.",
        egress: false,
    },
    ModeInfo {
        id: "dark",
        name: "Dark",
        summary: "Maximum isolation. As Island, single tenant, with FIPS 140-2 Level 4 key custody.",
        egress: false,
    },
];

/// One requirement and where this machine stands on it.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    /// Stable ID the page keys actions on.
    pub id: &'static str,
    /// What is required.
    pub title: &'static str,
    /// Where things stand, in a sentence.
    pub detail: String,
    /// `met`, `todo` (the app can set it up), `blocked` (this machine cannot).
    pub state: &'static str,
}

/// Where a mode stands on this machine.
#[derive(Debug, Clone, Serialize)]
pub struct Readiness {
    /// The mode.
    pub mode: &'static str,
    /// Whether the node can start in it.
    pub ready: bool,
    /// Requirements, in the order to address them. Empty for Light.
    pub checks: Vec<Check>,
}

/// Parse a settings mode ID.
pub fn parse_mode(id: &str) -> Option<DeploymentMode> {
    Some(match id {
        "light" => DeploymentMode::Light,
        "sovereign_cloud" => DeploymentMode::SovereignCloud,
        "vault" => DeploymentMode::Vault,
        "island" => DeploymentMode::Island,
        "dark" => DeploymentMode::Dark,
        _ => return None,
    })
}

/// The settings ID of a mode.
pub fn mode_id(mode: &DeploymentMode) -> &'static str {
    match mode {
        DeploymentMode::Light => "light",
        DeploymentMode::SovereignCloud => "sovereign_cloud",
        DeploymentMode::Vault => "vault",
        DeploymentMode::Island => "island",
        DeploymentMode::Dark => "dark",
    }
}

/// Whether a mode lets Cordon download models.
pub fn permits_downloads(mode: &DeploymentMode) -> bool {
    matches!(mode, DeploymentMode::Light | DeploymentMode::SovereignCloud)
}

/// What the hardware on this machine offers.
#[derive(Debug, Clone, Serialize, Default)]
pub struct HardwareProbe {
    /// `tpm2-tools` answers and a TPM is readable.
    pub tpm: bool,
    /// A confidential-VM report interface is present.
    pub sev_snp: bool,
}

/// Look for a hardware root of trust. Runs `tpm2_pcrread` when it is on
/// `PATH`, so call it off the UI thread.
pub fn probe() -> HardwareProbe {
    HardwareProbe {
        tpm: cordon_core::tpm::is_available(),
        sev_snp: cordon_core::confidential_vm::is_available(),
    }
}

/// Where `mode` stands with these settings on this machine.
pub fn readiness(
    mode: &DeploymentMode,
    settings: &Settings,
    paths: &Paths,
    hardware: &HardwareProbe,
    key_present: bool,
) -> Readiness {
    let id = mode_id(mode);
    if *mode == DeploymentMode::Light {
        return Readiness {
            mode: id,
            ready: true,
            checks: Vec::new(),
        };
    }

    let mut checks = Vec::new();

    checks.push(Check {
        id: "key",
        title: "Client Master Key",
        detail: if key_present {
            "Present. It signs the audit log and responses, and opens sealed models.".into()
        } else {
            "Signatures in this mode come from a key you hold. Create or import one.".into()
        },
        state: if key_present { "met" } else { "todo" },
    });

    let bundle_selected = settings
        .bundle()
        .is_some_and(|id| crate::bundles::find(&paths.bundle_dir, id).is_some());
    checks.push(Check {
        id: "bundle",
        title: "Sealed model",
        detail: if bundle_selected {
            "The selected model is an encrypted bundle.".into()
        } else {
            "Weights must be encrypted at rest in this mode. Seal a model and select it.".into()
        },
        state: if bundle_selected { "met" } else { "todo" },
    });

    checks.push(Check {
        id: "mtls",
        title: "Mutual TLS",
        detail:
            "Every client presents a certificate from this app's CA. Set up automatically at start."
                .into(),
        state: "met",
    });

    let source = settings.hardware.source.as_deref();
    let (root_state, root_detail): (&'static str, String) = match source {
        Some("tpm2") if !hardware.tpm => (
            "blocked",
            "TPM 2.0 selected, but tpm2-tools cannot read a TPM on this machine.".into(),
        ),
        Some("tpm2")
            if settings
                .hardware
                .tpm_ak_context
                .as_ref()
                .is_none_or(|p| !p.is_file()) =>
        {
            (
                "todo",
                "TPM found. Choose its attestation key context (created with tpm2_createak)."
                    .into(),
            )
        }
        Some("tpm2") => ("met", "TPM 2.0 with an attestation key.".into()),
        Some("sev_snp") if !hardware.sev_snp => (
            "blocked",
            "AMD SEV-SNP selected, but this machine is not a confidential VM.".into(),
        ),
        Some("sev_snp")
            if settings
                .hardware
                .amd_root
                .as_ref()
                .is_none_or(|p| !p.is_file()) =>
        {
            (
                "todo",
                "Confidential VM found. Choose the AMD root certificate (ARK) to pin.".into(),
            )
        }
        Some("sev_snp") => (
            "met",
            "AMD SEV-SNP confidential VM, AMD root pinned.".into(),
        ),
        _ if hardware.sev_snp => ("todo", "A confidential VM is available. Select it.".into()),
        _ if hardware.tpm => ("todo", "A TPM 2.0 is available. Select it.".into()),
        _ => ("blocked", unavailable_reason().into()),
    };
    checks.push(Check {
        id: "root",
        title: "Hardware root of trust",
        detail: root_detail,
        state: root_state,
    });

    let pinned = match source {
        Some("tpm2") => !settings.hardware.pcrs.is_empty(),
        Some("sev_snp") => settings.hardware.measurement.is_some(),
        _ => false,
    };
    checks.push(Check {
        id: "pins",
        title: "Pinned measurements",
        detail: if pinned {
            "Recorded. Attestation reports are checked against them.".into()
        } else {
            "Record this machine's current measurements, so an impostor can be told apart.".into()
        },
        state: if pinned {
            "met"
        } else if root_state == "blocked" {
            "blocked"
        } else {
            "todo"
        },
    });

    if !permits_downloads(mode) {
        checks.push(Check {
            id: "egress",
            title: "No outbound connections",
            detail: "Cordon will not download models or contact any service. Models arrive as sealed bundles."
                .into(),
            state: "met",
        });
    }

    if *mode == DeploymentMode::Dark {
        checks.push(Check {
            id: "fips",
            title: "FIPS 140-2 Level 4 key custody",
            detail: if settings.hardware.fips_level_4 {
                "Declared by you. Cordon records the declaration; it cannot verify it.".into()
            } else {
                "Dark mode claims Level 4 custody for the key. Confirm yours meets it.".into()
            },
            state: if settings.hardware.fips_level_4 {
                "met"
            } else {
                "todo"
            },
        });
    }

    let ready = checks.iter().all(|c| c.state == "met");
    Readiness {
        mode: id,
        ready,
        checks,
    }
}

fn unavailable_reason() -> &'static str {
    if cfg!(target_os = "linux") {
        "No TPM readable through tpm2-tools, and not a confidential VM. Install tpm2-tools, or run on an SEV-SNP guest."
    } else if cfg!(windows) {
        "Cordon reads hardware attestation on Linux (TPM 2.0 through tpm2-tools, or an AMD SEV-SNP guest). Run this mode on a Linux host."
    } else {
        "This platform offers no hardware attestation Cordon can read. Run this mode on a Linux host with a TPM 2.0 or on an SEV-SNP guest."
    }
}

/// Read the measurements to pin from the hardware in `settings`.
pub fn capture(
    settings: &Settings,
) -> anyhow::Result<(std::collections::BTreeMap<u8, String>, Option<String>)> {
    match settings.hardware.source.as_deref() {
        Some("tpm2") => {
            let pcrs = cordon_core::tpm::read_pcrs(PINNED_PCRS)?;
            if pcrs.is_empty() {
                anyhow::bail!("The TPM returned no PCR values.");
            }
            Ok((pcrs, None))
        }
        Some("sev_snp") => {
            let report = cordon_core::confidential_vm::request_report(&[0u8; 32])?;
            let parsed =
                cordon_crypto::sev_snp::SevSnpReport::parse(&report.report).map_err(|e| {
                    anyhow::anyhow!("the platform returned an unreadable report: {}", e)
                })?;
            if parsed.policy.debug_allowed {
                anyhow::bail!(
                    "This guest was launched with debugging allowed, which lets the hypervisor read its memory. Relaunch it with debugging disabled."
                );
            }
            Ok((Default::default(), Some(parsed.measurement_hex())))
        }
        _ => anyhow::bail!("Choose a hardware root of trust first."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let p = Paths::new(dir.path().to_path_buf(), dir.path().join("logs"));
        (dir, p)
    }

    #[test]
    fn light_needs_nothing() {
        let (_d, p) = paths();
        let r = readiness(
            &DeploymentMode::Light,
            &Settings::default(),
            &p,
            &HardwareProbe::default(),
            false,
        );
        assert!(r.ready);
        assert!(r.checks.is_empty());
    }

    #[test]
    fn a_hardened_mode_without_hardware_is_blocked_not_faked() {
        let (_d, p) = paths();
        let r = readiness(
            &DeploymentMode::Vault,
            &Settings::default(),
            &p,
            &HardwareProbe::default(),
            true,
        );
        assert!(!r.ready);
        let root = r.checks.iter().find(|c| c.id == "root").unwrap();
        assert_eq!(root.state, "blocked");
        assert!(r.checks.iter().any(|c| c.id == "egress"));
        assert!(!r.checks.iter().any(|c| c.id == "fips"));
    }

    #[test]
    fn dark_asks_for_the_custody_declaration() {
        let (_d, p) = paths();
        let r = readiness(
            &DeploymentMode::Dark,
            &Settings::default(),
            &p,
            &HardwareProbe::default(),
            true,
        );
        assert!(r.checks.iter().any(|c| c.id == "fips" && c.state == "todo"));
    }

    #[test]
    fn every_mode_round_trips_through_its_id() {
        for m in MODES {
            let mode = parse_mode(m.id).unwrap();
            assert_eq!(mode_id(&mode), m.id);
            assert_eq!(permits_downloads(&mode), m.egress, "{}", m.id);
        }
    }
}
