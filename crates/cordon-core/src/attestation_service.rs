//! Attestation service (Layer 2).
//!
//! Produces a signed report describing the platform Cordon is running on, and
//! decides whether that report satisfies the measurements the operator pinned at
//! deployment time.
//!
//! # Two measurement sources, and what each one proves
//!
//! * [`MeasurementSource::Tpm2`] reads PCR values from a TPM 2.0 device. The
//!   values describe the boot chain, so a match means the platform booted the
//!   firmware, bootloader, and kernel the operator expects.
//!
//! * [`MeasurementSource::SoftwareMeasurement`] derives values from Cordon's own
//!   build and configuration. This is a **software integrity measurement**: it
//!   proves the node is running the configuration the operator expects, and
//!   nothing whatsoever about the platform underneath it. An attacker with code
//!   execution on the host can reproduce it exactly. It is confined to Light
//!   mode by [`CordonConfig::validate`], and it is reported as
//!   `software_measurement` everywhere so no caller can mistake it for hardware
//!   attestation.
//!
//! # Why expectations are pinned, not supplied
//!
//! Verification compares a report against measurements the **operator** pinned
//! in configuration. It deliberately does not accept expectations from the
//! caller: a node that verifies against caller-supplied values can always be
//! made to verify, since any caller can read the node's own measurements from
//! `GET /v1/attestation` and hand them straight back. Pinning is what makes the
//! check mean anything.

use base64::Engine;
use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::config::{CordonConfig, MeasurementSource, TeePreference};
use crate::error::{CordonError, CordonResult};
use cordon_crypto::attestation::{
    compute_combined_hash, AttestationReport, CombinedAttestation, ExpectedMeasurements, TeeQuote,
    TeeType, TpmPcrSet, TpmQuote,
};

/// PCR register allocations.
pub struct PcrAllocations;

#[allow(missing_docs)] // Each constant is named for the component it measures.
impl PcrAllocations {
    pub const UEFI_FIRMWARE: u8 = 0;
    pub const UEFI_CONFIG: u8 = 1;
    pub const UEFI_DRIVER_CODE: u8 = 2;
    pub const UEFI_DRIVER_CONFIG: u8 = 3;
    pub const BOOTLOADER_CODE: u8 = 4;
    pub const BOOTLOADER_CONFIG: u8 = 5;
    pub const SECURE_BOOT_STATE: u8 = 7;
    pub const KERNEL_CMDLINE: u8 = 8;
    pub const KERNEL_MODULES: u8 = 9;
    pub const CORDON_RUNTIME: u8 = 11;
    pub const CORDON_CONFIG: u8 = 12;
    pub const MODEL_MANIFEST: u8 = 13;
    pub const OPERATOR_AUTH_KEY: u8 = 14;

    /// Every allocated index, in order.
    pub const ALL: &'static [u8] = &[0, 1, 2, 3, 4, 5, 7, 8, 9, 11, 12, 13, 14];
}

/// Record of one client's successful verification.
#[derive(Debug, Clone)]
pub struct VerificationRecord {
    /// The client that verified.
    pub client_id: String,
    /// When it verified.
    pub verified_at: DateTime<Utc>,
    /// Combined hash of the report it accepted.
    pub combined_hash: String,
}

/// Attestation lifecycle manager.
pub struct AttestationService {
    config: CordonConfig,
    /// Platform measurements, by PCR index.
    measurements: RwLock<HashMap<u8, String>>,
    /// Enclave measurement.
    mrenclave: RwLock<String>,
    /// Signer measurement.
    mrsigner: RwLock<String>,
    /// Clients that have verified this node, keyed by client ID. Verification is
    /// per-client rather than a single global flag: one caller accepting a report
    /// says nothing about whether another caller would.
    verified_clients: RwLock<HashMap<String, VerificationRecord>>,
    /// Timestamp of the most recent report generation.
    last_attestation: Mutex<Option<DateTime<Utc>>>,
    /// Measurement source actually in effect after startup probing.
    source: RwLock<MeasurementSource>,
}

impl AttestationService {
    /// Build the service and take the initial measurements.
    ///
    /// When the configuration calls for TPM measurements and no TPM is
    /// reachable, this fails rather than falling back to a software
    /// measurement — a node cannot honour a hardware-attestation claim it has no
    /// hardware to back.
    pub fn new(config: CordonConfig) -> CordonResult<Self> {
        let service = Self {
            source: RwLock::new(config.attestation.measurement_source),
            config,
            measurements: RwLock::new(HashMap::new()),
            mrenclave: RwLock::new(String::new()),
            mrsigner: RwLock::new(String::new()),
            verified_clients: RwLock::new(HashMap::new()),
            last_attestation: Mutex::new(None),
        };
        service.take_measurements()?;
        Ok(service)
    }

    fn take_measurements(&self) -> CordonResult<()> {
        let measurements = match self.config.attestation.measurement_source {
            MeasurementSource::Tpm2 => self.read_tpm_measurements()?,
            MeasurementSource::SoftwareMeasurement => {
                tracing::warn!(
                    "Attestation measurements are derived from configuration, not from \
                     hardware. This attests that Cordon is running the expected \
                     configuration; it attests nothing about the platform. Light mode only."
                );
                self.derive_software_measurements()
            }
        };
        *self.measurements.write() = measurements;

        let version = env!("CARGO_PKG_VERSION");
        let mut hasher = Sha256::new();
        hasher.update(b"CORDON_ENCLAVE_v2");
        hasher.update(version.as_bytes());
        hasher.update(self.config.node_id.as_bytes());
        *self.mrenclave.write() = hex::encode(hasher.finalize());

        let mut hasher = Sha256::new();
        hasher.update(b"CORDON_SIGNER_v2");
        hasher.update(self.config.node_id.as_bytes());
        *self.mrsigner.write() = hex::encode(hasher.finalize());

        Ok(())
    }

    fn read_tpm_measurements(&self) -> CordonResult<HashMap<u8, String>> {
        if !crate::tpm::is_available() {
            return Err(CordonError::AttestationInvalid(format!(
                "attestation.measurement_source is \"tpm2\" but no TPM is reachable. \
                 Cordon will not fall back to a software measurement in {} mode: \
                 doing so would report a hardware guarantee it cannot provide. \
                 Install tpm2-tools and confirm the device, or run in Light mode.",
                self.config.mode
            )));
        }

        let pcrs = crate::tpm::read_pcrs(PcrAllocations::ALL)
            .map_err(|e| CordonError::AttestationInvalid(format!("cannot read TPM PCRs: {}", e)))?;

        if pcrs.is_empty() {
            return Err(CordonError::AttestationInvalid(
                "the TPM returned no PCR values".into(),
            ));
        }

        tracing::info!(pcrs = pcrs.len(), "Platform measurements read from TPM 2.0");
        Ok(pcrs)
    }

    /// Derive measurements from the build and configuration.
    ///
    /// Deterministic for a given node identity and version, so an operator can
    /// pin the values and detect a configuration change. Not a platform
    /// measurement — see the module documentation.
    fn derive_software_measurements(&self) -> HashMap<u8, String> {
        let node_id = &self.config.node_id;
        let deployment_id = &self.config.deployment_id;
        let version = env!("CARGO_PKG_VERSION");

        let derive = |index: u8, input: &str| -> String {
            let mut hasher = Sha256::new();
            hasher.update(b"CORDON_SOFTWARE_MEASUREMENT_v1");
            hasher.update(format!("PCR[{}]:{}", index, input).as_bytes());
            hasher.update(node_id.as_bytes());
            format!("sha256:{}", hex::encode(hasher.finalize()))
        };

        let mut m = HashMap::new();
        m.insert(
            PcrAllocations::CORDON_RUNTIME,
            derive(
                PcrAllocations::CORDON_RUNTIME,
                &format!("cordon-{}-{}", version, deployment_id),
            ),
        );
        m.insert(
            PcrAllocations::CORDON_CONFIG,
            derive(
                PcrAllocations::CORDON_CONFIG,
                &format!(
                    "mode={};tee={}",
                    self.config.mode, self.config.tee.preferred
                ),
            ),
        );
        m.insert(
            PcrAllocations::MODEL_MANIFEST,
            derive(PcrAllocations::MODEL_MANIFEST, "no-model-loaded"),
        );
        m
    }

    /// The measurement source in effect.
    pub fn measurement_source(&self) -> MeasurementSource {
        *self.source.read()
    }

    /// Whether measurements come from hardware.
    pub fn has_hardware_measurements(&self) -> bool {
        self.measurement_source() == MeasurementSource::Tpm2
    }

    /// Extend the model-manifest measurement when a bundle is loaded.
    pub fn extend_model_manifest(&self, manifest_hash: &str) {
        let mut measurements = self.measurements.write();
        let current = measurements
            .get(&PcrAllocations::MODEL_MANIFEST)
            .cloned()
            .unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(current.as_bytes());
        hasher.update(manifest_hash.as_bytes());
        measurements.insert(
            PcrAllocations::MODEL_MANIFEST,
            format!("sha256:{}", hex::encode(hasher.finalize())),
        );
        tracing::info!("Model manifest measurement extended");
    }

    /// Generate a report bound to a client-supplied nonce.
    ///
    /// The nonce is the client's anti-replay guarantee: a report is only fresh
    /// evidence if it commits to a value the client chose.
    pub fn generate_attestation(
        &self,
        client_nonce: &str,
        node_id: &str,
    ) -> CordonResult<AttestationReport> {
        if client_nonce.len() < 16 {
            return Err(CordonError::ValidationFailed(
                "attestation nonce must be at least 16 characters so a report cannot \
                 be replayed against a guessable challenge"
                    .into(),
            ));
        }

        let now = Utc::now();

        let pcr_values = {
            let measurements = self.measurements.read();
            let mut set = TpmPcrSet::new();
            for (&idx, value) in measurements.iter() {
                set.set(idx, value.clone());
            }
            set
        };

        let mrenclave = self.mrenclave.read().clone();
        let mrsigner = self.mrsigner.read().clone();
        let source = self.measurement_source();

        // A TPM-backed report carries a real quote signed by the attestation
        // key; a software measurement carries none, and says so rather than
        // manufacturing a value that resembles one.
        let (aik_public_key_hex, quote_signature_hex, ek_cert_chain) = match source {
            MeasurementSource::Tpm2 => match crate::tpm::quote(client_nonce) {
                Ok(quote) => (
                    quote.aik_public_key_hex,
                    quote.signature_hex,
                    quote.ek_cert_chain,
                ),
                Err(e) => {
                    return Err(CordonError::AttestationInvalid(format!(
                        "TPM quote failed: {}. The node cannot produce a hardware \
                         attestation report.",
                        e
                    )));
                }
            },
            MeasurementSource::SoftwareMeasurement => (
                String::new(),
                String::new(),
                vec![base64::engine::general_purpose::STANDARD
                    .encode(b"NO_HARDWARE_ATTESTATION_KEY")],
            ),
        };

        let tpm_quote = TpmQuote {
            pcr_values,
            aik_public_key_hex,
            quote_signature_hex,
            nonce: client_nonce.to_string(),
            timestamp: now,
            ek_cert_chain,
        };

        let tee_type = match self.config.tee.preferred {
            TeePreference::SgxV2 => TeeType::IntelSgxV2,
            TeePreference::AmdSevSnp => TeeType::AmdSevSnp,
            TeePreference::ArmTrustZone => TeeType::ArmTrustZone,
            TeePreference::Simulation => TeeType::Simulation,
        };

        let tee_quote = TeeQuote {
            tee_type,
            mrenclave: mrenclave.clone(),
            mrsigner,
            isv_svn: self.config.tee.minimum_security_version,
            raw_report_b64: base64::engine::general_purpose::STANDARD.encode(format!(
                "CORDON_MEASUREMENT_REPORT:{}:{}",
                node_id, mrenclave
            )),
            report_signature_b64: String::new(),
            measurement_source: source.to_string(),
        };

        let combined_hash = compute_combined_hash(&tpm_quote, &tee_quote)
            .map_err(|e| CordonError::Internal(e.to_string()))?;

        let report = AttestationReport {
            combined: CombinedAttestation {
                tpm_quote,
                tee_quote,
                combined_hash,
                node_id: node_id.to_string(),
                cordon_version: env!("CARGO_PKG_VERSION").to_string(),
                generated_at: now,
            },
            client_nonce: client_nonce.to_string(),
        };

        *self.last_attestation.lock() = Some(now);
        Ok(report)
    }

    /// The measurements this node checks a report against, as pinned by the
    /// operator. `None` when nothing is pinned, which makes verification
    /// impossible rather than automatic.
    pub fn pinned_measurements(&self) -> Option<ExpectedMeasurements> {
        let pinned = self.config.attestation.expected.as_ref()?;
        if pinned.is_empty() {
            return None;
        }

        let mut pcr_values = TpmPcrSet::new();
        for (&idx, value) in &pinned.pcr_values {
            pcr_values.set(idx, value.clone());
        }

        Some(ExpectedMeasurements {
            pcr_values,
            mrenclave: pinned.mrenclave.clone().unwrap_or_default(),
            mrsigner: pinned.mrsigner.clone().unwrap_or_default(),
            min_isv_svn: pinned.min_isv_svn,
            tee_type: match self.config.tee.preferred {
                TeePreference::SgxV2 => TeeType::IntelSgxV2,
                TeePreference::AmdSevSnp => TeeType::AmdSevSnp,
                TeePreference::ArmTrustZone => TeeType::ArmTrustZone,
                TeePreference::Simulation => TeeType::Simulation,
            },
        })
    }

    /// Verify a report against the operator-pinned measurements and, on success,
    /// record that `client_id` has attested this node.
    pub fn verify_for_client(
        &self,
        report: &AttestationReport,
        client_nonce: &str,
        client_id: &str,
    ) -> CordonResult<()> {
        let expected = self.pinned_measurements().ok_or_else(|| {
            CordonError::AttestationInvalid(
                "this node has no pinned expected measurements, so an attestation \
                 report cannot be verified against anything. Pin them under \
                 [attestation.expected] — capture the current values with \
                 `cordon attest --pin`."
                    .into(),
            )
        })?;

        report
            .verify(&expected, client_nonce)
            .map_err(|e| CordonError::AttestationInvalid(e.to_string()))?;

        self.verified_clients.write().insert(
            client_id.to_string(),
            VerificationRecord {
                client_id: client_id.to_string(),
                verified_at: Utc::now(),
                combined_hash: report.combined.combined_hash.clone(),
            },
        );
        tracing::info!(client_id, "Attestation verified by client");
        Ok(())
    }

    /// Whether `client_id` has verified this node within the re-attestation
    /// interval.
    pub fn is_verified_by(&self, client_id: &str) -> bool {
        let interval = chrono::Duration::hours(self.config.attestation.interval_hours as i64);
        self.verified_clients
            .read()
            .get(client_id)
            .map(|r| Utc::now() - r.verified_at < interval)
            .unwrap_or(false)
    }

    /// Whether any client has verified this node recently.
    pub fn is_verified_by_anyone(&self) -> bool {
        let interval = chrono::Duration::hours(self.config.attestation.interval_hours as i64);
        let now = Utc::now();
        self.verified_clients
            .read()
            .values()
            .any(|r| now - r.verified_at < interval)
    }

    /// Drop verification records that have aged past the re-attestation
    /// interval, forcing those clients to attest again.
    pub fn expire_stale_verifications(&self) -> usize {
        let interval = chrono::Duration::hours(self.config.attestation.interval_hours as i64);
        let now = Utc::now();
        let mut clients = self.verified_clients.write();
        let before = clients.len();
        clients.retain(|_, r| now - r.verified_at < interval);
        before - clients.len()
    }

    /// Timestamp of the most recent report generation.
    pub fn last_attestation_time(&self) -> Option<DateTime<Utc>> {
        *self.last_attestation.lock()
    }

    /// The current enclave measurement.
    pub fn mrenclave(&self) -> String {
        self.mrenclave.read().clone()
    }

    /// The current signer measurement.
    pub fn mrsigner(&self) -> String {
        self.mrsigner.read().clone()
    }

    /// A digest over every current measurement, for health output.
    pub fn measurement_snapshot_hash(&self) -> String {
        let measurements = self.measurements.read();
        let mut sorted: Vec<_> = measurements.iter().collect();
        sorted.sort_by_key(|(k, _)| *k);
        let mut hasher = Sha256::new();
        for (idx, value) in sorted {
            hasher.update(format!("{}:{}", idx, value).as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    /// The current measurements, for `cordon attest --pin`.
    pub fn current_measurements(&self) -> HashMap<u8, String> {
        self.measurements.read().clone()
    }

    /// Number of clients holding a live verification.
    pub fn verified_client_count(&self) -> usize {
        self.expire_stale_verifications();
        self.verified_clients.read().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ExpectedMeasurementsConfig;

    fn service_with(expected: Option<ExpectedMeasurementsConfig>) -> AttestationService {
        let mut config = CordonConfig::default_light("node-1".into(), "deployment-1".into());
        config.attestation.measurement_source = MeasurementSource::SoftwareMeasurement;
        config.attestation.expected = expected;
        AttestationService::new(config).unwrap()
    }

    fn nonce() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    #[test]
    fn software_measurements_are_labelled_as_such() {
        let service = service_with(None);
        assert_eq!(
            service.measurement_source(),
            MeasurementSource::SoftwareMeasurement
        );
        assert!(!service.has_hardware_measurements());

        let report = service.generate_attestation(&nonce(), "node-1").unwrap();
        assert_eq!(
            report.combined.tee_quote.measurement_source,
            "software_measurement"
        );
        // No hardware key means no fabricated quote signature.
        assert!(report.combined.tpm_quote.quote_signature_hex.is_empty());
        assert!(report.combined.tpm_quote.aik_public_key_hex.is_empty());
    }

    #[test]
    fn short_nonces_are_refused() {
        let service = service_with(None);
        assert!(service.generate_attestation("short", "node-1").is_err());
    }

    /// The bypass this design exists to prevent: read the node's own
    /// measurements, hand them back, and be marked verified.
    #[test]
    fn a_node_without_pinned_measurements_cannot_be_verified() {
        let service = service_with(None);
        let n = nonce();
        let report = service.generate_attestation(&n, "node-1").unwrap();

        let err = service
            .verify_for_client(&report, &n, "attacker")
            .unwrap_err()
            .to_string();
        assert!(err.contains("pinned"), "unexpected error: {}", err);
        assert!(!service.is_verified_by("attacker"));
        assert!(!service.is_verified_by_anyone());
    }

    #[test]
    fn an_empty_pin_set_is_not_a_pin_set() {
        let service = service_with(Some(ExpectedMeasurementsConfig::default()));
        assert!(service.pinned_measurements().is_none());
    }

    #[test]
    fn verification_succeeds_against_matching_pins() {
        let mut config = CordonConfig::default_light("node-1".into(), "deployment-1".into());
        config.attestation.measurement_source = MeasurementSource::SoftwareMeasurement;
        let probe = AttestationService::new(config.clone()).unwrap();

        config.attestation.expected = Some(ExpectedMeasurementsConfig {
            pcr_values: probe.current_measurements(),
            mrenclave: Some(probe.mrenclave()),
            mrsigner: Some(probe.mrsigner()),
            min_isv_svn: 0,
        });
        let service = AttestationService::new(config).unwrap();

        let n = nonce();
        let report = service.generate_attestation(&n, "node-1").unwrap();
        service.verify_for_client(&report, &n, "alice").unwrap();
        assert!(service.is_verified_by("alice"));
        // Verification is per-client: Alice's success is not Bob's.
        assert!(!service.is_verified_by("bob"));
    }

    #[test]
    fn verification_fails_against_mismatched_pins() {
        let service = service_with(Some(ExpectedMeasurementsConfig {
            mrenclave: Some("f".repeat(64)),
            ..ExpectedMeasurementsConfig::default()
        }));
        let n = nonce();
        let report = service.generate_attestation(&n, "node-1").unwrap();
        assert!(service.verify_for_client(&report, &n, "alice").is_err());
        assert!(!service.is_verified_by("alice"));
    }

    #[test]
    fn a_report_bound_to_a_different_nonce_is_rejected() {
        let mut config = CordonConfig::default_light("node-1".into(), "deployment-1".into());
        config.attestation.measurement_source = MeasurementSource::SoftwareMeasurement;
        let probe = AttestationService::new(config.clone()).unwrap();
        config.attestation.expected = Some(ExpectedMeasurementsConfig {
            pcr_values: probe.current_measurements(),
            mrenclave: Some(probe.mrenclave()),
            mrsigner: Some(probe.mrsigner()),
            min_isv_svn: 0,
        });
        let service = AttestationService::new(config).unwrap();

        let report = service.generate_attestation(&nonce(), "node-1").unwrap();
        assert!(service
            .verify_for_client(&report, &nonce(), "alice")
            .is_err());
    }

    #[test]
    fn tpm_source_without_a_tpm_fails_closed() {
        let mut config = CordonConfig::default_light("node-1".into(), "deployment-1".into());
        config.attestation.measurement_source = MeasurementSource::Tpm2;
        // No TPM is present in CI, so construction must fail rather than
        // silently produce software measurements under a hardware label.
        if !crate::tpm::is_available() {
            assert!(AttestationService::new(config).is_err());
        }
    }
}
