//! Attestation Service — Layer 2, §5.3 and §5.4
#![allow(missing_docs)] // PCR index constants are self-describing
//!
//! Generates combined TPM + TEE attestation reports.
//! In production, TPM quotes come from tpm2-tools and TEE quotes from
//! Intel SGX DCAP or AMD SEV-SNP firmware. This implementation provides
//! the service layer that wraps the hardware calls.

use std::collections::HashMap;
use chrono::Utc;
use sha2::{Digest, Sha256};
use parking_lot::Mutex;
use base64::Engine;

use cordon_crypto::attestation::{
    AttestationReport, CombinedAttestation, TeeQuote, TeeType, TpmPcrSet, TpmQuote,
    compute_combined_hash,
};
use crate::config::{CordonConfig, TeePreference};
use crate::error::{CordonError, CordonResult};

/// PCR register allocations per spec §3.2
pub struct PcrAllocations;
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
}

/// Attestation service — manages the attestation lifecycle
pub struct AttestationService {
    config: CordonConfig,
    /// Current simulated PCR values (in production these come from the TPM)
    current_pcrs: Mutex<HashMap<u8, String>>,
    /// Current MRENCLAVE (in production from SGX/SEV hardware)
    mrenclave: Mutex<String>,
    /// Whether attestation has been successfully verified by client
    client_verified: Mutex<bool>,
    /// Last attestation timestamp
    last_attestation: Mutex<Option<chrono::DateTime<Utc>>>,
    /// Backend actually in use: "tpm2" (real PCRs) or "simulation".
    mode: Mutex<String>,
}

impl AttestationService {
    /// Create a new attestation service
    pub fn new(config: CordonConfig) -> Self {
        let service = Self {
            config,
            current_pcrs: Mutex::new(HashMap::new()),
            mrenclave: Mutex::new(String::new()),
            client_verified: Mutex::new(false),
            last_attestation: Mutex::new(None),
            mode: Mutex::new("simulation".to_string()),
        };
        service.initialize_measurements();
        service
    }

    /// The attestation backend actually in use ("tpm2" or "simulation").
    pub fn mode(&self) -> String {
        self.mode.lock().clone()
    }

    /// Initialize PCR measurements and enclave measurement.
    /// In production: reads from TPM hardware and TEE firmware.
    /// Here: derives deterministic values from node configuration.
    fn initialize_measurements(&self) {
        let node_id = &self.config.node_id;
        let deployment_id = &self.config.deployment_id;
        let version = env!("CARGO_PKG_VERSION");

        // Deterministic PCR derivation from node config (simulation)
        // In production: these come from tpm2-tools `tpm2_quote`
        let derive_pcr = |index: u8, input: &str| -> String {
            let mut hasher = Sha256::new();
            hasher.update(format!("PCR[{}]:{}", index, input).as_bytes());
            hasher.update(node_id.as_bytes());
            format!("sha256:{}", hex::encode(hasher.finalize()))
        };

        let mut pcrs = self.current_pcrs.lock();
        pcrs.insert(PcrAllocations::UEFI_FIRMWARE,
            derive_pcr(0, &format!("uefi-firmware-{}", version)));
        pcrs.insert(PcrAllocations::UEFI_CONFIG,
            derive_pcr(1, "uefi-config"));
        pcrs.insert(PcrAllocations::UEFI_DRIVER_CODE,
            derive_pcr(2, "uefi-drivers"));
        pcrs.insert(PcrAllocations::UEFI_DRIVER_CONFIG,
            derive_pcr(3, "uefi-driver-config"));
        pcrs.insert(PcrAllocations::BOOTLOADER_CODE,
            derive_pcr(4, "grub2-bootloader"));
        pcrs.insert(PcrAllocations::BOOTLOADER_CONFIG,
            derive_pcr(5, "grub-config"));
        pcrs.insert(PcrAllocations::SECURE_BOOT_STATE,
            derive_pcr(7, "secure-boot-enabled-client-keys-only"));
        pcrs.insert(PcrAllocations::KERNEL_CMDLINE,
            derive_pcr(8, "kernel-cmdline-hardened"));
        pcrs.insert(PcrAllocations::KERNEL_MODULES,
            derive_pcr(9, "kernel-modules-signed"));
        pcrs.insert(PcrAllocations::CORDON_RUNTIME,
            derive_pcr(11, &format!("cordon-runtime-{}-{}", version, deployment_id)));
        pcrs.insert(PcrAllocations::CORDON_CONFIG,
            derive_pcr(12, &format!("cordon-config-{}", node_id)));
        pcrs.insert(PcrAllocations::MODEL_MANIFEST,
            derive_pcr(13, "no-model-loaded")); // Updated when model loads
        pcrs.insert(PcrAllocations::OPERATOR_AUTH_KEY,
            derive_pcr(14, "operator-auth-key-placeholder"));

        // Real TPM overlay: when the operator opted in (CORDON_TPM=1) and a TPM
        // is reachable, replace the simulated PCR values with real ones read
        // from the hardware via tpm2-tools. Otherwise keep the simulated set.
        if crate::tpm::enabled() {
            let wanted: Vec<u8> = pcrs.keys().copied().collect();
            match crate::tpm::read_pcrs(&wanted) {
                Ok(real) if !real.is_empty() => {
                    for (idx, val) in real {
                        pcrs.insert(idx, val);
                    }
                    *self.mode.lock() = "tpm2".to_string();
                    tracing::info!("Attestation backend: TPM 2.0 (real PCR values)");
                }
                Ok(_) => {
                    tracing::warn!("CORDON_TPM set but tpm2_pcrread returned no PCRs — using simulation");
                }
                Err(e) => {
                    tracing::warn!("CORDON_TPM set but TPM unavailable ({}) — using simulation", e);
                }
            }
        }

        // MRENCLAVE — measurement of the enclave binary
        // In production: Intel SGX MRENCLAVE or AMD SEV SNP measurement
        let mut hasher = Sha256::new();
        hasher.update(b"CORDON_ENCLAVE_v2");
        hasher.update(version.as_bytes());
        hasher.update(node_id.as_bytes());
        *self.mrenclave.lock() = hex::encode(hasher.finalize());
    }

    /// Extend PCR[13] with the model bundle manifest hash
    /// Called when a model bundle is loaded (§5.4 step 4)
    pub fn extend_model_manifest_pcr(&self, manifest_hash: &str) {
        let mut pcrs = self.current_pcrs.lock();
        let current = pcrs.get(&PcrAllocations::MODEL_MANIFEST)
            .cloned()
            .unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(current.as_bytes());
        hasher.update(manifest_hash.as_bytes());
        let new_value = format!("sha256:{}", hex::encode(hasher.finalize()));
        pcrs.insert(PcrAllocations::MODEL_MANIFEST, new_value);
        tracing::info!("PCR[13] extended with model manifest hash");
    }

    /// Generate a combined attestation report for a client-provided nonce
    pub fn generate_attestation(
        &self,
        client_nonce: &str,
        node_id: &str,
    ) -> CordonResult<AttestationReport> {
        let now = Utc::now();

        // Build PCR set
        let pcr_values = {
            let pcrs = self.current_pcrs.lock();
            let mut pcrset = TpmPcrSet::new();
            for (&idx, val) in pcrs.iter() {
                pcrset.set(idx, val.clone());
            }
            pcrset
        };

        let mrenclave = self.mrenclave.lock().clone();

        // Build MRSIGNER (measurement of the signing key for this enclave)
        let mut hasher = Sha256::new();
        hasher.update(b"CORDON_SIGNER_v2");
        hasher.update(node_id.as_bytes());
        let mrsigner = hex::encode(hasher.finalize());

        // Build AIK key (simulated — in production from TPM)
        let aik_key = {
            let mut h = Sha256::new();
            h.update(b"CORDON_AIK_PUBLIC_KEY");
            h.update(node_id.as_bytes());
            hex::encode(h.finalize())
        };

        // Build quote signature (simulated — in production TPM signs with AIK)
        let quote_sig = {
            let mut h = Sha256::new();
            h.update(b"TPM_QUOTE_SIG");
            h.update(client_nonce.as_bytes());
            h.update(aik_key.as_bytes());
            hex::encode(h.finalize())
        };

        // Endorsement key cert chain (simulated)
        let ek_cert = base64::engine::general_purpose::STANDARD
            .encode(format!("SIMULATED_EK_CERT:{}", node_id).as_bytes());

        let tpm_quote = TpmQuote {
            pcr_values,
            aik_public_key_hex: aik_key,
            quote_signature_hex: quote_sig,
            nonce: client_nonce.to_string(),
            timestamp: now,
            ek_cert_chain: vec![ek_cert],
        };

        let tee_type = match self.config.tee.preferred {
            TeePreference::SgxV2 => TeeType::IntelSgxV2,
            TeePreference::AmdSevSnp => TeeType::AmdSevSnp,
            TeePreference::ArmTrustZone => TeeType::ArmTrustZone,
            TeePreference::Simulation => TeeType::Simulation,
        };

        let raw_report = base64::engine::general_purpose::STANDARD
            .encode(format!("CORDON_TEE_REPORT:{}:{}", node_id, mrenclave).as_bytes());
        let report_sig = base64::engine::general_purpose::STANDARD
            .encode(format!("CORDON_TEE_SIG:{}:{}", mrenclave, client_nonce).as_bytes());

        let tee_quote = TeeQuote {
            tee_type,
            mrenclave: mrenclave.clone(),
            mrsigner,
            isv_svn: self.config.tee.minimum_security_version,
            raw_report_b64: raw_report,
            report_signature_b64: report_sig,
        };

        let combined_hash = compute_combined_hash(&tpm_quote, &tee_quote)
            .map_err(|e| CordonError::Internal(e.to_string()))?;

        let combined = CombinedAttestation {
            tpm_quote,
            tee_quote,
            combined_hash,
            node_id: node_id.to_string(),
            cordon_version: env!("CARGO_PKG_VERSION").to_string(),
            generated_at: now,
        };

        let report = AttestationReport {
            combined,
            client_nonce: client_nonce.to_string(),
        };

        *self.last_attestation.lock() = Some(now);

        tracing::info!("Attestation report generated for nonce {}", &client_nonce[..8.min(client_nonce.len())]);
        Ok(report)
    }

    /// Mark attestation as verified by client
    pub fn mark_client_verified(&self) {
        *self.client_verified.lock() = true;
        tracing::info!("Attestation verified by client");
    }

    /// Whether attestation has been client-verified
    pub fn is_client_verified(&self) -> bool {
        *self.client_verified.lock()
    }

    /// Get last attestation time
    pub fn last_attestation_time(&self) -> Option<chrono::DateTime<Utc>> {
        *self.last_attestation.lock()
    }

    /// Get current MRENCLAVE
    pub fn mrenclave(&self) -> String {
        self.mrenclave.lock().clone()
    }

    /// Get current PCR snapshot hash (for health checks)
    pub fn pcr_snapshot_hash(&self) -> String {
        let pcrs = self.current_pcrs.lock();
        let mut sorted: Vec<_> = pcrs.iter().collect();
        sorted.sort_by_key(|(k, _)| *k);
        let mut hasher = Sha256::new();
        for (idx, val) in sorted {
            hasher.update(format!("{}:{}", idx, val).as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    /// Check whether re-attestation is needed based on interval
    pub fn needs_re_attestation(&self) -> bool {
        let last = *self.last_attestation.lock();
        match last {
            None => true,
            Some(t) => {
                let elapsed_hours = (Utc::now() - t).num_hours();
                elapsed_hours >= self.config.tee.re_attestation_interval_hours as i64
            }
        }
    }
}

