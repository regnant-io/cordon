//! Attestation report types and the client-side verifier.
//!
//! A report is produced by a node and checked by someone who does not trust
//! that node. Everything here is arranged around that asymmetry.
//!
//! # What verification establishes, and what it does not
//!
//! [`AttestationReport::verify`] returns a [`VerifiedAttestation`] rather than a
//! bare `bool`, because "verified" is not one property. Three separate things
//! can be true or false, and collapsing them loses exactly the distinctions a
//! careful operator needs:
//!
//! * **The measurements match what the operator pinned.** Always established
//!   when `verify` returns `Ok`; a mismatch is an error.
//! * **A hardware quote was verified.** The platform signed a structure
//!   committing to those measurements and to the verifier's own challenge. On a
//!   software measurement there is no quote at all, and the result says so
//!   rather than implying one passed.
//! * **The quote binds the node's response-signing key.** See below. Without
//!   this, a valid quote proves something about a machine, and the signature on
//!   your inference response proves something about a key, and nothing connects
//!   the two.
//!
//! # Binding the signing key
//!
//! A TPM quote commits to a
//! caller-supplied `extraData` field. Cordon puts
//! [`attestation_challenge`] there: a digest over the node's response-signing
//! public key *and* the verifier's nonce.
//!
//! That single field is what turns two unrelated facts into one useful one. A
//! quote over a nonce alone proves the platform is live and in a known state.
//! A response signature proves some key signed your output. Only when the
//! platform's own signature commits to that key can you conclude that the key
//! signing your inference lives on the platform you just attested, which is
//! the whole claim a confidential inference node is making.
//!
//! # Canonical encoding
//!
//! Digests a verifier must recompute are built with
//! [`crate::canonical::CanonicalWriter`], not `serde_json`. The reasons are in
//! that module; the short version is that `serde_json` over a `HashMap` is not
//! reproducible, and this verifier used to fail on genuine reports because of
//! it.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::canonical::CanonicalWriter;
use crate::error::{CryptoError, CryptoResult};
use crate::kdf::ct_eq;

/// Domain separator for the value placed in a quote's `extraData`.
const CHALLENGE_DOMAIN: &[u8] = b"CORDON_ATTEST_CHALLENGE_v1";

/// TPM Platform Configuration Register (PCR) snapshot.
///
/// Backed by a `BTreeMap` rather than a `HashMap` so iteration is in ascending
/// index order everywhere: in the canonical encoding, in serialized JSON, and
/// in anything a verifier recomputes. With a `HashMap` the order was randomised
/// per instance, and a client that deserialized a report computed a different
/// digest from the one the node computed over the very same values.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TpmPcrSet {
    /// PCR index to SHA-256 value, conventionally `"sha256:<hex>"`.
    pub values: BTreeMap<u8, String>,
}

impl TpmPcrSet {
    /// Create an empty PCR set.
    pub fn new() -> Self {
        Self {
            values: BTreeMap::new(),
        }
    }

    /// Set a PCR value.
    pub fn set(&mut self, index: u8, value: String) {
        self.values.insert(index, value);
    }

    /// Get a PCR value.
    pub fn get(&self, index: u8) -> Option<&str> {
        self.values.get(&index).map(|s| s.as_str())
    }

    /// Whether any PCR is recorded.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Every (index, value) pair, ascending by index.
    pub fn entries(&self) -> impl Iterator<Item = (u8, &str)> {
        self.values.iter().map(|(k, v)| (*k, v.as_str()))
    }

    /// The raw PCR bytes, ascending by index, for recomputing a quote digest.
    ///
    /// Values are stored as `"sha256:<hex>"`; the prefix is dropped and the hex
    /// decoded. A value that is not decodable is skipped, which will make the
    /// recomputed digest disagree, the right outcome for a malformed report.
    pub fn raw_values_in_index_order(&self) -> Vec<(u8, Vec<u8>)> {
        self.values
            .iter()
            .filter_map(|(index, value)| {
                let hex_part = value.strip_prefix("sha256:").unwrap_or(value);
                hex::decode(hex_part).ok().map(|bytes| (*index, bytes))
            })
            .collect()
    }

    /// Verify this PCR set matches expected values.
    pub fn verify_against(&self, expected: &TpmPcrSet) -> CryptoResult<()> {
        for (index, expected_val) in &expected.values {
            let actual = self.get(*index).ok_or_else(|| {
                CryptoError::AttestationFailed(format!(
                    "PCR[{}] missing from attestation report",
                    index
                ))
            })?;
            if !ct_eq(actual.as_bytes(), expected_val.as_bytes()) {
                return Err(CryptoError::PcrMismatch {
                    index: *index,
                    expected: expected_val.clone(),
                    actual: actual.to_string(),
                });
            }
        }
        Ok(())
    }

    /// Canonical bytes for this PCR set.
    fn canonical(&self) -> CanonicalWriter {
        let mut writer = CanonicalWriter::new("pcr_set");
        writer.write_u32(self.values.len() as u32);
        for (index, value) in &self.values {
            writer.write_u8(*index).write_str(value);
        }
        writer
    }
}

/// TPM quote, a signed snapshot of PCR values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmQuote {
    /// PCR values at the time of the quote.
    pub pcr_values: TpmPcrSet,
    /// Attestation key public area (`TPMT_PUBLIC`), hex encoded.
    pub aik_public_key_hex: String,
    /// The `TPMS_ATTEST` structure the TPM signed, hex encoded.
    ///
    /// Without this a verifier has a signature and nothing to check it against,
    /// no way to confirm the quote answers their challenge, and no way to bind
    /// the PCR values above to the signature. Empty on a software measurement,
    /// where no TPM produced anything.
    #[serde(default)]
    pub attest_message_hex: String,
    /// The `TPMT_SIGNATURE` over `attest_message_hex`, hex encoded.
    pub quote_signature_hex: String,
    /// The challenge this quote answers; see [`attestation_challenge`].
    pub nonce: String,
    /// When the quote was taken.
    pub timestamp: DateTime<Utc>,
    /// TPM endorsement key certificate chain, base64 DER.
    pub ek_cert_chain: Vec<String>,
}

impl TpmQuote {
    /// Whether this quote carries hardware evidence that can be checked.
    pub fn has_hardware_evidence(&self) -> bool {
        !self.attest_message_hex.is_empty()
            && !self.quote_signature_hex.is_empty()
            && !self.aik_public_key_hex.is_empty()
    }

    fn canonical(&self) -> CanonicalWriter {
        let mut writer = CanonicalWriter::new("tpm_quote");
        writer
            .write_section(&self.pcr_values.canonical())
            .write_str(&self.aik_public_key_hex)
            .write_str(&self.attest_message_hex)
            .write_str(&self.quote_signature_hex)
            .write_str(&self.nonce)
            .write_i64(self.timestamp.timestamp_millis())
            .write_u32(self.ek_cert_chain.len() as u32);
        for cert in &self.ek_cert_chain {
            writer.write_str(cert);
        }
        writer
    }
}

/// TEE measurement, an enclave measurement from hardware, or a software
/// measurement clearly labelled as such.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeQuote {
    /// TEE type.
    pub tee_type: TeeType,
    /// MRENCLAVE; measurement of code and data loaded into the enclave.
    pub mrenclave: String,
    /// MRSIGNER; measurement of the enclave's signer.
    pub mrsigner: String,
    /// ISV SVN (security version number).
    pub isv_svn: u16,
    /// Raw TEE attestation report, base64.
    pub raw_report_b64: String,
    /// Hardware signature over the report (AMD SP or Intel DCAP). Empty when no
    /// hardware signer produced it.
    pub report_signature_b64: String,
    /// Where the measurements came from: `tpm2` for values read from a TPM,
    /// `software_measurement` for a digest of Cordon's own build and
    /// configuration. A verifier must treat the latter as evidence about
    /// software only; it says nothing about the platform.
    #[serde(default = "unknown_measurement_source")]
    pub measurement_source: String,
    /// The node's response-signing public key, hex encoded.
    ///
    /// This is the key the platform quote commits to. A verifier that checks
    /// the quote learns that *this* key was resident on the attested platform,
    /// which is what connects an attestation to the signature on an inference
    /// response.
    #[serde(default)]
    pub enclave_signing_key_hex: String,
}

fn unknown_measurement_source() -> String {
    "unknown".to_string()
}

impl TeeQuote {
    fn canonical(&self) -> CanonicalWriter {
        let mut writer = CanonicalWriter::new("tee_quote");
        writer
            .write_str(&self.tee_type.to_string())
            .write_str(&self.mrenclave)
            .write_str(&self.mrsigner)
            .write_u16(self.isv_svn)
            .write_str(&self.raw_report_b64)
            .write_str(&self.report_signature_b64)
            .write_str(&self.measurement_source)
            .write_str(&self.enclave_signing_key_hex);
        writer
    }
}

/// TEE technology type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeeType {
    /// Intel SGX v2.
    IntelSgxV2,
    /// AMD SEV-SNP.
    AmdSevSnp,
    /// ARM TrustZone.
    ArmTrustZone,
    /// Software simulation, not for production.
    #[default]
    Simulation,
}

impl std::fmt::Display for TeeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TeeType::IntelSgxV2 => write!(f, "intel_sgx_v2"),
            TeeType::AmdSevSnp => write!(f, "amd_sev_snp"),
            TeeType::ArmTrustZone => write!(f, "arm_trustzone"),
            TeeType::Simulation => write!(f, "simulation"),
        }
    }
}

/// Hardware evidence from a confidential-computing platform.
///
/// Kept separate from [`TpmQuote`] because the two answer different questions.
/// A TPM attests how a machine booted; the operator still owns the machine
/// afterwards. A confidential VM's report attests a running guest whose memory
/// the operator cannot read, which is the property Cordon's threat model
/// otherwise has to say it does not have.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlatformEvidence {
    /// No confidential-VM evidence. Any hardware claim rests on
    /// [`CombinedAttestation::tpm_quote`].
    #[default]
    None,
    /// AMD SEV-SNP.
    SevSnp {
        /// The raw 1184-byte attestation report, base64.
        report_b64: String,
        /// The chip's VCEK certificate, base64 DER.
        vcek_der_b64: String,
        /// Intermediates between the VCEK and the root, leaf-ward first,
        /// base64 DER. The root itself is pinned by the verifier, not carried
        /// here, a chain that shipped its own root would prove nothing.
        certificate_chain_b64: Vec<String>,
    },
    /// AWS Nitro Enclaves.
    ///
    /// One field, because a Nitro attestation document is self-contained: the
    /// COSE_Sign1 envelope carries the leaf certificate and the certificate
    /// bundle inside the signed payload. The bundle includes AWS's own copy of
    /// the root, which the verifier ignores in favour of the one the operator
    /// pinned; see [`crate::nitro::NitroExpectations::root_der`].
    Nitro {
        /// The attestation document, base64 COSE_Sign1.
        document_b64: String,
    },
}

impl PlatformEvidence {
    /// A short name for logs and health output.
    pub fn kind(&self) -> &'static str {
        match self {
            PlatformEvidence::None => "none",
            PlatformEvidence::SevSnp { .. } => "amd_sev_snp",
            PlatformEvidence::Nitro { .. } => "aws_nitro_enclaves",
        }
    }

    fn canonical(&self) -> CanonicalWriter {
        let mut writer = CanonicalWriter::new("platform_evidence");
        writer.write_str(self.kind());
        match self {
            PlatformEvidence::None => {}
            PlatformEvidence::SevSnp {
                report_b64,
                vcek_der_b64,
                certificate_chain_b64,
            } => {
                writer
                    .write_str(report_b64)
                    .write_str(vcek_der_b64)
                    .write_u32(certificate_chain_b64.len() as u32);
                for cert in certificate_chain_b64 {
                    writer.write_str(cert);
                }
            }
            PlatformEvidence::Nitro { document_b64 } => {
                writer.write_str(document_b64);
            }
        }
        writer
    }
}

/// Measurements and policy an operator pins for a SEV-SNP deployment.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SevSnpPins {
    /// The AMD root key certificate, base64 DER.
    ///
    /// Pinned by the verifier rather than taken from the report: a chain is
    /// only worth walking if its root is one you already trust.
    pub amd_root_der_b64: String,
    /// Minimum acceptable bootloader SVN.
    #[serde(default)]
    pub min_bootloader_svn: u8,
    /// Minimum acceptable TEE SVN.
    #[serde(default)]
    pub min_tee_svn: u8,
    /// Minimum acceptable SNP firmware SVN.
    #[serde(default)]
    pub min_snp_svn: u8,
    /// Minimum acceptable microcode SVN.
    #[serde(default)]
    pub min_microcode_svn: u8,
    /// Refuse a guest whose launch policy permits debugging. Defaults to true
    /// through [`Self::secure_defaults`]; a debuggable guest's memory is
    /// readable by the hypervisor, which nullifies the arrangement.
    #[serde(default = "default_true")]
    pub refuse_debuggable_guest: bool,
    /// The VMPL the report must have been produced at. Cordon runs at 0.
    #[serde(default)]
    pub expected_vmpl: u32,
}

fn default_true() -> bool {
    true
}

impl SevSnpPins {
    /// Pins with the safe defaults, given a root certificate.
    pub fn secure_defaults(amd_root_der_b64: String) -> Self {
        Self {
            amd_root_der_b64,
            refuse_debuggable_guest: true,
            ..Self::default()
        }
    }
}

/// Measurements an operator pins for an AWS Nitro Enclaves deployment.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NitroPins {
    /// The AWS Nitro Enclaves root CA, base64 DER.
    ///
    /// Pinned by the verifier rather than read from the document's own
    /// `cabundle`, for the same reason the AMD root is: a document that
    /// supplies its own root proves only that its author owns a key.
    pub root_der_b64: String,
    /// Expected PCR values, lowercase hex, by index.
    ///
    /// PCR0 measures the enclave image, PCR1 the kernel and bootstrap, PCR2 the
    /// application. Pin at least PCR0. PCR4 is the parent instance ID and PCR3
    /// the IAM role, which tie a deployment to one machine or one role; pin
    /// those only if that is what you mean.
    #[serde(default)]
    pub pcr_values: std::collections::BTreeMap<u8, String>,
    /// How stale a document may be, in seconds. Zero disables the check; the
    /// nonce remains the primary defence against replay.
    #[serde(default = "default_nitro_max_age")]
    pub max_age_seconds: u64,
}

fn default_nitro_max_age() -> u64 {
    300
}

impl NitroPins {
    /// Pins with the safe defaults, given a root certificate.
    pub fn secure_defaults(root_der_b64: String) -> Self {
        Self {
            root_der_b64,
            pcr_values: std::collections::BTreeMap::new(),
            max_age_seconds: default_nitro_max_age(),
        }
    }
}

/// Combined attestation report; measurements plus whatever hardware evidence
/// the platform can produce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinedAttestation {
    /// TPM quote. Carries PCR measurements, and on a TPM platform the signed
    /// quote over them.
    pub tpm_quote: TpmQuote,
    /// TEE measurement.
    pub tee_quote: TeeQuote,
    /// Confidential-VM evidence, when the platform is one.
    #[serde(default)]
    pub platform_evidence: PlatformEvidence,
    /// Canonical digest over the report's contents; see
    /// [`compute_combined_hash`].
    pub combined_hash: String,
    /// Cordon node ID.
    pub node_id: String,
    /// Cordon version.
    pub cordon_version: String,
    /// When the report was generated.
    pub generated_at: DateTime<Utc>,
}

/// Measurements pinned at deployment time that a report must satisfy.
///
/// An empty field means "not pinned" and is skipped during verification. An
/// expectation set that pins nothing at all is rejected outright by
/// [`AttestationReport::verify`], because it would accept every report.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExpectedMeasurements {
    /// Expected PCR values.
    pub pcr_values: TpmPcrSet,
    /// Expected MRENCLAVE value.
    pub mrenclave: String,
    /// Expected MRSIGNER value.
    pub mrsigner: String,
    /// Minimum ISV SVN.
    pub min_isv_svn: u16,
    /// Accepted TEE type.
    pub tee_type: TeeType,
    /// Pins for a SEV-SNP platform. `None` means a SEV-SNP report cannot be
    /// verified, there is no root to chain to, and such a report is refused
    /// rather than accepted on its measurements alone.
    #[serde(default)]
    pub sev_snp: Option<SevSnpPins>,
    /// Pins for an AWS Nitro Enclaves platform. `None` means a Nitro document
    /// cannot be verified, there is no root to chain to, and such a document
    /// is refused rather than accepted on its measurements alone.
    #[serde(default)]
    pub nitro: Option<NitroPins>,
}

impl ExpectedMeasurements {
    /// Whether this expectation set pins any measurement at all.
    ///
    /// Nitro deployments pin PCRs under [`NitroPins::pcr_values`] rather than
    /// in [`Self::pcr_values`], which holds TPM PCRs. Leaving the Nitro pins
    /// out of this check would make a fully-pinned Nitro configuration look
    /// empty and be refused.
    pub fn is_empty(&self) -> bool {
        let nitro_pins_nothing = self
            .nitro
            .as_ref()
            .map_or(true, |pins| pins.pcr_values.is_empty());
        self.pcr_values.is_empty()
            && self.mrenclave.is_empty()
            && self.mrsigner.is_empty()
            && nitro_pins_nothing
    }
}

/// What a platform quote established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformQuoteStatus {
    /// No hardware quote was present. The report rests on a software
    /// measurement, which attests configuration and nothing about the platform.
    Absent,
    /// A hardware quote was present and every check passed.
    Verified {
        /// Whether the attestation key was itself shown to belong to genuine
        /// hardware by a certificate chain to a vendor root. Not yet
        /// implemented, so this is `false` even on a fully verified quote, the
        /// quote proves the holder of the AK produced it, not that the AK is a
        /// real TPM's.
        ak_is_trusted: bool,
    },
}

impl PlatformQuoteStatus {
    /// Whether a hardware quote was present and verified.
    pub fn is_hardware_verified(&self) -> bool {
        matches!(self, PlatformQuoteStatus::Verified { .. })
    }
}

/// What verifying a report established.
///
/// Deliberately not a `bool`. A caller that needs "the measurements matched"
/// and a caller that needs "the platform signed a quote binding my challenge to
/// this node's signing key" are asking different questions, and a single flag
/// would answer the weaker one while appearing to answer the stronger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    /// What the platform quote established.
    pub platform_quote: PlatformQuoteStatus,
    /// Whether the quote committed to the node's response-signing key, so that
    /// signatures from that key are attributable to the attested platform.
    pub binds_signing_key: bool,
    /// The measurement source the report declared.
    pub measurement_source: String,
}

impl VerifiedAttestation {
    /// Whether this amounts to a hardware root of trust: a verified platform
    /// quote that also commits to the key signing this node's responses.
    ///
    /// Anything less is worth having and is not this.
    pub fn is_hardware_rooted(&self) -> bool {
        self.platform_quote.is_hardware_verified() && self.binds_signing_key
    }
}

/// Attestation report for client verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    /// The combined attestation data.
    pub combined: CombinedAttestation,
    /// The nonce the client issued, for anti-replay verification.
    pub client_nonce: String,
}

impl AttestationReport {
    /// Verify this report against operator-pinned measurements.
    ///
    /// Returns what was established. An error means the report is unusable: the
    /// expectations pin nothing, a measurement disagreed, the report's own
    /// digest does not match its contents, or a hardware quote was present and
    /// failed a check. A report that carries no hardware quote is not an error;
    /// it is a software measurement, and the returned
    /// [`PlatformQuoteStatus::Absent`] says so.
    pub fn verify(
        &self,
        expected: &ExpectedMeasurements,
        client_nonce: &str,
    ) -> CryptoResult<VerifiedAttestation> {
        // 0. Refuse an expectation set that pins nothing. Every subsequent check
        //    would pass vacuously, so an unpinned verifier would accept any
        //    report at all; including one from an impostor.
        if expected.is_empty() {
            return Err(CryptoError::AttestationFailed(
                "no measurements are pinned, so this report cannot be verified against \
                 anything"
                    .into(),
            ));
        }

        // 1. The report's digest must match its own contents, so nothing was
        //    altered between the node and here.
        self.verify_combined_hash()?;

        // 2. The report must answer the challenge this verifier issued.
        if !ct_eq(
            self.combined.tpm_quote.nonce.as_bytes(),
            client_nonce.as_bytes(),
        ) {
            return Err(CryptoError::NonceMismatch);
        }

        // 3. Measurements against what the operator pinned.
        self.combined
            .tpm_quote
            .pcr_values
            .verify_against(&expected.pcr_values)?;

        // An empty expectation means the operator did not pin this measurement,
        // not that any value satisfies it; the "something was pinned" check
        // above is what prevents an entirely empty expectation set from
        // verifying trivially.
        if !expected.mrenclave.is_empty()
            && !ct_eq(
                self.combined.tee_quote.mrenclave.as_bytes(),
                expected.mrenclave.as_bytes(),
            )
        {
            return Err(CryptoError::EnclaveMeasurementMismatch {
                expected: expected.mrenclave.clone(),
                actual: self.combined.tee_quote.mrenclave.clone(),
            });
        }

        if !expected.mrsigner.is_empty()
            && !ct_eq(
                self.combined.tee_quote.mrsigner.as_bytes(),
                expected.mrsigner.as_bytes(),
            )
        {
            return Err(CryptoError::AttestationFailed(format!(
                "MRSIGNER mismatch: expected {}, got {}",
                expected.mrsigner, self.combined.tee_quote.mrsigner
            )));
        }

        if self.combined.tee_quote.isv_svn < expected.min_isv_svn {
            return Err(CryptoError::AttestationFailed(format!(
                "ISV SVN {} is below the minimum {}",
                self.combined.tee_quote.isv_svn, expected.min_isv_svn
            )));
        }

        if self.combined.tee_quote.tee_type != expected.tee_type {
            return Err(CryptoError::AttestationFailed(format!(
                "TEE type mismatch: expected {}, got {}",
                expected.tee_type, self.combined.tee_quote.tee_type
            )));
        }

        // 4. The platform quote, when there is one.
        let (platform_quote, binds_signing_key) =
            self.verify_platform_quote(expected, client_nonce)?;

        Ok(VerifiedAttestation {
            platform_quote,
            binds_signing_key,
            measurement_source: self.combined.tee_quote.measurement_source.clone(),
        })
    }

    /// Check whatever hardware evidence the report carries.
    ///
    /// Confidential-VM evidence takes precedence: on a platform that has it,
    /// it is the stronger claim, and a report that carries it should stand or
    /// fall on it rather than on a TPM quote alongside.
    fn verify_platform_quote(
        &self,
        expected: &ExpectedMeasurements,
        client_nonce: &str,
    ) -> CryptoResult<(PlatformQuoteStatus, bool)> {
        if !matches!(self.combined.platform_evidence, PlatformEvidence::None) {
            return self.verify_confidential_vm_evidence(expected, client_nonce);
        }
        self.verify_tpm_quote(client_nonce)
    }

    /// Check a confidential-VM report.
    fn verify_confidential_vm_evidence(
        &self,
        expected: &ExpectedMeasurements,
        client_nonce: &str,
    ) -> CryptoResult<(PlatformQuoteStatus, bool)> {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

        let (report_b64, vcek_der_b64, certificate_chain_b64) =
            match &self.combined.platform_evidence {
                PlatformEvidence::SevSnp {
                    report_b64,
                    vcek_der_b64,
                    certificate_chain_b64,
                } => (report_b64, vcek_der_b64, certificate_chain_b64),
                PlatformEvidence::Nitro { document_b64 } => {
                    return self.verify_nitro_evidence(expected, client_nonce, document_b64);
                }
                PlatformEvidence::None => return Ok((PlatformQuoteStatus::Absent, false)),
            };

        let pins = expected.sev_snp.as_ref().ok_or_else(|| {
            CryptoError::AttestationFailed(
                "this report carries SEV-SNP evidence, but no AMD root certificate is \
                 pinned to check it against. A chain is only worth walking if its root \
                 is one you already trust; pin it under [attestation.expected.sev_snp]."
                    .into(),
            )
        })?;

        let decode = |what: &str, value: &str| -> CryptoResult<Vec<u8>> {
            B64.decode(value)
                .map_err(|e| CryptoError::AttestationFailed(format!("malformed {}: {}", what, e)))
        };

        let report_bytes = decode("SEV-SNP report", report_b64)?;
        let vcek_der = decode("VCEK certificate", vcek_der_b64)?;
        let root_der = decode("pinned AMD root certificate", &pins.amd_root_der_b64)?;

        let mut chain: Vec<Vec<u8>> = Vec::with_capacity(certificate_chain_b64.len() + 1);
        for cert in certificate_chain_b64 {
            chain.push(decode("certificate in the VCEK chain", cert)?);
        }
        // The root the *verifier* pinned terminates the chain, never one the
        // report supplied.
        chain.push(root_der);
        let chain_refs: Vec<&[u8]> = chain.iter().map(|c| c.as_slice()).collect();

        let expectations = crate::sev_snp::SevSnpExpectations {
            measurement: expected.mrenclave.clone(),
            minimum_tcb: crate::sev_snp::TcbVersion {
                bootloader: pins.min_bootloader_svn,
                tee: pins.min_tee_svn,
                snp: pins.min_snp_svn,
                microcode: pins.min_microcode_svn,
                raw: 0,
            },
            refuse_debuggable_guest: pins.refuse_debuggable_guest,
            expected_vmpl: pins.expected_vmpl,
        };

        let challenge = confidential_vm_challenge(
            &self.combined.tee_quote.enclave_signing_key_hex,
            client_nonce,
        );

        let (_report, verification) = crate::sev_snp::verify_report(
            &report_bytes,
            &vcek_der,
            &chain_refs,
            &challenge,
            &expectations,
        )?;

        if let Some(failure) = verification.first_failure() {
            return Err(CryptoError::AttestationFailed(format!(
                "SEV-SNP attestation failed: {}",
                failure
            )));
        }

        Ok((
            PlatformQuoteStatus::Verified {
                // The VCEK chained to a root the verifier pinned, which is
                // exactly what "this key belongs to genuine hardware" means
                // here; unlike the TPM path, where the equivalent check is not
                // yet implemented.
                ak_is_trusted: true,
            },
            !self.combined.tee_quote.enclave_signing_key_hex.is_empty(),
        ))
    }

    /// Check an AWS Nitro Enclaves attestation document.
    ///
    /// The document is self-contained, it carries its own leaf certificate and
    /// bundle, so the only thing that has to come from outside it is the root,
    /// which comes from the operator's pins.
    fn verify_nitro_evidence(
        &self,
        expected: &ExpectedMeasurements,
        client_nonce: &str,
        document_b64: &str,
    ) -> CryptoResult<(PlatformQuoteStatus, bool)> {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

        let pins = expected.nitro.as_ref().ok_or_else(|| {
            CryptoError::AttestationFailed(
                "this report carries Nitro Enclaves evidence, but no AWS Nitro root                  certificate is pinned to check it against. A chain is only worth                  walking if its root is one you already trust; pin it under                  [attestation.expected.nitro]."
                    .into(),
            )
        })?;

        let document = B64.decode(document_b64).map_err(|e| {
            CryptoError::AttestationFailed(format!("malformed Nitro attestation document: {}", e))
        })?;
        let root_der = B64.decode(&pins.root_der_b64).map_err(|e| {
            CryptoError::AttestationFailed(format!(
                "malformed pinned AWS Nitro root certificate: {}",
                e
            ))
        })?;

        let expectations = crate::nitro::NitroExpectations {
            root_der,
            pcrs: pins.pcr_values.clone(),
            max_age_seconds: pins.max_age_seconds,
        };

        // Nitro's nonce field is variable-length, so the challenge goes in at
        // its natural width rather than padded to a fixed report field the way
        // SEV-SNP's REPORT_DATA requires.
        let challenge = attestation_challenge(
            &self.combined.tee_quote.enclave_signing_key_hex,
            client_nonce,
        );

        let now_ms = u64::try_from(Utc::now().timestamp_millis()).unwrap_or(0);
        let (_document, verification) =
            crate::nitro::verify_document(&document, &challenge, &expectations, now_ms)?;

        if let Some(failure) = verification.first_failure() {
            return Err(CryptoError::AttestationFailed(format!(
                "Nitro Enclaves attestation failed: {}",
                failure
            )));
        }

        Ok((
            PlatformQuoteStatus::Verified {
                // The leaf chained to a root the verifier pinned, which is what
                // "this key belongs to genuine hardware" means here.
                ak_is_trusted: true,
            },
            !self.combined.tee_quote.enclave_signing_key_hex.is_empty(),
        ))
    }

    /// Check the TPM quote, if the report carries one.
    fn verify_tpm_quote(&self, client_nonce: &str) -> CryptoResult<(PlatformQuoteStatus, bool)> {
        let quote = &self.combined.tpm_quote;
        if !quote.has_hardware_evidence() {
            return Ok((PlatformQuoteStatus::Absent, false));
        }

        let attest_message = hex::decode(&quote.attest_message_hex).map_err(|e| {
            CryptoError::AttestationFailed(format!("malformed quote message: {}", e))
        })?;
        let signature = hex::decode(&quote.quote_signature_hex).map_err(|e| {
            CryptoError::AttestationFailed(format!("malformed quote signature: {}", e))
        })?;
        let ak_public = hex::decode(&quote.aik_public_key_hex).map_err(|e| {
            CryptoError::AttestationFailed(format!("malformed attestation key: {}", e))
        })?;

        // The value the quote should commit to: this verifier's nonce bound
        // together with the node's response-signing key.
        let challenge = attestation_challenge(
            &self.combined.tee_quote.enclave_signing_key_hex,
            client_nonce,
        );

        let verification = crate::tpm2::verify_quote(
            &attest_message,
            &signature,
            &ak_public,
            &challenge,
            &quote.pcr_values.raw_values_in_index_order(),
        )?;

        if !verification.signature_valid {
            return Err(CryptoError::AttestationFailed(
                "the platform quote's signature does not verify under the attestation key \
                 the report supplied"
                    .into(),
            ));
        }
        if !verification.pcr_digest_matches {
            return Err(CryptoError::AttestationFailed(
                "the PCR values in this report do not hash to the digest the platform \
                 signed. The measurements shown are not the ones that were quoted."
                    .into(),
            ));
        }
        if !verification.nonce_matches {
            return Err(CryptoError::AttestationFailed(
                "the platform quote does not commit to this verifier's challenge. Either \
                 it is a replay of an earlier quote, or it does not bind this node's \
                 response-signing key."
                    .into(),
            ));
        }

        Ok((
            PlatformQuoteStatus::Verified {
                ak_is_trusted: verification.ak_is_trusted,
            },
            // Reaching here means `extraData` equalled a challenge computed
            // over the declared signing key, so the platform committed to it.
            !self.combined.tee_quote.enclave_signing_key_hex.is_empty(),
        ))
    }

    /// Verify the report's digest matches its contents.
    fn verify_combined_hash(&self) -> CryptoResult<()> {
        let computed = compute_combined_hash(
            &self.combined.tpm_quote,
            &self.combined.tee_quote,
            &self.combined.platform_evidence,
        )?;
        if !ct_eq(computed.as_bytes(), self.combined.combined_hash.as_bytes()) {
            return Err(CryptoError::AttestationFailed(
                "the report's combined hash does not match its contents; it has been \
                 altered in transit"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// The value a platform quote must commit to in its `extraData`.
///
/// `SHA-256(domain || signing key || nonce)`. Both inputs matter and for
/// different reasons: the nonce makes the quote fresh, and the signing key makes
/// it *about this node's responses* rather than about a machine in the
/// abstract. A verifier recomputes this from the key the report declares and
/// the nonce it chose itself, so a node cannot substitute either.
pub fn attestation_challenge(enclave_signing_key_hex: &str, client_nonce: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(CHALLENGE_DOMAIN);
    hasher.update((enclave_signing_key_hex.len() as u32).to_be_bytes());
    hasher.update(enclave_signing_key_hex.as_bytes());
    hasher.update((client_nonce.len() as u32).to_be_bytes());
    hasher.update(client_nonce.as_bytes());
    hasher.finalize().to_vec()
}

/// The 64 bytes a confidential-VM report commits to.
///
/// The same challenge as [`attestation_challenge`], zero-padded to the width of
/// a SEV-SNP `REPORT_DATA` or TDX `REPORTDATA` field. The padding is part of
/// the committed value: the hardware signs the whole field, so a verifier must
/// pad identically or compare against something the platform never saw.
pub fn confidential_vm_challenge(enclave_signing_key_hex: &str, client_nonce: &str) -> [u8; 64] {
    let digest = attestation_challenge(enclave_signing_key_hex, client_nonce);
    let mut padded = [0u8; 64];
    let len = digest.len().min(64);
    padded[..len].copy_from_slice(&digest[..len]);
    padded
}

/// Build the combined attestation digest over the report's contents.
///
/// Canonically encoded, so a client that deserialized the report computes the
/// same value the node did.
pub fn compute_combined_hash(
    tpm_quote: &TpmQuote,
    tee_quote: &TeeQuote,
    platform_evidence: &PlatformEvidence,
) -> CryptoResult<String> {
    let mut writer = CanonicalWriter::new("combined_attestation");
    writer
        .write_section(&tpm_quote.canonical())
        .write_section(&tee_quote.canonical())
        .write_section(&platform_evidence.canonical());
    Ok(writer.digest_hex())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pcr_set(entries: &[(u8, &str)]) -> TpmPcrSet {
        let mut set = TpmPcrSet::new();
        for (index, value) in entries {
            set.set(*index, (*value).to_string());
        }
        set
    }

    fn tpm_quote(nonce: &str) -> TpmQuote {
        TpmQuote {
            pcr_values: pcr_set(&[
                (0, "sha256:aa"),
                (4, "sha256:bb"),
                (7, "sha256:cc"),
                (11, "sha256:dd"),
                (12, "sha256:ee"),
            ]),
            aik_public_key_hex: String::new(),
            attest_message_hex: String::new(),
            quote_signature_hex: String::new(),
            nonce: nonce.to_string(),
            timestamp: DateTime::from_timestamp_millis(1_700_000_000_000).unwrap(),
            ek_cert_chain: vec!["Y2hhaW4=".into()],
        }
    }

    fn tee_quote() -> TeeQuote {
        TeeQuote {
            tee_type: TeeType::Simulation,
            mrenclave: "a".repeat(64),
            mrsigner: "b".repeat(64),
            isv_svn: 3,
            raw_report_b64: "cmVwb3J0".into(),
            report_signature_b64: String::new(),
            measurement_source: "software_measurement".into(),
            enclave_signing_key_hex: "c".repeat(64),
        }
    }

    fn report(nonce: &str) -> AttestationReport {
        let tpm = tpm_quote(nonce);
        let tee = tee_quote();
        let combined_hash = compute_combined_hash(&tpm, &tee, &PlatformEvidence::None).unwrap();
        AttestationReport {
            combined: CombinedAttestation {
                tpm_quote: tpm,
                tee_quote: tee,
                platform_evidence: PlatformEvidence::None,
                combined_hash,
                node_id: "node-1".into(),
                cordon_version: "2.0.0".into(),
                generated_at: DateTime::from_timestamp_millis(1_700_000_000_000).unwrap(),
            },
            client_nonce: nonce.to_string(),
        }
    }

    fn expectations() -> ExpectedMeasurements {
        ExpectedMeasurements {
            pcr_values: pcr_set(&[(0, "sha256:aa"), (4, "sha256:bb")]),
            mrenclave: "a".repeat(64),
            mrsigner: "b".repeat(64),
            min_isv_svn: 0,
            tee_type: TeeType::Simulation,
            sev_snp: None,
            nitro: None,
        }
    }

    /// The regression this module was rewritten for. A report is built by the
    /// node, serialized, and verified by a client that deserialized it, which
    /// is the only way verification is ever actually used. Under the old
    /// `HashMap` plus `serde_json` encoding the recomputed digest depended on
    /// per-instance hash ordering, and this failed on genuine reports.
    #[test]
    fn a_report_verifies_after_a_json_round_trip() {
        let original = report("a-nonce-long-enough");

        // Round-trip repeatedly: a single pass could coincidentally agree.
        for _ in 0..20 {
            let json = serde_json::to_string(&original).unwrap();
            let received: AttestationReport = serde_json::from_str(&json).unwrap();
            received
                .verify(&expectations(), "a-nonce-long-enough")
                .expect("a genuine report must verify after deserialization");
        }
    }

    #[test]
    fn the_combined_hash_is_stable_across_rebuilt_pcr_sets() {
        let entries: Vec<(u8, String)> = (0..13u8)
            .map(|i| (i, format!("sha256:{:02x}", i)))
            .collect();

        let digest_of_a_fresh_set = || {
            let mut set = TpmPcrSet::new();
            // Insert in a different order each time; the encoding must not care.
            for (index, value) in entries.iter().rev() {
                set.set(*index, value.clone());
            }
            let mut quote = tpm_quote("nonce");
            quote.pcr_values = set;
            compute_combined_hash(&quote, &tee_quote(), &PlatformEvidence::None).unwrap()
        };

        let first = digest_of_a_fresh_set();
        for _ in 0..20 {
            assert_eq!(digest_of_a_fresh_set(), first);
        }
    }

    #[test]
    fn an_altered_report_fails_its_own_digest() {
        let mut altered = report("a-nonce-long-enough");
        altered.combined.tee_quote.mrenclave = "f".repeat(64);

        let err = altered
            .verify(&expectations(), "a-nonce-long-enough")
            .unwrap_err()
            .to_string();
        assert!(err.contains("altered in transit"), "unexpected: {}", err);
    }

    #[test]
    fn every_field_is_covered_by_the_combined_hash() {
        let base =
            compute_combined_hash(&tpm_quote("n"), &tee_quote(), &PlatformEvidence::None).unwrap();

        let mut different_pcr = tpm_quote("n");
        different_pcr.pcr_values.set(0, "sha256:ff".into());
        assert_ne!(
            compute_combined_hash(&different_pcr, &tee_quote(), &PlatformEvidence::None).unwrap(),
            base
        );

        let mut extra_pcr = tpm_quote("n");
        extra_pcr.pcr_values.set(14, "sha256:11".into());
        assert_ne!(
            compute_combined_hash(&extra_pcr, &tee_quote(), &PlatformEvidence::None).unwrap(),
            base
        );

        assert_ne!(
            compute_combined_hash(&tpm_quote("other"), &tee_quote(), &PlatformEvidence::None)
                .unwrap(),
            base
        );

        let mut different_key = tee_quote();
        different_key.enclave_signing_key_hex = "d".repeat(64);
        assert_ne!(
            compute_combined_hash(&tpm_quote("n"), &different_key, &PlatformEvidence::None)
                .unwrap(),
            base
        );

        let mut different_source = tee_quote();
        different_source.measurement_source = "tpm2".into();
        assert_ne!(
            compute_combined_hash(&tpm_quote("n"), &different_source, &PlatformEvidence::None)
                .unwrap(),
            base
        );
    }

    /// The bypass pinning exists to prevent: read a node's own measurements and
    /// hand them straight back.
    #[test]
    fn an_empty_expectation_set_verifies_nothing() {
        let err = report("a-nonce-long-enough")
            .verify(&ExpectedMeasurements::default(), "a-nonce-long-enough")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no measurements are pinned"),
            "unexpected: {}",
            err
        );
    }

    #[test]
    fn a_report_answering_a_different_challenge_is_refused() {
        let err = report("nonce-one")
            .verify(&expectations(), "nonce-two")
            .unwrap_err();
        assert!(matches!(err, CryptoError::NonceMismatch));
    }

    #[test]
    fn mismatched_measurements_are_refused() {
        let mut expected = expectations();
        expected.mrenclave = "f".repeat(64);
        assert!(report("a-nonce-long-enough")
            .verify(&expected, "a-nonce-long-enough")
            .is_err());

        let mut expected = expectations();
        expected.pcr_values.set(0, "sha256:ff".into());
        assert!(report("a-nonce-long-enough")
            .verify(&expected, "a-nonce-long-enough")
            .is_err());

        let mut expected = expectations();
        expected.min_isv_svn = 99;
        assert!(report("a-nonce-long-enough")
            .verify(&expected, "a-nonce-long-enough")
            .is_err());

        let mut expected = expectations();
        expected.tee_type = TeeType::AmdSevSnp;
        assert!(report("a-nonce-long-enough")
            .verify(&expected, "a-nonce-long-enough")
            .is_err());
    }

    #[test]
    fn a_pinned_pcr_missing_from_the_report_is_refused() {
        let mut expected = expectations();
        expected.pcr_values.set(9, "sha256:99".into());
        let err = report("a-nonce-long-enough")
            .verify(&expected, "a-nonce-long-enough")
            .unwrap_err()
            .to_string();
        assert!(err.contains("PCR[9] missing"), "unexpected: {}", err);
    }

    /// A software measurement must not be mistaken for hardware. It verifies,
    /// the configuration is what the operator pinned, but the result says
    /// plainly that no platform quote backed it.
    #[test]
    fn a_software_measurement_reports_no_platform_quote() {
        let verified = report("a-nonce-long-enough")
            .verify(&expectations(), "a-nonce-long-enough")
            .unwrap();

        assert_eq!(verified.platform_quote, PlatformQuoteStatus::Absent);
        assert!(!verified.binds_signing_key);
        assert!(
            !verified.is_hardware_rooted(),
            "a configuration digest is not a hardware root of trust"
        );
        assert_eq!(verified.measurement_source, "software_measurement");
    }

    /// The binding that connects an attestation to the signature on a response.
    #[test]
    fn the_challenge_commits_to_both_the_key_and_the_nonce() {
        let base = attestation_challenge("aa", "nonce");
        assert_eq!(base.len(), 32);
        assert_eq!(base, attestation_challenge("aa", "nonce"));

        assert_ne!(base, attestation_challenge("bb", "nonce"));
        assert_ne!(base, attestation_challenge("aa", "other-nonce"));

        // Length prefixing means the two inputs cannot be slid past each other.
        assert_ne!(
            attestation_challenge("ab", "cd"),
            attestation_challenge("a", "bcd")
        );
    }

    #[test]
    fn pcr_values_decode_to_raw_bytes_in_index_order() {
        let set = pcr_set(&[(4, "sha256:bbbb"), (0, "sha256:aaaa"), (11, "cccc")]);
        let raw = set.raw_values_in_index_order();
        assert_eq!(
            raw,
            vec![
                (0, vec![0xAA, 0xAA]),
                (4, vec![0xBB, 0xBB]),
                (11, vec![0xCC, 0xCC]),
            ]
        );
    }

    #[test]
    fn a_quote_without_a_signed_message_carries_no_hardware_evidence() {
        let mut quote = tpm_quote("n");
        assert!(!quote.has_hardware_evidence());

        quote.aik_public_key_hex = "aa".into();
        quote.quote_signature_hex = "bb".into();
        assert!(
            !quote.has_hardware_evidence(),
            "a signature with nothing to verify it against is not evidence"
        );

        quote.attest_message_hex = "cc".into();
        assert!(quote.has_hardware_evidence());
    }
}
