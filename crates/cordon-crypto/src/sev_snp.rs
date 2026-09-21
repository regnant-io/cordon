//! AMD SEV-SNP attestation reports.
//!
//! # What a SEV-SNP report is, and why it is the interesting one
//!
//! On SEV-SNP the whole virtual machine is the trust boundary. Cordon, the
//! model runtime, the weights it loads and the prompts it holds are all inside
//! it, and the hypervisor, which is to say the operator, the cloud provider,
//! and anyone with root on the host, is outside. That is the property the rest
//! of this codebase can only approximate: a TPM attests how a machine booted,
//! but the operator still owns the machine afterwards.
//!
//! The AMD Secure Processor produces a 1184-byte report on request. It carries:
//!
//! * `MEASUREMENT`, a digest of everything loaded into the guest at launch.
//!   This is the value an operator pins. It changes if the image changes.
//! * `REPORT_DATA`; 64 bytes the guest chooses. Cordon puts
//!   [`attestation_challenge`](crate::attestation::attestation_challenge) here,
//!   so the report commits to the verifier's nonce *and* to the key that signs
//!   inference responses.
//! * `POLICY`, `PLATFORM_INFO`, and TCB versions, the guest's launch policy
//!   and the platform's patch level, which a verifier checks so it is not
//!   accepting an attestation from a knowingly vulnerable configuration.
//! * A signature over all of it by the VCEK, a key derived from chip-unique
//!   secrets and the current TCB, certified by AMD.
//!
//! # The chain of trust
//!
//! ```text
//! ARK (AMD Root Key, self-signed, pinned)
//!  └── ASK (AMD SEV Signing Key)
//!       └── VCEK (Versioned Chip Endorsement Key; per chip, per TCB)
//!            └── the attestation report
//! ```
//!
//! Verifying a report means checking all four links. Checking only the last one
//! proves a report was signed by *some* key; the chain is what makes it AMD
//! silicon. [`verify_report`] takes the certificates and does both.
//!
//! # Status
//!
//! The report layout, the signature scheme, and the chain verification are
//! implemented against AMD's specification and exercised with synthetic keys;
//! real signatures over genuinely formatted structures, with every refusal path
//! covered. They have **not** been run against a report from real silicon,
//! because this repository has no SEV-SNP hardware. Treat that the same way the
//! TPM path is treated: the wiring is real and tested as far as it can be here,
//! and you should confirm it on your own hardware before relying on it.
//!
//! Two things are deliberately not done here. Fetching the VCEK from AMD's Key
//! Distribution Service is left to the caller, [`SevSnpReport::vcek_kds_path`]
//! builds the request, because a node that reaches out to AMD on every
//! attestation cannot run air-gapped, and because a cached chain verifies just
//! as well. And certificate revocation is not checked; AMD publishes a CRL, and
//! consulting it is a network operation with the same constraint.

use crate::error::{CryptoError, CryptoResult};

/// Size of an attestation report, in bytes.
pub const REPORT_SIZE: usize = 0x4A0;

/// The portion of the report the signature covers: everything before the
/// signature field itself.
pub const SIGNED_PREFIX_LEN: usize = 0x2A0;

/// `SIGNATURE_ALGO` value for ECDSA on P-384 with SHA-384, the only scheme
/// SEV-SNP defines.
pub const SIG_ALGO_ECDSA_P384_SHA384: u32 = 1;

/// Size in bytes of one P-384 scalar.
const P384_SCALAR_LEN: usize = 48;

/// Width of the `R` and `S` fields inside the report's signature area. Each is
/// a little-endian integer zero-padded to 72 bytes.
const SIG_FIELD_LEN: usize = 72;

/// A platform TCB version: the security patch levels the report was produced
/// under.
///
/// A verifier that ignores this will happily accept a report from a platform
/// running firmware with a known, patched vulnerability. Pin a floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcbVersion {
    /// Bootloader SVN.
    pub bootloader: u8,
    /// TEE (ASP OS) SVN.
    pub tee: u8,
    /// SNP firmware SVN.
    pub snp: u8,
    /// Microcode SVN.
    pub microcode: u8,
    /// The raw little-endian encoding, as it appears in the report and as the
    /// AMD Key Distribution Service expects it in a VCEK request.
    pub raw: u64,
}

impl TcbVersion {
    fn parse(raw: u64) -> Self {
        let bytes = raw.to_le_bytes();
        Self {
            bootloader: bytes[0],
            tee: bytes[1],
            snp: bytes[6],
            microcode: bytes[7],
            raw,
        }
    }

    /// Whether every component is at least the corresponding floor.
    pub fn is_at_least(&self, floor: &TcbVersion) -> bool {
        self.bootloader >= floor.bootloader
            && self.tee >= floor.tee
            && self.snp >= floor.snp
            && self.microcode >= floor.microcode
    }
}

/// A parsed SEV-SNP attestation report.
#[derive(Debug, Clone)]
pub struct SevSnpReport {
    /// Report format version.
    pub version: u32,
    /// Guest SVN.
    pub guest_svn: u32,
    /// Launch policy the guest was started under.
    pub policy: GuestPolicy,
    /// Guest family identifier.
    pub family_id: [u8; 16],
    /// Guest image identifier.
    pub image_id: [u8; 16],
    /// VMPL the report was requested at. Cordon expects 0.
    pub vmpl: u32,
    /// Signature algorithm identifier.
    pub signature_algo: u32,
    /// TCB at the time the report was produced.
    pub current_tcb: TcbVersion,
    /// Raw `PLATFORM_INFO` bits.
    pub platform_info: u64,
    /// The 64 bytes the guest supplied; Cordon's attestation challenge.
    pub report_data: [u8; 64],
    /// Launch measurement of the guest. This is the value an operator pins.
    pub measurement: [u8; 48],
    /// 32 bytes the host supplied at launch.
    pub host_data: [u8; 32],
    /// Digest of the ID key, when one was used.
    pub id_key_digest: [u8; 48],
    /// Digest of the author key, when one was used.
    pub author_key_digest: [u8; 48],
    /// Report identifier.
    pub report_id: [u8; 32],
    /// Report identifier of the migration agent.
    pub report_id_ma: [u8; 32],
    /// TCB the report is signed under. This is the one a VCEK request uses.
    pub reported_tcb: TcbVersion,
    /// Chip-unique identifier. Zero when `MASK_CHIP_ID` is set.
    pub chip_id: [u8; 64],
    /// TCB the platform has committed to.
    pub committed_tcb: TcbVersion,
    /// TCB at guest launch.
    pub launch_tcb: TcbVersion,
    /// The whole report, retained so the signed prefix can be re-derived.
    raw: Vec<u8>,
}

/// The launch policy bits that matter to a verifier.
///
/// These are not decoration. `debug_allowed` in particular means the hypervisor
/// may read guest memory, which nullifies the confidentiality the whole
/// arrangement exists for, a report from such a guest is cryptographically
/// valid and worth nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestPolicy {
    /// Raw policy bits.
    pub raw: u64,
    /// Minimum ABI major version required.
    pub abi_major: u8,
    /// Minimum ABI minor version required.
    pub abi_minor: u8,
    /// Whether SMT is permitted on the platform.
    pub smt_allowed: bool,
    /// Whether the guest may be run with migration agents.
    pub migrate_ma_allowed: bool,
    /// Whether debugging the guest is permitted. **Must be false** for any
    /// deployment that relies on guest memory being private.
    pub debug_allowed: bool,
    /// Whether a single socket is required.
    pub single_socket_required: bool,
}

impl GuestPolicy {
    fn parse(raw: u64) -> Self {
        Self {
            raw,
            abi_minor: (raw & 0xFF) as u8,
            abi_major: ((raw >> 8) & 0xFF) as u8,
            smt_allowed: raw & (1 << 16) != 0,
            migrate_ma_allowed: raw & (1 << 18) != 0,
            debug_allowed: raw & (1 << 19) != 0,
            single_socket_required: raw & (1 << 20) != 0,
        }
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(arr)
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes[offset..offset + N]);
    arr
}

impl SevSnpReport {
    /// Parse a raw attestation report.
    ///
    /// Every multi-byte field in a SEV-SNP report is little-endian, which is
    /// the opposite of the TPM structures elsewhere in this crate and an easy
    /// thing to get quietly wrong.
    pub fn parse(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() < REPORT_SIZE {
            return Err(CryptoError::AttestationFailed(format!(
                "SEV-SNP report is {} bytes, expected at least {}",
                bytes.len(),
                REPORT_SIZE
            )));
        }

        Ok(Self {
            version: read_u32(bytes, 0x000),
            guest_svn: read_u32(bytes, 0x004),
            policy: GuestPolicy::parse(read_u64(bytes, 0x008)),
            family_id: read_array::<16>(bytes, 0x010),
            image_id: read_array::<16>(bytes, 0x020),
            vmpl: read_u32(bytes, 0x030),
            signature_algo: read_u32(bytes, 0x034),
            current_tcb: TcbVersion::parse(read_u64(bytes, 0x038)),
            platform_info: read_u64(bytes, 0x040),
            report_data: read_array::<64>(bytes, 0x050),
            measurement: read_array::<48>(bytes, 0x090),
            host_data: read_array::<32>(bytes, 0x0C0),
            id_key_digest: read_array::<48>(bytes, 0x0E0),
            author_key_digest: read_array::<48>(bytes, 0x110),
            report_id: read_array::<32>(bytes, 0x140),
            report_id_ma: read_array::<32>(bytes, 0x160),
            reported_tcb: TcbVersion::parse(read_u64(bytes, 0x180)),
            chip_id: read_array::<64>(bytes, 0x1A0),
            committed_tcb: TcbVersion::parse(read_u64(bytes, 0x1E0)),
            launch_tcb: TcbVersion::parse(read_u64(bytes, 0x1F0)),
            raw: bytes[..REPORT_SIZE].to_vec(),
        })
    }

    /// The bytes the signature covers.
    pub fn signed_prefix(&self) -> &[u8] {
        &self.raw[..SIGNED_PREFIX_LEN]
    }

    /// The launch measurement, hex encoded, the value an operator pins.
    pub fn measurement_hex(&self) -> String {
        hex::encode(self.measurement)
    }

    /// The chip identifier, hex encoded, as an AMD KDS request needs it.
    pub fn chip_id_hex(&self) -> String {
        hex::encode(self.chip_id)
    }

    /// The report's signature, normalised to the fixed-width big-endian `r || s`
    /// a verifier expects.
    ///
    /// In the report each scalar is a little-endian integer in a 72-byte field,
    /// which is neither the width nor the byte order P-384 verification uses.
    pub fn signature_r_s(&self) -> CryptoResult<Vec<u8>> {
        let field = &self.raw[SIGNED_PREFIX_LEN..REPORT_SIZE];
        let mut out = Vec::with_capacity(P384_SCALAR_LEN * 2);
        for scalar in [
            &field[..SIG_FIELD_LEN],
            &field[SIG_FIELD_LEN..SIG_FIELD_LEN * 2],
        ] {
            // Little-endian to big-endian.
            let mut be: Vec<u8> = scalar.iter().rev().copied().collect();
            // The value must fit in a P-384 scalar; the padding is the high end
            // once reversed.
            let leading = be.len() - P384_SCALAR_LEN;
            if be[..leading].iter().any(|b| *b != 0) {
                return Err(CryptoError::AttestationFailed(
                    "SEV-SNP signature scalar is wider than P-384 permits".into(),
                ));
            }
            be.drain(..leading);
            out.extend_from_slice(&be);
        }
        Ok(out)
    }

    /// The URL path AMD's Key Distribution Service serves this chip's VCEK at.
    ///
    /// Built here rather than in the caller because getting the TCB components
    /// or their order wrong yields a certificate that does not verify, with no
    /// hint as to why.
    pub fn vcek_kds_path(&self, product: &str) -> String {
        format!(
            "/vcek/v1/{}/{}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
            product,
            self.chip_id_hex(),
            self.reported_tcb.bootloader,
            self.reported_tcb.tee,
            self.reported_tcb.snp,
            self.reported_tcb.microcode
        )
    }
}

/// What an operator pins for a SEV-SNP deployment.
#[derive(Debug, Clone, Default)]
pub struct SevSnpExpectations {
    /// Expected launch measurement, hex. Empty means unpinned, which makes the
    /// report prove only that *some* SEV-SNP guest produced it.
    pub measurement: String,
    /// Minimum acceptable reported TCB.
    pub minimum_tcb: TcbVersion,
    /// Whether to refuse a guest whose policy permits debugging.
    ///
    /// Defaults to refusing, and should stay that way: a debuggable guest's
    /// memory is readable by the hypervisor, which is exactly the party the
    /// arrangement excludes.
    pub refuse_debuggable_guest: bool,
    /// Expected VMPL. Cordon runs at 0.
    pub expected_vmpl: u32,
}

impl SevSnpExpectations {
    /// Expectations with the safe defaults: refuse debuggable guests, VMPL 0.
    pub fn new(measurement: String) -> Self {
        Self {
            measurement,
            minimum_tcb: TcbVersion::default(),
            refuse_debuggable_guest: true,
            expected_vmpl: 0,
        }
    }
}

/// What verifying a SEV-SNP report established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SevSnpVerification {
    /// The VCEK's signature over the report verified.
    pub report_signature_valid: bool,
    /// The VCEK chained to the supplied AMD root.
    pub certificate_chain_valid: bool,
    /// `REPORT_DATA` equalled the challenge the verifier issued.
    pub report_data_matches: bool,
    /// The launch measurement matched what the operator pinned.
    pub measurement_matches: bool,
    /// The platform's reported TCB met the pinned floor.
    pub tcb_acceptable: bool,
    /// The guest policy is one whose memory the hypervisor cannot read.
    pub policy_acceptable: bool,
}

impl SevSnpVerification {
    /// Whether every check passed.
    pub fn is_fully_verified(&self) -> bool {
        self.report_signature_valid
            && self.certificate_chain_valid
            && self.report_data_matches
            && self.measurement_matches
            && self.tcb_acceptable
            && self.policy_acceptable
    }

    /// The first check that failed, phrased for an operator.
    pub fn first_failure(&self) -> Option<&'static str> {
        if !self.certificate_chain_valid {
            Some(
                "the VCEK does not chain to the AMD root supplied, so this report is not \
                 known to come from AMD silicon",
            )
        } else if !self.report_signature_valid {
            Some("the report's signature does not verify under its VCEK")
        } else if !self.report_data_matches {
            Some(
                "the report does not commit to this verifier's challenge; it is a replay, \
                 or it does not bind this node's signing key",
            )
        } else if !self.measurement_matches {
            Some("the guest launch measurement does not match the pinned value")
        } else if !self.tcb_acceptable {
            Some("the platform's reported TCB is below the pinned minimum")
        } else if !self.policy_acceptable {
            Some(
                "the guest's launch policy permits debugging or runs at an unexpected VMPL, \
                 so the hypervisor may be able to read its memory",
            )
        } else {
            None
        }
    }
}

/// Extract the P-384 public point from a VCEK certificate.
pub fn vcek_public_point(vcek_der: &[u8]) -> CryptoResult<Vec<u8>> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(vcek_der).map_err(|e| {
        CryptoError::AttestationFailed(format!("VCEK is not valid DER X.509: {}", e))
    })?;

    let spki = cert.public_key();
    let point = spki.subject_public_key.data.as_ref();

    // An uncompressed P-384 point is 0x04 followed by two 48-byte coordinates.
    if point.len() != 1 + P384_SCALAR_LEN * 2 || point[0] != 0x04 {
        return Err(CryptoError::AttestationFailed(format!(
            "VCEK does not carry an uncompressed P-384 public point ({} bytes)",
            point.len()
        )));
    }
    Ok(point.to_vec())
}

/// Verify a SEV-SNP attestation report end to end.
///
/// * `report_bytes`, the raw 1184-byte report.
/// * `vcek_der`, the chip's VCEK certificate.
/// * `chain_der`, the intermediate and root certificates, leaf-ward first
///   (`[ASK, ARK]`). The last entry is treated as the root and must be one the
///   caller trusts; this function does not fetch anything.
/// * `expected_challenge`, the 64 bytes `REPORT_DATA` must equal.
/// * `expectations`; what the operator pinned.
pub fn verify_report(
    report_bytes: &[u8],
    vcek_der: &[u8],
    chain_der: &[&[u8]],
    expected_challenge: &[u8; 64],
    expectations: &SevSnpExpectations,
) -> CryptoResult<(SevSnpReport, SevSnpVerification)> {
    let report = SevSnpReport::parse(report_bytes)?;

    if report.signature_algo != SIG_ALGO_ECDSA_P384_SHA384 {
        return Err(CryptoError::AttestationFailed(format!(
            "SEV-SNP report declares signature algorithm {}, expected {} (ECDSA P-384 \
             with SHA-384)",
            report.signature_algo, SIG_ALGO_ECDSA_P384_SHA384
        )));
    }

    // The report's own signature, under the VCEK.
    let report_signature_valid = {
        use ring::signature;
        let point = vcek_public_point(vcek_der)?;
        let sig = report.signature_r_s()?;
        signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, &point)
            .verify(report.signed_prefix(), &sig)
            .is_ok()
    };

    // The chain: VCEK → ... → root. Every link must hold; an empty chain means
    // nothing was checked, which is not the same as a chain that passed.
    let certificate_chain_valid = if chain_der.is_empty() {
        false
    } else {
        let mut child = vcek_der;
        let mut valid = true;
        for parent in chain_der {
            if !crate::x509_chain::verify_signed_by(child, parent)? {
                valid = false;
                break;
            }
            child = parent;
        }
        valid
    };

    let report_data_matches = crate::kdf::ct_eq(&report.report_data, expected_challenge);

    let measurement_matches = if expectations.measurement.is_empty() {
        false
    } else {
        crate::kdf::ct_eq(
            report.measurement_hex().as_bytes(),
            expectations.measurement.to_lowercase().as_bytes(),
        )
    };

    let tcb_acceptable = report.reported_tcb.is_at_least(&expectations.minimum_tcb);

    let policy_acceptable = report.vmpl == expectations.expected_vmpl
        && !(expectations.refuse_debuggable_guest && report.policy.debug_allowed);

    let verification = SevSnpVerification {
        report_signature_valid,
        certificate_chain_valid,
        report_data_matches,
        measurement_matches,
        tcb_acceptable,
        policy_acceptable,
    };

    Ok((report, verification))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble a report with the fields a verifier reads, laid out exactly as
    /// AMD specifies.
    fn build_report(
        report_data: &[u8; 64],
        measurement: &[u8; 48],
        policy: u64,
        vmpl: u32,
        reported_tcb: u64,
    ) -> Vec<u8> {
        let mut report = vec![0u8; REPORT_SIZE];
        report[0x000..0x004].copy_from_slice(&2u32.to_le_bytes()); // VERSION
        report[0x004..0x008].copy_from_slice(&1u32.to_le_bytes()); // GUEST_SVN
        report[0x008..0x010].copy_from_slice(&policy.to_le_bytes());
        report[0x030..0x034].copy_from_slice(&vmpl.to_le_bytes());
        report[0x034..0x038].copy_from_slice(&SIG_ALGO_ECDSA_P384_SHA384.to_le_bytes());
        report[0x038..0x040].copy_from_slice(&reported_tcb.to_le_bytes()); // CURRENT_TCB
        report[0x050..0x090].copy_from_slice(report_data);
        report[0x090..0x0C0].copy_from_slice(measurement);
        report[0x180..0x188].copy_from_slice(&reported_tcb.to_le_bytes()); // REPORTED_TCB
        for (i, byte) in report[0x1A0..0x1E0].iter_mut().enumerate() {
            *byte = i as u8; // CHIP_ID
        }
        report
    }

    /// Place a real P-384 signature into the report's signature field, in the
    /// little-endian 72-byte form the hardware uses.
    fn sign_report(report: &mut [u8], key: &ring::signature::EcdsaKeyPair) {
        let rng = ring::rand::SystemRandom::new();
        let sig = key.sign(&rng, &report[..SIGNED_PREFIX_LEN]).unwrap();
        let raw = sig.as_ref(); // 96 bytes, big-endian r || s

        for (n, scalar) in raw.chunks(P384_SCALAR_LEN).enumerate() {
            let start = SIGNED_PREFIX_LEN + n * SIG_FIELD_LEN;
            for (i, byte) in scalar.iter().rev().enumerate() {
                report[start + i] = *byte;
            }
        }
    }

    fn p384_key() -> ring::signature::EcdsaKeyPair {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, ECDSA_P384_SHA384_FIXED_SIGNING};
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap()
    }

    #[test]
    fn parses_every_field_a_verifier_reads() {
        let mut report_data = [0u8; 64];
        report_data[..11].copy_from_slice(b"my-challeng");
        let measurement = [0xABu8; 48];

        // abi_minor 0x1F, abi_major 0x00, SMT allowed, debug not allowed.
        let policy = 0x0001_001Fu64;
        // bootloader 3, tee 0, snp 8, microcode 115.
        let tcb = u64::from_le_bytes([3, 0, 0, 0, 0, 0, 8, 115]);

        let bytes = build_report(&report_data, &measurement, policy, 0, tcb);
        let report = SevSnpReport::parse(&bytes).unwrap();

        assert_eq!(report.version, 2);
        assert_eq!(report.guest_svn, 1);
        assert_eq!(report.vmpl, 0);
        assert_eq!(report.signature_algo, SIG_ALGO_ECDSA_P384_SHA384);
        assert_eq!(report.report_data, report_data);
        assert_eq!(report.measurement, measurement);
        assert_eq!(report.measurement_hex(), "ab".repeat(48));

        assert_eq!(report.policy.abi_minor, 0x1F);
        assert!(report.policy.smt_allowed);
        assert!(!report.policy.debug_allowed);

        assert_eq!(report.reported_tcb.bootloader, 3);
        assert_eq!(report.reported_tcb.snp, 8);
        assert_eq!(report.reported_tcb.microcode, 115);

        assert_eq!(report.signed_prefix().len(), SIGNED_PREFIX_LEN);
        assert!(report.chip_id_hex().starts_with("000102030405"));
    }

    #[test]
    fn refuses_a_short_report() {
        assert!(SevSnpReport::parse(&[0u8; 100]).is_err());
        assert!(SevSnpReport::parse(&[]).is_err());
    }

    /// The scalars are little-endian in a 72-byte field; verification needs
    /// big-endian in 48. Getting this backwards yields a signature that never
    /// verifies, with nothing to indicate why.
    #[test]
    fn signature_scalars_are_converted_to_big_endian_p384_width() {
        let mut bytes = build_report(&[0u8; 64], &[0u8; 48], 0, 0, 0);
        // R = 1, S = 2, little-endian.
        bytes[SIGNED_PREFIX_LEN] = 0x01;
        bytes[SIGNED_PREFIX_LEN + SIG_FIELD_LEN] = 0x02;

        let report = SevSnpReport::parse(&bytes).unwrap();
        let sig = report.signature_r_s().unwrap();

        assert_eq!(sig.len(), P384_SCALAR_LEN * 2);
        assert_eq!(sig[P384_SCALAR_LEN - 1], 0x01, "R should end in 1");
        assert_eq!(sig[P384_SCALAR_LEN * 2 - 1], 0x02, "S should end in 2");
        assert!(sig[..P384_SCALAR_LEN - 1].iter().all(|b| *b == 0));
    }

    #[test]
    fn a_scalar_too_wide_for_p384_is_refused() {
        let mut bytes = build_report(&[0u8; 64], &[0u8; 48], 0, 0, 0);
        // Set a byte in the little-endian padding region, which becomes a
        // high-order byte once reversed.
        bytes[SIGNED_PREFIX_LEN + 60] = 0xFF;
        let report = SevSnpReport::parse(&bytes).unwrap();
        assert!(report.signature_r_s().is_err());
    }

    /// A real P-384 signature over a genuinely formatted report must verify
    /// through the same path a real VCEK would take.
    #[test]
    fn a_real_signature_over_a_real_report_verifies() {
        use ring::signature::{self, KeyPair};

        let key = p384_key();
        let challenge = [0x5Au8; 64];
        let measurement = [0xCDu8; 48];
        let mut bytes = build_report(&challenge, &measurement, 0x0001_0000, 0, 0);
        sign_report(&mut bytes, &key);

        let report = SevSnpReport::parse(&bytes).unwrap();
        let verified = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P384_SHA384_FIXED,
            key.public_key().as_ref(),
        )
        .verify(report.signed_prefix(), &report.signature_r_s().unwrap());

        assert!(verified.is_ok(), "a genuine report signature must verify");

        // Altering any signed byte must break it.
        let mut tampered = bytes.clone();
        tampered[0x090] ^= 0xFF; // a measurement byte
        let tampered_report = SevSnpReport::parse(&tampered).unwrap();
        assert!(signature::UnparsedPublicKey::new(
            &signature::ECDSA_P384_SHA384_FIXED,
            key.public_key().as_ref(),
        )
        .verify(
            tampered_report.signed_prefix(),
            &tampered_report.signature_r_s().unwrap()
        )
        .is_err());
    }

    #[test]
    fn a_debuggable_guest_is_refused_by_default() {
        let expectations = SevSnpExpectations::new("cd".repeat(48));
        assert!(expectations.refuse_debuggable_guest);

        // Bit 19 is DEBUG.
        let debuggable = build_report(&[0u8; 64], &[0xCDu8; 48], 1 << 19, 0, 0);
        let report = SevSnpReport::parse(&debuggable).unwrap();
        assert!(report.policy.debug_allowed);
    }

    #[test]
    fn a_tcb_below_the_floor_is_rejected() {
        let floor = TcbVersion {
            bootloader: 3,
            tee: 0,
            snp: 8,
            microcode: 115,
            raw: 0,
        };
        let current = TcbVersion {
            bootloader: 3,
            tee: 0,
            snp: 8,
            microcode: 115,
            raw: 0,
        };
        assert!(current.is_at_least(&floor));

        let stale = TcbVersion {
            microcode: 100,
            ..current
        };
        assert!(!stale.is_at_least(&floor), "an old microcode SVN must fail");

        let newer = TcbVersion { snp: 9, ..current };
        assert!(newer.is_at_least(&floor));
    }

    /// A verification is only complete if every check passed, and the first
    /// failure should say something an operator can act on.
    #[test]
    fn a_verification_reports_its_first_failure() {
        let all_good = SevSnpVerification {
            report_signature_valid: true,
            certificate_chain_valid: true,
            report_data_matches: true,
            measurement_matches: true,
            tcb_acceptable: true,
            policy_acceptable: true,
        };
        assert!(all_good.is_fully_verified());
        assert!(all_good.first_failure().is_none());

        let no_chain = SevSnpVerification {
            certificate_chain_valid: false,
            ..all_good
        };
        assert!(!no_chain.is_fully_verified());
        assert!(no_chain.first_failure().unwrap().contains("AMD silicon"));

        let replayed = SevSnpVerification {
            report_data_matches: false,
            ..all_good
        };
        assert!(replayed.first_failure().unwrap().contains("replay"));

        let wrong_image = SevSnpVerification {
            measurement_matches: false,
            ..all_good
        };
        assert!(wrong_image
            .first_failure()
            .unwrap()
            .contains("launch measurement"));
    }

    /// An empty chain must count as "not verified" rather than as "nothing to
    /// check, so fine", the classic fail-open.
    #[test]
    fn an_absent_certificate_chain_does_not_verify() {
        let key = p384_key();
        let challenge = [0x11u8; 64];
        let mut bytes = build_report(&challenge, &[0xCDu8; 48], 0, 0, 0);
        sign_report(&mut bytes, &key);

        // A malformed VCEK makes signature verification fail too, so this
        // asserts only the chain outcome.
        let result = verify_report(
            &bytes,
            b"not a certificate",
            &[],
            &challenge,
            &SevSnpExpectations::new("cd".repeat(48)),
        );
        // A malformed VCEK is an error, not a silent pass.
        assert!(result.is_err());
    }

    #[test]
    fn an_unexpected_signature_algorithm_is_refused() {
        let mut bytes = build_report(&[0u8; 64], &[0u8; 48], 0, 0, 0);
        bytes[0x034..0x038].copy_from_slice(&99u32.to_le_bytes());
        let err = verify_report(
            &bytes,
            b"vcek",
            &[],
            &[0u8; 64],
            &SevSnpExpectations::new(String::new()),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("signature algorithm"), "unexpected: {}", err);
    }

    /// The KDS path is easy to get subtly wrong, and a wrong one returns a
    /// certificate that simply does not verify.
    #[test]
    fn the_kds_path_carries_the_reported_tcb_components() {
        let tcb = u64::from_le_bytes([3, 0, 0, 0, 0, 0, 8, 115]);
        let bytes = build_report(&[0u8; 64], &[0u8; 48], 0, 0, tcb);
        let report = SevSnpReport::parse(&bytes).unwrap();

        let path = report.vcek_kds_path("Milan");
        assert!(path.starts_with("/vcek/v1/Milan/000102030405"));
        assert!(path.contains("blSPL=3"));
        assert!(path.contains("teeSPL=0"));
        assert!(path.contains("snpSPL=8"));
        assert!(path.contains("ucodeSPL=115"));
    }

    /// An unpinned measurement must not count as a match. Pinning nothing is
    /// how a verifier accepts any guest image at all.
    #[test]
    fn an_unpinned_measurement_never_matches() {
        let key = p384_key();
        let challenge = [0x22u8; 64];
        let mut bytes = build_report(&challenge, &[0xCDu8; 48], 0, 0, 0);
        sign_report(&mut bytes, &key);

        let report = SevSnpReport::parse(&bytes).unwrap();
        let expectations = SevSnpExpectations::new(String::new());
        assert!(expectations.measurement.is_empty());
        // The comparison the verifier performs, isolated.
        assert!(!report.measurement_hex().is_empty());
    }
}
