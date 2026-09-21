//! SEV-SNP verification from the client's side of the wire.
//!
//! A confidential VM is the one measurement source that makes the node's memory
//! private from whoever runs the host, so it is the source on which Cordon's
//! strongest claim rests. These tests assemble a report the way the AMD Secure
//! Processor does, sign it with a real P-384 key standing in for a VCEK,
//! certify that key with a real certificate chain standing in for AMD's, and
//! then verify the whole thing from a serialized [`AttestationReport`].
//!
//! No AMD hardware was involved, and that limit is worth stating: what is
//! demonstrated is that the report layout, the signature normalisation, the
//! chain walk, the challenge binding and every refusal path are correct against
//! the specification. Whether a genuine Secure Processor produces bytes that
//! match the specification in every particular is something only real silicon
//! can settle.

use chrono::Utc;
use cordon_crypto::attestation::{
    compute_combined_hash, confidential_vm_challenge, AttestationReport, CombinedAttestation,
    ExpectedMeasurements, PlatformEvidence, SevSnpPins, TeeQuote, TeeType, TpmPcrSet, TpmQuote,
};
use cordon_crypto::sev_snp::{REPORT_SIZE, SIGNED_PREFIX_LEN, SIG_ALGO_ECDSA_P384_SHA384};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P384_SHA384_FIXED_SIGNING};

const NONCE: &str = "a-challenge-the-client-chose";
const SIGNING_KEY: &str = "9999999999999999999999999999999999999999999999999999999999999999";

/// The launch measurement an operator would pin.
fn measurement() -> [u8; 48] {
    let mut m = [0u8; 48];
    for (i, byte) in m.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(3).wrapping_add(7);
    }
    m
}

/// Lay out an attestation report exactly as AMD specifies, then sign it.
fn build_signed_report(
    vcek: &EcdsaKeyPair,
    challenge: &[u8; 64],
    measurement: &[u8; 48],
    policy: u64,
    vmpl: u32,
) -> Vec<u8> {
    let mut report = vec![0u8; REPORT_SIZE];
    report[0x000..0x004].copy_from_slice(&2u32.to_le_bytes());
    report[0x004..0x008].copy_from_slice(&1u32.to_le_bytes());
    report[0x008..0x010].copy_from_slice(&policy.to_le_bytes());
    report[0x030..0x034].copy_from_slice(&vmpl.to_le_bytes());
    report[0x034..0x038].copy_from_slice(&SIG_ALGO_ECDSA_P384_SHA384.to_le_bytes());
    // bootloader 4, tee 0, snp 20, microcode 210; a plausible modern TCB.
    let tcb = u64::from_le_bytes([4, 0, 0, 0, 0, 0, 20, 210]);
    report[0x038..0x040].copy_from_slice(&tcb.to_le_bytes());
    report[0x050..0x090].copy_from_slice(challenge);
    report[0x090..0x0C0].copy_from_slice(measurement);
    report[0x180..0x188].copy_from_slice(&tcb.to_le_bytes());
    for (i, byte) in report[0x1A0..0x1E0].iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(11);
    }

    let rng = SystemRandom::new();
    let raw = vcek.sign(&rng, &report[..SIGNED_PREFIX_LEN]).unwrap();
    // Each scalar goes back as a little-endian integer in a 72-byte field.
    for (n, scalar) in raw.as_ref().chunks(48).enumerate() {
        let start = SIGNED_PREFIX_LEN + n * 72;
        for (i, byte) in scalar.iter().rev().enumerate() {
            report[start + i] = *byte;
        }
    }
    report
}

/// AMD's chain is ARK → ASK → VCEK. AMD signs with RSASSA-PSS; this stands the
/// chain up with P-384 instead, because `rcgen` cannot generate RSA keys and
/// the property under test is the chain *walk*, name matching, link-by-link
/// verification, and termination at the pinned root, not which signature
/// algorithm AMD happens to use. The verifier dispatches on each certificate's
/// declared algorithm, so both paths are the same code with a different arm.
struct Chain {
    root_der: Vec<u8>,
    intermediate_der: Vec<u8>,
    vcek_der: Vec<u8>,
    /// The key whose public half is certified by `vcek_der`, so a report signed
    /// with it verifies under that certificate.
    vcek_key: EcdsaKeyPair,
}

fn build_chain() -> Chain {
    fn params(name: &str, is_ca: bool) -> CertificateParams {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, name);
        params.distinguished_name = dn;
        params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;
        params.is_ca = if is_ca {
            IsCa::Ca(rcgen::BasicConstraints::Unconstrained)
        } else {
            IsCa::NoCa
        };
        params
    }

    let root = Certificate::from_params(params("AMD Root Key Test", true)).unwrap();
    let ask = Certificate::from_params(params("AMD SEV Signing Key Test", true)).unwrap();

    // The VCEK's certificate must carry the public half of the key that signs
    // the attestation report, or the report signature check is meaningless.
    let vcek_pkcs8 = {
        let rng = SystemRandom::new();
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap()
    };
    let vcek_key = {
        let rng = SystemRandom::new();
        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, vcek_pkcs8.as_ref(), &rng)
            .unwrap()
    };
    let mut vcek_params = params("VCEK Test", false);
    vcek_params.key_pair = Some(
        KeyPair::from_der_and_sign_algo(vcek_pkcs8.as_ref(), &rcgen::PKCS_ECDSA_P384_SHA384)
            .unwrap(),
    );
    let vcek = Certificate::from_params(vcek_params).unwrap();

    Chain {
        root_der: root.serialize_der().unwrap(),
        intermediate_der: ask.serialize_der_with_signer(&root).unwrap(),
        vcek_der: vcek.serialize_der_with_signer(&ask).unwrap(),
        vcek_key,
    }
}

/// Assemble the report a node would return, with SEV-SNP evidence attached.
fn node_report(chain: &Chain, report_bytes: &[u8], include_chain: bool) -> AttestationReport {
    let tpm_quote = TpmQuote {
        pcr_values: TpmPcrSet::new(),
        aik_public_key_hex: String::new(),
        attest_message_hex: String::new(),
        quote_signature_hex: String::new(),
        nonce: NONCE.to_string(),
        timestamp: Utc::now(),
        ek_cert_chain: vec![],
    };

    let tee_quote = TeeQuote {
        tee_type: TeeType::AmdSevSnp,
        mrenclave: hex::encode(measurement()),
        mrsigner: String::new(),
        isv_svn: 0,
        raw_report_b64: String::new(),
        report_signature_b64: String::new(),
        measurement_source: "sev_snp".into(),
        enclave_signing_key_hex: SIGNING_KEY.to_string(),
    };

    let platform_evidence = PlatformEvidence::SevSnp {
        report_b64: B64.encode(report_bytes),
        vcek_der_b64: B64.encode(&chain.vcek_der),
        certificate_chain_b64: if include_chain {
            vec![B64.encode(&chain.intermediate_der)]
        } else {
            vec![]
        },
    };

    let combined_hash = compute_combined_hash(&tpm_quote, &tee_quote, &platform_evidence).unwrap();

    AttestationReport {
        combined: CombinedAttestation {
            tpm_quote,
            tee_quote,
            platform_evidence,
            combined_hash,
            node_id: "node-1".into(),
            cordon_version: "2.0.0".into(),
            generated_at: Utc::now(),
        },
        client_nonce: NONCE.to_string(),
    }
}

fn client_pins(chain: &Chain) -> ExpectedMeasurements {
    ExpectedMeasurements {
        pcr_values: TpmPcrSet::new(),
        mrenclave: hex::encode(measurement()),
        mrsigner: String::new(),
        min_isv_svn: 0,
        tee_type: TeeType::AmdSevSnp,
        sev_snp: Some(SevSnpPins {
            amd_root_der_b64: B64.encode(&chain.root_der),
            min_bootloader_svn: 4,
            min_tee_svn: 0,
            min_snp_svn: 20,
            min_microcode_svn: 200,
            refuse_debuggable_guest: true,
            expected_vmpl: 0,
        }),
        // Pins for a source this report does not carry.
        nitro: None,
    }
}

fn over_the_wire(report: &AttestationReport) -> AttestationReport {
    serde_json::from_str(&serde_json::to_string(report).unwrap()).unwrap()
}

#[test]
fn a_client_can_verify_a_confidential_vm_report() {
    let chain = build_chain();
    let challenge = confidential_vm_challenge(SIGNING_KEY, NONCE);
    let bytes = build_signed_report(&chain.vcek_key, &challenge, &measurement(), 0x0001_0000, 0);

    let established = over_the_wire(&node_report(&chain, &bytes, true))
        .verify(&client_pins(&chain), NONCE)
        .expect("a genuine SEV-SNP report must verify");

    assert!(established.platform_quote.is_hardware_verified());
    assert!(established.binds_signing_key);
    assert!(
        established.is_hardware_rooted(),
        "a chained, challenge-bound report is a hardware root of trust"
    );
    assert_eq!(established.measurement_source, "sev_snp");
}

/// A report with no root pinned must be refused, not accepted on its
/// measurements. A chain is worth walking only if its root is already trusted.
#[test]
fn a_report_with_no_pinned_amd_root_is_refused() {
    let chain = build_chain();
    let challenge = confidential_vm_challenge(SIGNING_KEY, NONCE);
    let bytes = build_signed_report(&chain.vcek_key, &challenge, &measurement(), 0, 0);

    let mut pins = client_pins(&chain);
    pins.sev_snp = None;

    let err = over_the_wire(&node_report(&chain, &bytes, true))
        .verify(&pins, NONCE)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("no AMD root certificate is pinned"),
        "unexpected error: {}",
        err
    );
}

/// A VCEK that does not chain to the pinned root proves nothing about AMD
/// silicon, however valid its signature over the report.
#[test]
fn a_vcek_from_another_chain_is_refused() {
    let genuine = build_chain();
    let impostor = build_chain();
    let challenge = confidential_vm_challenge(SIGNING_KEY, NONCE);
    let bytes = build_signed_report(&impostor.vcek_key, &challenge, &measurement(), 0, 0);

    // The report is internally consistent and signed by the impostor's VCEK,
    // but the client pins the genuine root.
    let err = over_the_wire(&node_report(&impostor, &bytes, true))
        .verify(&client_pins(&genuine), NONCE)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("AMD silicon") || err.contains("chain"),
        "unexpected error: {}",
        err
    );
}

/// The replay defence: a report answering someone else's challenge.
#[test]
fn a_replayed_report_is_refused() {
    let chain = build_chain();
    let stale = confidential_vm_challenge(SIGNING_KEY, "an-older-challenge");
    let bytes = build_signed_report(&chain.vcek_key, &stale, &measurement(), 0, 0);

    let err = over_the_wire(&node_report(&chain, &bytes, true))
        .verify(&client_pins(&chain), NONCE)
        .unwrap_err()
        .to_string();
    assert!(err.contains("replay"), "unexpected error: {}", err);
}

/// The key binding: a report that does not commit to the key signing responses
/// leaves the attestation and the response signature unconnected.
#[test]
fn a_report_not_bound_to_the_signing_key_is_refused() {
    let chain = build_chain();
    let other_key_challenge = confidential_vm_challenge("1".repeat(64).as_str(), NONCE);
    let bytes = build_signed_report(&chain.vcek_key, &other_key_challenge, &measurement(), 0, 0);

    let err = over_the_wire(&node_report(&chain, &bytes, true))
        .verify(&client_pins(&chain), NONCE)
        .unwrap_err()
        .to_string();
    // The report commits to a challenge computed over a different key, so the
    // committed value does not match; the same check that catches a replay.
    assert!(
        err.contains("bind this node's signing key"),
        "unexpected error: {}",
        err
    );
}

/// A different guest image must not satisfy a pinned measurement.
#[test]
fn a_different_launch_measurement_is_refused() {
    let chain = build_chain();
    let challenge = confidential_vm_challenge(SIGNING_KEY, NONCE);
    let mut other = measurement();
    other[0] ^= 0xFF;
    let bytes = build_signed_report(&chain.vcek_key, &challenge, &other, 0, 0);

    // The report declares the value the client pinned, but the hardware signed
    // a different one.
    let mut report = node_report(&chain, &bytes, true);
    report.combined.tee_quote.mrenclave = hex::encode(measurement());
    report.combined.combined_hash = compute_combined_hash(
        &report.combined.tpm_quote,
        &report.combined.tee_quote,
        &report.combined.platform_evidence,
    )
    .unwrap();

    let err = over_the_wire(&report)
        .verify(&client_pins(&chain), NONCE)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("launch measurement"),
        "unexpected error: {}",
        err
    );
}

/// A debuggable guest's memory is readable by the hypervisor, which nullifies
/// the confidentiality the whole arrangement is for. The report is
/// cryptographically valid and must still be refused.
#[test]
fn a_debuggable_guest_is_refused() {
    let chain = build_chain();
    let challenge = confidential_vm_challenge(SIGNING_KEY, NONCE);
    // Bit 19 is DEBUG.
    let bytes = build_signed_report(&chain.vcek_key, &challenge, &measurement(), 1 << 19, 0);

    let err = over_the_wire(&node_report(&chain, &bytes, true))
        .verify(&client_pins(&chain), NONCE)
        .unwrap_err()
        .to_string();
    assert!(err.contains("debugging"), "unexpected error: {}", err);
}

/// A platform running firmware below the pinned floor is refused, so a known,
/// patched vulnerability cannot be attested around.
#[test]
fn a_platform_below_the_tcb_floor_is_refused() {
    let chain = build_chain();
    let challenge = confidential_vm_challenge(SIGNING_KEY, NONCE);
    let bytes = build_signed_report(&chain.vcek_key, &challenge, &measurement(), 0, 0);

    let mut pins = client_pins(&chain);
    if let Some(snp) = pins.sev_snp.as_mut() {
        snp.min_microcode_svn = 255; // above what the report declares
    }

    let err = over_the_wire(&node_report(&chain, &bytes, true))
        .verify(&pins, NONCE)
        .unwrap_err()
        .to_string();
    assert!(err.contains("TCB"), "unexpected error: {}", err);
}

/// Evidence arriving without the intermediate cannot be chained, and an
/// unchainable VCEK must fail rather than fall through to the measurements.
#[test]
fn evidence_without_the_intermediate_certificate_is_refused() {
    let chain = build_chain();
    let challenge = confidential_vm_challenge(SIGNING_KEY, NONCE);
    let bytes = build_signed_report(&chain.vcek_key, &challenge, &measurement(), 0, 0);

    let err = over_the_wire(&node_report(&chain, &bytes, false))
        .verify(&client_pins(&chain), NONCE)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("AMD silicon") || err.contains("chain"),
        "unexpected error: {}",
        err
    );
}

#[test]
fn tampering_with_the_report_after_signing_is_caught() {
    let chain = build_chain();
    let challenge = confidential_vm_challenge(SIGNING_KEY, NONCE);
    let mut bytes = build_signed_report(&chain.vcek_key, &challenge, &measurement(), 0, 0);

    // Flip a byte inside the signed prefix.
    bytes[0x0A0] ^= 0xFF;

    let err = over_the_wire(&node_report(&chain, &bytes, true))
        .verify(&client_pins(&chain), NONCE)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("signature") || err.contains("launch measurement"),
        "unexpected error: {}",
        err
    );
}
