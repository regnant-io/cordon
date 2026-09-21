//! End-to-end attestation verification, from the client's side of the wire.
//!
//! These tests stand where a client stands: they receive a serialized report,
//! deserialize it, and verify it against measurements they pinned themselves,
//! with no access to whatever the node was holding in memory. That is the only
//! position from which verification means anything, and it is the position the
//! previous implementation could not actually be used from, the report carried
//! a signature with no signed message, and its digest was computed over a
//! `HashMap` whose iteration order differed between the node and the client.
//!
//! A real TPM is stood in for with a NIST P-256 key, which is one of the key
//! types a TPM attestation key can be. The structures are the genuine TPM wire
//! formats and the signature is real; only the hardware is not.

use chrono::Utc;
use cordon_crypto::attestation::{
    attestation_challenge, compute_combined_hash, AttestationReport, CombinedAttestation,
    ExpectedMeasurements, PlatformEvidence, PlatformQuoteStatus, TeeQuote, TeeType, TpmPcrSet,
    TpmQuote,
};
use cordon_crypto::tpm2::{
    compute_pcr_digest, TPM_ALG_ECC, TPM_ALG_ECDSA, TPM_ALG_NULL, TPM_ALG_SHA256,
    TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE,
};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

/// The PCR indices Cordon quotes, and plausible values for them.
fn measurements() -> Vec<(u8, Vec<u8>)> {
    [0u8, 1, 2, 3, 4, 5, 7, 8, 9, 11, 12, 13, 14]
        .iter()
        .map(|index| {
            let mut value = vec![0u8; 32];
            value[0] = *index;
            value[31] = index.wrapping_mul(7);
            (*index, value)
        })
        .collect()
}

/// A `TPMT_PUBLIC` for a P-256 attestation key.
fn ecc_public_area(point: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
    bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    bytes.extend_from_slice(&0x0005_0072u32.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    bytes.extend_from_slice(&TPM_ALG_ECDSA.to_be_bytes());
    bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    bytes.extend_from_slice(&0x0003u16.to_be_bytes()); // NIST P-256
    bytes.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    bytes.extend_from_slice(&32u16.to_be_bytes());
    bytes.extend_from_slice(&point[1..33]);
    bytes.extend_from_slice(&32u16.to_be_bytes());
    bytes.extend_from_slice(&point[33..]);
    bytes
}

/// A `TPMS_ATTEST` quoting `pcrs` and committing to `challenge`.
fn attest_structure(challenge: &[u8], pcrs: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
    out.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&[0xAB, 0xCD, 0xEF, 0x01]); // qualifiedSigner
    out.extend_from_slice(&(challenge.len() as u16).to_be_bytes());
    out.extend_from_slice(challenge);
    out.extend_from_slice(&99_999u64.to_be_bytes()); // clock
    out.extend_from_slice(&0u32.to_be_bytes()); // resetCount
    out.extend_from_slice(&0u32.to_be_bytes()); // restartCount
    out.push(1); // safe
    out.extend_from_slice(&0x0001_0000_0000_0001u64.to_be_bytes());

    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    out.push(3);
    let mut mask = [0u8; 3];
    for (index, _) in pcrs {
        mask[(*index / 8) as usize] |= 1 << (*index % 8);
    }
    out.extend_from_slice(&mask);

    let values: Vec<Vec<u8>> = pcrs.iter().map(|(_, v)| v.clone()).collect();
    let digest = compute_pcr_digest(&values);
    out.extend_from_slice(&(digest.len() as u16).to_be_bytes());
    out.extend_from_slice(&digest);
    out
}

fn ecdsa_signature_structure(raw: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&TPM_ALG_ECDSA.to_be_bytes());
    bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    bytes.extend_from_slice(&32u16.to_be_bytes());
    bytes.extend_from_slice(&raw[..32]);
    bytes.extend_from_slice(&32u16.to_be_bytes());
    bytes.extend_from_slice(&raw[32..]);
    bytes
}

/// Everything a node would produce for one attestation request.
struct NodeReport {
    report: AttestationReport,
    signing_key_hex: String,
}

/// Build a report the way a node with a TPM would: take measurements, compute
/// the challenge over the response-signing key and the client's nonce, have the
/// "TPM" sign a quote over it, and assemble.
fn node_produces_report(nonce: &str, signing_key_hex: &str) -> NodeReport {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let ak =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();

    let pcrs = measurements();
    let challenge = attestation_challenge(signing_key_hex, nonce);
    let attest = attest_structure(&challenge, &pcrs);
    let signature = ecdsa_signature_structure(ak.sign(&rng, &attest).unwrap().as_ref());

    let mut pcr_values = TpmPcrSet::new();
    for (index, value) in &pcrs {
        pcr_values.set(*index, format!("sha256:{}", hex::encode(value)));
    }

    let tpm_quote = TpmQuote {
        pcr_values,
        aik_public_key_hex: hex::encode(ecc_public_area(ak.public_key().as_ref())),
        attest_message_hex: hex::encode(&attest),
        quote_signature_hex: hex::encode(&signature),
        nonce: nonce.to_string(),
        timestamp: Utc::now(),
        ek_cert_chain: vec![],
    };

    let tee_quote = TeeQuote {
        tee_type: TeeType::AmdSevSnp,
        mrenclave: "e".repeat(64),
        mrsigner: "5".repeat(64),
        isv_svn: 3,
        raw_report_b64: "cmVwb3J0".into(),
        report_signature_b64: String::new(),
        measurement_source: "tpm2".into(),
        enclave_signing_key_hex: signing_key_hex.to_string(),
    };

    let combined_hash =
        compute_combined_hash(&tpm_quote, &tee_quote, &PlatformEvidence::None).unwrap();

    NodeReport {
        report: AttestationReport {
            combined: CombinedAttestation {
                tpm_quote,
                tee_quote,
                platform_evidence: PlatformEvidence::None,
                combined_hash,
                node_id: "node-1".into(),
                cordon_version: "2.0.0".into(),
                generated_at: Utc::now(),
            },
            client_nonce: nonce.to_string(),
        },
        signing_key_hex: signing_key_hex.to_string(),
    }
}

/// What a client pins, having reviewed a node it trusts.
fn client_pins() -> ExpectedMeasurements {
    let mut pcr_values = TpmPcrSet::new();
    for (index, value) in measurements() {
        pcr_values.set(index, format!("sha256:{}", hex::encode(value)));
    }
    ExpectedMeasurements {
        pcr_values,
        mrenclave: "e".repeat(64),
        mrsigner: "5".repeat(64),
        min_isv_svn: 1,
        tee_type: TeeType::AmdSevSnp,
        sev_snp: None,
        nitro: None,
    }
}

/// Serialize and deserialize, so the client is verifying what came off the
/// wire rather than what the node had in memory.
fn over_the_wire(report: &AttestationReport) -> AttestationReport {
    serde_json::from_str(&serde_json::to_string(report).unwrap()).unwrap()
}

#[test]
fn a_client_can_independently_verify_a_hardware_backed_report() {
    let nonce = "a-challenge-the-client-chose";
    let signing_key = "9".repeat(64);
    let produced = node_produces_report(nonce, &signing_key);

    let received = over_the_wire(&produced.report);
    let established = received
        .verify(&client_pins(), nonce)
        .expect("a genuine hardware-backed report must verify from the wire");

    assert!(matches!(
        established.platform_quote,
        PlatformQuoteStatus::Verified { .. }
    ));
    assert!(
        established.binds_signing_key,
        "the quote must commit to the key that signs responses"
    );
    assert!(
        established.is_hardware_rooted(),
        "a verified quote binding the signing key is a hardware root of trust"
    );
    assert_eq!(established.measurement_source, "tpm2");
}

/// The digest must be reproducible by anyone. Under the previous encoding it
/// depended on per-instance hash-map ordering, so this failed at random on
/// genuine reports.
#[test]
fn verification_is_reproducible_across_many_round_trips() {
    let nonce = "a-challenge-the-client-chose";
    let produced = node_produces_report(nonce, &"9".repeat(64));
    let pins = client_pins();

    for attempt in 0..50 {
        over_the_wire(&produced.report)
            .verify(&pins, nonce)
            .unwrap_or_else(|e| panic!("attempt {} failed: {}", attempt, e));
    }
}

/// The attack the nonce exists to stop: a report taken earlier, replayed to a
/// client that issued a different challenge.
#[test]
fn a_replayed_report_is_refused() {
    let produced = node_produces_report("the-original-challenge", &"9".repeat(64));
    let received = over_the_wire(&produced.report);

    assert!(
        received
            .verify(&client_pins(), "a-different-challenge")
            .is_err(),
        "a quote answering someone else's challenge must not verify"
    );
}

/// The attack the key binding exists to stop. A node presents a genuine quote
/// but claims a signing key the quote does not commit to, so that responses
/// signed by some other key appear to come from the attested platform.
#[test]
fn a_report_claiming_a_key_the_quote_does_not_bind_is_refused() {
    let nonce = "a-challenge-the-client-chose";
    let produced = node_produces_report(nonce, &"9".repeat(64));

    let mut swapped = produced.report.clone();
    swapped.combined.tee_quote.enclave_signing_key_hex = "1".repeat(64);
    // Re-digest so the report is internally consistent; the substitution has
    // to be caught by the quote, not merely by the combined hash.
    swapped.combined.combined_hash = compute_combined_hash(
        &swapped.combined.tpm_quote,
        &swapped.combined.tee_quote,
        &swapped.combined.platform_evidence,
    )
    .unwrap();

    let err = over_the_wire(&swapped)
        .verify(&client_pins(), nonce)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("does not commit to this verifier's challenge"),
        "unexpected error: {}",
        err
    );
    assert_ne!(produced.signing_key_hex, "1".repeat(64));
}

/// The attack the PCR digest check exists to stop. A node presents a genuine
/// quote and reports measurements alongside it that the TPM never signed for.
#[test]
fn a_report_whose_measurements_were_not_quoted_is_refused() {
    let nonce = "a-challenge-the-client-chose";
    let produced = node_produces_report(nonce, &"9".repeat(64));

    let mut lying = produced.report.clone();
    // Present the values the client pinned, over a quote of different ones.
    lying
        .combined
        .tpm_quote
        .pcr_values
        .set(4, format!("sha256:{}", "ab".repeat(32)));
    lying.combined.combined_hash = compute_combined_hash(
        &lying.combined.tpm_quote,
        &lying.combined.tee_quote,
        &lying.combined.platform_evidence,
    )
    .unwrap();

    let mut pins = client_pins();
    pins.pcr_values
        .set(4, format!("sha256:{}", "ab".repeat(32)));

    let err = over_the_wire(&lying)
        .verify(&pins, nonce)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("do not hash to the digest the platform signed"),
        "unexpected error: {}",
        err
    );
}

/// A report with the signed message stripped must not quietly downgrade to
/// "measurements matched". It carries no hardware evidence, and says so.
#[test]
fn stripping_the_signed_message_removes_the_hardware_claim() {
    let nonce = "a-challenge-the-client-chose";
    let produced = node_produces_report(nonce, &"9".repeat(64));

    let mut stripped = produced.report.clone();
    stripped.combined.tpm_quote.attest_message_hex = String::new();
    stripped.combined.combined_hash = compute_combined_hash(
        &stripped.combined.tpm_quote,
        &stripped.combined.tee_quote,
        &stripped.combined.platform_evidence,
    )
    .unwrap();

    let established = over_the_wire(&stripped)
        .verify(&client_pins(), nonce)
        .unwrap();

    assert_eq!(established.platform_quote, PlatformQuoteStatus::Absent);
    assert!(
        !established.is_hardware_rooted(),
        "measurements without a quote are not a hardware root of trust"
    );
}

/// A quote signed by a key other than the one the report presents.
#[test]
fn a_quote_from_a_different_attestation_key_is_refused() {
    let nonce = "a-challenge-the-client-chose";
    let signing_key = "9".repeat(64);
    let genuine = node_produces_report(nonce, &signing_key);
    let impostor = node_produces_report(nonce, &signing_key);

    let mut mixed = genuine.report.clone();
    mixed.combined.tpm_quote.aik_public_key_hex = impostor
        .report
        .combined
        .tpm_quote
        .aik_public_key_hex
        .clone();
    mixed.combined.combined_hash = compute_combined_hash(
        &mixed.combined.tpm_quote,
        &mixed.combined.tee_quote,
        &mixed.combined.platform_evidence,
    )
    .unwrap();

    let err = over_the_wire(&mixed)
        .verify(&client_pins(), nonce)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("does not verify under the attestation key"),
        "unexpected error: {}",
        err
    );
}

/// Any alteration in transit must be caught by the report's own digest before
/// any of the more specific checks run.
#[test]
fn alteration_in_transit_is_caught() {
    let nonce = "a-challenge-the-client-chose";
    let produced = node_produces_report(nonce, &"9".repeat(64));

    let mut tampered = produced.report.clone();
    tampered.combined.tee_quote.isv_svn = 99;
    // Deliberately not re-digested.

    let err = over_the_wire(&tampered)
        .verify(&client_pins(), nonce)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("altered in transit"),
        "unexpected error: {}",
        err
    );
}
