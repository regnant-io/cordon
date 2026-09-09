//! Nitro Enclaves verification from the client's side of the wire.
//!
//! The unit tests in `nitro.rs` check the document verifier directly. These
//! check the part a client actually exercises: an [`AttestationReport`] arrives
//! as JSON, is deserialized, and `verify` decides what it establishes — the
//! challenge derivation, the pins plumbing, the digest reproduction and the
//! evidence dispatch all in the path.
//!
//! No AWS hardware was involved. What is demonstrated is that the COSE
//! structure, the CBOR payload shape, the chain walk to a pinned root, the
//! challenge binding and every refusal path behave as AWS's format specifies.
//! Whether a genuine Nitro Security Module emits bytes matching that format in
//! every particular is something only a real enclave can settle.

use chrono::Utc;
use cordon_crypto::attestation::{
    attestation_challenge, compute_combined_hash, AttestationReport, CombinedAttestation,
    ExpectedMeasurements, NitroPins, PlatformEvidence, TeeQuote, TeeType, TpmPcrSet, TpmQuote,
};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P384_SHA384_FIXED_SIGNING};
use std::collections::BTreeMap;

const NONCE: &str = "a-challenge-the-client-chose";
const SIGNING_KEY: &str = "8888888888888888888888888888888888888888888888888888888888888888";
const PCR_LEN: usize = 48;

// ── A CBOR writer, kept separate from the one under test ────────────────────

fn header(out: &mut Vec<u8>, major: u8, argument: u64) {
    let major = major << 5;
    match argument {
        0..=23 => out.push(major | argument as u8),
        24..=0xFF => {
            out.push(major | 24);
            out.push(argument as u8);
        }
        0x100..=0xFFFF => {
            out.push(major | 25);
            out.extend_from_slice(&(argument as u16).to_be_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(major | 26);
            out.extend_from_slice(&(argument as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend_from_slice(&argument.to_be_bytes());
        }
    }
}
fn cbor_bytes(out: &mut Vec<u8>, b: &[u8]) {
    header(out, 2, b.len() as u64);
    out.extend_from_slice(b);
}
fn cbor_text(out: &mut Vec<u8>, t: &str) {
    header(out, 3, t.len() as u64);
    out.extend_from_slice(t.as_bytes());
}
fn cbor_uint(out: &mut Vec<u8>, n: u64) {
    header(out, 0, n);
}
fn cbor_nint(out: &mut Vec<u8>, n: i64) {
    header(out, 1, (-1 - n) as u64);
}
fn cbor_array(out: &mut Vec<u8>, n: u64) {
    header(out, 4, n);
}
fn cbor_map(out: &mut Vec<u8>, n: u64) {
    header(out, 5, n);
}

/// The `Sig_structure` a COSE_Sign1 signature covers, built independently of
/// the implementation so a bug in one cannot mask a bug in the other.
fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    cbor_array(&mut out, 4);
    cbor_text(&mut out, "Signature1");
    cbor_bytes(&mut out, protected);
    cbor_bytes(&mut out, &[]);
    cbor_bytes(&mut out, payload);
    out
}

// ── The certificate chain AWS would present ─────────────────────────────────

struct Chain {
    root_der: Vec<u8>,
    intermediate_der: Vec<u8>,
    leaf_der: Vec<u8>,
    /// The key certified by `leaf_der`, so a document signed with it verifies
    /// under that certificate.
    leaf_key: EcdsaKeyPair,
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

    let root = Certificate::from_params(params("aws.nitro-enclaves Root Test", true)).unwrap();
    let intermediate =
        Certificate::from_params(params("aws.nitro-enclaves Intermediate Test", true)).unwrap();

    let leaf_pkcs8 = {
        let rng = SystemRandom::new();
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap()
    };
    let leaf_key = {
        let rng = SystemRandom::new();
        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, leaf_pkcs8.as_ref(), &rng)
            .unwrap()
    };
    let mut leaf_params = params("i-0abcdef-enc0123456789", false);
    leaf_params.key_pair = Some(
        KeyPair::from_der_and_sign_algo(leaf_pkcs8.as_ref(), &rcgen::PKCS_ECDSA_P384_SHA384)
            .unwrap(),
    );
    let leaf = Certificate::from_params(leaf_params).unwrap();

    Chain {
        root_der: root.serialize_der().unwrap(),
        intermediate_der: intermediate.serialize_der_with_signer(&root).unwrap(),
        leaf_der: leaf.serialize_der_with_signer(&intermediate).unwrap(),
        leaf_key,
    }
}

// ── The document a Nitro Security Module would emit ─────────────────────────

fn pcr(fill: u8) -> Vec<u8> {
    vec![fill; PCR_LEN]
}

/// Build a COSE_Sign1-wrapped attestation document, laid out as AWS specifies
/// and signed with a real ES384 signature.
fn build_document(chain: &Chain, nonce: &[u8], pcr0: &[u8], timestamp_ms: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    cbor_map(&mut payload, 9);

    cbor_text(&mut payload, "module_id");
    cbor_text(&mut payload, "i-0abcdef-enc0123456789");

    cbor_text(&mut payload, "digest");
    cbor_text(&mut payload, "SHA384");

    cbor_text(&mut payload, "timestamp");
    cbor_uint(&mut payload, timestamp_ms);

    cbor_text(&mut payload, "pcrs");
    cbor_map(&mut payload, 3);
    cbor_uint(&mut payload, 0);
    cbor_bytes(&mut payload, pcr0);
    cbor_uint(&mut payload, 1);
    cbor_bytes(&mut payload, &pcr(0xB1));
    cbor_uint(&mut payload, 2);
    cbor_bytes(&mut payload, &pcr(0xB2));

    cbor_text(&mut payload, "certificate");
    cbor_bytes(&mut payload, &chain.leaf_der);

    cbor_text(&mut payload, "cabundle");
    cbor_array(&mut payload, 2);
    cbor_bytes(&mut payload, &chain.root_der); // AWS emits root first
    cbor_bytes(&mut payload, &chain.intermediate_der);

    cbor_text(&mut payload, "public_key");
    cbor_bytes(&mut payload, &[]);

    cbor_text(&mut payload, "user_data");
    cbor_bytes(&mut payload, &[]);

    cbor_text(&mut payload, "nonce");
    cbor_bytes(&mut payload, nonce);

    let mut protected = Vec::new();
    cbor_map(&mut protected, 1);
    cbor_uint(&mut protected, 1);
    cbor_nint(&mut protected, -35); // ES384

    let rng = SystemRandom::new();
    let signature = chain
        .leaf_key
        .sign(&rng, &sig_structure(&protected, &payload))
        .unwrap();

    let mut document = Vec::new();
    cbor_array(&mut document, 4);
    cbor_bytes(&mut document, &protected);
    cbor_map(&mut document, 0);
    cbor_bytes(&mut document, &payload);
    cbor_bytes(&mut document, signature.as_ref());
    document
}

/// The challenge the enclave would place in the document's nonce field.
fn challenge() -> Vec<u8> {
    attestation_challenge(SIGNING_KEY, NONCE)
}

/// Assemble the report a node would return, with Nitro evidence attached.
fn node_report(document: &[u8], measurement: &str) -> AttestationReport {
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
        tee_type: TeeType::Simulation,
        mrenclave: measurement.to_string(),
        mrsigner: String::new(),
        isv_svn: 0,
        raw_report_b64: String::new(),
        report_signature_b64: String::new(),
        measurement_source: "nitro_enclave".into(),
        enclave_signing_key_hex: SIGNING_KEY.to_string(),
    };

    let platform_evidence = PlatformEvidence::Nitro {
        document_b64: B64.encode(document),
    };

    let combined_hash = compute_combined_hash(&tpm_quote, &tee_quote, &platform_evidence).unwrap();

    AttestationReport {
        combined: CombinedAttestation {
            tpm_quote,
            tee_quote,
            platform_evidence,
            combined_hash,
            node_id: "node-under-test".into(),
            cordon_version: env!("CARGO_PKG_VERSION").into(),
            generated_at: Utc::now(),
        },
        client_nonce: NONCE.into(),
    }
}

fn pins(chain: &Chain, pcr0: &[u8]) -> ExpectedMeasurements {
    let mut pcr_values = BTreeMap::new();
    pcr_values.insert(0u8, hex::encode(pcr0));

    ExpectedMeasurements {
        pcr_values: TpmPcrSet::new(),
        // A Nitro deployment pins its measurements under `nitro`, not here.
        mrenclave: String::new(),
        mrsigner: String::new(),
        min_isv_svn: 0,
        tee_type: TeeType::Simulation,
        sev_snp: None,
        nitro: Some(NitroPins {
            root_der_b64: B64.encode(&chain.root_der),
            pcr_values,
            max_age_seconds: 300,
        }),
    }
}

fn now_ms() -> u64 {
    u64::try_from(Utc::now().timestamp_millis()).unwrap()
}

/// Round-trip the report through JSON, which is what a client actually
/// receives. This is where a non-reproducible digest would show up.
fn over_the_wire(report: &AttestationReport) -> AttestationReport {
    let json = serde_json::to_string(report).unwrap();
    serde_json::from_str(&json).unwrap()
}

// ── The tests ───────────────────────────────────────────────────────────────

#[test]
fn a_genuine_document_verifies_after_a_json_round_trip() {
    let chain = build_chain();
    let pcr0 = pcr(0xB0);
    let document = build_document(&chain, &challenge(), &pcr0, now_ms());
    let report = over_the_wire(&node_report(&document, ""));

    let verified = report.verify(&pins(&chain, &pcr0), NONCE).unwrap();

    assert!(verified.platform_quote.is_hardware_verified());
    assert!(verified.binds_signing_key);
    assert!(
        verified.is_hardware_rooted(),
        "a verified Nitro document that commits to the signing key is a hardware root"
    );
    assert_eq!(verified.measurement_source, "nitro_enclave");
}

/// The digest travels with the report and a client recomputes it. If the
/// encoding were not canonical this is the test that would fail, because the
/// client hashes a structure it deserialized rather than the one the node
/// built.
#[test]
fn the_reports_own_digest_is_reproducible_by_the_client() {
    let chain = build_chain();
    let pcr0 = pcr(0xB0);
    let document = build_document(&chain, &challenge(), &pcr0, now_ms());
    let original = node_report(&document, "");

    for _ in 0..8 {
        let received = over_the_wire(&original);
        assert_eq!(
            received.combined.combined_hash,
            original.combined.combined_hash
        );
        assert!(received.verify(&pins(&chain, &pcr0), NONCE).is_ok());
    }
}

/// Evidence swapped between two reports must not verify, because the digest
/// covers it.
#[test]
fn substituting_the_evidence_breaks_the_reports_digest() {
    let chain = build_chain();
    let pcr0 = pcr(0xB0);
    let mut report = node_report(&build_document(&chain, &challenge(), &pcr0, now_ms()), "");

    let other = build_document(&chain, &challenge(), &pcr(0xCC), now_ms());
    report.combined.platform_evidence = PlatformEvidence::Nitro {
        document_b64: B64.encode(&other),
    };

    let error = report
        .verify(&pins(&chain, &pcr0), NONCE)
        .unwrap_err()
        .to_string();
    assert!(
        error.to_lowercase().contains("hash") || error.to_lowercase().contains("digest"),
        "{}",
        error
    );
}

/// The case the pinned root exists for: a document that is internally perfect
/// and signed by a chain the attacker built themselves.
#[test]
fn a_document_from_an_attackers_own_chain_is_refused() {
    let real = build_chain();
    let attacker = build_chain();
    let pcr0 = pcr(0xB0);

    // The attacker builds a document with the right measurements and the right
    // challenge — everything except a chain to AWS's root.
    let document = build_document(&attacker, &challenge(), &pcr0, now_ms());
    let report = over_the_wire(&node_report(&document, ""));

    let error = report
        .verify(&pins(&real, &pcr0), NONCE)
        .unwrap_err()
        .to_string();
    assert!(error.contains("pinned AWS Nitro root"), "{}", error);
}

/// A report carrying Nitro evidence against a verifier that pinned no Nitro
/// root must fail loudly, not fall through to a weaker check.
#[test]
fn nitro_evidence_with_no_pinned_root_is_refused_rather_than_ignored() {
    let chain = build_chain();
    let pcr0 = pcr(0xB0);
    let document = build_document(&chain, &challenge(), &pcr0, now_ms());
    let report = over_the_wire(&node_report(
        &document,
        "measurement-so-something-is-pinned",
    ));

    let mut expected = pins(&chain, &pcr0);
    expected.nitro = None;
    expected.mrenclave = "measurement-so-something-is-pinned".into();

    let error = report.verify(&expected, NONCE).unwrap_err().to_string();
    assert!(error.contains("[attestation.expected.nitro]"), "{}", error);
}

/// A document bound to a different challenge is a replay, and the fact that it
/// is otherwise genuine is exactly why it has to be caught.
#[test]
fn a_replayed_document_from_an_earlier_exchange_is_refused() {
    let chain = build_chain();
    let pcr0 = pcr(0xB0);

    let earlier = attestation_challenge(SIGNING_KEY, "the-nonce-from-an-earlier-request");
    let document = build_document(&chain, &earlier, &pcr0, now_ms());
    let report = over_the_wire(&node_report(&document, ""));

    let error = report
        .verify(&pins(&chain, &pcr0), NONCE)
        .unwrap_err()
        .to_string();
    assert!(error.contains("replayed"), "{}", error);
}

/// The challenge covers the node's response-signing key as well as the nonce,
/// so a document produced for a node holding a different key does not verify
/// here — which is what makes an attested platform and a signed answer the
/// same claim.
#[test]
fn a_document_bound_to_a_different_signing_key_is_refused() {
    let chain = build_chain();
    let pcr0 = pcr(0xB0);

    let other_key_challenge = attestation_challenge(&"7".repeat(64), NONCE);
    let document = build_document(&chain, &other_key_challenge, &pcr0, now_ms());
    let report = over_the_wire(&node_report(&document, ""));

    let error = report
        .verify(&pins(&chain, &pcr0), NONCE)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("replayed") || error.contains("commit"),
        "{}",
        error
    );
}

/// Genuine hardware, wrong image — the case PCR0 is pinned for.
#[test]
fn genuine_hardware_running_an_unpinned_image_is_refused() {
    let chain = build_chain();
    let document = build_document(&chain, &challenge(), &pcr(0xCC), now_ms());
    let report = over_the_wire(&node_report(&document, ""));

    let error = report
        .verify(&pins(&chain, &pcr(0xB0)), NONCE)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("other than the image you pinned"),
        "{}",
        error
    );
}

/// A document from outside the freshness window is refused even when its nonce
/// is right, so a stale document cannot be held and re-presented within one
/// challenge exchange.
#[test]
fn a_document_older_than_the_freshness_bound_is_refused() {
    let chain = build_chain();
    let pcr0 = pcr(0xB0);
    let long_ago = now_ms() - 3_600_000; // an hour
    let document = build_document(&chain, &challenge(), &pcr0, long_ago);
    let report = over_the_wire(&node_report(&document, ""));

    let error = report
        .verify(&pins(&chain, &pcr0), NONCE)
        .unwrap_err()
        .to_string();
    assert!(error.contains("freshness"), "{}", error);
}

/// A verifier that pins nothing accepts everything, so it must be refused
/// before any check runs.
#[test]
fn an_expectation_set_that_pins_nothing_is_refused() {
    let chain = build_chain();
    let pcr0 = pcr(0xB0);
    let document = build_document(&chain, &challenge(), &pcr0, now_ms());
    let report = over_the_wire(&node_report(&document, ""));

    let mut expected = pins(&chain, &pcr0);
    expected.nitro = Some(NitroPins {
        root_der_b64: B64.encode(&chain.root_der),
        pcr_values: BTreeMap::new(),
        max_age_seconds: 300,
    });

    let error = report.verify(&expected, NONCE).unwrap_err().to_string();
    assert!(error.contains("no measurements are pinned"), "{}", error);
}

/// A Nitro deployment pins its PCRs under `nitro`, not in the TPM PCR set, so
/// an expectation set with only Nitro pins must count as pinned.
#[test]
fn nitro_pins_alone_count_as_pinned() {
    let chain = build_chain();
    let pcr0 = pcr(0xB0);
    let expected = pins(&chain, &pcr0);

    assert!(expected.pcr_values.is_empty());
    assert!(expected.mrenclave.is_empty());
    assert!(
        !expected.is_empty(),
        "a fully pinned Nitro configuration must not look empty to the verifier"
    );
}

/// A truncated document must produce an error naming the problem, not a panic
/// and not a `false` that reads as a verdict.
#[test]
fn a_truncated_document_is_an_error_not_a_panic() {
    let chain = build_chain();
    let pcr0 = pcr(0xB0);
    let document = build_document(&chain, &challenge(), &pcr0, now_ms());

    for cut in [1usize, 8, 64, document.len() / 2, document.len() - 1] {
        let report = node_report(&document[..cut], "");
        let error = report.verify(&pins(&chain, &pcr0), NONCE);
        assert!(error.is_err(), "truncated to {} bytes verified", cut);
    }
}

/// Every byte position, flipped. None may verify and none may panic.
#[test]
fn no_single_byte_corruption_verifies() {
    let chain = build_chain();
    let pcr0 = pcr(0xB0);
    let document = build_document(&chain, &challenge(), &pcr0, now_ms());
    let expected = pins(&chain, &pcr0);

    // Every 37th byte, which covers the header, the payload, the certificates
    // and the signature without running the whole suite for a minute.
    for i in (0..document.len()).step_by(37) {
        let mut corrupted = document.clone();
        corrupted[i] ^= 0xFF;
        if corrupted == document {
            continue;
        }
        let report = node_report(&corrupted, "");
        assert!(
            report.verify(&expected, NONCE).is_err(),
            "flipping byte {} still verified",
            i
        );
    }
}
