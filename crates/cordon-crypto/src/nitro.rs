//! AWS Nitro Enclaves attestation.
//!
//! A Nitro Enclave is a stripped VM carved out of a parent EC2 instance: no
//! persistent storage, no interactive access, no external network, and a single
//! vsock channel to the parent. The parent instance, and anyone with root on
//! it, cannot read the enclave's memory. That is the same property AMD SEV-SNP
//! provides, reached a different way, and it is the property that separates a
//! trusted execution environment from a well-configured server.
//!
//! The Nitro Security Module signs an *attestation document*: a CBOR map,
//! wrapped in a COSE_Sign1 structure, signed with ECDSA P-384 over SHA-384 by a
//! certificate that chains to the AWS Nitro Enclaves root CA. Verifying one
//! means four separate things, and this module reports them separately because
//! collapsing them into a boolean is how a verifier ends up trusting a document
//! that was correctly signed by the wrong party:
//!
//! 1. **The signature holds** over the COSE `Signature1` structure, under the
//!    key in the document's own leaf certificate.
//! 2. **That leaf chains to a root the operator pinned.** Step 1 alone proves
//!    only that the document is internally consistent; anyone can generate a
//!    key, sign a document with it, and ship the certificate alongside.
//! 3. **The PCRs match what the operator pinned.** The chain proves it is a
//!    genuine enclave; the PCRs are what say it is *your* enclave running *your*
//!    image.
//! 4. **The document commits to this conversation**, the caller's nonce and
//!    the key that will sign the answer, so it describes the machine you are
//!    talking to rather than one that was genuine an hour ago.
//!
//! ## What is verified here and what is not
//!
//! This module verifies documents. It does not obtain them: acquiring one
//! requires an `ioctl` on `/dev/nsm` from inside an enclave, which is a
//! different problem with different constraints, discussed in
//! `cordon-core`'s `confidential_vm` module and in `SECURITY.md`.
//!
//! Like the SEV-SNP module, this is written to AWS's published format and
//! exercised against synthetic keys and genuinely-shaped documents. It has not
//! been run against a real Nitro Security Module.

use crate::cbor::{self, CborValue};
use crate::error::{CryptoError, CryptoResult};
use std::collections::BTreeMap;

/// COSE header label for the signature algorithm (RFC 8152 §3.1).
const COSE_HEADER_ALG: i64 = 1;

/// `ES384`; ECDSA with SHA-384. The only algorithm a Nitro document uses, and
/// the only one accepted here.
const COSE_ALG_ES384: i64 = -35;

/// An ES384 signature is two 48-byte scalars, concatenated, big-endian.
const ES384_SIGNATURE_LEN: usize = 96;

/// A SHA-384 PCR value.
const PCR_LEN: usize = 48;

/// The Nitro Security Module reports 32 PCR slots.
const PCR_COUNT: u64 = 32;

/// AWS caps each caller-supplied field. A document claiming more did not come
/// from an NSM, and refusing early keeps a malformed document from reaching the
/// comparison logic at all.
const MAX_NONCE_LEN: usize = 512;
/// See [`MAX_NONCE_LEN`].
const MAX_USER_DATA_LEN: usize = 512;
/// See [`MAX_NONCE_LEN`].
const MAX_PUBLIC_KEY_LEN: usize = 1024;

/// A parsed COSE_Sign1 envelope.
///
/// The protected header and payload are kept as the exact bytes that arrived,
/// not re-encoded from the parsed form. The signature covers those bytes, so
/// re-encoding them, even correctly, would mean checking a signature against
/// something the signer never saw.
#[derive(Debug, Clone)]
pub struct CoseSign1 {
    /// The protected header, as it appeared on the wire.
    pub protected: Vec<u8>,
    /// The payload, as it appeared on the wire.
    pub payload: Vec<u8>,
    /// The 96-byte ES384 signature.
    pub signature: Vec<u8>,
}

impl CoseSign1 {
    /// Parse a COSE_Sign1 structure: a four-element array holding the protected
    /// header, the unprotected header, the payload and the signature.
    pub fn parse(bytes: &[u8]) -> CryptoResult<Self> {
        let value = cbor::decode(bytes)?;
        let items = value.as_array("COSE_Sign1")?;
        if items.len() != 4 {
            return Err(CryptoError::AttestationFailed(format!(
                "a COSE_Sign1 structure has four elements; this one has {}",
                items.len()
            )));
        }

        let protected = items[0].as_bytes("COSE protected header")?.to_vec();
        let payload = items[2].as_bytes("COSE payload")?.to_vec();
        let signature = items[3].as_bytes("COSE signature")?.to_vec();

        // The algorithm is read from the *protected* header, which the
        // signature covers. The unprotected header is not signed, so anything
        // it claims is a claim by whoever last touched the document.
        let header = cbor::decode(&protected)?;
        let alg = header
            .get_int(COSE_HEADER_ALG, "COSE protected header")?
            .ok_or_else(|| {
                CryptoError::AttestationFailed(
                    "the COSE protected header names no signature algorithm".into(),
                )
            })?
            .as_i64("alg")?;
        if alg != COSE_ALG_ES384 {
            return Err(CryptoError::AttestationFailed(format!(
                "the document is signed with COSE algorithm {}, but a Nitro attestation \
                 document uses {} (ES384, ECDSA P-384 with SHA-384)",
                alg, COSE_ALG_ES384
            )));
        }

        if signature.len() != ES384_SIGNATURE_LEN {
            return Err(CryptoError::AttestationFailed(format!(
                "an ES384 signature is {} bytes; this one is {}",
                ES384_SIGNATURE_LEN,
                signature.len()
            )));
        }

        if payload.is_empty() {
            return Err(CryptoError::AttestationFailed(
                "the COSE_Sign1 carries no payload, so there is no attestation document \
                 in it to verify"
                    .into(),
            ));
        }

        Ok(CoseSign1 {
            protected,
            payload,
            signature,
        })
    }

    /// The bytes the signature is actually computed over.
    pub fn signed_bytes(&self) -> Vec<u8> {
        cbor::sig_structure_single_signer(&self.protected, &[], &self.payload)
    }
}

/// The contents of a Nitro attestation document.
#[derive(Debug, Clone)]
pub struct NitroAttestationDoc {
    /// The enclave's module ID, e.g. `i-0abc...-enc0123...`.
    pub module_id: String,
    /// Milliseconds since the Unix epoch, as the NSM saw it.
    pub timestamp_ms: u64,
    /// The PCR hash algorithm the document declares. Always `SHA384`.
    pub digest: String,
    /// Platform configuration registers, by index.
    ///
    /// A `BTreeMap` so an operator reviewing pinned values, and a diff between
    /// two pinnings, come out in index order.
    pub pcrs: BTreeMap<u8, Vec<u8>>,
    /// The leaf certificate, DER, whose key signed this document.
    pub certificate: Vec<u8>,
    /// The certificate bundle, DER, **root first**, the order AWS emits.
    pub cabundle: Vec<Vec<u8>>,
    /// Caller-supplied public key, if the enclave asked for one to be included.
    pub public_key: Option<Vec<u8>>,
    /// Caller-supplied user data.
    pub user_data: Option<Vec<u8>>,
    /// Caller-supplied nonce; where Cordon puts its challenge.
    pub nonce: Option<Vec<u8>>,
}

impl NitroAttestationDoc {
    /// Parse the CBOR payload of a COSE_Sign1.
    pub fn parse(payload: &[u8]) -> CryptoResult<Self> {
        let doc = cbor::decode(payload)?;

        let module_id = doc.require("module_id")?.as_text("module_id")?.to_string();
        if module_id.is_empty() {
            return Err(CryptoError::AttestationFailed(
                "the attestation document names no enclave".into(),
            ));
        }

        let timestamp_ms = doc.require("timestamp")?.as_u64("timestamp")?;

        let digest = doc.require("digest")?.as_text("digest")?.to_string();
        if digest != "SHA384" {
            return Err(CryptoError::AttestationFailed(format!(
                "the attestation document declares PCR digest `{}`; Cordon verifies \
                 SHA384, which is what the Nitro Security Module emits",
                digest
            )));
        }

        let mut pcrs = BTreeMap::new();
        for (key, value) in doc.require("pcrs")?.as_map("pcrs")? {
            let index = key.as_u64("PCR index")?;
            if index >= PCR_COUNT {
                return Err(CryptoError::AttestationFailed(format!(
                    "the attestation document reports PCR {}, but the Nitro Security \
                     Module has {} of them",
                    index, PCR_COUNT
                )));
            }
            let bytes = value.as_bytes("PCR value")?;
            if bytes.len() != PCR_LEN {
                return Err(CryptoError::AttestationFailed(format!(
                    "PCR {} is {} bytes; a SHA-384 measurement is {}",
                    index,
                    bytes.len(),
                    PCR_LEN
                )));
            }
            if pcrs.insert(index as u8, bytes.to_vec()).is_some() {
                return Err(CryptoError::AttestationFailed(format!(
                    "the attestation document reports PCR {} twice",
                    index
                )));
            }
        }
        if pcrs.is_empty() {
            return Err(CryptoError::AttestationFailed(
                "the attestation document reports no PCRs, so there is nothing in it \
                 that identifies which enclave image is running"
                    .into(),
            ));
        }

        let certificate = doc
            .require("certificate")?
            .as_bytes("certificate")?
            .to_vec();
        if certificate.is_empty() {
            return Err(CryptoError::AttestationFailed(
                "the attestation document carries an empty certificate".into(),
            ));
        }

        let mut cabundle = Vec::new();
        for (i, entry) in doc
            .require("cabundle")?
            .as_array("cabundle")?
            .iter()
            .enumerate()
        {
            let der = entry.as_bytes("cabundle entry")?;
            if der.is_empty() {
                return Err(CryptoError::AttestationFailed(format!(
                    "cabundle entry {} is empty",
                    i
                )));
            }
            cabundle.push(der.to_vec());
        }
        if cabundle.is_empty() {
            return Err(CryptoError::AttestationFailed(
                "the attestation document carries no certificate bundle, so its leaf \
                 certificate chains to nothing"
                    .into(),
            ));
        }

        let public_key = optional_bytes(&doc, "public_key", MAX_PUBLIC_KEY_LEN)?;
        let user_data = optional_bytes(&doc, "user_data", MAX_USER_DATA_LEN)?;
        let nonce = optional_bytes(&doc, "nonce", MAX_NONCE_LEN)?;

        Ok(NitroAttestationDoc {
            module_id,
            timestamp_ms,
            digest,
            pcrs,
            certificate,
            cabundle,
            public_key,
            user_data,
            nonce,
        })
    }

    /// A PCR as lowercase hex, for display and for comparison against a pin.
    pub fn pcr_hex(&self, index: u8) -> Option<String> {
        self.pcrs.get(&index).map(hex::encode)
    }

    /// Every PCR as hex, in index order; what `cordon attest --pin` writes out.
    pub fn pcrs_hex(&self) -> BTreeMap<u8, String> {
        self.pcrs
            .iter()
            .map(|(i, v)| (*i, hex::encode(v)))
            .collect()
    }

    /// The certificates between the leaf and the root, ordered leaf-ward first.
    ///
    /// AWS emits `cabundle` root-first, and the first entry is its own copy of
    /// the root, which a verifier must not use, since a document that supplies
    /// its own root proves only that its author owns a key. The root comes from
    /// the operator's configuration instead, so that entry is dropped here and
    /// the rest reversed.
    fn intermediates(&self) -> Vec<&[u8]> {
        self.cabundle
            .iter()
            .skip(1)
            .rev()
            .map(|der| der.as_slice())
            .collect()
    }
}

fn optional_bytes(doc: &CborValue, key: &str, max: usize) -> CryptoResult<Option<Vec<u8>>> {
    match doc.get(key)? {
        None => Ok(None),
        Some(v) if v.is_null() => Ok(None),
        Some(v) => {
            let bytes = v.as_bytes(key)?;
            if bytes.len() > max {
                return Err(CryptoError::AttestationFailed(format!(
                    "`{}` is {} bytes; the Nitro Security Module accepts at most {}",
                    key,
                    bytes.len(),
                    max
                )));
            }
            if bytes.is_empty() {
                Ok(None)
            } else {
                Ok(Some(bytes.to_vec()))
            }
        }
    }
}

/// What an operator pins for a Nitro deployment.
#[derive(Debug, Clone, Default)]
pub struct NitroExpectations {
    /// The AWS Nitro Enclaves root CA, DER.
    ///
    /// Pinned rather than taken from the document's own `cabundle`: a chain is
    /// only worth walking if its far end is something you trusted beforehand.
    pub root_der: Vec<u8>,
    /// PCR values that must match, as lowercase hex, by index.
    ///
    /// Pin at least PCR0 (the enclave image), and PCR1 and PCR2 if you want to
    /// distinguish the kernel and the application within it. PCRs left out of
    /// this map are reported but not enforced; pinning PCR4 (the instance ID)
    /// ties the deployment to one machine, which is sometimes what you want and
    /// usually not.
    pub pcrs: BTreeMap<u8, String>,
    /// How stale a document may be.
    ///
    /// The nonce is the primary defence against replay; this is a second bound
    /// for the case where a document is presented outside a challenge/response
    /// exchange. Zero disables the check.
    pub max_age_seconds: u64,
}

/// What verifying a Nitro document established, reported as separate facts.
#[derive(Debug, Clone, Default)]
pub struct NitroVerification {
    /// The COSE signature holds under the document's own leaf certificate.
    pub signature_valid: bool,
    /// The leaf chains to the pinned AWS root.
    pub certificate_chain_valid: bool,
    /// Every certificate in the chain is inside its validity window.
    pub chain_currently_valid: bool,
    /// The document's nonce equals the challenge the verifier issued.
    pub nonce_matches: bool,
    /// Every pinned PCR is present and equal.
    pub pcrs_match: bool,
    /// The document is no older than the configured bound.
    pub fresh: bool,
}

impl NitroVerification {
    /// Whether every check passed.
    pub fn is_fully_verified(&self) -> bool {
        self.signature_valid
            && self.certificate_chain_valid
            && self.chain_currently_valid
            && self.nonce_matches
            && self.pcrs_match
            && self.fresh
    }

    /// The first failure, phrased so an operator knows what it means.
    ///
    /// Ordered from "this is not a genuine document" outward to "this is a
    /// genuine document that does not describe what you expected", because
    /// those call for very different responses.
    pub fn first_failure(&self) -> Option<&'static str> {
        if !self.signature_valid {
            Some(
                "the attestation document's signature does not verify under the certificate \
                 it carries, so the document has been altered or was never signed by an NSM",
            )
        } else if !self.certificate_chain_valid {
            Some(
                "the document's certificate does not chain to the pinned AWS Nitro root, so \
                 it was signed by something other than genuine Nitro hardware; a valid \
                 signature under an unknown key proves only that its author owns that key",
            )
        } else if !self.chain_currently_valid {
            Some(
                "a certificate in the chain is outside its validity window; a Nitro leaf \
                 certificate lives about three hours, so this document is stale rather than \
                 forged",
            )
        } else if !self.nonce_matches {
            Some(
                "the document does not commit to this request's challenge, so it may be a \
                 genuine document captured from an earlier exchange and replayed",
            )
        } else if !self.pcrs_match {
            Some(
                "the enclave's measurements do not match the pinned values: this is genuine \
                 Nitro hardware running something other than the image you pinned",
            )
        } else if !self.fresh {
            Some("the attestation document is older than the configured freshness bound")
        } else {
            None
        }
    }
}

/// Verify a Nitro attestation document end to end.
///
/// * `document`, the raw COSE_Sign1 bytes as the NSM produced them.
/// * `expected_challenge`, the bytes the document's `nonce` must equal. Unlike
///   SEV-SNP's fixed 64-byte `REPORT_DATA`, Nitro's nonce is variable-length, so
///   the challenge goes in unpadded and is compared at its own length.
/// * `expectations`; what the operator pinned.
/// * `now_ms`, the verifier's clock, milliseconds since the Unix epoch. Passed
///   in rather than read here so freshness is testable.
pub fn verify_document(
    document: &[u8],
    expected_challenge: &[u8],
    expectations: &NitroExpectations,
    now_ms: u64,
) -> CryptoResult<(NitroAttestationDoc, NitroVerification)> {
    let envelope = CoseSign1::parse(document)?;
    let doc = NitroAttestationDoc::parse(&envelope.payload)?;

    // The signature, under the key in the document's own leaf certificate. This
    // establishes internal consistency and nothing more; the chain walk below
    // is what makes it mean something.
    let signature_valid = {
        use ring::signature;
        let key = crate::x509_chain::public_key_bytes(&doc.certificate)?;
        signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, &key)
            .verify(&envelope.signed_bytes(), &envelope.signature)
            .is_ok()
    };

    let certificate_chain_valid = if expectations.root_der.is_empty() {
        // Nothing pinned means nothing checked. Reporting `true` here would be
        // the single most dangerous default this module could have.
        false
    } else {
        crate::x509_chain::verify_chain_to_root(
            &doc.certificate,
            &doc.intermediates(),
            &expectations.root_der,
        )?
    };

    let chain_currently_valid = {
        let mut valid = crate::x509_chain::is_currently_valid(&doc.certificate)?;
        for der in &doc.cabundle {
            valid &= crate::x509_chain::is_currently_valid(der)?;
        }
        valid
    };

    let nonce_matches = match (&doc.nonce, expected_challenge.is_empty()) {
        // An empty expected challenge means the caller issued none. That is not
        // a match; it is an unbound document.
        (_, true) => false,
        (None, _) => false,
        (Some(nonce), _) => crate::kdf::ct_eq(nonce, expected_challenge),
    };

    let pcrs_match = if expectations.pcrs.is_empty() {
        // As with the root: pinning nothing checks nothing.
        false
    } else {
        expectations.pcrs.iter().all(|(index, expected)| {
            doc.pcr_hex(*index).is_some_and(|actual| {
                crate::kdf::ct_eq(actual.as_bytes(), expected.to_lowercase().as_bytes())
            })
        })
    };

    let fresh = if expectations.max_age_seconds == 0 {
        true
    } else {
        // A document timestamped in the future is not fresh, it is wrong; but
        // small clock skew between the enclave and the verifier is ordinary, so
        // the future side is bounded by the same window rather than refused
        // outright.
        let window_ms = expectations.max_age_seconds.saturating_mul(1000);
        now_ms.abs_diff(doc.timestamp_ms) <= window_ms
    };

    Ok((
        doc,
        NitroVerification {
            signature_valid,
            certificate_chain_valid,
            chain_currently_valid,
            nonce_matches,
            pcrs_match,
            fresh,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal CBOR writers, enough to build a document the parser must accept.
    /// Deliberately separate from the reader so a bug in one cannot hide a bug
    /// in the other.
    mod build {
        pub fn header(out: &mut Vec<u8>, major: u8, argument: u64) {
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
                // A millisecond timestamp does not fit in 32 bits. Leaving this
                // arm out truncated it silently, which is how the freshness
                // test came to fail against a correct implementation.
                _ => {
                    out.push(major | 27);
                    out.extend_from_slice(&argument.to_be_bytes());
                }
            }
        }
        pub fn bytes(out: &mut Vec<u8>, b: &[u8]) {
            header(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        pub fn text(out: &mut Vec<u8>, t: &str) {
            header(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        }
        pub fn uint(out: &mut Vec<u8>, n: u64) {
            header(out, 0, n);
        }
        pub fn nint(out: &mut Vec<u8>, n: i64) {
            header(out, 1, (-1 - n) as u64);
        }
        pub fn array(out: &mut Vec<u8>, n: u64) {
            header(out, 4, n);
        }
        pub fn map(out: &mut Vec<u8>, n: u64) {
            header(out, 5, n);
        }
        pub fn null(out: &mut Vec<u8>) {
            out.push(0xF6);
        }
    }

    use rcgen::{Certificate, CertificateParams, DnType, IsCa, KeyPair, PKCS_ECDSA_P384_SHA384};
    use ring::signature::{EcdsaKeyPair, ECDSA_P384_SHA384_FIXED_SIGNING};

    fn ca(name: &str) -> Certificate {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.alg = &PKCS_ECDSA_P384_SHA384;
        params.key_pair = Some(KeyPair::generate(&PKCS_ECDSA_P384_SHA384).unwrap());
        Certificate::from_params(params).unwrap()
    }

    /// A leaf whose private key is available to `ring`, so the test can sign
    /// with the same key the certificate publishes.
    fn leaf_with_key(name: &str) -> (Certificate, EcdsaKeyPair) {
        let key_pair = KeyPair::generate(&PKCS_ECDSA_P384_SHA384).unwrap();
        let pkcs8 = key_pair.serialize_der();
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, name);
        params.alg = &PKCS_ECDSA_P384_SHA384;
        params.key_pair = Some(key_pair);
        let cert = Certificate::from_params(params).unwrap();

        let rng = ring::rand::SystemRandom::new();
        let signing =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &pkcs8, &rng).unwrap();
        (cert, signing)
    }

    struct Fixture {
        document: Vec<u8>,
        root_der: Vec<u8>,
        challenge: Vec<u8>,
        pcr0: String,
        timestamp_ms: u64,
    }

    /// Assemble a document laid out the way an NSM lays one out, signed with a
    /// real ES384 signature by a leaf that really chains to the root.
    fn fixture() -> Fixture {
        FixtureBuilder::default().build()
    }

    #[derive(Default)]
    struct FixtureBuilder {
        omit_nonce: bool,
        wrong_pcr: bool,
        detached_root: bool,
        corrupt_signature: bool,
        rewrite_protected_header: bool,
        /// Override the COSE algorithm in the protected header. `None` means
        /// ES384, which is what an NSM emits.
        cose_alg: Option<i64>,
    }

    impl FixtureBuilder {
        fn build(self) -> Fixture {
            let root = ca("AWS Nitro Enclaves Root - TEST");
            let intermediate = ca("aws.nitro-enclaves TEST intermediate");
            let (leaf, signing_key) = leaf_with_key("i-0123456789abcdef0-enc0123456789abcdef");

            let root_der = root.serialize_der().unwrap();
            let intermediate_der = intermediate.serialize_der_with_signer(&root).unwrap();
            let leaf_der = leaf.serialize_der_with_signer(&intermediate).unwrap();

            let challenge = vec![0xC1u8; 32];
            let pcr0 = vec![0xA0u8; PCR_LEN];
            let pcr1 = vec![0xA1u8; PCR_LEN];
            let pcr2 = vec![0xA2u8; PCR_LEN];
            let timestamp_ms = 1_760_000_000_000u64;

            // The payload map: nine keys, in the order AWS emits them.
            let mut payload = Vec::new();
            build::map(&mut payload, 9);

            build::text(&mut payload, "module_id");
            build::text(&mut payload, "i-0123456789abcdef0-enc0123456789abcdef");

            build::text(&mut payload, "digest");
            build::text(&mut payload, "SHA384");

            build::text(&mut payload, "timestamp");
            build::uint(&mut payload, timestamp_ms);

            build::text(&mut payload, "pcrs");
            build::map(&mut payload, 3);
            build::uint(&mut payload, 0);
            build::bytes(&mut payload, if self.wrong_pcr { &pcr1 } else { &pcr0 });
            build::uint(&mut payload, 1);
            build::bytes(&mut payload, &pcr1);
            build::uint(&mut payload, 2);
            build::bytes(&mut payload, &pcr2);

            build::text(&mut payload, "certificate");
            build::bytes(&mut payload, &leaf_der);

            build::text(&mut payload, "cabundle");
            if self.detached_root {
                // A bundle that omits the root entirely.
                build::array(&mut payload, 1);
                build::bytes(&mut payload, &intermediate_der);
            } else {
                build::array(&mut payload, 2);
                build::bytes(&mut payload, &root_der); // AWS emits root first
                build::bytes(&mut payload, &intermediate_der);
            }

            build::text(&mut payload, "public_key");
            build::null(&mut payload);

            build::text(&mut payload, "user_data");
            build::null(&mut payload);

            build::text(&mut payload, "nonce");
            if self.omit_nonce {
                build::null(&mut payload);
            } else {
                build::bytes(&mut payload, &challenge);
            }

            // The protected header: {1: -35}.
            let mut protected = Vec::new();
            build::map(&mut protected, 1);
            build::uint(&mut protected, 1);
            build::nint(&mut protected, self.cose_alg.unwrap_or(COSE_ALG_ES384));

            // Sign the Sig_structure, exactly as COSE specifies.
            let signed = cbor::sig_structure_single_signer(&protected, &[], &payload);
            let rng = ring::rand::SystemRandom::new();
            let mut signature = signing_key.sign(&rng, &signed).unwrap().as_ref().to_vec();
            if self.corrupt_signature {
                signature[0] ^= 0xFF;
            }

            // Optionally rewrite the protected header *after* signing, which is
            // exactly the attack the Sig_structure exists to prevent.
            if self.rewrite_protected_header {
                protected.clear();
                build::map(&mut protected, 2);
                build::uint(&mut protected, 1);
                build::nint(&mut protected, COSE_ALG_ES384);
                build::uint(&mut protected, 99);
                build::uint(&mut protected, 1);
            }

            let mut document = Vec::new();
            build::array(&mut document, 4);
            build::bytes(&mut document, &protected);
            build::map(&mut document, 0); // unprotected header
            build::bytes(&mut document, &payload);
            build::bytes(&mut document, &signature);

            Fixture {
                document,
                root_der,
                challenge,
                pcr0: hex::encode(&pcr0),
                timestamp_ms,
            }
        }
    }

    fn expectations(f: &Fixture) -> NitroExpectations {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0u8, f.pcr0.clone());
        NitroExpectations {
            root_der: f.root_der.clone(),
            pcrs,
            max_age_seconds: 300,
        }
    }

    #[test]
    fn a_genuine_document_verifies_on_every_count() {
        let f = fixture();
        let (doc, v) =
            verify_document(&f.document, &f.challenge, &expectations(&f), f.timestamp_ms).unwrap();

        assert!(v.signature_valid, "signature");
        assert!(v.certificate_chain_valid, "chain");
        assert!(v.chain_currently_valid, "validity window");
        assert!(v.nonce_matches, "nonce");
        assert!(v.pcrs_match, "pcrs");
        assert!(v.fresh, "freshness");
        assert!(v.is_fully_verified());
        assert_eq!(v.first_failure(), None);

        assert_eq!(doc.digest, "SHA384");
        assert_eq!(doc.pcrs.len(), 3);
        assert_eq!(doc.pcr_hex(0).unwrap(), f.pcr0);
        assert!(doc.module_id.starts_with("i-"));
        assert_eq!(doc.timestamp_ms, f.timestamp_ms);
    }

    #[test]
    fn a_flipped_signature_bit_fails_the_signature_and_nothing_else() {
        let f = FixtureBuilder {
            corrupt_signature: true,
            ..Default::default()
        }
        .build();
        let (_, v) =
            verify_document(&f.document, &f.challenge, &expectations(&f), f.timestamp_ms).unwrap();

        assert!(!v.signature_valid);
        // The other facts are still established; reporting them separately is
        // what lets an operator tell a corrupted document from a wrong one.
        assert!(v.certificate_chain_valid);
        assert!(v.pcrs_match);
        assert!(v.first_failure().unwrap().contains("has been altered"));
    }

    /// The whole reason COSE signs a `Sig_structure` rather than the payload:
    /// the protected header names the algorithm, so leaving it uncovered would
    /// let an attacker downgrade it after the fact.
    #[test]
    fn rewriting_the_protected_header_after_signing_breaks_the_signature() {
        let f = FixtureBuilder {
            rewrite_protected_header: true,
            ..Default::default()
        }
        .build();
        let (_, v) =
            verify_document(&f.document, &f.challenge, &expectations(&f), f.timestamp_ms).unwrap();
        assert!(!v.signature_valid);
    }

    /// A perfectly-signed document from a key nobody trusts.
    #[test]
    fn a_document_signed_by_an_attackers_own_chain_fails_the_pinned_root() {
        let f = fixture();
        let mut expected = expectations(&f);
        expected.root_der = ca("some other root").serialize_der().unwrap();

        let (_, v) = verify_document(&f.document, &f.challenge, &expected, f.timestamp_ms).unwrap();

        assert!(
            v.signature_valid,
            "it is a well-formed, correctly signed document"
        );
        assert!(
            !v.certificate_chain_valid,
            "but not one from the pinned root"
        );
        assert!(v
            .first_failure()
            .unwrap()
            .contains("chain to the pinned AWS Nitro root"));
    }

    /// Pinning nothing must check nothing, and say so, rather than passing.
    #[test]
    fn an_unpinned_root_is_a_failure_not_a_pass() {
        let f = fixture();
        let mut expected = expectations(&f);
        expected.root_der.clear();

        let (_, v) = verify_document(&f.document, &f.challenge, &expected, f.timestamp_ms).unwrap();
        assert!(v.signature_valid);
        assert!(!v.certificate_chain_valid);
    }

    #[test]
    fn an_unpinned_pcr_set_is_a_failure_not_a_pass() {
        let f = fixture();
        let mut expected = expectations(&f);
        expected.pcrs.clear();

        let (_, v) = verify_document(&f.document, &f.challenge, &expected, f.timestamp_ms).unwrap();
        assert!(!v.pcrs_match);
    }

    /// Genuine hardware, wrong image. This is the case PCR pinning exists for,
    /// and its message has to be distinguishable from a forgery.
    #[test]
    fn genuine_hardware_running_the_wrong_image_fails_on_measurements() {
        let f = FixtureBuilder {
            wrong_pcr: true,
            ..Default::default()
        }
        .build();
        let mut expected = expectations(&f);
        expected.pcrs.insert(0, "a0".repeat(PCR_LEN));

        let (_, v) = verify_document(&f.document, &f.challenge, &expected, f.timestamp_ms).unwrap();

        assert!(v.signature_valid && v.certificate_chain_valid);
        assert!(!v.pcrs_match);
        assert!(v
            .first_failure()
            .unwrap()
            .contains("other than the image you pinned"));
    }

    /// A pinned PCR the document does not report must not pass by absence.
    #[test]
    fn a_pinned_pcr_the_document_omits_does_not_pass() {
        let f = fixture();
        let mut expected = expectations(&f);
        expected.pcrs.insert(8, "ff".repeat(PCR_LEN));

        let (_, v) = verify_document(&f.document, &f.challenge, &expected, f.timestamp_ms).unwrap();
        assert!(!v.pcrs_match);
    }

    #[test]
    fn a_document_bound_to_a_different_challenge_fails_the_nonce() {
        let f = fixture();
        let (_, v) = verify_document(
            &f.document,
            &[0xEEu8; 32],
            &expectations(&f),
            f.timestamp_ms,
        )
        .unwrap();

        assert!(v.signature_valid && v.certificate_chain_valid && v.pcrs_match);
        assert!(!v.nonce_matches);
        assert!(v.first_failure().unwrap().contains("replayed"));
    }

    /// A document carrying no nonce is unbound, which is a failure rather than
    /// a case where the nonce check does not apply.
    #[test]
    fn a_document_with_no_nonce_is_unbound() {
        let f = FixtureBuilder {
            omit_nonce: true,
            ..Default::default()
        }
        .build();
        let (doc, v) =
            verify_document(&f.document, &f.challenge, &expectations(&f), f.timestamp_ms).unwrap();
        assert!(doc.nonce.is_none());
        assert!(!v.nonce_matches);
    }

    /// And a verifier that issued no challenge has not bound anything either.
    #[test]
    fn an_empty_challenge_never_matches() {
        let f = fixture();
        let (_, v) = verify_document(&f.document, &[], &expectations(&f), f.timestamp_ms).unwrap();
        assert!(!v.nonce_matches);
    }

    #[test]
    fn a_stale_document_fails_freshness_in_both_directions() {
        let f = fixture();
        let expected = expectations(&f); // 300-second window

        let (_, old) = verify_document(
            &f.document,
            &f.challenge,
            &expected,
            f.timestamp_ms + 301_000,
        )
        .unwrap();
        assert!(!old.fresh);

        let (_, future) = verify_document(
            &f.document,
            &f.challenge,
            &expected,
            f.timestamp_ms - 301_000,
        )
        .unwrap();
        assert!(
            !future.fresh,
            "a document from the future is not fresh either"
        );

        let (_, skewed) = verify_document(
            &f.document,
            &f.challenge,
            &expected,
            f.timestamp_ms + 299_000,
        )
        .unwrap();
        assert!(skewed.fresh, "ordinary clock skew is not a failure");
    }

    /// The document supplies its own copy of the root and the verifier must not
    /// use it, so dropping the first bundle entry cannot break a chain that
    /// otherwise reaches the pinned root.
    #[test]
    fn the_bundles_own_root_entry_is_ignored() {
        let with_root = fixture();
        let without_root = FixtureBuilder {
            detached_root: true,
            ..Default::default()
        }
        .build();

        let (doc, _) = verify_document(
            &with_root.document,
            &with_root.challenge,
            &expectations(&with_root),
            with_root.timestamp_ms,
        )
        .unwrap();
        assert_eq!(doc.cabundle.len(), 2);
        assert_eq!(doc.intermediates().len(), 1, "the root entry is dropped");

        // A bundle holding only the intermediate has that intermediate at
        // index 0, so it is dropped and the leaf is checked directly against
        // the root, which fails, correctly, because the intermediate is
        // missing from the walk.
        let (_, v) = verify_document(
            &without_root.document,
            &without_root.challenge,
            &expectations(&without_root),
            without_root.timestamp_ms,
        )
        .unwrap();
        assert!(!v.certificate_chain_valid);
    }

    /// An algorithm other than ES384 is refused when the envelope is parsed,
    /// before any key is fetched. Verifying it under P-384 anyway would be an
    /// algorithm-confusion bug waiting for someone to find a curve where the
    /// same bytes mean something different.
    #[test]
    fn a_document_signed_with_the_wrong_cose_algorithm_is_refused_outright() {
        for alg in [
            -7,  /* ES256 */
            -36, /* ES512 */
            -8,  /* EdDSA */
        ] {
            let f = FixtureBuilder {
                cose_alg: Some(alg),
                ..Default::default()
            }
            .build();
            let error = CoseSign1::parse(&f.document).unwrap_err().to_string();
            assert!(error.contains("ES384"), "alg {}: {}", alg, error);
            assert!(error.contains(&alg.to_string()), "alg {}: {}", alg, error);
        }
    }

    /// A protected header with no algorithm at all is refused too, rather than
    /// defaulting to the one the verifier hopes for.
    #[test]
    fn a_protected_header_naming_no_algorithm_is_refused() {
        let mut document = Vec::new();
        build::array(&mut document, 4);
        build::bytes(&mut document, &[0xA0]); // empty map
        build::map(&mut document, 0);
        build::bytes(&mut document, &[0x00]);
        build::bytes(&mut document, &[0u8; ES384_SIGNATURE_LEN]);

        let error = CoseSign1::parse(&document).unwrap_err().to_string();
        assert!(error.contains("names no signature algorithm"), "{}", error);
    }

    /// A signature of the wrong length is a malformed document, not a failed
    /// verification; `ring` would refuse it either way, but saying so at parse
    /// time gives an operator a message they can act on.
    #[test]
    fn a_signature_of_the_wrong_length_is_refused_at_parse_time() {
        let mut document = Vec::new();
        build::array(&mut document, 4);
        build::bytes(&mut document, &[0xA1, 0x01, 0x38, 0x22]);
        build::map(&mut document, 0);
        build::bytes(&mut document, &[0x00]);
        build::bytes(&mut document, &[0u8; 64]); // P-256 sized

        let error = CoseSign1::parse(&document).unwrap_err().to_string();
        assert!(error.contains("96 bytes"), "{}", error);
    }

    /// An envelope with an empty payload has nothing in it to verify, and must
    /// say that rather than parsing an empty document into empty fields.
    #[test]
    fn an_envelope_with_no_payload_is_refused() {
        let mut document = Vec::new();
        build::array(&mut document, 4);
        build::bytes(&mut document, &[0xA1, 0x01, 0x38, 0x22]);
        build::map(&mut document, 0);
        build::bytes(&mut document, &[]);
        build::bytes(&mut document, &[0u8; ES384_SIGNATURE_LEN]);

        let error = CoseSign1::parse(&document).unwrap_err().to_string();
        assert!(error.contains("no payload"), "{}", error);
    }

    #[test]
    fn a_cose_structure_of_the_wrong_shape_is_refused() {
        let mut document = Vec::new();
        build::array(&mut document, 3);
        build::bytes(&mut document, &[0xA1, 0x01, 0x38, 0x22]);
        build::map(&mut document, 0);
        build::bytes(&mut document, &[0x00]);

        let error = CoseSign1::parse(&document).unwrap_err().to_string();
        assert!(error.contains("four elements"), "{}", error);
    }

    #[test]
    fn a_document_missing_a_required_field_says_which_one() {
        let mut payload = Vec::new();
        build::map(&mut payload, 1);
        build::text(&mut payload, "module_id");
        build::text(&mut payload, "i-0-enc0");

        let error = NitroAttestationDoc::parse(&payload)
            .unwrap_err()
            .to_string();
        assert!(error.contains("timestamp"), "{}", error);
    }

    #[test]
    fn a_pcr_of_the_wrong_length_is_refused() {
        let mut payload = Vec::new();
        build::map(&mut payload, 4);
        build::text(&mut payload, "module_id");
        build::text(&mut payload, "i-0-enc0");
        build::text(&mut payload, "timestamp");
        build::uint(&mut payload, 1);
        build::text(&mut payload, "digest");
        build::text(&mut payload, "SHA384");
        build::text(&mut payload, "pcrs");
        build::map(&mut payload, 1);
        build::uint(&mut payload, 0);
        build::bytes(&mut payload, &[0u8; 32]); // SHA-256 sized

        let error = NitroAttestationDoc::parse(&payload)
            .unwrap_err()
            .to_string();
        assert!(error.contains("SHA-384 measurement"), "{}", error);
    }

    #[test]
    fn a_document_declaring_a_different_pcr_digest_is_refused() {
        let mut payload = Vec::new();
        build::map(&mut payload, 3);
        build::text(&mut payload, "module_id");
        build::text(&mut payload, "i-0-enc0");
        build::text(&mut payload, "timestamp");
        build::uint(&mut payload, 1);
        build::text(&mut payload, "digest");
        build::text(&mut payload, "SHA256");

        let error = NitroAttestationDoc::parse(&payload)
            .unwrap_err()
            .to_string();
        assert!(error.contains("SHA384"), "{}", error);
    }

    #[test]
    fn an_oversized_nonce_is_refused_before_it_is_compared() {
        let mut payload = Vec::new();
        build::map(&mut payload, 1);
        build::text(&mut payload, "nonce");
        build::bytes(&mut payload, &vec![0u8; MAX_NONCE_LEN + 1]);
        let doc = cbor::decode(&payload).unwrap();

        let error = optional_bytes(&doc, "nonce", MAX_NONCE_LEN)
            .unwrap_err()
            .to_string();
        assert!(error.contains("at most"), "{}", error);
    }

    /// Every failure path must produce a message that says what happened, not
    /// a bare `false`.
    #[test]
    fn every_failure_has_something_to_say() {
        let cases = [
            NitroVerification::default(),
            NitroVerification {
                signature_valid: true,
                ..Default::default()
            },
            NitroVerification {
                signature_valid: true,
                certificate_chain_valid: true,
                ..Default::default()
            },
            NitroVerification {
                signature_valid: true,
                certificate_chain_valid: true,
                chain_currently_valid: true,
                ..Default::default()
            },
            NitroVerification {
                signature_valid: true,
                certificate_chain_valid: true,
                chain_currently_valid: true,
                nonce_matches: true,
                ..Default::default()
            },
            NitroVerification {
                signature_valid: true,
                certificate_chain_valid: true,
                chain_currently_valid: true,
                nonce_matches: true,
                pcrs_match: true,
                ..Default::default()
            },
        ];
        for (i, case) in cases.iter().enumerate() {
            assert!(!case.is_fully_verified(), "case {}", i);
            let message = case.first_failure().unwrap_or_else(|| panic!("case {}", i));
            assert!(
                message.len() > 40,
                "case {} says too little: {}",
                i,
                message
            );
        }
    }
}
