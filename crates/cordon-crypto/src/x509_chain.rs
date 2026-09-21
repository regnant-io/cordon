//! Walking an X.509 chain to a root the verifier already trusts.
//!
//! Two attestation sources need this and they need it to behave identically.
//! AMD SEV-SNP presents a VCEK endorsed by AMD; AWS Nitro presents a per-enclave
//! certificate endorsed by the Nitro root. In both cases the chain is delivered
//! *by the party being verified*, so the only thing that makes it worth walking
//! is that its far end is a certificate the verifier pinned in advance and did
//! not learn from the document.
//!
//! Nothing here fetches, downloads, or falls back to a system trust store. A
//! root arrives from the operator's configuration or the chain is not checked.

use crate::error::{CryptoError, CryptoResult};

/// Verify that `child` was signed by `parent`.
///
/// The signature algorithm is dispatched from the child certificate rather than
/// assumed. Assuming it would mean a chain using anything else fails with
/// "signature invalid", which reads as an attack when it is a mismatch, and
/// would quietly rule out any root an operator might reasonably pin for a
/// private deployment.
///
/// Returns `Ok(false)` when the certificates are well-formed and the signature
/// does not hold, and `Err` when something could not be checked at all. The
/// distinction matters: the first is a verdict, the second is a verifier that
/// did not run.
pub fn verify_signed_by(child_der: &[u8], parent_der: &[u8]) -> CryptoResult<bool> {
    use ring::signature;
    use x509_parser::prelude::*;

    let (_, child) = X509Certificate::from_der(child_der).map_err(|e| {
        CryptoError::AttestationFailed(format!("certificate is not valid DER X.509: {}", e))
    })?;
    let (_, parent) = X509Certificate::from_der(parent_der).map_err(|e| {
        CryptoError::AttestationFailed(format!("issuer is not valid DER X.509: {}", e))
    })?;

    // The issuer name must match before any cryptography is worth doing.
    if child.issuer() != parent.subject() {
        return Ok(false);
    }

    let signed = child.tbs_certificate.as_ref();
    let signature = child.signature_value.data.as_ref();
    let parent_key = parent.public_key().subject_public_key.data.as_ref();

    // Dispatch on the algorithm the child certificate says it was signed with.
    let algorithm = child.signature_algorithm.algorithm.to_id_string();
    let verified = match algorithm.as_str() {
        // RSASSA-PSS; what AMD uses.
        "1.2.840.113549.1.1.10" => {
            signature::UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA384, parent_key)
                .verify(signed, signature)
                .is_ok()
        }
        // sha384WithRSAEncryption
        "1.2.840.113549.1.1.12" => {
            signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA384, parent_key)
                .verify(signed, signature)
                .is_ok()
        }
        // sha256WithRSAEncryption
        "1.2.840.113549.1.1.11" => {
            signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, parent_key)
                .verify(signed, signature)
                .is_ok()
        }
        // ecdsa-with-SHA384; what AWS uses throughout the Nitro chain. X.509
        // carries ECDSA signatures ASN.1-encoded, not in the fixed-width form
        // a SEV-SNP report uses.
        "1.2.840.10045.4.3.3" => {
            signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_ASN1, parent_key)
                .verify(signed, signature)
                .is_ok()
        }
        // ecdsa-with-SHA256
        "1.2.840.10045.4.3.2" => {
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, parent_key)
                .verify(signed, signature)
                .is_ok()
        }
        other => {
            return Err(CryptoError::AttestationFailed(format!(
                "certificate is signed with algorithm {}, which Cordon does not verify. \
                 AMD's chain uses RSASSA-PSS with SHA-384 and AWS's uses ECDSA with SHA-384.",
                other
            )));
        }
    };

    Ok(verified)
}

/// Walk `leaf` through `intermediates` to `root`.
///
/// `intermediates` are ordered leaf-ward first: the certificate that signed the
/// leaf comes first, and the one signed by the root comes last. `root` is the
/// certificate the verifier pinned, and is checked as the issuer of the last
/// link rather than being taken on trust from the document.
///
/// An empty chain is not a passing chain. If `intermediates` is empty the leaf
/// must have been issued directly by the pinned root; otherwise every link is
/// checked and the walk stops at the first that fails.
pub fn verify_chain_to_root(
    leaf_der: &[u8],
    intermediates_der: &[&[u8]],
    root_der: &[u8],
) -> CryptoResult<bool> {
    let mut child = leaf_der;
    for parent in intermediates_der {
        if !verify_signed_by(child, parent)? {
            return Ok(false);
        }
        child = parent;
    }
    verify_signed_by(child, root_der)
}

/// Whether a certificate is currently within its validity window.
///
/// Reported separately from the signature rather than folded into it. An
/// expired certificate with a good signature and a forged one are different
/// problems with different responses, and an operator whose node stops working
/// deserves to be told which one they have.
pub fn is_currently_valid(cert_der: &[u8]) -> CryptoResult<bool> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
        CryptoError::AttestationFailed(format!("certificate is not valid DER X.509: {}", e))
    })?;
    Ok(cert.validity().is_valid())
}

/// The subject public key of a certificate, as the raw bytes `ring` expects.
pub fn public_key_bytes(cert_der: &[u8]) -> CryptoResult<Vec<u8>> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
        CryptoError::AttestationFailed(format!("certificate is not valid DER X.509: {}", e))
    })?;
    Ok(cert.public_key().subject_public_key.data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{Certificate, CertificateParams, DnType, IsCa, KeyPair, PKCS_ECDSA_P384_SHA384};

    fn ca(name: &str) -> Certificate {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.alg = &PKCS_ECDSA_P384_SHA384;
        params.key_pair = Some(KeyPair::generate(&PKCS_ECDSA_P384_SHA384).unwrap());
        Certificate::from_params(params).unwrap()
    }

    fn leaf(name: &str) -> Certificate {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, name);
        params.alg = &PKCS_ECDSA_P384_SHA384;
        params.key_pair = Some(KeyPair::generate(&PKCS_ECDSA_P384_SHA384).unwrap());
        Certificate::from_params(params).unwrap()
    }

    #[test]
    fn a_two_link_chain_reaches_the_pinned_root() {
        let root = ca("root");
        let intermediate = ca("intermediate");
        let end = leaf("leaf");

        let root_der = root.serialize_der().unwrap();
        let intermediate_der = intermediate.serialize_der_with_signer(&root).unwrap();
        let leaf_der = end.serialize_der_with_signer(&intermediate).unwrap();

        assert!(verify_chain_to_root(&leaf_der, &[&intermediate_der], &root_der).unwrap());
    }

    #[test]
    fn a_leaf_issued_directly_by_the_root_needs_no_intermediates() {
        let root = ca("root");
        let end = leaf("leaf");
        let root_der = root.serialize_der().unwrap();
        let leaf_der = end.serialize_der_with_signer(&root).unwrap();

        assert!(verify_chain_to_root(&leaf_der, &[], &root_der).unwrap());
    }

    /// The point of pinning: a chain that is internally perfect but ends
    /// somewhere else must not pass.
    #[test]
    fn a_self_consistent_chain_to_the_wrong_root_fails() {
        let real_root = ca("the root the operator pinned");
        let attacker_root = ca("a root the attacker made");
        let intermediate = ca("intermediate");
        let end = leaf("leaf");

        let intermediate_der = intermediate
            .serialize_der_with_signer(&attacker_root)
            .unwrap();
        let leaf_der = end.serialize_der_with_signer(&intermediate).unwrap();

        // The attacker's own chain verifies against the attacker's own root.
        let attacker_root_der = attacker_root.serialize_der().unwrap();
        assert!(verify_chain_to_root(&leaf_der, &[&intermediate_der], &attacker_root_der).unwrap());

        // Against the pinned one, it does not.
        let real_root_der = real_root.serialize_der().unwrap();
        assert!(!verify_chain_to_root(&leaf_der, &[&intermediate_der], &real_root_der).unwrap());
    }

    #[test]
    fn a_broken_link_in_the_middle_fails_the_whole_chain() {
        let root = ca("root");
        let intermediate = ca("intermediate");
        let unrelated = ca("intermediate"); // same name, different key
        let end = leaf("leaf");

        let root_der = root.serialize_der().unwrap();
        let intermediate_der = intermediate.serialize_der_with_signer(&root).unwrap();
        // The leaf is signed by `unrelated`, whose subject name matches, so the
        // name check passes and only the signature catches it.
        let leaf_der = end.serialize_der_with_signer(&unrelated).unwrap();

        assert!(!verify_chain_to_root(&leaf_der, &[&intermediate_der], &root_der).unwrap());
    }

    #[test]
    fn a_mismatched_issuer_name_fails_before_any_cryptography() {
        let root = ca("root");
        let other = ca("somebody else");
        let end = leaf("leaf");

        let leaf_der = end.serialize_der_with_signer(&root).unwrap();
        let other_der = other.serialize_der().unwrap();

        assert!(!verify_signed_by(&leaf_der, &other_der).unwrap());
    }

    /// Garbage must produce an error, not a `false` that reads as a verdict.
    #[test]
    fn bytes_that_are_not_a_certificate_are_an_error_not_a_verdict() {
        let root = ca("root").serialize_der().unwrap();
        assert!(verify_signed_by(b"not a certificate", &root).is_err());
        assert!(verify_signed_by(&root, b"not a certificate").is_err());
    }

    #[test]
    fn a_freshly_issued_certificate_is_within_its_validity_window() {
        let root = ca("root").serialize_der().unwrap();
        assert!(is_currently_valid(&root).unwrap());
    }

    #[test]
    fn the_extracted_public_key_is_the_p384_point() {
        let root = ca("root").serialize_der().unwrap();
        let key = public_key_bytes(&root).unwrap();
        assert_eq!(
            key.len(),
            97,
            "uncompressed P-384 is 0x04 plus two 48-byte coordinates"
        );
        assert_eq!(key[0], 0x04);
    }
}
