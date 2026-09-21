//! TPM 2.0 wire structures, and verification of a quote against them.
//!
//! # What a TPM quote actually is
//!
//! `tpm2_quote` produces two files. One holds a `TPMS_ATTEST` structure, the
//! message the TPM signed, and the other a `TPMT_SIGNATURE` over it. The
//! attestation is only worth anything if a verifier checks four things, in this
//! order:
//!
//! 1. The signature over `TPMS_ATTEST` verifies under the attestation key.
//! 2. The `extraData` field inside `TPMS_ATTEST` is the challenge the verifier
//!    issued, so the quote is fresh rather than replayed.
//! 3. The `pcrDigest` inside `TPMS_ATTEST` matches a digest recomputed from the
//!    PCR values the report claims, so the claimed values are the ones the TPM
//!    actually signed over.
//! 4. Those PCR values match what the operator pinned.
//!
//! Carrying a signature without the signed message makes steps 1 through 3
//! impossible: there is nothing to verify the signature against, nothing that
//! binds the nonce, and nothing that binds the PCR values. A verifier handed
//! only measurements and a signature is being asked to trust the node's own
//! summary of what the TPM said, which is the thing attestation exists to
//! avoid. This module parses the structures so all four checks can be made.
//!
//! # What this does not do
//!
//! It does not establish that the attestation key belongs to a genuine TPM.
//! That requires walking the endorsement key certificate to a TPM vendor's root
//! and confirming the AK is bound to that EK, which is a separate problem with
//! its own trust store. Until that is done, a verified quote proves the report
//! was produced by whoever holds the AK and is bound to the verifier's nonce;
//! real and useful, and short of proof that the platform is genuine hardware.
//! [`TpmQuoteVerification::ak_is_trusted`] records which of the two you have.

use crate::error::{CryptoError, CryptoResult};

/// `TPM_GENERATED_VALUE`, the magic every TPM-generated attestation begins
/// with. Its purpose is to make it impossible to get a TPM to sign an
/// attestation-shaped structure that it did not itself generate.
pub const TPM_GENERATED_VALUE: u32 = 0xFF54_4347;

/// `TPM_ST_ATTEST_QUOTE`, the structure tag for a PCR quote.
pub const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

/// `TPM_ALG_RSA`.
pub const TPM_ALG_RSA: u16 = 0x0001;
/// `TPM_ALG_ECC`.
pub const TPM_ALG_ECC: u16 = 0x0023;
/// `TPM_ALG_SHA256`.
pub const TPM_ALG_SHA256: u16 = 0x000B;
/// `TPM_ALG_NULL`.
pub const TPM_ALG_NULL: u16 = 0x0010;
/// `TPM_ALG_RSASSA`; RSA PKCS#1 v1.5 signature.
pub const TPM_ALG_RSASSA: u16 = 0x0014;
/// `TPM_ALG_RSAPSS`.
pub const TPM_ALG_RSAPSS: u16 = 0x0016;
/// `TPM_ALG_ECDSA`.
pub const TPM_ALG_ECDSA: u16 = 0x0018;

/// A cursor over a TPM structure, reading big-endian fields and refusing to run
/// off the end.
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn take(&mut self, n: usize, what: &str) -> CryptoResult<&'a [u8]> {
        if self.remaining() < n {
            return Err(CryptoError::AttestationFailed(format!(
                "TPM structure truncated: wanted {} bytes for {} at offset {}, {} remain",
                n,
                what,
                self.offset,
                self.remaining()
            )));
        }
        let slice = &self.bytes[self.offset..self.offset + n];
        self.offset += n;
        Ok(slice)
    }

    fn u8(&mut self, what: &str) -> CryptoResult<u8> {
        Ok(self.take(1, what)?[0])
    }

    fn u16(&mut self, what: &str) -> CryptoResult<u16> {
        let b = self.take(2, what)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self, what: &str) -> CryptoResult<u32> {
        let b = self.take(4, what)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self, what: &str) -> CryptoResult<u64> {
        let b = self.take(8, what)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(b);
        Ok(u64::from_be_bytes(arr))
    }

    /// A `TPM2B_*`: a 16-bit length followed by that many bytes.
    fn sized_buffer(&mut self, what: &str) -> CryptoResult<&'a [u8]> {
        let len = self.u16(what)? as usize;
        self.take(len, what)
    }
}

/// One `TPMS_PCR_SELECTION`: which PCRs, in which bank, a quote covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrSelection {
    /// Hash algorithm of the bank, e.g. [`TPM_ALG_SHA256`].
    pub hash_alg: u16,
    /// Selected PCR indices, ascending.
    pub indices: Vec<u8>,
}

/// A parsed `TPMS_ATTEST` carrying a `TPMS_QUOTE_INFO`.
#[derive(Debug, Clone)]
pub struct AttestQuote {
    /// The `qualifiedSigner` name of the attestation key.
    pub qualified_signer: Vec<u8>,
    /// `extraData`, the challenge the verifier supplied. This is what makes a
    /// quote fresh rather than replayable.
    pub extra_data: Vec<u8>,
    /// TPM clock at the time of the quote, in milliseconds since TPM start.
    pub clock: u64,
    /// Number of TPM resets since the clock was last set.
    pub reset_count: u32,
    /// Number of TPM restarts.
    pub restart_count: u32,
    /// Whether the TPM considers its clock trustworthy.
    pub clock_safe: bool,
    /// Firmware version reported by the TPM.
    pub firmware_version: u64,
    /// Which PCRs this quote covers.
    pub pcr_selections: Vec<PcrSelection>,
    /// The digest the TPM computed over the selected PCRs.
    pub pcr_digest: Vec<u8>,
}

impl AttestQuote {
    /// Parse a `TPMS_ATTEST` produced by `tpm2_quote -m`.
    ///
    /// Refuses any structure that does not begin with [`TPM_GENERATED_VALUE`],
    /// which is the field that distinguishes something a TPM signed from
    /// something merely shaped like it.
    pub fn parse(bytes: &[u8]) -> CryptoResult<Self> {
        let mut r = Reader::new(bytes);

        let magic = r.u32("magic")?;
        if magic != TPM_GENERATED_VALUE {
            return Err(CryptoError::AttestationFailed(format!(
                "not a TPM-generated attestation: magic is 0x{:08X}, expected 0x{:08X}",
                magic, TPM_GENERATED_VALUE
            )));
        }

        let structure_type = r.u16("type")?;
        if structure_type != TPM_ST_ATTEST_QUOTE {
            return Err(CryptoError::AttestationFailed(format!(
                "attestation is type 0x{:04X}, expected a PCR quote (0x{:04X})",
                structure_type, TPM_ST_ATTEST_QUOTE
            )));
        }

        let qualified_signer = r.sized_buffer("qualifiedSigner")?.to_vec();
        let extra_data = r.sized_buffer("extraData")?.to_vec();

        // TPMS_CLOCK_INFO
        let clock = r.u64("clock")?;
        let reset_count = r.u32("resetCount")?;
        let restart_count = r.u32("restartCount")?;
        let clock_safe = r.u8("safe")? != 0;

        let firmware_version = r.u64("firmwareVersion")?;

        // TPMS_QUOTE_INFO: TPML_PCR_SELECTION then TPM2B_DIGEST.
        let selection_count = r.u32("pcrSelect count")?;
        if selection_count > 16 {
            return Err(CryptoError::AttestationFailed(format!(
                "implausible PCR selection count {}",
                selection_count
            )));
        }
        let mut pcr_selections = Vec::with_capacity(selection_count as usize);
        for _ in 0..selection_count {
            let hash_alg = r.u16("selection hashAlg")?;
            let size_of_select = r.u8("sizeofSelect")? as usize;
            let mask = r.take(size_of_select, "pcrSelect")?;
            let mut indices = Vec::new();
            for (byte_index, byte) in mask.iter().enumerate() {
                for bit in 0..8u8 {
                    if byte & (1 << bit) != 0 {
                        indices.push((byte_index * 8) as u8 + bit);
                    }
                }
            }
            pcr_selections.push(PcrSelection { hash_alg, indices });
        }

        let pcr_digest = r.sized_buffer("pcrDigest")?.to_vec();

        Ok(Self {
            qualified_signer,
            extra_data,
            clock,
            reset_count,
            restart_count,
            clock_safe,
            firmware_version,
            pcr_selections,
            pcr_digest,
        })
    }

    /// Every PCR index this quote covers in the SHA-256 bank, ascending.
    pub fn sha256_indices(&self) -> Vec<u8> {
        self.pcr_selections
            .iter()
            .filter(|s| s.hash_alg == TPM_ALG_SHA256)
            .flat_map(|s| s.indices.iter().copied())
            .collect()
    }
}

/// A parsed `TPMT_SIGNATURE`.
#[derive(Debug, Clone)]
pub struct TpmSignature {
    /// Signature algorithm, e.g. [`TPM_ALG_RSASSA`].
    pub sig_alg: u16,
    /// Hash algorithm the signature was computed over.
    pub hash_alg: u16,
    /// The signature bytes. For ECDSA this is `r || s`, each zero-padded to the
    /// curve size.
    pub signature: Vec<u8>,
}

impl TpmSignature {
    /// Parse a `TPMT_SIGNATURE` produced by `tpm2_quote -s`.
    pub fn parse(bytes: &[u8]) -> CryptoResult<Self> {
        let mut r = Reader::new(bytes);
        let sig_alg = r.u16("sigAlg")?;
        let hash_alg = r.u16("hashAlg")?;

        let signature = match sig_alg {
            TPM_ALG_RSASSA | TPM_ALG_RSAPSS => r.sized_buffer("sig")?.to_vec(),
            TPM_ALG_ECDSA => {
                // TPMS_SIGNATURE_ECDSA: two TPM2B_ECC_PARAMETER, r then s.
                let r_part = r.sized_buffer("signatureR")?.to_vec();
                let s_part = r.sized_buffer("signatureS")?.to_vec();
                let width = r_part.len().max(s_part.len());
                let mut out = vec![0u8; width * 2];
                out[width - r_part.len()..width].copy_from_slice(&r_part);
                out[width * 2 - s_part.len()..].copy_from_slice(&s_part);
                out
            }
            other => {
                return Err(CryptoError::AttestationFailed(format!(
                    "unsupported TPM signature algorithm 0x{:04X}",
                    other
                )));
            }
        };

        Ok(Self {
            sig_alg,
            hash_alg,
            signature,
        })
    }
}

/// An attestation key's public half, parsed from a `TPMT_PUBLIC`.
#[derive(Debug, Clone)]
pub enum TpmPublicKey {
    /// RSA, with a big-endian modulus and exponent.
    Rsa {
        /// Big-endian modulus.
        modulus: Vec<u8>,
        /// Public exponent, big-endian, minimal length.
        exponent: Vec<u8>,
    },
    /// NIST P-256, as uncompressed `04 || X || Y`.
    EcP256 {
        /// SEC1 uncompressed point.
        point: Vec<u8>,
    },
}

impl TpmPublicKey {
    /// Parse a `TPMT_PUBLIC` as written by `tpm2_readpublic -f tpmt`.
    pub fn parse(bytes: &[u8]) -> CryptoResult<Self> {
        let mut r = Reader::new(bytes);

        let key_type = r.u16("type")?;
        let _name_alg = r.u16("nameAlg")?;
        let _object_attributes = r.u32("objectAttributes")?;
        let _auth_policy = r.sized_buffer("authPolicy")?;

        match key_type {
            TPM_ALG_RSA => {
                // TPMS_RSA_PARMS
                let symmetric = r.u16("symmetric.algorithm")?;
                if symmetric != TPM_ALG_NULL {
                    // A restricted decryption key carries key bits and a mode.
                    let _key_bits = r.u16("symmetric.keyBits")?;
                    let _mode = r.u16("symmetric.mode")?;
                }
                let scheme = r.u16("scheme.scheme")?;
                if scheme != TPM_ALG_NULL {
                    let _hash = r.u16("scheme.hashAlg")?;
                }
                let _key_bits = r.u16("keyBits")?;
                let exponent_raw = r.u32("exponent")?;
                // Zero means the default, 65537.
                let exponent_value = if exponent_raw == 0 {
                    65537
                } else {
                    exponent_raw
                };

                let modulus = r.sized_buffer("unique.rsa")?.to_vec();
                if modulus.is_empty() {
                    return Err(CryptoError::AttestationFailed(
                        "TPM public area carries an empty RSA modulus".into(),
                    ));
                }

                // Trim leading zeroes so the exponent is minimal, as the
                // verifier expects.
                let exponent_bytes = exponent_value.to_be_bytes();
                let first_significant = exponent_bytes
                    .iter()
                    .position(|b| *b != 0)
                    .unwrap_or(exponent_bytes.len() - 1);

                Ok(TpmPublicKey::Rsa {
                    modulus,
                    exponent: exponent_bytes[first_significant..].to_vec(),
                })
            }
            TPM_ALG_ECC => {
                // TPMS_ECC_PARMS
                let symmetric = r.u16("symmetric.algorithm")?;
                if symmetric != TPM_ALG_NULL {
                    let _key_bits = r.u16("symmetric.keyBits")?;
                    let _mode = r.u16("symmetric.mode")?;
                }
                let scheme = r.u16("scheme.scheme")?;
                if scheme != TPM_ALG_NULL {
                    let _hash = r.u16("scheme.hashAlg")?;
                }
                let curve_id = r.u16("curveID")?;
                let kdf = r.u16("kdf.scheme")?;
                if kdf != TPM_ALG_NULL {
                    let _hash = r.u16("kdf.hashAlg")?;
                }

                // 0x0003 is TPM_ECC_NIST_P256.
                if curve_id != 0x0003 {
                    return Err(CryptoError::AttestationFailed(format!(
                        "unsupported TPM ECC curve 0x{:04X}; only NIST P-256 is verified",
                        curve_id
                    )));
                }

                let x = r.sized_buffer("unique.x")?;
                let y = r.sized_buffer("unique.y")?;
                let mut point = Vec::with_capacity(65);
                point.push(0x04);
                point.extend(std::iter::repeat_n(0, 32usize.saturating_sub(x.len())));
                point.extend_from_slice(x);
                point.extend(std::iter::repeat_n(0, 32usize.saturating_sub(y.len())));
                point.extend_from_slice(y);

                Ok(TpmPublicKey::EcP256 { point })
            }
            other => Err(CryptoError::AttestationFailed(format!(
                "unsupported TPM key type 0x{:04X}",
                other
            ))),
        }
    }

    /// Verify `signature` over `message` under this key.
    pub fn verify(&self, message: &[u8], signature: &TpmSignature) -> CryptoResult<()> {
        use ring::signature;

        if signature.hash_alg != TPM_ALG_SHA256 {
            return Err(CryptoError::AttestationFailed(format!(
                "TPM quote is hashed with algorithm 0x{:04X}; Cordon verifies SHA-256 quotes",
                signature.hash_alg
            )));
        }

        match (self, signature.sig_alg) {
            (TpmPublicKey::Rsa { modulus, exponent }, TPM_ALG_RSASSA) => {
                let components = signature::RsaPublicKeyComponents {
                    n: modulus.as_slice(),
                    e: exponent.as_slice(),
                };
                components
                    .verify(
                        &signature::RSA_PKCS1_2048_8192_SHA256,
                        message,
                        &signature.signature,
                    )
                    .map_err(|_| CryptoError::SignatureInvalid)
            }
            (TpmPublicKey::Rsa { modulus, exponent }, TPM_ALG_RSAPSS) => {
                let components = signature::RsaPublicKeyComponents {
                    n: modulus.as_slice(),
                    e: exponent.as_slice(),
                };
                components
                    .verify(
                        &signature::RSA_PSS_2048_8192_SHA256,
                        message,
                        &signature.signature,
                    )
                    .map_err(|_| CryptoError::SignatureInvalid)
            }
            (TpmPublicKey::EcP256 { point }, TPM_ALG_ECDSA) => {
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                    .verify(message, &signature.signature)
                    .map_err(|_| CryptoError::SignatureInvalid)
            }
            (key, alg) => Err(CryptoError::AttestationFailed(format!(
                "signature algorithm 0x{:04X} does not match the attestation key ({})",
                alg,
                match key {
                    TpmPublicKey::Rsa { .. } => "RSA",
                    TpmPublicKey::EcP256 { .. } => "ECDSA P-256",
                }
            ))),
        }
    }
}

/// Recompute the digest a TPM would produce over a set of PCR values.
///
/// `TPMS_QUOTE_INFO.pcrDigest` is the hash of the selected PCR contents
/// concatenated in ascending index order. Recomputing it from the values a
/// report claims, and comparing against the digest the TPM signed, is what
/// binds those claimed values to the signature; without this step a node could
/// sign a genuine quote and then report whatever PCR values it liked alongside
/// it.
pub fn compute_pcr_digest(values_in_index_order: &[Vec<u8>]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for value in values_in_index_order {
        hasher.update(value);
    }
    hasher.finalize().to_vec()
}

/// What checking a quote established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmQuoteVerification {
    /// The signature over `TPMS_ATTEST` verified under the attestation key.
    pub signature_valid: bool,
    /// `extraData` matched the challenge the verifier issued.
    pub nonce_matches: bool,
    /// The PCR values the report claims hash to the digest the TPM signed.
    pub pcr_digest_matches: bool,
    /// Whether the attestation key was shown to belong to a genuine TPM by a
    /// certificate chain to a vendor root.
    ///
    /// Always `false` today: Cordon carries the endorsement key certificate but
    /// does not yet walk it to a TPM vendor's root. A quote can therefore be
    /// fully verified and still not prove the platform is genuine hardware,
    /// which is a distinction worth keeping visible rather than collapsing into
    /// a single "verified" boolean.
    pub ak_is_trusted: bool,
}

impl TpmQuoteVerification {
    /// Whether every check that Cordon performs passed.
    pub fn is_fully_verified(&self) -> bool {
        self.signature_valid && self.nonce_matches && self.pcr_digest_matches
    }
}

/// Verify a TPM quote end to end.
///
/// * `attest_message`, the raw `TPMS_ATTEST` the TPM signed.
/// * `signature`, the raw `TPMT_SIGNATURE` over it.
/// * `ak_public`, the raw `TPMT_PUBLIC` of the attestation key.
/// * `expected_extra_data`, the challenge the verifier issued.
/// * `claimed_pcrs`, the PCR values the report claims, ascending by index.
pub fn verify_quote(
    attest_message: &[u8],
    signature: &[u8],
    ak_public: &[u8],
    expected_extra_data: &[u8],
    claimed_pcrs: &[(u8, Vec<u8>)],
) -> CryptoResult<TpmQuoteVerification> {
    let attest = AttestQuote::parse(attest_message)?;
    let sig = TpmSignature::parse(signature)?;
    let key = TpmPublicKey::parse(ak_public)?;

    // 1. The TPM signed this exact message.
    let signature_valid = key.verify(attest_message, &sig).is_ok();

    // 2. The message commits to the challenge we issued, so it is not a replay
    //    of an older quote.
    let nonce_matches = crate::kdf::ct_eq(&attest.extra_data, expected_extra_data);

    // 3. The PCR values the report claims are the ones the TPM hashed. Compare
    //    against the quote's own selection so a report cannot satisfy this by
    //    omitting an inconvenient PCR.
    let quoted_indices = attest.sha256_indices();
    let mut claimed_sorted: Vec<&(u8, Vec<u8>)> = claimed_pcrs.iter().collect();
    claimed_sorted.sort_by_key(|(index, _)| *index);

    let claimed_indices: Vec<u8> = claimed_sorted.iter().map(|(i, _)| *i).collect();
    let pcr_digest_matches = if claimed_indices != quoted_indices {
        false
    } else {
        let values: Vec<Vec<u8>> = claimed_sorted.iter().map(|(_, v)| v.clone()).collect();
        crate::kdf::ct_eq(&compute_pcr_digest(&values), &attest.pcr_digest)
    };

    Ok(TpmQuoteVerification {
        signature_valid,
        nonce_matches,
        pcr_digest_matches,
        ak_is_trusted: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `TPMS_ATTEST` carrying a PCR quote, so the parser is exercised
    /// against the layout `tpm2_quote` actually emits.
    fn attest_bytes(magic: u32, extra_data: &[u8], indices: &[u8], pcr_digest: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&magic.to_be_bytes());
        out.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());

        // qualifiedSigner
        out.extend_from_slice(&(4u16).to_be_bytes());
        out.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        // extraData
        out.extend_from_slice(&(extra_data.len() as u16).to_be_bytes());
        out.extend_from_slice(extra_data);
        // TPMS_CLOCK_INFO
        out.extend_from_slice(&(1_234u64).to_be_bytes());
        out.extend_from_slice(&(2u32).to_be_bytes());
        out.extend_from_slice(&(3u32).to_be_bytes());
        out.push(1);
        // firmwareVersion
        out.extend_from_slice(&(0x0001_0002_0003_0004u64).to_be_bytes());

        // TPML_PCR_SELECTION: one SHA-256 selection with a 3-byte mask.
        out.extend_from_slice(&(1u32).to_be_bytes());
        out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        out.push(3);
        let mut mask = [0u8; 3];
        for index in indices {
            mask[(*index / 8) as usize] |= 1 << (*index % 8);
        }
        out.extend_from_slice(&mask);

        // pcrDigest
        out.extend_from_slice(&(pcr_digest.len() as u16).to_be_bytes());
        out.extend_from_slice(pcr_digest);
        out
    }

    #[test]
    fn parses_a_quote_and_recovers_its_fields() {
        let digest = vec![0x11u8; 32];
        let bytes = attest_bytes(
            TPM_GENERATED_VALUE,
            b"my-challenge",
            &[0, 4, 7, 11],
            &digest,
        );
        let attest = AttestQuote::parse(&bytes).unwrap();

        assert_eq!(attest.extra_data, b"my-challenge");
        assert_eq!(attest.sha256_indices(), vec![0, 4, 7, 11]);
        assert_eq!(attest.pcr_digest, digest);
        assert_eq!(attest.reset_count, 2);
        assert!(attest.clock_safe);
    }

    /// The magic value is what separates a structure a TPM generated from one
    /// that merely looks like it, so a wrong value must be refused outright.
    #[test]
    fn refuses_a_structure_the_tpm_did_not_generate() {
        let bytes = attest_bytes(0xDEAD_BEEF, b"challenge", &[0], &[0u8; 32]);
        let err = AttestQuote::parse(&bytes).unwrap_err().to_string();
        assert!(err.contains("TPM-generated"), "unexpected error: {}", err);
    }

    #[test]
    fn refuses_a_truncated_structure_rather_than_panicking() {
        let bytes = attest_bytes(TPM_GENERATED_VALUE, b"challenge", &[0], &[0u8; 32]);
        for cut in 1..bytes.len() {
            // Every prefix must produce an error, never a panic.
            let _ = AttestQuote::parse(&bytes[..cut]);
        }
        assert!(AttestQuote::parse(&bytes[..10]).is_err());
        assert!(AttestQuote::parse(&[]).is_err());
    }

    #[test]
    fn parses_an_rsassa_signature() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TPM_ALG_RSASSA.to_be_bytes());
        bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        bytes.extend_from_slice(&(256u16).to_be_bytes());
        bytes.extend_from_slice(&[0x42u8; 256]);

        let sig = TpmSignature::parse(&bytes).unwrap();
        assert_eq!(sig.sig_alg, TPM_ALG_RSASSA);
        assert_eq!(sig.hash_alg, TPM_ALG_SHA256);
        assert_eq!(sig.signature.len(), 256);
    }

    /// ECDSA arrives as two separately sized integers and must be normalised to
    /// the fixed-width `r || s` form a verifier expects.
    #[test]
    fn normalises_an_ecdsa_signature_to_fixed_width() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TPM_ALG_ECDSA.to_be_bytes());
        bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        // r is a full 32 bytes, s is short and must be left-padded.
        bytes.extend_from_slice(&(32u16).to_be_bytes());
        bytes.extend_from_slice(&[0x01u8; 32]);
        bytes.extend_from_slice(&(30u16).to_be_bytes());
        bytes.extend_from_slice(&[0x02u8; 30]);

        let sig = TpmSignature::parse(&bytes).unwrap();
        assert_eq!(sig.signature.len(), 64);
        assert_eq!(&sig.signature[..32], &[0x01u8; 32]);
        assert_eq!(&sig.signature[32..34], &[0x00, 0x00]);
        assert_eq!(&sig.signature[34..], &[0x02u8; 30]);
    }

    #[test]
    fn refuses_an_unsupported_signature_algorithm() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(0x1234u16).to_be_bytes());
        bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        assert!(TpmSignature::parse(&bytes).is_err());
    }

    #[test]
    fn parses_an_rsa_public_area() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TPM_ALG_RSA.to_be_bytes());
        bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        bytes.extend_from_slice(&(0x0005_0072u32).to_be_bytes()); // objectAttributes
        bytes.extend_from_slice(&(0u16).to_be_bytes()); // empty authPolicy
        bytes.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // symmetric
        bytes.extend_from_slice(&TPM_ALG_RSASSA.to_be_bytes()); // scheme
        bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes()); // scheme hash
        bytes.extend_from_slice(&(2048u16).to_be_bytes()); // keyBits
        bytes.extend_from_slice(&(0u32).to_be_bytes()); // exponent: default
        bytes.extend_from_slice(&(256u16).to_be_bytes());
        bytes.extend_from_slice(&[0x9Au8; 256]);

        match TpmPublicKey::parse(&bytes).unwrap() {
            TpmPublicKey::Rsa { modulus, exponent } => {
                assert_eq!(modulus.len(), 256);
                // A zero exponent means the default of 65537 = 0x010001.
                assert_eq!(exponent, vec![0x01, 0x00, 0x01]);
            }
            other => panic!("expected an RSA key, got {:?}", other),
        }
    }

    #[test]
    fn the_pcr_digest_is_the_hash_of_the_values_in_order() {
        use sha2::{Digest, Sha256};
        let a = vec![0xAAu8; 32];
        let b = vec![0xBBu8; 32];

        let mut expected = Sha256::new();
        expected.update(&a);
        expected.update(&b);
        assert_eq!(
            compute_pcr_digest(&[a.clone(), b.clone()]),
            expected.finalize().to_vec()
        );

        // Order is part of the digest.
        assert_ne!(
            compute_pcr_digest(&[a.clone(), b.clone()]),
            compute_pcr_digest(&[b, a])
        );
    }

    /// The check that binds reported PCR values to the signature. A node that
    /// signs a genuine quote and then reports different values alongside it
    /// must fail here.
    #[test]
    fn claimed_pcr_values_must_hash_to_the_signed_digest() {
        let real = vec![vec![0xAAu8; 32], vec![0xBBu8; 32]];
        let digest = compute_pcr_digest(&real);
        let message = attest_bytes(TPM_GENERATED_VALUE, b"challenge-value", &[0, 4], &digest);

        // A key that will not verify, so only the PCR check is under test.
        let ak = {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&TPM_ALG_RSA.to_be_bytes());
            bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
            bytes.extend_from_slice(&(0u32).to_be_bytes());
            bytes.extend_from_slice(&(0u16).to_be_bytes());
            bytes.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
            bytes.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
            bytes.extend_from_slice(&(2048u16).to_be_bytes());
            bytes.extend_from_slice(&(65537u32).to_be_bytes());
            bytes.extend_from_slice(&(256u16).to_be_bytes());
            bytes.extend_from_slice(&[0x9Au8; 256]);
            bytes
        };
        let sig = {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&TPM_ALG_RSASSA.to_be_bytes());
            bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
            bytes.extend_from_slice(&(256u16).to_be_bytes());
            bytes.extend_from_slice(&[0x00u8; 256]);
            bytes
        };

        let honest = verify_quote(
            &message,
            &sig,
            &ak,
            b"challenge-value",
            &[(0, real[0].clone()), (4, real[1].clone())],
        )
        .unwrap();
        assert!(honest.pcr_digest_matches);
        assert!(honest.nonce_matches);

        // Same signed quote, different claimed values.
        let lying = verify_quote(
            &message,
            &sig,
            &ak,
            b"challenge-value",
            &[(0, vec![0xFFu8; 32]), (4, real[1].clone())],
        )
        .unwrap();
        assert!(!lying.pcr_digest_matches);

        // Same signed quote, an inconvenient PCR omitted.
        let partial = verify_quote(
            &message,
            &sig,
            &ak,
            b"challenge-value",
            &[(0, real[0].clone())],
        )
        .unwrap();
        assert!(!partial.pcr_digest_matches);

        // A quote answering a different challenge.
        let replayed = verify_quote(&message, &sig, &ak, b"another-challenge", &[]).unwrap();
        assert!(!replayed.nonce_matches);
    }

    /// Build a `TPMT_PUBLIC` for a NIST P-256 key from its uncompressed point,
    /// as `tpm2_readpublic -f tpmt` would emit for an ECC attestation key.
    fn ecc_public_area(point: &[u8]) -> Vec<u8> {
        assert_eq!(point.len(), 65, "expected an uncompressed SEC1 point");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
        bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        bytes.extend_from_slice(&(0x0005_0072u32).to_be_bytes()); // objectAttributes
        bytes.extend_from_slice(&(0u16).to_be_bytes()); // authPolicy
        bytes.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // symmetric
        bytes.extend_from_slice(&TPM_ALG_ECDSA.to_be_bytes()); // scheme
        bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes()); // scheme hash
        bytes.extend_from_slice(&(0x0003u16).to_be_bytes()); // NIST P-256
        bytes.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // kdf
        bytes.extend_from_slice(&(32u16).to_be_bytes());
        bytes.extend_from_slice(&point[1..33]); // X
        bytes.extend_from_slice(&(32u16).to_be_bytes());
        bytes.extend_from_slice(&point[33..]); // Y
        bytes
    }

    /// Wrap a raw `r || s` signature as a `TPMT_SIGNATURE`.
    fn ecdsa_signature_structure(raw: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TPM_ALG_ECDSA.to_be_bytes());
        bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        bytes.extend_from_slice(&(32u16).to_be_bytes());
        bytes.extend_from_slice(&raw[..32]);
        bytes.extend_from_slice(&(32u16).to_be_bytes());
        bytes.extend_from_slice(&raw[32..]);
        bytes
    }

    /// End to end over real cryptography: a genuine signature over a genuine
    /// quote must verify, and any alteration to either must not.
    #[test]
    fn a_real_signature_over_a_real_quote_verifies() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let ak_public = ecc_public_area(key_pair.public_key().as_ref());

        let pcr_values = vec![vec![0xA1u8; 32], vec![0xB2u8; 32], vec![0xC3u8; 32]];
        let message = attest_bytes(
            TPM_GENERATED_VALUE,
            b"a-verifier-issued-challenge",
            &[0, 4, 7],
            &compute_pcr_digest(&pcr_values),
        );
        let signature = ecdsa_signature_structure(key_pair.sign(&rng, &message).unwrap().as_ref());

        let claimed: Vec<(u8, Vec<u8>)> = vec![
            (0, pcr_values[0].clone()),
            (4, pcr_values[1].clone()),
            (7, pcr_values[2].clone()),
        ];

        let verification = verify_quote(
            &message,
            &signature,
            &ak_public,
            b"a-verifier-issued-challenge",
            &claimed,
        )
        .unwrap();
        assert!(
            verification.is_fully_verified(),
            "a genuine quote failed to verify: {:?}",
            verification
        );
        // Verifying the quote is not the same as trusting the key.
        assert!(!verification.ak_is_trusted);

        // Altering the signed message must invalidate the signature.
        let mut tampered = message.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        let altered = verify_quote(
            &tampered,
            &signature,
            &ak_public,
            b"a-verifier-issued-challenge",
            &claimed,
        )
        .unwrap();
        assert!(!altered.signature_valid);

        // A signature from a different key must not verify.
        let other_pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let other =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, other_pkcs8.as_ref(), &rng)
                .unwrap();
        let wrong_key = ecc_public_area(other.public_key().as_ref());
        let impostor = verify_quote(
            &message,
            &signature,
            &wrong_key,
            b"a-verifier-issued-challenge",
            &claimed,
        )
        .unwrap();
        assert!(!impostor.signature_valid);
    }

    #[test]
    fn a_verification_needs_every_check_to_pass() {
        let all = TpmQuoteVerification {
            signature_valid: true,
            nonce_matches: true,
            pcr_digest_matches: true,
            ak_is_trusted: false,
        };
        assert!(all.is_fully_verified());

        for spoiled in [
            TpmQuoteVerification {
                signature_valid: false,
                ..all.clone()
            },
            TpmQuoteVerification {
                nonce_matches: false,
                ..all.clone()
            },
            TpmQuoteVerification {
                pcr_digest_matches: false,
                ..all.clone()
            },
        ] {
            assert!(!spoiled.is_fully_verified());
        }
    }
}
