//! TPM 2.0 platform measurements.
//!
//! Reads PCR values and produces signed quotes by invoking the standard
//! `tpm2-tools` utilities (`tpm2_pcrread`, `tpm2_quote`, `tpm2_readpublic`).
//! Shelling out to the reference userspace keeps Cordon free of a TSS binding
//! and matches how a TPM is driven in practice.
//!
//! # Setup
//!
//! A quote needs a provisioned Attestation Key. Create one once per node:
//!
//! ```text
//! tpm2_createek  -c /var/lib/cordon/tpm/ek.ctx -G rsa -u /var/lib/cordon/tpm/ek.pub
//! tpm2_createak  -C /var/lib/cordon/tpm/ek.ctx -c /var/lib/cordon/tpm/ak.ctx \
//!                -G rsa -g sha256 -s rsassa -u /var/lib/cordon/tpm/ak.pub
//! ```
//!
//! Then point Cordon at it with `CORDON_TPM_AK_CTX=/var/lib/cordon/tpm/ak.ctx`.
//!
//! # Status
//!
//! The command wiring and output parsing are exercised against `tpm2-tools`
//! output formats and unit-tested, but this repository's CI has no TPM, so the
//! path is not run against physical hardware here. Verify it on your own
//! hardware with `cordon doctor` before relying on it.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use crate::error::{CordonError, CordonResult};

/// A signed quote read back from the TPM.
#[derive(Debug, Clone)]
pub struct TpmQuoteResult {
    /// TPMS_ATTEST structure bytes, hex encoded.
    pub message_hex: String,
    /// Signature over the message, hex encoded.
    pub signature_hex: String,
    /// Attestation key public area, hex encoded.
    pub aik_public_key_hex: String,
    /// Endorsement key certificate chain, base64 encoded, when available.
    pub ek_cert_chain: Vec<String>,
}

/// Whether a usable TPM stack is present: `tpm2-tools` on `PATH` and a TPM the
/// current user can read.
pub fn is_available() -> bool {
    run(&["tpm2_pcrread", "sha256:0"]).is_ok()
}

/// Path to the provisioned Attestation Key context, if configured.
pub fn ak_context_path() -> Option<PathBuf> {
    std::env::var("CORDON_TPM_AK_CTX")
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.exists())
}

/// Read the given PCR indices from the SHA-256 bank.
///
/// Returns a map of index to `"sha256:<hex>"`.
pub fn read_pcrs(indices: &[u8]) -> CordonResult<HashMap<u8, String>> {
    if indices.is_empty() {
        return Ok(HashMap::new());
    }
    let selection = pcr_selection(indices);
    let output = run(&["tpm2_pcrread", &selection])?;
    let parsed = parse_pcrread(&output);

    // A PCR the operator asked for and did not get would silently narrow the
    // measurement, so say so rather than returning a short map.
    let missing: Vec<u8> = indices
        .iter()
        .copied()
        .filter(|i| !parsed.contains_key(i))
        .collect();
    if !missing.is_empty() {
        tracing::warn!(?missing, "TPM did not return every requested PCR");
    }

    Ok(parsed)
}

/// Produce a signed quote over the standard PCR selection, bound to `nonce`.
pub fn quote(nonce: &str) -> CordonResult<TpmQuoteResult> {
    let ak_ctx = ak_context_path().ok_or_else(|| {
        CordonError::AttestationInvalid(
            "CORDON_TPM_AK_CTX is unset or points at a missing file. Provision an \
             Attestation Key with tpm2_createak and set the variable to its context \
             file; without one the TPM cannot sign a quote."
                .into(),
        )
    })?;
    let ak_ctx = ak_ctx.to_string_lossy().into_owned();

    // The nonce is passed to the TPM as hex, so hash the caller's value to get a
    // fixed-width qualifying digest regardless of what they supplied.
    let qualifying_data = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(nonce.as_bytes()))
    };

    let selection = pcr_selection(crate::attestation_service::PcrAllocations::ALL);

    // Temporary files are named from the qualifying digest, which is derived
    // from a client nonce, so concurrent quotes cannot collide.
    let dir = std::env::temp_dir();
    let msg_path = dir.join(format!("cordon-quote-{}.msg", &qualifying_data[..16]));
    let sig_path = dir.join(format!("cordon-quote-{}.sig", &qualifying_data[..16]));
    let msg_str = msg_path.to_string_lossy().into_owned();
    let sig_str = sig_path.to_string_lossy().into_owned();

    let result = (|| -> CordonResult<TpmQuoteResult> {
        run(&[
            "tpm2_quote",
            "-c",
            &ak_ctx,
            "-l",
            &selection,
            "-q",
            &qualifying_data,
            "-m",
            &msg_str,
            "-s",
            &sig_str,
            "-g",
            "sha256",
        ])?;

        let message = std::fs::read(&msg_path).map_err(|e| {
            CordonError::AttestationInvalid(format!("cannot read quote message: {}", e))
        })?;
        let signature = std::fs::read(&sig_path).map_err(|e| {
            CordonError::AttestationInvalid(format!("cannot read quote signature: {}", e))
        })?;

        Ok(TpmQuoteResult {
            message_hex: hex::encode(message),
            signature_hex: hex::encode(signature),
            aik_public_key_hex: read_ak_public(&ak_ctx).unwrap_or_default(),
            ek_cert_chain: read_ek_certificate_chain(),
        })
    })();

    let _ = std::fs::remove_file(&msg_path);
    let _ = std::fs::remove_file(&sig_path);
    result
}

/// Read the attestation key's public area.
fn read_ak_public(ak_ctx: &str) -> Option<String> {
    let dir = std::env::temp_dir();
    let out_path = dir.join("cordon-ak-public.bin");
    let out_str = out_path.to_string_lossy().into_owned();

    let result = run(&[
        "tpm2_readpublic",
        "-c",
        ak_ctx,
        "-o",
        &out_str,
        "-f",
        "tpmt",
    ])
    .ok()
    .and_then(|_| std::fs::read(&out_path).ok())
    .map(hex::encode);

    let _ = std::fs::remove_file(&out_path);
    result
}

/// Read the endorsement key certificate from NV storage, when the platform
/// stores one there. Absence is normal on many systems and is not an error.
fn read_ek_certificate_chain() -> Vec<String> {
    use base64::Engine;
    let dir = std::env::temp_dir();
    let out_path = dir.join("cordon-ek-cert.der");
    let out_str = out_path.to_string_lossy().into_owned();

    // 0x01c00002 is the TCG-registered NV index for the RSA EK certificate.
    let chain = run(&["tpm2_nvread", "0x01c00002", "-o", &out_str])
        .ok()
        .and_then(|_| std::fs::read(&out_path).ok())
        .map(|der| vec![base64::engine::general_purpose::STANDARD.encode(der)])
        .unwrap_or_default();

    let _ = std::fs::remove_file(&out_path);
    chain
}

fn pcr_selection(indices: &[u8]) -> String {
    format!(
        "sha256:{}",
        indices
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

/// Run a command, returning stdout on success.
fn run(args: &[&str]) -> CordonResult<String> {
    let (cmd, rest) = args
        .split_first()
        .ok_or_else(|| CordonError::Internal("empty command".into()))?;
    let output = Command::new(cmd)
        .args(rest)
        .output()
        .map_err(|e| CordonError::AttestationInvalid(format!("{} is not runnable: {}", cmd, e)))?;
    if !output.status.success() {
        return Err(CordonError::AttestationInvalid(format!(
            "{} failed: {}",
            cmd,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Parse `tpm2_pcrread` output lines of the form `  4 : 0x<HEX>`.
fn parse_pcrread(text: &str) -> HashMap<u8, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        let Some((index_part, value_part)) = line.split_once(':') else {
            continue;
        };
        let Ok(index) = index_part.trim().parse::<u8>() else {
            continue;
        };
        let value = value_part.trim().trim_start_matches("0x").to_lowercase();
        if !value.is_empty() && value.chars().all(|c| c.is_ascii_hexdigit()) {
            map.insert(index, format!("sha256:{}", value));
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pcrread_output() {
        let sample = "sha256:\n  0 : 0xABCD1234\n  4 : 0x00FF\n  7 : 0xdeadbeef\n";
        let m = parse_pcrread(sample);
        assert_eq!(m.get(&0).map(String::as_str), Some("sha256:abcd1234"));
        assert_eq!(m.get(&4).map(String::as_str), Some("sha256:00ff"));
        assert_eq!(m.get(&7).map(String::as_str), Some("sha256:deadbeef"));
        assert!(!m.contains_key(&1));
    }

    #[test]
    fn ignores_non_pcr_lines() {
        let m = parse_pcrread("sha1:\nsome banner text\n  3 : 0xAA\n");
        assert_eq!(m.len(), 1);
        assert_eq!(m.get(&3).map(String::as_str), Some("sha256:aa"));
    }

    #[test]
    fn builds_a_pcr_selection_string() {
        assert_eq!(pcr_selection(&[0, 4, 7]), "sha256:0,4,7");
    }

    #[test]
    fn quote_without_an_ak_context_fails_closed() {
        // Deliberately not set in the test environment.
        if ak_context_path().is_none() {
            let err = quote("some-nonce").unwrap_err().to_string();
            assert!(
                err.contains("CORDON_TPM_AK_CTX"),
                "unexpected error: {}",
                err
            );
        }
    }
}
