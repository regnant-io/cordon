//! Real TPM 2.0 attestation backend (§3, §5).
//!
//! This talks to a real TPM via the standard `tpm2-tools` userspace utilities
//! (`tpm2_pcrread`, `tpm2_quote`) by shelling out — the same interface a
//! production Cordon node uses. It adds no crate dependencies, compiles on every
//! platform, and degrades gracefully: when the tools or a TPM are absent, the
//! probe reports unavailable and the caller falls back to the simulated backend.
//!
//! Selection: set `CORDON_TPM=1` to prefer the real backend. A real quote also
//! needs a provisioned Attestation Key context file in `CORDON_TPM_AK_CTX`.
//!
//! NOTE: exercised against `tpm2-tools` output formats; not run against physical
//! TPM hardware in this repo's CI. The parsing and command wiring are real.

use std::collections::HashMap;
use std::process::Command;

use crate::error::{CordonError, CordonResult};

/// Whether a usable TPM stack (tpm2-tools + accessible TPM) is present.
pub fn probe() -> bool {
    // `tpm2_pcrread` returning success implies both the tool and a TPM device.
    run(&["tpm2_pcrread", "sha256:0"]).is_ok()
}

/// Whether the operator has opted into the real TPM backend.
pub fn enabled() -> bool {
    std::env::var("CORDON_TPM").map(|v| v == "1" || v == "true").unwrap_or(false)
}

/// Read the given PCR indices (SHA-256 bank) from the TPM.
///
/// Returns a map of index → `"sha256:<hex>"` matching the simulated format.
pub fn read_pcrs(indices: &[u8]) -> CordonResult<HashMap<u8, String>> {
    if indices.is_empty() {
        return Ok(HashMap::new());
    }
    let list = format!(
        "sha256:{}",
        indices.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",")
    );
    let out = run(&["tpm2_pcrread", &list])?;
    Ok(parse_pcrread(&out))
}

/// Produce a signed TPM quote over the given PCR selection and nonce.
///
/// Requires an Attestation Key context file path in `CORDON_TPM_AK_CTX`.
/// Returns the raw quote message and signature as hex.
pub fn quote(nonce_hex: &str, indices: &[u8]) -> CordonResult<TpmQuoteRaw> {
    let ak_ctx = std::env::var("CORDON_TPM_AK_CTX").map_err(|_| {
        CordonError::AttestationInvalid(
            "CORDON_TPM_AK_CTX not set — provision an Attestation Key context for real quotes".into(),
        )
    })?;
    let list = format!(
        "sha256:{}",
        indices.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",")
    );
    let dir = std::env::temp_dir();
    let msg_path = dir.join(format!("cordon-quote-msg-{}", nonce_hex)).to_string_lossy().into_owned();
    let sig_path = dir.join(format!("cordon-quote-sig-{}", nonce_hex)).to_string_lossy().into_owned();

    // tpm2_quote -c <ak_ctx> -l sha256:0,4,7 -q <nonce> -m msg -s sig -g sha256
    run(&[
        "tpm2_quote", "-c", &ak_ctx, "-l", &list, "-q", nonce_hex,
        "-m", &msg_path, "-s", &sig_path, "-g", "sha256",
    ])?;

    let msg = std::fs::read(&msg_path)
        .map_err(|e| CordonError::AttestationInvalid(format!("reading quote message: {}", e)))?;
    let sig = std::fs::read(&sig_path)
        .map_err(|e| CordonError::AttestationInvalid(format!("reading quote signature: {}", e)))?;
    // Best-effort cleanup.
    let _ = std::fs::remove_file(&msg_path);
    let _ = std::fs::remove_file(&sig_path);

    Ok(TpmQuoteRaw {
        message_hex: hex::encode(msg),
        signature_hex: hex::encode(sig),
    })
}

/// Raw output of a real TPM quote.
#[derive(Debug, Clone)]
pub struct TpmQuoteRaw {
    /// TPMS_ATTEST structure bytes (hex).
    pub message_hex: String,
    /// Signature over the message (hex).
    pub signature_hex: String,
}

/// Run a command, returning stdout on success.
fn run(args: &[&str]) -> CordonResult<String> {
    let (cmd, rest) = args.split_first()
        .ok_or_else(|| CordonError::Internal("empty command".into()))?;
    let output = Command::new(cmd)
        .args(rest)
        .output()
        .map_err(|e| CordonError::AttestationInvalid(format!("{} not runnable: {}", cmd, e)))?;
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
        // Expect `<idx> : 0x<hex>`
        if let Some((idx_part, val_part)) = line.split_once(':') {
            if let Ok(idx) = idx_part.trim().parse::<u8>() {
                let val = val_part.trim().trim_start_matches("0x").to_lowercase();
                if !val.is_empty() && val.chars().all(|c| c.is_ascii_hexdigit()) {
                    map.insert(idx, format!("sha256:{}", val));
                }
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pcrread() {
        let sample = "sha256:\n  0 : 0xABCD1234\n  4 : 0x00FF\n  7 : 0xdeadbeef\n";
        let m = parse_pcrread(sample);
        assert_eq!(m.get(&0).map(String::as_str), Some("sha256:abcd1234"));
        assert_eq!(m.get(&4).map(String::as_str), Some("sha256:00ff"));
        assert_eq!(m.get(&7).map(String::as_str), Some("sha256:deadbeef"));
        assert!(!m.contains_key(&1));
    }
}
