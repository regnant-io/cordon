//! Client-side audit log verification — §9.3
//!
//! Implements the cordon-verify-log logic. Requires only the exported log
//! and the client's K_log public key. No connection to the Cordon node required.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::error::{AuditError, AuditResult};
use crate::log::{AuditEntry, GENESIS_CONSTANT};
use cordon_crypto::signing::VerifyingKey;

/// Result of a log verification
#[derive(Debug)]
pub struct VerificationResult {
    /// Whether the log is fully valid
    pub valid: bool,
    /// Total entries verified
    pub entries_verified: usize,
    /// Timestamp of the first entry
    pub first_entry: Option<DateTime<Utc>>,
    /// Timestamp of the last entry
    pub last_entry: Option<DateTime<Utc>>,
    /// Hash of the last entry (for anchoring)
    pub log_tail_hash: Option<String>,
    /// Any violations found
    pub violations: Vec<String>,
}

/// Verify a complete audit log chain.
///
/// # Arguments
/// * `log_path` - Path to the JSONL log file or directory
/// * `verifying_key` - Client's K_log verifying key
/// * `deployment_id` - Expected deployment ID (for genesis verification)
///
/// # Returns
/// A `VerificationResult` with full details. Never panics — all errors captured in result.
pub fn verify_log_chain(
    log_path: &Path,
    verifying_key: &VerifyingKey,
    deployment_id: &str,
) -> AuditResult<VerificationResult> {
    let entries = load_entries(log_path)?;

    if entries.is_empty() {
        return Ok(VerificationResult {
            valid: true,
            entries_verified: 0,
            first_entry: None,
            last_entry: None,
            log_tail_hash: None,
            violations: vec![],
        });
    }

    let mut violations = Vec::new();

    let expected_genesis = compute_genesis_hash(deployment_id);
    let mut prev_hash = expected_genesis;
    let mut expected_seq = 0u64;

    for (i, entry) in entries.iter().enumerate() {
        // Check sequence number
        if entry.sequence != expected_seq + 1 {
            violations.push(format!(
                "Sequence gap at entry {} (log_id: {}): expected {}, got {}",
                i,
                entry.log_id,
                expected_seq + 1,
                entry.sequence
            ));
        }
        expected_seq = entry.sequence;

        // Verify chain link: entry_hash = SHA-256(prev_hash || timestamp || payload_hash)
        let expected_hash = {
            let mut hasher = Sha256::new();
            hasher.update(prev_hash.as_bytes());
            hasher.update(entry.timestamp.to_rfc3339().as_bytes());
            hasher.update(entry.payload_hash.as_bytes());
            hex::encode(hasher.finalize())
        };

        if entry.entry_hash != expected_hash {
            if i == 0 {
                violations.push(format!(
                    "Genesis hash mismatch at entry 0 (log_id: {}): expected genesis link {}, got {}",
                    entry.log_id, expected_hash, entry.entry_hash
                ));
            } else {
                violations.push(format!(
                    "Chain broken at entry {} (log_id: {}): hash mismatch",
                    i, entry.log_id
                ));
            }
        }

        // Verify payload hash
        let payload_bytes = serde_json::to_vec(&entry.payload)
            .map_err(|e| AuditError::SerializationError(e.to_string()))?;
        let payload_hash = hex::encode(Sha256::digest(&payload_bytes));
        if payload_hash != entry.payload_hash {
            violations.push(format!(
                "Payload hash mismatch at entry {} (log_id: {})",
                i, entry.log_id
            ));
        }

        // Verify signature
        let sig = cordon_crypto::signing::Signature::from_hex(&entry.signature)
            .map_err(|e| AuditError::CryptoError(e.to_string()))?;
        if let Err(e) = verifying_key.verify(entry.entry_hash.as_bytes(), &sig) {
            violations.push(format!(
                "Signature invalid at entry {} (log_id: {}): {}",
                i, entry.log_id, e
            ));
        }

        prev_hash = entry.entry_hash.clone();
    }

    let valid = violations.is_empty();
    let n = entries.len();

    Ok(VerificationResult {
        valid,
        entries_verified: n,
        first_entry: entries.first().map(|e| e.timestamp),
        last_entry: entries.last().map(|e| e.timestamp),
        log_tail_hash: entries.last().map(|e| e.entry_hash.clone()),
        violations,
    })
}

/// Load entries from a path (file or directory)
fn load_entries(path: &Path) -> AuditResult<Vec<AuditEntry>> {
    let mut all_entries = Vec::new();

    if path.is_dir() {
        let mut files: Vec<_> = std::fs::read_dir(path)
            .map_err(|e| AuditError::IoError(e.to_string()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().map(|e| e == "jsonl").unwrap_or(false))
            .collect();
        files.sort();

        for file in files {
            all_entries.extend(load_entries_from_file(&file)?);
        }
    } else {
        all_entries = load_entries_from_file(path)?;
    }

    Ok(all_entries)
}

fn load_entries_from_file(path: &Path) -> AuditResult<Vec<AuditEntry>> {
    let content = std::fs::read_to_string(path).map_err(|e| AuditError::IoError(e.to_string()))?;
    let mut entries = Vec::new();
    for (line_no, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(line)
            .map_err(|e| AuditError::SerializationError(format!("Line {}: {}", line_no + 1, e)))?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Compute the expected genesis hash for a deployment
pub fn compute_genesis_hash(deployment_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(GENESIS_CONSTANT);
    hasher.update(deployment_id.as_bytes());
    hasher.update(b"GENESIS");
    hex::encode(hasher.finalize())
}

/// Get a summary of events in a log by type
pub fn summarize_events(entries: &[AuditEntry]) -> std::collections::HashMap<String, usize> {
    let mut counts = std::collections::HashMap::new();
    for entry in entries {
        *counts
            .entry(entry.payload.event_type_str().to_string())
            .or_insert(0) += 1;
    }
    counts
}
