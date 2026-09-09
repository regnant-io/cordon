//! Tests for the tamper-evident chain.
//!
//! These assert the properties the whole crate exists to provide, stated as
//! the attacks they defeat: an operator who edits, deletes, reorders, or
//! re-signs a record cannot make the log verify again without the key the
//! client derived. Each test tampers with the log on disk exactly as an
//! operator with filesystem access would, and then runs the same offline
//! verifier `cordon-verify-log` runs.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::events::{AuditEvent, LifecycleEvent, LifecycleEventType};
use crate::log::{AuditEntry, AuditLog, LogConfig};
use crate::verify::verify_log_chain;
use cordon_crypto::signing::{SigningKey, VerifyingKey};

fn event(node: &str) -> AuditEvent {
    AuditEvent::Lifecycle(LifecycleEvent {
        event: LifecycleEventType::Boot,
        cordon_version: "test".into(),
        tee_type: "simulation".into(),
        node_id: node.into(),
    })
}

fn config(dir: &Path) -> LogConfig {
    LogConfig::new(dir.to_path_buf(), "deployment-1".into(), "node-1".into())
}

/// Build a log in a fresh directory. Returns the directory guard, the log, and
/// the verifying key a client holding the CMK would independently derive.
fn fixture() -> (tempfile::TempDir, AuditLog, VerifyingKey) {
    let dir = tempfile::tempdir().unwrap();
    let signing_key = SigningKey::from_seed(&[0x5Au8; 32]);
    let verifying_key = signing_key.verifying_key();
    let log = AuditLog::open(config(dir.path()), signing_key).unwrap();
    (dir, log, verifying_key)
}

fn log_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|e| e == "jsonl").unwrap_or(false))
        .collect();
    files.sort();
    files
}

fn only_log_file(dir: &Path) -> PathBuf {
    let mut files = log_files(dir);
    assert_eq!(files.len(), 1, "expected exactly one log file");
    files.pop().unwrap()
}

#[test]
fn a_new_log_starts_with_a_genesis_linked_entry() {
    let (dir, log, vk) = fixture();
    assert_eq!(log.sequence(), 1, "opening a log writes its genesis entry");

    let result = verify_log_chain(dir.path(), &vk, "deployment-1").unwrap();
    assert!(result.valid, "violations: {:?}", result.violations);
    assert_eq!(result.entries_verified, 1);
}

#[test]
fn appending_advances_the_chain_and_still_verifies() {
    let (dir, log, vk) = fixture();
    for i in 0..25 {
        log.append(event(&format!("node-{}", i))).unwrap();
    }
    assert_eq!(log.sequence(), 26);

    let result = verify_log_chain(dir.path(), &vk, "deployment-1").unwrap();
    assert!(result.valid, "violations: {:?}", result.violations);
    assert_eq!(result.entries_verified, 26);
    assert_eq!(result.log_tail_hash, log.tail_hash());
}

#[test]
fn each_entry_links_to_the_one_before_it() {
    let (dir, log, _) = fixture();
    log.append(event("a")).unwrap();
    log.append(event("b")).unwrap();

    let content = std::fs::read_to_string(only_log_file(dir.path())).unwrap();
    let entries: Vec<AuditEntry> = content
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();

    for pair in entries.windows(2) {
        let mut hasher = Sha256::new();
        hasher.update(pair[0].entry_hash.as_bytes());
        hasher.update(pair[1].timestamp.to_rfc3339().as_bytes());
        hasher.update(pair[1].payload_hash.as_bytes());
        assert_eq!(pair[1].entry_hash, hex::encode(hasher.finalize()));
    }
}

/// The property the crate exists for: an operator who edits a record cannot
/// make the log verify again without the client's signing key.
#[test]
fn rewriting_an_entry_is_detected() {
    let (dir, log, vk) = fixture();
    log.append(event("original")).unwrap();
    log.append(event("after")).unwrap();

    let path = only_log_file(dir.path());
    let before = std::fs::read_to_string(&path).unwrap();
    let rewritten = before.replace("\"node_id\":\"original\"", "\"node_id\":\"forged\"");
    assert_ne!(before, rewritten, "the tamper did not apply");
    std::fs::write(&path, rewritten).unwrap();

    let result = verify_log_chain(dir.path(), &vk, "deployment-1").unwrap();
    assert!(!result.valid);
    assert!(
        result.violations.iter().any(|v| v.contains("Payload hash")),
        "expected a payload hash violation, got {:?}",
        result.violations
    );
}

#[test]
fn deleting_an_entry_breaks_the_chain() {
    let (dir, log, vk) = fixture();
    for i in 0..4 {
        log.append(event(&format!("n{}", i))).unwrap();
    }

    let path = only_log_file(dir.path());
    let content = std::fs::read_to_string(&path).unwrap();
    let kept: Vec<&str> = content
        .lines()
        .enumerate()
        .filter(|(i, _)| *i != 2)
        .map(|(_, l)| l)
        .collect();
    std::fs::write(&path, kept.join("\n") + "\n").unwrap();

    let result = verify_log_chain(dir.path(), &vk, "deployment-1").unwrap();
    assert!(!result.valid, "a deleted entry must break the chain");
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.contains("Chain broken") || v.contains("Sequence gap")),
        "violations: {:?}",
        result.violations
    );
}

/// Shuffling the *lines* in a segment is not tampering — the chain's order is
/// carried by its sequence numbers, not by where a line happens to sit in a
/// file. A verifier that treated storage order as chain order would report an
/// intact log as broken, and would hand an operator a way to fake that.
#[test]
fn shuffling_lines_within_a_segment_does_not_break_the_chain() {
    let (dir, log, vk) = fixture();
    log.append(event("first")).unwrap();
    log.append(event("second")).unwrap();
    log.append(event("third")).unwrap();

    let path = only_log_file(dir.path());
    let content = std::fs::read_to_string(&path).unwrap();
    let mut lines: Vec<&str> = content.lines().collect();
    lines.swap(2, 3);
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();

    let result = verify_log_chain(dir.path(), &vk, "deployment-1").unwrap();
    assert!(
        result.valid,
        "storage order is not chain order: {:?}",
        result.violations
    );
    assert_eq!(result.entries_verified, 4);
}

/// Genuinely reordering the chain means renumbering entries, and that must be
/// caught: the hash of each entry commits to its predecessor, so two entries
/// cannot trade places without both hashes ceasing to line up.
#[test]
fn renumbering_entries_breaks_the_chain() {
    let (dir, log, vk) = fixture();
    log.append(event("first")).unwrap();
    log.append(event("second")).unwrap();
    log.append(event("third")).unwrap();

    let path = only_log_file(dir.path());
    let content = std::fs::read_to_string(&path).unwrap();
    let mut entries: Vec<AuditEntry> = content
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();

    // Swap the sequence numbers of two adjacent entries, so the log claims an
    // order its hashes do not support.
    let (a, b) = (entries[2].sequence, entries[3].sequence);
    entries[2].sequence = b;
    entries[3].sequence = a;

    let rewritten: Vec<String> = entries
        .iter()
        .map(|e| serde_json::to_string(e).unwrap())
        .collect();
    std::fs::write(&path, rewritten.join("\n") + "\n").unwrap();

    let result = verify_log_chain(dir.path(), &vk, "deployment-1").unwrap();
    assert!(!result.valid, "a renumbered chain must be detected");
    assert!(
        result.violations.iter().any(|v| v.contains("Chain broken")),
        "violations: {:?}",
        result.violations
    );
}

/// A signature from any other key must not satisfy the verifier — otherwise a
/// node could sign its own history with a key it generated and still pass.
#[test]
fn a_log_signed_by_another_key_does_not_verify() {
    let (dir, log, _) = fixture();
    log.append(event("a")).unwrap();

    let stranger = SigningKey::generate().verifying_key();
    let result = verify_log_chain(dir.path(), &stranger, "deployment-1").unwrap();
    assert!(!result.valid);
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.contains("Signature invalid")),
        "violations: {:?}",
        result.violations
    );
}

/// The genesis link binds the chain to a deployment, so a log lifted from one
/// deployment does not verify against another.
#[test]
fn the_chain_is_bound_to_its_deployment_id() {
    let (dir, log, vk) = fixture();
    log.append(event("a")).unwrap();

    let result = verify_log_chain(dir.path(), &vk, "a-different-deployment").unwrap();
    assert!(!result.valid);
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.contains("Genesis hash mismatch")),
        "violations: {:?}",
        result.violations
    );
}

#[test]
fn reopening_a_log_resumes_its_chain() {
    let dir = tempfile::tempdir().unwrap();
    let seed = [0x11u8; 32];
    let vk = SigningKey::from_seed(&seed).verifying_key();

    let tail = {
        let log = AuditLog::open(config(dir.path()), SigningKey::from_seed(&seed)).unwrap();
        log.append(event("before-restart")).unwrap();
        log.tail_hash().unwrap()
    };

    let log = AuditLog::open(config(dir.path()), SigningKey::from_seed(&seed)).unwrap();
    assert_eq!(
        log.tail_hash().unwrap(),
        tail,
        "reopening must continue the chain, not restart it"
    );
    log.append(event("after-restart")).unwrap();

    let result = verify_log_chain(dir.path(), &vk, "deployment-1").unwrap();
    assert!(result.valid, "violations: {:?}", result.violations);
    assert_eq!(result.entries_verified, 3);
}

#[test]
fn the_tail_reader_returns_the_newest_entries_in_order() {
    let (_dir, log, _) = fixture();
    for i in 0..50 {
        log.append(event(&format!("n{:02}", i))).unwrap();
    }

    let tail = log.read_tail_entries(5).unwrap();
    assert_eq!(tail.len(), 5);
    // Chronological order, ending at the newest entry (51 = genesis + 50).
    let sequences: Vec<u64> = tail.iter().map(|e| e.sequence).collect();
    assert_eq!(sequences, vec![47, 48, 49, 50, 51]);
}

#[test]
fn the_tail_reader_handles_a_request_larger_than_the_log() {
    let (_dir, log, _) = fixture();
    log.append(event("only")).unwrap();
    assert_eq!(log.read_tail_entries(1000).unwrap().len(), 2);
    assert!(log.read_tail_entries(0).unwrap().is_empty());
}

#[test]
fn rotation_keeps_the_chain_continuous_across_files() {
    let dir = tempfile::tempdir().unwrap();
    let seed = [0x77u8; 32];
    let vk = SigningKey::from_seed(&seed).verifying_key();

    let mut cfg = config(dir.path());
    // Small enough that a handful of entries forces several rotations.
    cfg.max_file_size_bytes = 512;

    let log = AuditLog::open(cfg, SigningKey::from_seed(&seed)).unwrap();
    for i in 0..20 {
        log.append(event(&format!("n{:02}", i))).unwrap();
    }

    assert!(
        log_files(dir.path()).len() > 1,
        "the log should have rotated"
    );

    let result = verify_log_chain(dir.path(), &vk, "deployment-1").unwrap();
    assert!(
        result.valid,
        "rotation must not break the chain: {:?}",
        result.violations
    );
    assert_eq!(result.entries_verified, 21);
}

#[test]
fn an_empty_directory_verifies_vacuously() {
    let dir = tempfile::tempdir().unwrap();
    let vk = SigningKey::generate().verifying_key();
    let result = verify_log_chain(dir.path(), &vk, "deployment-1").unwrap();
    assert!(result.valid);
    assert_eq!(result.entries_verified, 0);
    assert!(result.log_tail_hash.is_none());
}

#[cfg(unix)]
#[test]
fn log_files_are_not_world_readable() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, log, _) = fixture();
    log.append(event("a")).unwrap();

    let mode = std::fs::metadata(only_log_file(dir.path()))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "audit log mode was {:o}", mode);
}
