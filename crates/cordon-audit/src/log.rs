//! Merkle-chained audit log implementation — §9.1
//!
//! Each entry: entry_hash_n = SHA-256(entry_hash_{n-1} || timestamp_n || payload_hash_n)
//!             signature_n  = Ed25519_Sign(K_log, entry_hash_n)
//!
//! Properties:
//! - Modification of entry n: changes payload_hash_n → changes entry_hash_n → invalidates signature_n
//! - Deletion of entry n: breaks chain link → detected
//! - Insertion: requires K_log → held by client → vendor cannot forge
//! - Genesis entry uses well-known constant

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use uuid::Uuid;

use crate::error::{AuditError, AuditResult};
use crate::events::AuditEvent;
use cordon_crypto::signing::{SigningKey, VerifyingKey};

/// Genesis constant — well-known value embedded in the Cordon binary.
/// The genesis entry hash includes this constant; it is verified during log verification.
pub const GENESIS_CONSTANT: &[u8] = b"CORDON_LOG_GENESIS_V2";

/// Configuration for the audit log
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Directory where log files are stored
    pub log_dir: PathBuf,
    /// Deployment ID (included in genesis hash)
    pub deployment_id: String,
    /// Node ID
    pub node_id: String,
    /// Maximum log file size before rotation (bytes)
    pub max_file_size_bytes: u64,
    /// Whether to fsync after every write (performance vs durability trade-off)
    pub fsync_on_write: bool,
}

impl LogConfig {
    /// Create a new log config with sane defaults
    pub fn new(log_dir: PathBuf, deployment_id: String, node_id: String) -> Self {
        Self {
            log_dir,
            deployment_id,
            node_id,
            max_file_size_bytes: 512 * 1024 * 1024, // 512 MB
            fsync_on_write: true,
        }
    }
}

/// A single audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique entry ID
    pub log_id: Uuid,
    /// Entry timestamp (UTC)
    pub timestamp: DateTime<Utc>,
    /// SHA-256 of the serialized payload (hex)
    pub payload_hash: String,
    /// Chained hash: SHA-256(prev_hash || timestamp || payload_hash) (hex)
    pub entry_hash: String,
    /// Ed25519 signature over entry_hash (hex)
    pub signature: String,
    /// The actual event payload
    pub payload: AuditEvent,
    /// Sequence number (monotonically increasing)
    pub sequence: u64,
}

/// Internal write state for the audit log
struct LogState {
    /// Current log file writer
    writer: BufWriter<File>,
    /// Hash of the most recently written entry
    last_hash: String,
    /// Current sequence number
    sequence: u64,
    /// Current log file path
    current_file: PathBuf,
    /// Bytes written to current file
    bytes_written: u64,
}

/// Merkle-chained audit log
pub struct AuditLog {
    config: LogConfig,
    signing_key: SigningKey,
    state: Mutex<Option<LogState>>,
}

impl AuditLog {
    /// Create or open an audit log.
    ///
    /// If the log directory exists and contains entries, resumes from the last entry.
    /// If the directory is empty or new, creates a genesis entry.
    pub fn open(config: LogConfig, signing_key: SigningKey) -> AuditResult<Self> {
        std::fs::create_dir_all(&config.log_dir)
            .map_err(|e| AuditError::IoError(format!("Cannot create log dir: {}", e)))?;

        let log = Self {
            config,
            signing_key,
            state: Mutex::new(None),
        };

        log.initialize()?;
        Ok(log)
    }

    /// Initialize the log — either resume from existing or create genesis
    fn initialize(&self) -> AuditResult<()> {
        let existing = self.find_existing_log_file()?;

        let (file_path, last_hash, sequence) = match existing {
            Some((path, last_hash, seq)) => (path, last_hash, seq),
            None => {
                // Create new log file with genesis entry
                let path = self.new_log_file_path();
                let genesis_hash = self.compute_genesis_hash();
                (path, genesis_hash, 0u64)
            }
        };

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
            .map_err(|e| AuditError::IoError(format!("Cannot open log file: {}", e)))?;

        let bytes_written = file.metadata().map(|m| m.len()).unwrap_or(0);

        let writer = BufWriter::new(file);

        let mut state = self.state.lock();
        *state = Some(LogState {
            writer,
            last_hash,
            sequence,
            current_file: file_path,
            bytes_written,
        });

        // Write genesis event if this is a new log
        if sequence == 0 {
            drop(state);
            self.write_genesis()?;
        }

        Ok(())
    }

    /// Write a genesis lifecycle entry
    fn write_genesis(&self) -> AuditResult<()> {
        use crate::events::{LifecycleEvent, LifecycleEventType};

        let event = AuditEvent::Lifecycle(LifecycleEvent {
            event: LifecycleEventType::Boot,
            cordon_version: env!("CARGO_PKG_VERSION").to_string(),
            tee_type: "initialized".to_string(),
            node_id: self.config.node_id.clone(),
        });
        self.append(event)?;
        Ok(())
    }

    /// Append an event to the audit log.
    ///
    /// This is the only public write method. The log is append-only.
    /// Write failure returns an error — callers must treat write failure as fatal.
    pub fn append(&self, event: AuditEvent) -> AuditResult<AuditEntry> {
        let mut state_guard = self.state.lock();
        let state = state_guard
            .as_mut()
            .ok_or_else(|| AuditError::WriteFailed("Log not initialized".into()))?;

        let now = Utc::now();
        let log_id = Uuid::new_v4();
        let sequence = state.sequence + 1;

        // Compute payload hash
        let payload_bytes = serde_json::to_vec(&event)
            .map_err(|e| AuditError::SerializationError(e.to_string()))?;
        let payload_hash = hex::encode(Sha256::digest(&payload_bytes));

        // Compute chained entry hash
        let entry_hash = {
            let mut hasher = Sha256::new();
            hasher.update(state.last_hash.as_bytes());
            hasher.update(now.to_rfc3339().as_bytes());
            hasher.update(payload_hash.as_bytes());
            hex::encode(hasher.finalize())
        };

        // Sign the entry hash
        let sig = self.signing_key.sign(entry_hash.as_bytes());
        let signature = sig.to_hex();

        let entry = AuditEntry {
            log_id,
            timestamp: now,
            payload_hash,
            entry_hash: entry_hash.clone(),
            signature,
            payload: event,
            sequence,
        };

        // Serialize and write
        let mut line = serde_json::to_string(&entry)
            .map_err(|e| AuditError::SerializationError(e.to_string()))?;
        line.push('\n');

        let bytes = line.as_bytes();
        state
            .writer
            .write_all(bytes)
            .map_err(|e| AuditError::WriteFailed(e.to_string()))?;

        if self.config.fsync_on_write {
            state
                .writer
                .flush()
                .map_err(|e| AuditError::WriteFailed(e.to_string()))?;
        }

        state.bytes_written += bytes.len() as u64;
        state.last_hash = entry_hash;
        state.sequence = sequence;

        // Rotate log file if needed
        if state.bytes_written >= self.config.max_file_size_bytes {
            self.rotate_log_file(state)?;
        }

        Ok(entry)
    }

    /// Get the current tail hash (for external verification or anchoring)
    pub fn tail_hash(&self) -> Option<String> {
        let state = self.state.lock();
        state.as_ref().map(|s| s.last_hash.clone())
    }

    /// Get the current sequence number
    pub fn sequence(&self) -> u64 {
        let state = self.state.lock();
        state.as_ref().map(|s| s.sequence).unwrap_or(0)
    }

    /// Get the verifying key for this log (share with client for verification)
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Compute the genesis hash for this deployment
    fn compute_genesis_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(GENESIS_CONSTANT);
        hasher.update(self.config.deployment_id.as_bytes());
        // Genesis timestamp is the constant zero time for determinism
        hasher.update(b"GENESIS");
        hex::encode(hasher.finalize())
    }

    /// Find the most recent existing log file and read its last entry
    fn find_existing_log_file(&self) -> AuditResult<Option<(PathBuf, String, u64)>> {
        let mut log_files: Vec<PathBuf> = std::fs::read_dir(&self.config.log_dir)
            .map_err(|e| AuditError::IoError(e.to_string()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().map(|e| e == "jsonl").unwrap_or(false))
            .collect();

        if log_files.is_empty() {
            return Ok(None);
        }

        log_files.sort();
        let latest = log_files.last().unwrap().clone();

        // Read last line to get last entry
        let content =
            std::fs::read_to_string(&latest).map_err(|e| AuditError::IoError(e.to_string()))?;
        let last_line = content.lines().last();

        match last_line {
            None => Ok(None),
            Some(line) => {
                let entry: AuditEntry = serde_json::from_str(line)
                    .map_err(|e| AuditError::SerializationError(e.to_string()))?;
                Ok(Some((latest, entry.entry_hash, entry.sequence)))
            }
        }
    }

    /// Create a new log file path with timestamp
    fn new_log_file_path(&self) -> PathBuf {
        let ts = Utc::now().format("%Y%m%dT%H%M%S");
        self.config
            .log_dir
            .join(format!("cordon-audit-{}-{}.jsonl", ts, Uuid::new_v4()))
    }

    /// Rotate the log file (called when current file exceeds max size)
    fn rotate_log_file(&self, state: &mut LogState) -> AuditResult<()> {
        // Flush current writer
        state
            .writer
            .flush()
            .map_err(|e| AuditError::WriteFailed(e.to_string()))?;

        // Open new file
        let new_path = self.new_log_file_path();
        let new_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&new_path)
            .map_err(|e| AuditError::IoError(format!("Cannot create rotated log: {}", e)))?;

        state.writer = BufWriter::new(new_file);
        state.current_file = new_path;
        state.bytes_written = 0;

        tracing::info!("Audit log rotated to {:?}", state.current_file);
        Ok(())
    }

    /// Read the most recent `n` entries without loading the whole log.
    ///
    /// Files are visited newest-first and each is read only until enough
    /// entries have been collected, so tailing a multi-gigabyte log costs the
    /// size of its newest segment rather than the size of the log. The result is
    /// in chronological order.
    pub fn read_tail_entries(&self, n: usize) -> AuditResult<Vec<AuditEntry>> {
        if n == 0 {
            return Ok(Vec::new());
        }
        let mut files = self.log_files()?;
        files.reverse();

        let mut collected: Vec<AuditEntry> = Vec::with_capacity(n);
        for file in files {
            let content =
                std::fs::read_to_string(&file).map_err(|e| AuditError::IoError(e.to_string()))?;
            for line in content.lines().rev() {
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<AuditEntry>(line) {
                    Ok(entry) => collected.push(entry),
                    Err(e) => {
                        // A corrupt line is a finding, not a reason to fail the
                        // whole read — the chain verifier is what adjudicates it.
                        tracing::warn!(file = %file.display(), "Skipping unparseable audit line: {}", e);
                    }
                }
                if collected.len() >= n {
                    break;
                }
            }
            if collected.len() >= n {
                break;
            }
        }

        collected.reverse();
        Ok(collected)
    }

    /// Total entries across every log file, counted by line rather than parsed.
    pub fn count_entries(&self) -> AuditResult<usize> {
        let mut total = 0usize;
        for file in self.log_files()? {
            let content =
                std::fs::read_to_string(&file).map_err(|e| AuditError::IoError(e.to_string()))?;
            total += content.lines().filter(|l| !l.trim().is_empty()).count();
        }
        Ok(total)
    }

    /// Every log file in the directory, in chronological (filename) order.
    fn log_files(&self) -> AuditResult<Vec<PathBuf>> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(&self.config.log_dir)
            .map_err(|e| AuditError::IoError(e.to_string()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().map(|e| e == "jsonl").unwrap_or(false))
            .collect();
        files.sort();
        Ok(files)
    }

    /// Read every entry from every log file.
    ///
    /// Linear in the size of the log — use [`Self::read_tail_entries`] on any
    /// request path.
    pub fn read_all_entries(&self) -> AuditResult<Vec<AuditEntry>> {
        let mut entries = Vec::new();
        for file in self.log_files()? {
            let content =
                std::fs::read_to_string(&file).map_err(|e| AuditError::IoError(e.to_string()))?;
            for line in content.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                let entry: AuditEntry = serde_json::from_str(line)
                    .map_err(|e| AuditError::SerializationError(e.to_string()))?;
                entries.push(entry);
            }
        }

        Ok(entries)
    }
}
