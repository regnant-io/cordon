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
use std::path::{Path, PathBuf};
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
    /// Whether each entry is flushed *and* fsynced before `append` returns.
    ///
    /// This is what makes "log before process" survive a crash. Flushing alone
    /// only moves the entry out of Cordon's buffer into the kernel's page
    /// cache, where a power loss still discards it — and a request that was
    /// served but whose intake record was lost is exactly the gap the
    /// log-before-process rule exists to close. Durability costs one fsync per
    /// request; turn it off only where that is understood and accepted.
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

/// Name of the file that marks a log directory as having a live writer.
const WRITER_LOCK: &str = ".cordon-writer.lock";

/// An exclusive claim on a log directory, released when the log is dropped.
///
/// # Why this exists
///
/// Two Cordon processes pointed at one audit directory both read the highest
/// sequence, both continue from it, and both append. The chain forks: two
/// entries claim the same sequence, and neither hashes to the other's
/// predecessor. The verifier then reports a broken chain — which is exactly
/// what it should report, and exactly the wrong conclusion for an operator to
/// draw, because it reads as tampering when it was a second node started by
/// mistake.
///
/// A tamper-evident log that cries tamper over an operational slip is worse
/// than useless: it trains people to disbelieve it. So the second writer is
/// refused instead.
struct WriterLock {
    path: PathBuf,
}

impl WriterLock {
    /// Claim `log_dir`, or explain who already has it.
    fn acquire(log_dir: &Path, node_id: &str) -> AuditResult<Self> {
        let path = log_dir.join(WRITER_LOCK);

        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        match options.open(&path) {
            Ok(mut file) => {
                let _ = writeln!(file, "node_id={}", node_id);
                let _ = writeln!(file, "pid={}", std::process::id());
                let _ = writeln!(file, "since={}", Utc::now().to_rfc3339());
                let _ = file.sync_all();
                Ok(Self { path })
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let holder = std::fs::read_to_string(&path).unwrap_or_default();
                Err(AuditError::AlreadyLocked(format!(
                    "another Cordon node is already writing to the audit log at {}.\n\n{}\n\
                     Two writers fork the hash chain: both continue from the same \
                     sequence, and the log then fails verification as though it had been \
                     tampered with. Point this node at its own audit directory.\n\n\
                     If no node is running, the previous one did not shut down cleanly. \
                     Verify the chain with cordon-verify-log, then remove {} to release \
                     the claim.",
                    log_dir.display(),
                    holder.trim(),
                    path.display()
                )))
            }
            Err(e) => Err(AuditError::IoError(format!(
                "cannot claim the audit log at {}: {}",
                log_dir.display(),
                e
            ))),
        }
    }
}

impl Drop for WriterLock {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.path) {
            tracing::warn!(
                path = %self.path.display(),
                "could not release the audit log claim: {}. Remove the file before \
                 starting another node against this directory.",
                e
            );
        }
    }
}

/// Merkle-chained audit log
pub struct AuditLog {
    config: LogConfig,
    signing_key: SigningKey,
    state: Mutex<Option<LogState>>,
    /// Held for the life of the log. Dropping it releases the directory.
    _writer_lock: WriterLock,
}

impl AuditLog {
    /// Create or open an audit log.
    ///
    /// If the log directory exists and contains entries, resumes from the last entry.
    /// If the directory is empty or new, creates a genesis entry.
    ///
    /// Claims the directory exclusively: a second node pointed at the same one
    /// is refused rather than allowed to fork the chain. See [`WriterLock`].
    pub fn open(config: LogConfig, signing_key: SigningKey) -> AuditResult<Self> {
        std::fs::create_dir_all(&config.log_dir)
            .map_err(|e| AuditError::IoError(format!("Cannot create log dir: {}", e)))?;

        let writer_lock = WriterLock::acquire(&config.log_dir, &config.node_id)?;

        let log = Self {
            config,
            signing_key,
            state: Mutex::new(None),
            _writer_lock: writer_lock,
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
                let path = self.new_log_file_path(1);
                let genesis_hash = self.compute_genesis_hash();
                (path, genesis_hash, 0u64)
            }
        };

        let file = open_log_file(&file_path)?;

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
            // Both steps are required. `flush` empties Cordon's BufWriter into
            // the kernel; `sync_data` is what puts the bytes on the device. A
            // flush alone leaves the entry in the page cache, where a power loss
            // discards it — and the caller has already been told the request was
            // logged.
            state
                .writer
                .flush()
                .map_err(|e| AuditError::WriteFailed(e.to_string()))?;
            state.writer.get_ref().sync_data().map_err(|e| {
                AuditError::WriteFailed(format!("cannot fsync the audit log: {}", e))
            })?;
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

    /// Find the segment holding the highest sequence number, and resume from it.
    ///
    /// The file to resume into is chosen by reading each segment's last entry
    /// and taking the greatest sequence, not by sorting filenames. Filename
    /// order is a property of how a name was formatted; sequence order is a
    /// property of the chain itself, and only the second one is guaranteed to
    /// be the order the entries were written in.
    fn find_existing_log_file(&self) -> AuditResult<Option<(PathBuf, String, u64)>> {
        let mut newest: Option<(PathBuf, String, u64)> = None;

        for path in self.log_files()? {
            let Some(entry) = read_last_entry(&path)? else {
                continue; // An empty segment carries no chain state.
            };
            let replace = match &newest {
                Some((_, _, seq)) => entry.sequence > *seq,
                None => true,
            };
            if replace {
                newest = Some((path, entry.entry_hash, entry.sequence));
            }
        }

        Ok(newest)
    }

    /// Build the path for a new segment beginning at `first_sequence`.
    ///
    /// The sequence number leads the name, zero-padded to a fixed width, so
    /// segments sort into chain order as plain strings. An earlier format put
    /// only a whole-second timestamp and a random UUID in the name; two
    /// rotations inside the same second then sorted by the UUID, which is to
    /// say at random, and every reader that walked the directory in filename
    /// order reconstructed the chain out of order and reported it as broken.
    /// The timestamp is retained after the sequence for human legibility, and
    /// a short random suffix keeps two writers from colliding on one name.
    fn new_log_file_path(&self, first_sequence: u64) -> PathBuf {
        let ts = Utc::now().format("%Y%m%dT%H%M%S");
        let unique = Uuid::new_v4().simple().to_string();
        self.config.log_dir.join(format!(
            "cordon-audit-{:020}-{}-{}.jsonl",
            first_sequence,
            ts,
            &unique[..8]
        ))
    }

    /// Rotate the log file (called when current file exceeds max size)
    fn rotate_log_file(&self, state: &mut LogState) -> AuditResult<()> {
        // Flush current writer
        state
            .writer
            .flush()
            .map_err(|e| AuditError::WriteFailed(e.to_string()))?;

        // The new segment is named for the sequence it will begin at, which is
        // one past the entry just written.
        let new_path = self.new_log_file_path(state.sequence + 1);
        let new_file = open_log_file(&new_path)?;

        state.writer = BufWriter::new(new_file);
        state.current_file = new_path;
        state.bytes_written = 0;

        tracing::info!("Audit log rotated to {:?}", state.current_file);
        Ok(())
    }

    /// Read the most recent `n` entries without loading the whole log.
    ///
    /// Segments are visited newest-first and each is read only until enough
    /// entries have been collected, so tailing a multi-gigabyte log costs the
    /// size of its newest segments rather than the size of the log. The result
    /// is in chain order.
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

        // Order by the chain's own sequence rather than by the order segments
        // happened to be visited in.
        collected.sort_by_key(|e| e.sequence);
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

    /// Every log segment in the directory, in filename order.
    ///
    /// Filenames lead with a zero-padded sequence number, so this is chain
    /// order for any segment this version wrote. It is a hint rather than a
    /// guarantee — readers sort by each entry's own sequence afterwards, so a
    /// renamed or externally-produced segment cannot reorder the chain.
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

    /// The directory this log writes to.
    pub fn log_dir(&self) -> &std::path::Path {
        &self.config.log_dir
    }

    /// Read every entry from every log segment, in chain order.
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

        entries.sort_by_key(|e| e.sequence);
        Ok(entries)
    }
}

/// Read the last entry of a segment without loading the whole file.
///
/// Segments are capped at `max_file_size_bytes`, which defaults to 512 MB, so
/// reading one in full just to see its final line would make opening a log
/// proportional to the size of the log. The file is instead read backwards in
/// blocks until a complete final line is in hand.
fn read_last_entry(path: &PathBuf) -> AuditResult<Option<AuditEntry>> {
    use std::io::{Read, Seek, SeekFrom};

    const BLOCK: usize = 64 * 1024;

    let mut file = File::open(path).map_err(|e| AuditError::IoError(e.to_string()))?;
    let len = file
        .metadata()
        .map_err(|e| AuditError::IoError(e.to_string()))?
        .len();
    if len == 0 {
        return Ok(None);
    }

    let mut tail: Vec<u8> = Vec::new();
    let mut read_from = len;

    loop {
        let block = BLOCK.min(read_from as usize);
        read_from -= block as u64;

        let mut buf = vec![0u8; block];
        file.seek(SeekFrom::Start(read_from))
            .map_err(|e| AuditError::IoError(e.to_string()))?;
        file.read_exact(&mut buf)
            .map_err(|e| AuditError::IoError(e.to_string()))?;

        buf.extend_from_slice(&tail);
        tail = buf;

        // A complete final line needs a newline before it, unless we have
        // reached the start of the file.
        let text = String::from_utf8_lossy(&tail);
        let last = text.lines().rfind(|l| !l.trim().is_empty());
        let have_complete_line = tail.contains(&b'\n') || read_from == 0;

        if let Some(line) = last {
            if have_complete_line {
                return serde_json::from_str::<AuditEntry>(line)
                    .map(Some)
                    .map_err(|e| {
                        AuditError::SerializationError(format!(
                            "last entry of {:?} is unreadable: {}",
                            path, e
                        ))
                    });
            }
        }

        if read_from == 0 {
            return Ok(None);
        }
    }
}

/// Open a log file for appending, readable only by the account running Cordon.
///
/// Entries carry client identifiers, model identifiers, token counts, and
/// policy outcomes. None of that is secret in the way a key is, but none of it
/// belongs to every local account either, and the default umask would make it
/// world-readable.
fn open_log_file(path: &PathBuf) -> AuditResult<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    options
        .open(path)
        .map_err(|e| AuditError::IoError(format!("Cannot open log file {:?}: {}", path, e)))
}
