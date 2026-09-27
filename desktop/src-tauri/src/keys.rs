//! The Client Master Key, kept by the app.
//!
//! One key seals bundles and, outside Light mode, signs the audit log and
//! responses. The app keeps it in its data folder, readable only by the
//! account running it, and never shows it: the only ways out are an explicit
//! backup to a file the operator chooses, and the node reading it at start.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use cordon_crypto::hierarchy::MasterKey;

/// What the app knows about its key, safe to show.
#[derive(Debug, Clone, Serialize, Default)]
pub struct KeyStatus {
    /// Whether a key exists.
    pub present: bool,
    /// A short, stable name for the key: the start of a one-way digest of it.
    /// Lets an operator tell two keys apart without revealing either.
    pub id: Option<String>,
    /// When the key file was written.
    pub created: Option<chrono::DateTime<chrono::Utc>>,
}

/// The key file inside `dir`.
pub fn path(dir: &Path) -> PathBuf {
    dir.join("cmk.hex")
}

/// Load the key, if there is one.
pub fn load(dir: &Path) -> Result<Option<MasterKey>> {
    let file = path(dir);
    match std::fs::read_to_string(&file) {
        Ok(text) => MasterKey::from_hex(text.trim())
            .map(Some)
            .with_context(|| format!("{} does not hold a valid key", file.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("cannot read {}", file.display())),
    }
}

/// The key's status.
pub fn status(dir: &Path) -> KeyStatus {
    match load(dir) {
        Ok(Some(key)) => KeyStatus {
            present: true,
            id: Some(key_id(&key)),
            created: std::fs::metadata(path(dir))
                .and_then(|m| m.modified())
                .ok()
                .map(chrono::DateTime::from),
        },
        _ => KeyStatus::default(),
    }
}

/// A short, stable identifier for a key.
///
/// Domain-separated and truncated, so it identifies the key without being
/// usable as it or as anything derived from it.
pub fn key_id(key: &MasterKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"cordon-desktop-key-id-v1");
    hasher.update(key.to_hex().as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("{}-{}", &digest[..4], &digest[4..8])
}

/// Create a key. Refuses to replace one: every bundle sealed under the old
/// key would become unreadable.
pub fn create(dir: &Path) -> Result<KeyStatus> {
    if path(dir).exists() {
        bail!("A key already exists. Remove it first if you mean to replace it.");
    }
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    write(dir, &MasterKey::from_bytes(bytes))?;
    tracing::info!("Created a Client Master Key");
    Ok(status(dir))
}

/// Import a key from a file holding 64 hex characters, as `cordon keys
/// generate` writes. Refuses to replace a different key.
pub fn import(dir: &Path, from: &Path) -> Result<KeyStatus> {
    let text =
        std::fs::read_to_string(from).with_context(|| format!("cannot read {}", from.display()))?;
    let key = MasterKey::from_hex(text.trim())
        .context("That file does not hold a Client Master Key (64 hexadecimal characters).")?;
    if let Some(existing) = load(dir)? {
        if existing.to_hex() == key.to_hex() {
            return Ok(status(dir));
        }
        bail!("A different key already exists. Remove it first if you mean to replace it.");
    }
    write(dir, &key)?;
    tracing::info!(id = %key_id(&key), "Imported a Client Master Key");
    Ok(status(dir))
}

/// Copy the key to a file the operator chose, for safekeeping.
pub fn backup(dir: &Path, to: &Path) -> Result<()> {
    let key = load(dir)?.context("There is no key to back up.")?;
    write_secret(to, &key.to_hex())?;
    tracing::info!(to = %to.display(), "Backed up the Client Master Key");
    Ok(())
}

/// Delete the key.
pub fn remove(dir: &Path) -> Result<()> {
    let file = path(dir);
    if file.exists() {
        std::fs::remove_file(&file).with_context(|| format!("cannot remove {}", file.display()))?;
        tracing::warn!("Removed the Client Master Key");
    }
    Ok(())
}

fn write(dir: &Path, key: &MasterKey) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    write_secret(&path(dir), &key.to_hex())
}

/// Write a secret readable only by its owner where the platform allows it.
/// On Windows the file takes the ACL of the per-user data folder it is in.
fn write_secret(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = options
        .open(&tmp)
        .and_then(|mut f| f.write_all(contents.as_bytes()).and_then(|_| f.sync_all()))
        .and_then(|_| std::fs::rename(&tmp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.with_context(|| format!("cannot write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_created_once_and_identified_stably() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!status(dir.path()).present);
        let created = create(dir.path()).unwrap();
        assert!(created.present);
        assert_eq!(status(dir.path()).id, created.id);
        assert!(
            create(dir.path()).is_err(),
            "a second key must not replace the first"
        );
    }

    #[test]
    fn import_accepts_a_key_file_and_refuses_a_different_key() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("cmk.txt");
        std::fs::write(&source, format!("{}\n", "ab".repeat(32))).unwrap();
        let keys = dir.path().join("keys");
        import(&keys, &source).unwrap();
        import(&keys, &source).unwrap();

        std::fs::write(&source, "cd".repeat(32)).unwrap();
        assert!(import(&keys, &source).is_err());
        std::fs::write(&source, "not a key").unwrap();
        assert!(import(&dir.path().join("other"), &source).is_err());
    }

    #[test]
    fn a_backup_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        create(&keys).unwrap();
        let backup_file = dir.path().join("backup.hex");
        backup(&keys, &backup_file).unwrap();
        let restored = dir.path().join("restored");
        import(&restored, &backup_file).unwrap();
        assert_eq!(status(&keys).id, status(&restored).id);
    }
}
