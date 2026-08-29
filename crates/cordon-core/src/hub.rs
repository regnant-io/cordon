//! Model acquisition from the Hugging Face Hub.
//!
//! Backs `cordon pull`. Resolves a repository reference to a concrete GGUF file
//! at a pinned commit, downloads it with resume support, and verifies the
//! content hash the Hub publishes before the file is admitted to the local
//! model directory.
//!
//! # Reference syntax
//!
//! ```text
//! owner/repo                 latest revision, best available quantisation
//! owner/repo:Q4_K_M          latest revision, that quantisation
//! owner/repo@<revision>      pinned commit or branch
//! owner/repo@<revision>:Q4_K_M
//! hf.co/owner/repo:Q4_K_M    the `hf.co/` prefix is accepted and ignored
//! ```
//!
//! # Trust
//!
//! A pull reaches the public internet, so it is available only in deployment
//! modes whose egress policy permits it — see
//! [`CordonConfig::permits_model_download`](crate::config::CordonConfig::permits_model_download).
//! Air-gapped modes acquire models through `cordon-provision` from physical
//! media instead.
//!
//! Every download is checked against the SHA-256 the Hub reports for the file
//! (`X-Linked-Etag` for LFS objects). A repository that does not publish one is
//! downloaded and the computed digest is recorded, but the caller is told the
//! content was unverified so it can decide whether to proceed.

use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::error::{CordonError, CordonResult};

/// Base URL for the Hugging Face Hub. Overridable for mirrors and enterprise
/// Hub deployments via `HF_ENDPOINT`.
fn hub_endpoint() -> String {
    std::env::var("HF_ENDPOINT")
        .unwrap_or_else(|_| "https://huggingface.co".to_string())
        .trim_end_matches('/')
        .to_string()
}

/// Quantisations preferred when the caller does not name one, best balance
/// first. Q4_K_M is the usual default for local inference.
const QUANT_PREFERENCE: &[&str] = &[
    "Q4_K_M", "Q4_K_S", "Q5_K_M", "Q5_K_S", "Q8_0", "Q6_K", "Q4_0", "F16", "BF16", "F32",
];

/// A parsed model reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelRef {
    /// Repository owner.
    pub owner: String,
    /// Repository name.
    pub repo: String,
    /// Git revision (commit, branch, or tag). Defaults to `main`.
    pub revision: String,
    /// Requested quantisation, if the caller named one.
    pub quant: Option<String>,
}

impl ModelRef {
    /// Parse a reference in the syntax documented on this module.
    pub fn parse(input: &str) -> CordonResult<Self> {
        let input = input.trim();
        if input.is_empty() {
            return Err(CordonError::ValidationFailed(
                "empty model reference".into(),
            ));
        }

        // Accept and discard a hub host prefix, so references copied from a URL
        // or from an Ollama command work unchanged.
        let mut rest = input;
        for prefix in [
            "https://huggingface.co/",
            "http://huggingface.co/",
            "hf.co/",
            "huggingface.co/",
        ] {
            if let Some(stripped) = rest.strip_prefix(prefix) {
                rest = stripped;
                break;
            }
        }

        // `:quant` comes last and cannot contain `/` or `@`.
        let (rest, quant) = match rest.rsplit_once(':') {
            Some((head, tail))
                if !tail.contains('/') && !tail.contains('@') && !tail.is_empty() =>
            {
                (head, Some(tail.to_string()))
            }
            _ => (rest, None),
        };

        let (rest, revision) = match rest.split_once('@') {
            Some((head, tail)) if !tail.is_empty() => (head, tail.to_string()),
            _ => (rest, "main".to_string()),
        };

        let mut parts = rest.split('/').filter(|p| !p.is_empty());
        let owner = parts.next().ok_or_else(|| {
            CordonError::ValidationFailed(format!("model reference '{}' has no owner", input))
        })?;
        let repo = parts.next().ok_or_else(|| {
            CordonError::ValidationFailed(format!(
                "model reference '{}' must be owner/repo (for example \
                 HuggingFaceTB/SmolLM2-360M-Instruct-GGUF)",
                input
            ))
        })?;
        if parts.next().is_some() {
            return Err(CordonError::ValidationFailed(format!(
                "model reference '{}' has too many path segments",
                input
            )));
        }

        validate_path_segment(owner, "owner")?;
        validate_path_segment(repo, "repository")?;
        validate_path_segment(&revision, "revision")?;
        if let Some(q) = &quant {
            validate_path_segment(q, "quantisation")?;
        }

        Ok(Self {
            owner: owner.to_string(),
            repo: repo.to_string(),
            revision,
            quant,
        })
    }

    /// `owner/repo`.
    pub fn repo_id(&self) -> String {
        format!("{}/{}", self.owner, self.repo)
    }

    /// A filesystem-safe, collision-resistant local identifier.
    pub fn local_id(&self) -> String {
        let quant = self.quant.as_deref().unwrap_or("auto");
        format!(
            "{}--{}--{}",
            self.owner.to_lowercase(),
            self.repo.to_lowercase(),
            quant.to_lowercase()
        )
    }
}

impl std::fmt::Display for ModelRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.owner, self.repo)?;
        if self.revision != "main" {
            write!(f, "@{}", self.revision)?;
        }
        if let Some(q) = &self.quant {
            write!(f, ":{}", q)?;
        }
        Ok(())
    }
}

/// Reject anything that could escape the intended URL path.
fn validate_path_segment(segment: &str, what: &str) -> CordonResult<()> {
    if segment.is_empty() {
        return Err(CordonError::ValidationFailed(format!("empty {}", what)));
    }
    if segment == "." || segment == ".." || segment.contains("..") {
        return Err(CordonError::ValidationFailed(format!(
            "{} '{}' contains a path traversal",
            what, segment
        )));
    }
    if !segment
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(CordonError::ValidationFailed(format!(
            "{} '{}' contains characters outside [A-Za-z0-9._-]",
            what, segment
        )));
    }
    Ok(())
}

/// One file listed in a repository.
#[derive(Debug, Clone, Deserialize)]
struct Sibling {
    rfilename: String,
}

/// Repository metadata as returned by the Hub API.
#[derive(Debug, Clone, Deserialize)]
struct RepoInfo {
    #[serde(default)]
    sha: Option<String>,
    #[serde(default)]
    siblings: Vec<Sibling>,
    #[serde(default)]
    gated: serde_json::Value,
}

/// A GGUF file selected for download.
#[derive(Debug, Clone, Serialize)]
pub struct ResolvedModel {
    /// The reference that produced this resolution.
    pub repo_id: String,
    /// The commit the file was resolved at. Pinning to this makes a later pull
    /// reproducible even if the branch moves.
    pub revision: String,
    /// Path of the file within the repository.
    pub filename: String,
    /// Quantisation inferred from the filename.
    pub quant: Option<String>,
    /// Direct download URL.
    pub url: String,
}

/// Record written next to a downloaded model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadedModel {
    /// Local identifier, usable as `--model`.
    pub id: String,
    /// Source repository.
    pub repo_id: String,
    /// Resolved commit.
    pub revision: String,
    /// Source filename.
    pub filename: String,
    /// Quantisation, if it could be inferred.
    pub quant: Option<String>,
    /// Absolute path to the GGUF file.
    pub path: PathBuf,
    /// Size on disk in bytes.
    pub size_bytes: u64,
    /// SHA-256 of the file contents.
    pub sha256: String,
    /// Whether `sha256` was checked against a digest published by the Hub.
    /// When false the digest is merely what was received.
    pub digest_verified: bool,
    /// When the download completed.
    pub downloaded_at: chrono::DateTime<chrono::Utc>,
}

/// Progress during a download.
#[derive(Debug, Clone, Copy)]
pub struct Progress {
    /// Bytes written so far, including any resumed prefix.
    pub downloaded: u64,
    /// Total size, when the server reports one.
    pub total: Option<u64>,
}

/// A Hugging Face Hub client.
pub struct HubClient {
    http: reqwest::Client,
    endpoint: String,
    token: Option<String>,
}

impl HubClient {
    /// Build a client. The access token is read from `HF_TOKEN`, then
    /// `HUGGING_FACE_HUB_TOKEN`, and is required only for gated repositories.
    pub fn new() -> CordonResult<Self> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .pool_idle_timeout(Duration::from_secs(60))
            .user_agent(concat!("cordon/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| CordonError::Internal(format!("cannot build Hub client: {}", e)))?;

        let token = std::env::var("HF_TOKEN")
            .or_else(|_| std::env::var("HUGGING_FACE_HUB_TOKEN"))
            .ok()
            .filter(|t| !t.trim().is_empty());

        Ok(Self {
            http,
            endpoint: hub_endpoint(),
            token,
        })
    }

    fn authorized(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.token {
            Some(t) => builder.bearer_auth(t),
            None => builder,
        }
    }

    /// List the GGUF files a repository publishes, newest revision first.
    pub async fn list_gguf_files(&self, model: &ModelRef) -> CordonResult<(String, Vec<String>)> {
        let url = format!(
            "{}/api/models/{}/revision/{}",
            self.endpoint,
            model.repo_id(),
            model.revision
        );

        let response = self
            .authorized(self.http.get(&url).timeout(Duration::from_secs(30)))
            .send()
            .await
            .map_err(|e| {
                CordonError::ModelDownloadFailed(format!("cannot reach the Hub at {}: {}", url, e))
            })?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(CordonError::ModelDownloadFailed(format!(
                "repository {} has no revision '{}' (or does not exist)",
                model.repo_id(),
                model.revision
            )));
        }
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(CordonError::ModelDownloadFailed(format!(
                "access to {} was refused (HTTP {}). Gated repositories need an \
                 access token in HF_TOKEN, and the licence must be accepted on the \
                 Hub first.",
                model.repo_id(),
                status
            )));
        }
        if !status.is_success() {
            return Err(CordonError::ModelDownloadFailed(format!(
                "the Hub returned HTTP {} for {}",
                status,
                model.repo_id()
            )));
        }

        let info: RepoInfo = response.json().await.map_err(|e| {
            CordonError::ModelDownloadFailed(format!("malformed Hub response: {}", e))
        })?;

        if info.gated.as_bool() == Some(true) || info.gated.as_str().is_some() {
            tracing::info!(repo = %model.repo_id(), "Repository is gated; using the configured token");
        }

        let revision = info.sha.unwrap_or_else(|| model.revision.clone());
        let mut files: Vec<String> = info
            .siblings
            .into_iter()
            .map(|s| s.rfilename)
            .filter(|f| f.to_lowercase().ends_with(".gguf"))
            .collect();
        files.sort();

        Ok((revision, files))
    }

    /// Choose the GGUF file to download for a reference.
    pub async fn resolve(&self, model: &ModelRef) -> CordonResult<ResolvedModel> {
        let (revision, files) = self.list_gguf_files(model).await?;

        if files.is_empty() {
            return Err(CordonError::ModelDownloadFailed(format!(
                "{} publishes no .gguf files. Cordon serves GGUF models; look for a \
                 '-GGUF' repository, or convert the weights with llama.cpp's \
                 convert_hf_to_gguf.py.",
                model.repo_id()
            )));
        }

        // Multi-part GGUF files ("-00001-of-00003.gguf") need every shard, which
        // the single-file path here cannot express. Surface that plainly rather
        // than downloading one shard that will not load.
        let filename = match &model.quant {
            Some(requested) => {
                let wanted = requested.to_lowercase();
                files
                    .iter()
                    .find(|f| {
                        quant_of(f)
                            .map(|q| q.to_lowercase() == wanted)
                            .unwrap_or(false)
                    })
                    .or_else(|| files.iter().find(|f| f.to_lowercase().contains(&wanted)))
                    .cloned()
                    .ok_or_else(|| {
                        CordonError::ModelDownloadFailed(format!(
                            "{} has no '{}' quantisation. Available: {}",
                            model.repo_id(),
                            requested,
                            available_quants(&files)
                        ))
                    })?
            }
            None => pick_default_quant(&files).ok_or_else(|| {
                CordonError::ModelDownloadFailed(format!(
                    "cannot choose a quantisation for {} automatically. Pick one \
                     explicitly, for example {}:{}",
                    model.repo_id(),
                    model.repo_id(),
                    quant_of(&files[0]).unwrap_or_else(|| "Q4_K_M".into())
                ))
            })?,
        };

        if is_multipart(&filename) {
            return Err(CordonError::ModelDownloadFailed(format!(
                "'{}' is one shard of a multi-part GGUF. Cordon's puller handles \
                 single-file models; download the shards manually and merge them \
                 with llama.cpp's gguf-split, then use `cordon-provision`.",
                filename
            )));
        }

        let url = format!(
            "{}/{}/resolve/{}/{}",
            self.endpoint,
            model.repo_id(),
            revision,
            filename
        );

        Ok(ResolvedModel {
            repo_id: model.repo_id(),
            revision,
            quant: quant_of(&filename),
            filename,
            url,
        })
    }

    /// Download a resolved model into `dest_dir`, resuming a partial file if one
    /// is present, and verify its digest.
    ///
    /// Progress is reported through `on_progress`, which is called frequently
    /// and must not block.
    pub async fn download<F>(
        &self,
        resolved: &ResolvedModel,
        local_id: &str,
        dest_dir: &Path,
        mut on_progress: F,
    ) -> CordonResult<DownloadedModel>
    where
        F: FnMut(Progress) + Send,
    {
        tokio::fs::create_dir_all(dest_dir).await.map_err(|e| {
            CordonError::ModelDownloadFailed(format!("cannot create {}: {}", dest_dir.display(), e))
        })?;

        let final_path = dest_dir.join(format!("{}.gguf", local_id));
        let partial_path = dest_dir.join(format!("{}.gguf.partial", local_id));

        // A completed file with a matching digest short-circuits the download.
        let expected = self.published_digest(&resolved.url).await;
        if final_path.exists() {
            if let Some(existing) = self
                .reuse_existing(&final_path, expected.as_deref(), resolved, local_id)
                .await?
            {
                return Ok(existing);
            }
        }

        let resume_from = tokio::fs::metadata(&partial_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);

        let mut request = self
            .http
            .get(&resolved.url)
            // No overall timeout: model files are large and slow links are
            // legitimate. Stalls are caught by the connect timeout and by the
            // stream returning an error.
            .timeout(Duration::from_secs(60 * 60 * 6));
        if resume_from > 0 {
            tracing::info!(
                bytes = resume_from,
                "Resuming interrupted download of {}",
                resolved.filename
            );
            request = request.header(reqwest::header::RANGE, format!("bytes={}-", resume_from));
        }

        let response = self.authorized(request).send().await.map_err(|e| {
            CordonError::ModelDownloadFailed(format!("download failed to start: {}", e))
        })?;

        let status = response.status();
        if !status.is_success() {
            return Err(CordonError::ModelDownloadFailed(format!(
                "the Hub returned HTTP {} downloading {}",
                status, resolved.filename
            )));
        }

        // The server may ignore the Range header; in that case restart from zero
        // rather than appending to a prefix that is about to be duplicated.
        let resuming = status == reqwest::StatusCode::PARTIAL_CONTENT && resume_from > 0;
        let start_offset = if resuming { resume_from } else { 0 };

        let total = response
            .content_length()
            .map(|len| len + start_offset)
            .or_else(|| parse_content_range_total(&response));

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(!resuming)
            .open(&partial_path)
            .await
            .map_err(|e| {
                CordonError::ModelDownloadFailed(format!(
                    "cannot open {}: {}",
                    partial_path.display(),
                    e
                ))
            })?;

        let mut hasher = Sha256::new();
        if resuming {
            file.seek(std::io::SeekFrom::Start(start_offset))
                .await
                .map_err(|e| {
                    CordonError::ModelDownloadFailed(format!("cannot seek partial file: {}", e))
                })?;
            // Hash the prefix already on disk so the final digest covers the
            // whole file rather than only the resumed remainder.
            hash_prefix(&partial_path, start_offset, &mut hasher).await?;
        }

        let mut downloaded = start_offset;
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| {
                CordonError::ModelDownloadFailed(format!(
                    "download interrupted after {} bytes: {} (rerun `cordon pull` to resume)",
                    downloaded, e
                ))
            })?;
            hasher.update(&chunk);
            file.write_all(&chunk).await.map_err(|e| {
                CordonError::ModelDownloadFailed(format!("cannot write model file: {}", e))
            })?;
            downloaded += chunk.len() as u64;
            on_progress(Progress { downloaded, total });
        }

        file.flush()
            .await
            .map_err(|e| CordonError::ModelDownloadFailed(format!("cannot flush: {}", e)))?;
        file.sync_all()
            .await
            .map_err(|e| CordonError::ModelDownloadFailed(format!("cannot fsync: {}", e)))?;
        drop(file);

        let sha256 = hex::encode(hasher.finalize());
        let digest_verified = match &expected {
            Some(published) => {
                if !cordon_crypto::kdf::ct_eq(published.as_bytes(), sha256.as_bytes()) {
                    // Remove the file: a digest mismatch means corruption or
                    // substitution, and leaving it on disk invites its use.
                    let _ = tokio::fs::remove_file(&partial_path).await;
                    return Err(CordonError::ModelDownloadFailed(format!(
                        "digest mismatch for {}: the Hub published {} but {} was \
                         received. The download was discarded.",
                        resolved.filename, published, sha256
                    )));
                }
                true
            }
            None => {
                tracing::warn!(
                    file = %resolved.filename,
                    sha256 = %sha256,
                    "The Hub published no content digest for this file; its integrity \
                     could not be independently checked."
                );
                false
            }
        };

        tokio::fs::rename(&partial_path, &final_path)
            .await
            .map_err(|e| {
                CordonError::ModelDownloadFailed(format!("cannot finalise download: {}", e))
            })?;

        let size_bytes = tokio::fs::metadata(&final_path)
            .await
            .map(|m| m.len())
            .unwrap_or(downloaded);

        let record = DownloadedModel {
            id: local_id.to_string(),
            repo_id: resolved.repo_id.clone(),
            revision: resolved.revision.clone(),
            filename: resolved.filename.clone(),
            quant: resolved.quant.clone(),
            path: final_path,
            size_bytes,
            sha256,
            digest_verified,
            downloaded_at: chrono::Utc::now(),
        };
        write_record(dest_dir, &record).await?;
        Ok(record)
    }

    /// Ask the Hub for the SHA-256 of a file without downloading it.
    ///
    /// LFS objects carry the digest in `X-Linked-Etag`. Small files stored
    /// directly in git return a git blob hash instead, which is not a content
    /// SHA-256, so it is not used for verification.
    async fn published_digest(&self, url: &str) -> Option<String> {
        let response = self
            .authorized(self.http.head(url).timeout(Duration::from_secs(30)))
            .send()
            .await
            .ok()?;

        let etag = response
            .headers()
            .get("x-linked-etag")
            .or_else(|| response.headers().get(reqwest::header::ETAG))?
            .to_str()
            .ok()?
            .trim_matches('"')
            .to_lowercase();

        // A content SHA-256 is exactly 64 hex characters.
        (etag.len() == 64 && etag.chars().all(|c| c.is_ascii_hexdigit())).then_some(etag)
    }

    async fn reuse_existing(
        &self,
        path: &Path,
        expected: Option<&str>,
        resolved: &ResolvedModel,
        local_id: &str,
    ) -> CordonResult<Option<DownloadedModel>> {
        let Some(expected) = expected else {
            return Ok(None);
        };
        let actual = sha256_file(path).await?;
        if !cordon_crypto::kdf::ct_eq(actual.as_bytes(), expected.as_bytes()) {
            tracing::warn!(
                path = %path.display(),
                "Existing file does not match the published digest; re-downloading"
            );
            return Ok(None);
        }

        tracing::info!(path = %path.display(), "Model already present and verified");
        let size_bytes = tokio::fs::metadata(path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        Ok(Some(DownloadedModel {
            id: local_id.to_string(),
            repo_id: resolved.repo_id.clone(),
            revision: resolved.revision.clone(),
            filename: resolved.filename.clone(),
            quant: resolved.quant.clone(),
            path: path.to_path_buf(),
            size_bytes,
            sha256: actual,
            digest_verified: true,
            downloaded_at: chrono::Utc::now(),
        }))
    }
}

/// Write the sidecar record describing a downloaded model.
async fn write_record(dest_dir: &Path, record: &DownloadedModel) -> CordonResult<()> {
    let path = dest_dir.join(format!("{}.json", record.id));
    let json = serde_json::to_vec_pretty(record)
        .map_err(|e| CordonError::Internal(format!("cannot serialise model record: {}", e)))?;
    tokio::fs::write(&path, json)
        .await
        .map_err(|e| CordonError::ModelDownloadFailed(format!("cannot write model record: {}", e)))
}

/// Read every model record in a directory.
pub fn list_local_models(dir: &Path) -> CordonResult<Vec<DownloadedModel>> {
    let mut models = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(models);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        match std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<DownloadedModel>(&s).ok())
        {
            Some(record) if record.path.exists() => models.push(record),
            Some(record) => tracing::warn!(
                id = %record.id,
                "Model record references a missing file; ignoring"
            ),
            None => tracing::warn!(path = %path.display(), "Unreadable model record; ignoring"),
        }
    }
    models.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(models)
}

/// Look up one local model by identifier.
pub fn find_local_model(dir: &Path, id: &str) -> CordonResult<Option<DownloadedModel>> {
    Ok(list_local_models(dir)?.into_iter().find(|m| m.id == id))
}

/// Remove a local model and its record.
pub fn remove_local_model(dir: &Path, id: &str) -> CordonResult<bool> {
    let Some(model) = find_local_model(dir, id)? else {
        return Ok(false);
    };
    std::fs::remove_file(&model.path).map_err(|e| {
        CordonError::Internal(format!("cannot remove {}: {}", model.path.display(), e))
    })?;
    let _ = std::fs::remove_file(dir.join(format!("{}.json", id)));
    Ok(true)
}

/// SHA-256 a file without holding it in memory.
pub async fn sha256_file(path: &Path) -> CordonResult<String> {
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| CordonError::Internal(format!("cannot open {}: {}", path.display(), e)))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .await
            .map_err(|e| CordonError::Internal(format!("cannot read {}: {}", path.display(), e)))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

async fn hash_prefix(path: &Path, len: u64, hasher: &mut Sha256) -> CordonResult<()> {
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path).await.map_err(|e| {
        CordonError::ModelDownloadFailed(format!("cannot re-read partial download: {}", e))
    })?;
    let mut remaining = len;
    let mut buf = vec![0u8; 1024 * 1024];
    while remaining > 0 {
        let want = buf.len().min(remaining as usize);
        let n = file.read(&mut buf[..want]).await.map_err(|e| {
            CordonError::ModelDownloadFailed(format!("cannot re-read partial download: {}", e))
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    Ok(())
}

fn parse_content_range_total(response: &reqwest::Response) -> Option<u64> {
    response
        .headers()
        .get(reqwest::header::CONTENT_RANGE)?
        .to_str()
        .ok()?
        .rsplit('/')
        .next()?
        .parse()
        .ok()
}

/// Extract the quantisation label from a GGUF filename.
///
/// llama.cpp names files `<model>.<QUANT>.gguf` or `<model>-<QUANT>.gguf`, so
/// the label is the last dot- or dash-delimited component before the extension.
pub fn quant_of(filename: &str) -> Option<String> {
    let stem = filename
        .strip_suffix(".gguf")
        .or_else(|| filename.strip_suffix(".GGUF"))?;
    let candidate = stem.rsplit(['.', '-']).next().filter(|c| !c.is_empty())?;

    let upper = candidate.to_uppercase();
    let looks_like_quant = upper.starts_with('Q')
        || upper.starts_with("IQ")
        || matches!(upper.as_str(), "F16" | "F32" | "BF16");
    looks_like_quant.then_some(upper)
}

fn is_multipart(filename: &str) -> bool {
    filename.contains("-of-")
}

fn available_quants(files: &[String]) -> String {
    let mut quants: Vec<String> = files.iter().filter_map(|f| quant_of(f)).collect();
    quants.sort();
    quants.dedup();
    if quants.is_empty() {
        files.join(", ")
    } else {
        quants.join(", ")
    }
}

fn pick_default_quant(files: &[String]) -> Option<String> {
    let single: Vec<&String> = files.iter().filter(|f| !is_multipart(f)).collect();
    let pool = if single.is_empty() {
        files.iter().collect()
    } else {
        single
    };

    for preferred in QUANT_PREFERENCE {
        if let Some(found) = pool
            .iter()
            .find(|f| quant_of(f).map(|q| q == *preferred).unwrap_or(false))
        {
            return Some((*found).clone());
        }
    }
    pool.first().map(|f| (*f).clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_repo() {
        let r = ModelRef::parse("HuggingFaceTB/SmolLM2-360M-Instruct-GGUF").unwrap();
        assert_eq!(r.owner, "HuggingFaceTB");
        assert_eq!(r.repo, "SmolLM2-360M-Instruct-GGUF");
        assert_eq!(r.revision, "main");
        assert_eq!(r.quant, None);
    }

    #[test]
    fn parses_quant_tag() {
        let r = ModelRef::parse("owner/repo:Q4_K_M").unwrap();
        assert_eq!(r.quant.as_deref(), Some("Q4_K_M"));
        assert_eq!(r.revision, "main");
    }

    #[test]
    fn parses_revision_and_quant() {
        let r = ModelRef::parse("owner/repo@abc123:Q8_0").unwrap();
        assert_eq!(r.revision, "abc123");
        assert_eq!(r.quant.as_deref(), Some("Q8_0"));
    }

    #[test]
    fn strips_hub_host_prefixes() {
        for input in [
            "hf.co/owner/repo:Q4_K_M",
            "huggingface.co/owner/repo:Q4_K_M",
            "https://huggingface.co/owner/repo:Q4_K_M",
        ] {
            let r = ModelRef::parse(input).unwrap();
            assert_eq!(r.repo_id(), "owner/repo", "failed for {}", input);
            assert_eq!(r.quant.as_deref(), Some("Q4_K_M"));
        }
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(ModelRef::parse("../etc/passwd").is_err());
        assert!(ModelRef::parse("owner/..").is_err());
        assert!(ModelRef::parse("owner/repo@../../secret").is_err());
        assert!(ModelRef::parse("owner/repo/extra").is_err());
        assert!(ModelRef::parse("owner").is_err());
        assert!(ModelRef::parse("").is_err());
    }

    #[test]
    fn rejects_shell_and_url_metacharacters() {
        assert!(ModelRef::parse("owner/repo;rm -rf /").is_err());
        assert!(ModelRef::parse("owner/re%2Fpo").is_err());
        assert!(ModelRef::parse("owner/repo?x=1").is_err());
    }

    #[test]
    fn local_id_is_filesystem_safe() {
        let r = ModelRef::parse("HuggingFaceTB/SmolLM2-360M-Instruct-GGUF:Q4_K_M").unwrap();
        let id = r.local_id();
        assert!(!id.contains('/'));
        assert!(!id.contains('\\'));
        assert_eq!(id, "huggingfacetb--smollm2-360m-instruct-gguf--q4_k_m");
    }

    #[test]
    fn extracts_quantisation_from_filenames() {
        assert_eq!(quant_of("model.Q4_K_M.gguf").as_deref(), Some("Q4_K_M"));
        assert_eq!(
            quant_of("smollm2-360m-instruct-q8_0.gguf").as_deref(),
            Some("Q8_0")
        );
        assert_eq!(quant_of("model.f16.gguf").as_deref(), Some("F16"));
        assert_eq!(quant_of("model.IQ3_XS.gguf").as_deref(), Some("IQ3_XS"));
        assert_eq!(quant_of("notagguf.bin"), None);
    }

    #[test]
    fn default_quant_prefers_q4_k_m() {
        let files = vec![
            "m.F16.gguf".to_string(),
            "m.Q8_0.gguf".to_string(),
            "m.Q4_K_M.gguf".to_string(),
        ];
        assert_eq!(pick_default_quant(&files).as_deref(), Some("m.Q4_K_M.gguf"));
    }

    #[test]
    fn default_quant_skips_multipart_shards() {
        let files = vec![
            "m.Q4_K_M-00001-of-00002.gguf".to_string(),
            "m.Q8_0.gguf".to_string(),
        ];
        assert_eq!(pick_default_quant(&files).as_deref(), Some("m.Q8_0.gguf"));
    }

    #[test]
    fn detects_multipart_files() {
        assert!(is_multipart("m.Q4_K_M-00001-of-00002.gguf"));
        assert!(!is_multipart("m.Q4_K_M.gguf"));
    }

    #[test]
    fn display_round_trips() {
        for input in ["owner/repo", "owner/repo:Q4_K_M", "owner/repo@dev:Q8_0"] {
            let r = ModelRef::parse(input).unwrap();
            assert_eq!(r.to_string(), input);
        }
    }
}
