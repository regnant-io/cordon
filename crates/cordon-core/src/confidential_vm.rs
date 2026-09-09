//! Fetching an attestation report from inside a confidential VM.
//!
//! # Why this is file I/O and not an ioctl
//!
//! The obvious way to ask an AMD Secure Processor for a report is
//! `SNP_GET_REPORT` on `/dev/sev-guest`, which means an ioctl, which means
//! `unsafe` or a binding crate that contains it. This workspace sets
//! `#![forbid(unsafe_code)]` and that is worth keeping.
//!
//! Linux 6.7 added `configfs-tsm`, a vendor-neutral interface that exposes the
//! same operation as ordinary files: create a directory, write the 64 bytes you
//! want the report to commit to, read the report back, remove the directory.
//! Nothing here needs `unsafe`, nothing needs a new dependency, and the same
//! code path serves AMD SEV-SNP and Intel TDX because the kernel abstracts the
//! difference. The `provider` file says which one answered.
//!
//! ```text
//! mkdir  /sys/kernel/config/tsm/report/cordon-<n>
//! write  inblob     <- 64 bytes: the attestation challenge
//! read   outblob    -> the raw hardware report
//! read   provider   -> "sev_guest" | "tdx_guest"
//! read   auxblob    -> certificates, on platforms that cache them
//! rmdir  /sys/kernel/config/tsm/report/cordon-<n>
//! ```
//!
//! There is no fallback for kernels older than 6.7. A node configured for
//! confidential-VM attestation on such a kernel refuses to start rather than
//! reaching for `/dev/sev-guest` through a binding that would need `unsafe`, or
//! quietly measuring something weaker.
//!
//! # Status
//!
//! Written against the kernel's documented `configfs-tsm` layout. This
//! repository has no confidential-computing hardware, so the certificate-table
//! parsing and every error path are unit-tested, and the acquisition itself has
//! **not** been exercised against real silicon. Treat that the way
//! [`crate::tpm`] asks you to treat the TPM path: the wiring is written to the
//! specification and tested as far as it can be here, and you should confirm it
//! with `cordon doctor` on the machine you intend to deploy on.

use std::path::{Path, PathBuf};

use crate::error::{CordonError, CordonResult};

/// Where the kernel exposes the TSM report interface.
const TSM_REPORT_ROOT: &str = "/sys/kernel/config/tsm/report";

/// Bytes a report commits to. Both SEV-SNP's `REPORT_DATA` and TDX's
/// `REPORTDATA` are exactly this wide.
pub const REPORT_DATA_LEN: usize = 64;

/// Which confidential-computing platform produced a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfidentialPlatform {
    /// AMD SEV-SNP.
    SevSnp,
    /// Intel TDX.
    Tdx,
    /// A provider this build does not know how to interpret.
    Unknown,
}

impl ConfidentialPlatform {
    /// Map a `configfs-tsm` provider string.
    ///
    /// The kernel appends a version, as in `sev_guest:1`, so this matches on
    /// the prefix rather than the whole string.
    pub fn from_provider(provider: &str) -> Self {
        let name = provider.trim();
        if name.starts_with("sev_guest") {
            ConfidentialPlatform::SevSnp
        } else if name.starts_with("tdx_guest") {
            ConfidentialPlatform::Tdx
        } else {
            ConfidentialPlatform::Unknown
        }
    }

    /// Wire representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            ConfidentialPlatform::SevSnp => "amd_sev_snp",
            ConfidentialPlatform::Tdx => "intel_tdx",
            ConfidentialPlatform::Unknown => "unknown",
        }
    }
}

/// A hardware attestation report and what produced it.
#[derive(Debug, Clone)]
pub struct HardwareReport {
    /// Which platform answered.
    pub platform: ConfidentialPlatform,
    /// The raw report bytes.
    pub report: Vec<u8>,
    /// Certificates the platform cached alongside the report, when it has any.
    /// On SEV-SNP this is the VCEK chain, which spares an operator a round trip
    /// to AMD's Key Distribution Service — and lets an air-gapped deployment
    /// verify at all.
    pub certificates: Vec<u8>,
}

/// Whether a confidential-VM report interface is present on this machine.
pub fn is_available() -> bool {
    Path::new(TSM_REPORT_ROOT).is_dir()
}

/// Request a report committing to `report_data`.
///
/// `report_data` is the value a verifier checks to know the report is fresh and
/// what it is about. Cordon passes its attestation challenge, which is a digest
/// over the verifier's nonce and the node's response-signing key.
pub fn request_report(report_data: &[u8]) -> CordonResult<HardwareReport> {
    if report_data.len() > REPORT_DATA_LEN {
        return Err(CordonError::AttestationInvalid(format!(
            "report data is {} bytes; a hardware report commits to at most {}",
            report_data.len(),
            REPORT_DATA_LEN
        )));
    }

    if !is_available() {
        return Err(CordonError::AttestationInvalid(format!(
            "no confidential-VM report interface at {}. This node is not running \
             inside an AMD SEV-SNP or Intel TDX guest, or the kernel predates 6.7 \
             and does not expose configfs-tsm. Cordon will not substitute a weaker \
             measurement for one it was told to produce.",
            TSM_REPORT_ROOT
        )));
    }

    // The report is padded, not truncated: a short challenge still occupies a
    // fixed-width field, and the verifier compares the whole field.
    let mut padded = [0u8; REPORT_DATA_LEN];
    padded[..report_data.len()].copy_from_slice(report_data);

    let entry = ReportEntry::create()?;
    entry.write_input(&padded)?;

    let report = entry.read_binary("outblob")?;
    if report.is_empty() {
        return Err(CordonError::AttestationInvalid(
            "the platform returned an empty attestation report".into(),
        ));
    }

    let provider = entry.read_text("provider").unwrap_or_default();
    // `auxblob` is absent on some platforms and on older kernels; that is not
    // an error, it just means the caller supplies certificates itself.
    let certificates = entry.read_binary("auxblob").unwrap_or_default();

    Ok(HardwareReport {
        platform: ConfidentialPlatform::from_provider(&provider),
        report,
        certificates,
    })
    // `entry` drops here, removing the configfs directory.
}

/// The certificates a SEV-SNP platform caches alongside its reports.
///
/// Each is DER. Any of them may be absent: the host caches these for guests as
/// a convenience, and a host that has not been provisioned returns nothing,
/// leaving the operator to supply the chain.
#[derive(Debug, Clone, Default)]
pub struct CachedCertificates {
    /// The chip's Versioned Chip Endorsement Key, which signs reports.
    pub vcek: Option<Vec<u8>>,
    /// The AMD SEV Signing Key, which signs the VCEK.
    pub ask: Option<Vec<u8>>,
    /// The AMD Root Key. Present here for completeness only — a verifier must
    /// pin its own root, never adopt one that arrived with the evidence.
    pub ark: Option<Vec<u8>>,
}

/// Entry size in a SEV-SNP certificate table: a 16-byte GUID, then a 32-bit
/// offset and a 32-bit length.
const CERT_TABLE_ENTRY_LEN: usize = 24;

/// GUIDs the certificate table uses, as little-endian mixed-endian bytes — the
/// layout AMD's firmware writes.
const GUID_VCEK: [u8; 16] = [
    0x8d, 0x75, 0xda, 0x63, 0x64, 0xe6, 0x64, 0x45, 0xad, 0xc5, 0xf4, 0xb9, 0x3b, 0xe8, 0xac, 0xcd,
];
const GUID_ASK: [u8; 16] = [
    0x79, 0xb3, 0xb7, 0x4a, 0xac, 0xbb, 0xe4, 0x4f, 0xa0, 0x2f, 0x05, 0xae, 0xf3, 0x27, 0xc7, 0x82,
];
const GUID_ARK: [u8; 16] = [
    0xa4, 0x06, 0xb4, 0xc0, 0x03, 0xa8, 0x52, 0x49, 0x97, 0x43, 0x3f, 0xb6, 0x01, 0x4c, 0xd0, 0xae,
];

/// Parse the certificate table a SEV-SNP platform returns in `auxblob`.
///
/// The format is a table of `(GUID, offset, length)` entries terminated by an
/// all-zero entry, followed by the DER blobs those entries point into. Offsets
/// are relative to the start of the blob and are attacker-influenced in the
/// sense that a malicious host supplies them, so every one is bounds-checked —
/// a certificate that fails to parse is dropped rather than trusted, and the
/// verifier then simply has no chain, which fails closed.
pub fn parse_certificate_table(blob: &[u8]) -> CachedCertificates {
    let mut certs = CachedCertificates::default();
    if blob.is_empty() {
        return certs;
    }

    let mut offset = 0usize;
    while offset + CERT_TABLE_ENTRY_LEN <= blob.len() {
        let entry = &blob[offset..offset + CERT_TABLE_ENTRY_LEN];
        let guid: [u8; 16] = match entry[..16].try_into() {
            Ok(g) => g,
            Err(_) => break,
        };

        // An all-zero GUID terminates the table.
        if guid.iter().all(|b| *b == 0) {
            break;
        }

        let blob_offset = u32::from_le_bytes([entry[16], entry[17], entry[18], entry[19]]) as usize;
        let blob_len = u32::from_le_bytes([entry[20], entry[21], entry[22], entry[23]]) as usize;

        match blob_offset
            .checked_add(blob_len)
            .filter(|end| *end <= blob.len())
        {
            Some(end) => {
                let der = blob[blob_offset..end].to_vec();
                match guid {
                    g if g == GUID_VCEK => certs.vcek = Some(der),
                    g if g == GUID_ASK => certs.ask = Some(der),
                    g if g == GUID_ARK => certs.ark = Some(der),
                    _ => {}
                }
            }
            None => {
                tracing::warn!(
                    offset = blob_offset,
                    length = blob_len,
                    total = blob.len(),
                    "Certificate table entry points outside the blob; ignoring it"
                );
            }
        }

        offset += CERT_TABLE_ENTRY_LEN;
    }

    certs
}

/// One `configfs-tsm` report directory, removed when dropped.
struct ReportEntry {
    path: PathBuf,
}

impl ReportEntry {
    /// Create a uniquely named report entry.
    ///
    /// The name is unique per request so two concurrent attestation requests do
    /// not overwrite each other's `inblob` — which would silently give one
    /// caller a report committing to the other's challenge.
    fn create() -> CordonResult<Self> {
        let path =
            Path::new(TSM_REPORT_ROOT).join(format!("cordon-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir(&path).map_err(|e| {
            CordonError::AttestationInvalid(format!(
                "cannot create a TSM report entry at {}: {}. The node needs write \
                 access to configfs; check that it is mounted and that the service \
                 account can use it.",
                path.display(),
                e
            ))
        })?;
        Ok(Self { path })
    }

    fn write_input(&self, report_data: &[u8; REPORT_DATA_LEN]) -> CordonResult<()> {
        std::fs::write(self.path.join("inblob"), report_data).map_err(|e| {
            CordonError::AttestationInvalid(format!("cannot set the report challenge: {}", e))
        })
    }

    fn read_binary(&self, name: &str) -> CordonResult<Vec<u8>> {
        std::fs::read(self.path.join(name))
            .map_err(|e| CordonError::AttestationInvalid(format!("cannot read {}: {}", name, e)))
    }

    fn read_text(&self, name: &str) -> CordonResult<String> {
        std::fs::read_to_string(self.path.join(name))
            .map(|s| s.trim().to_string())
            .map_err(|e| CordonError::AttestationInvalid(format!("cannot read {}: {}", name, e)))
    }
}

impl Drop for ReportEntry {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir(&self.path) {
            // Leaving entries behind would eventually exhaust the interface, so
            // this is worth saying even though it is not fatal to the request.
            tracing::warn!(
                path = %self.path.display(),
                "could not remove the TSM report entry: {}. Remove it manually if \
                 attestation later fails to create one.",
                e
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_the_providers_the_kernel_reports() {
        assert_eq!(
            ConfidentialPlatform::from_provider("sev_guest"),
            ConfidentialPlatform::SevSnp
        );
        // The kernel appends a version.
        assert_eq!(
            ConfidentialPlatform::from_provider("sev_guest:1\n"),
            ConfidentialPlatform::SevSnp
        );
        assert_eq!(
            ConfidentialPlatform::from_provider("tdx_guest:1"),
            ConfidentialPlatform::Tdx
        );
        assert_eq!(
            ConfidentialPlatform::from_provider("something_else"),
            ConfidentialPlatform::Unknown
        );
        assert_eq!(
            ConfidentialPlatform::from_provider(""),
            ConfidentialPlatform::Unknown
        );
    }

    #[test]
    fn report_data_longer_than_the_field_is_refused() {
        let too_long = vec![0u8; REPORT_DATA_LEN + 1];
        let err = request_report(&too_long).unwrap_err().to_string();
        assert!(err.contains("at most"), "unexpected error: {}", err);
    }

    /// Asking for a hardware report on a machine that has no confidential-VM
    /// interface must fail, not fall back to something weaker. A node told to
    /// produce hardware evidence and quietly producing a configuration digest
    /// instead is the failure mode this whole module exists to avoid.
    #[test]
    fn a_machine_without_the_interface_fails_closed() {
        if !is_available() {
            let err = request_report(&[0u8; 32]).unwrap_err().to_string();
            assert!(
                err.contains("SEV-SNP") || err.contains("configfs-tsm"),
                "unexpected error: {}",
                err
            );
            assert!(
                err.contains("will not substitute"),
                "the refusal should say why it is refusing: {}",
                err
            );
        }
    }
}

#[cfg(test)]
mod certificate_table_tests {
    use super::*;

    /// Build the table layout AMD's firmware writes: fixed-size entries first,
    /// then the DER blobs they point into.
    fn build_table(entries: &[([u8; 16], &[u8])]) -> Vec<u8> {
        let header_len = (entries.len() + 1) * CERT_TABLE_ENTRY_LEN;
        let mut header = Vec::with_capacity(header_len);
        let mut body = Vec::new();

        for (guid, der) in entries {
            let offset = header_len + body.len();
            header.extend_from_slice(guid);
            header.extend_from_slice(&(offset as u32).to_le_bytes());
            header.extend_from_slice(&(der.len() as u32).to_le_bytes());
            body.extend_from_slice(der);
        }
        // Terminating all-zero entry.
        header.extend_from_slice(&[0u8; CERT_TABLE_ENTRY_LEN]);

        header.extend_from_slice(&body);
        header
    }

    #[test]
    fn extracts_each_certificate_by_its_guid() {
        let blob = build_table(&[
            (GUID_VCEK, b"vcek-der-bytes"),
            (GUID_ASK, b"ask-der"),
            (GUID_ARK, b"ark-der-here"),
        ]);

        let certs = parse_certificate_table(&blob);
        assert_eq!(certs.vcek.as_deref(), Some(&b"vcek-der-bytes"[..]));
        assert_eq!(certs.ask.as_deref(), Some(&b"ask-der"[..]));
        assert_eq!(certs.ark.as_deref(), Some(&b"ark-der-here"[..]));
    }

    #[test]
    fn a_host_that_cached_nothing_yields_nothing() {
        let certs = parse_certificate_table(&[]);
        assert!(certs.vcek.is_none() && certs.ask.is_none() && certs.ark.is_none());
    }

    #[test]
    fn a_partial_cache_returns_what_is_there() {
        let blob = build_table(&[(GUID_VCEK, b"only-the-vcek")]);
        let certs = parse_certificate_table(&blob);
        assert!(certs.vcek.is_some());
        assert!(certs.ask.is_none());
    }

    #[test]
    fn unrecognised_guids_are_skipped_without_disturbing_the_rest() {
        let unknown = [0x11u8; 16];
        let blob = build_table(&[(unknown, b"something-else"), (GUID_VCEK, b"the-vcek")]);
        let certs = parse_certificate_table(&blob);
        assert_eq!(certs.vcek.as_deref(), Some(&b"the-vcek"[..]));
    }

    /// The blob comes from the hypervisor, which is the party a confidential VM
    /// exists to distrust. An entry pointing outside the buffer must be ignored
    /// rather than read, and must not panic.
    #[test]
    fn entries_pointing_outside_the_blob_are_ignored() {
        let mut blob = build_table(&[(GUID_VCEK, b"vcek")]);
        // Rewrite the first entry's length to run past the end.
        let len_at = 16 + 4;
        blob[len_at..len_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());

        let certs = parse_certificate_table(&blob);
        assert!(
            certs.vcek.is_none(),
            "an out-of-range entry must be dropped"
        );
    }

    #[test]
    fn a_truncated_table_does_not_panic() {
        let blob = build_table(&[(GUID_VCEK, b"vcek"), (GUID_ASK, b"ask")]);
        for cut in 0..blob.len() {
            let _ = parse_certificate_table(&blob[..cut]);
        }
    }

    #[test]
    fn garbage_does_not_panic() {
        for len in [1usize, 7, 23, 24, 25, 100, 1000] {
            let noise: Vec<u8> = (0..len).map(|i| (i * 37 % 251) as u8).collect();
            let _ = parse_certificate_table(&noise);
        }
    }
}
