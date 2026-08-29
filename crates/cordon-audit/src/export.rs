//! Log export functionality — §9.4

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Export method
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportMethod {
    /// Operator pull via mTLS
    OperatorPull,
    /// Data diode (Merkle roots only)
    DataDiode,
    /// Physical media (FIPS USB HSM)
    PhysicalMedia,
    /// Encrypted push to management channel
    EncryptedPush,
}

/// Options for a log export request
#[derive(Debug, Clone)]
pub struct ExportOptions {
    /// Export method
    pub method: ExportMethod,
    /// Start of time range (None = from beginning)
    pub range_start: Option<DateTime<Utc>>,
    /// End of time range (None = to present)
    pub range_end: Option<DateTime<Utc>>,
    /// Recipient public key ID
    pub recipient_key_id: String,
    /// Whether to include full payloads or just hashes
    pub include_payloads: bool,
}
