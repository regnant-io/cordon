//! Canonical byte encoding for values a client must hash independently.
//!
//! # Why this exists
//!
//! An attestation report is verified by someone who did not build it. They
//! receive JSON, deserialize it, recompute a digest over the result, and check
//! that digest against the one the report carries. That only works if the
//! encoding is *canonical*: the same logical value must produce the same bytes
//! in every process, on every machine, forever.
//!
//! `serde_json` is not canonical, and the way it fails here is quiet.
//!
//! * A `HashMap` serializes in iteration order, and Rust randomises that per
//!   map instance. Two maps holding the same thirteen PCR values, built in the
//!   same process moments apart, iterate in different orders. The node computed
//!   its digest over one order; a client that deserialized the report got
//!   another, and the check failed on a perfectly genuine report.
//! * Struct field order follows declaration order, so reordering two fields
//!   during an unrelated refactor would silently invalidate every deployed
//!   verifier, with no compile error and no test failure, because the node
//!   agrees with itself.
//!
//! So the values a client must reproduce are encoded here instead, explicitly:
//! a version tag, then every field in a fixed order, each length-prefixed so no
//! concatenation of fields can be confused for a different one. Nothing about
//! the encoding depends on how a Rust struct happens to be laid out.
//!
//! # Format
//!
//! ```text
//! bytes  := tag || field*
//! tag    := "CORDON_CANON_v1" || section-name
//! field  := u8   (one byte)
//!         | u16  (2 bytes, big-endian)
//!         | u32  (4 bytes, big-endian)
//!         | i64  (8 bytes, big-endian)
//!         | blob (u32 big-endian length || bytes)
//! ```
//!
//! Big-endian throughout, so a hex dump reads in the order the fields are
//! written and an implementation in another language has one fewer thing to get
//! wrong.

/// Version tag prefixed to every canonical encoding.
///
/// Changing what any `write_*` call emits, or the order in which a section
/// writes its fields, is a breaking change to every verifier in the field and
/// must come with a new version here.
pub const CANONICAL_VERSION_TAG: &[u8] = b"CORDON_CANON_v1";

/// Accumulates a canonical byte string.
#[derive(Debug)]
pub struct CanonicalWriter {
    buffer: Vec<u8>,
}

impl CanonicalWriter {
    /// Begin an encoding for the named section.
    ///
    /// The section name is part of the digest, so bytes produced for one kind
    /// of value can never be mistaken for another's, a TPM quote and a TEE
    /// quote that happened to hold identical field values still encode
    /// differently.
    pub fn new(section: &str) -> Self {
        let mut writer = Self {
            buffer: Vec::with_capacity(256),
        };
        writer.buffer.extend_from_slice(CANONICAL_VERSION_TAG);
        writer.write_blob(section.as_bytes());
        writer
    }

    /// Append a single byte.
    pub fn write_u8(&mut self, value: u8) -> &mut Self {
        self.buffer.push(value);
        self
    }

    /// Append a 16-bit value, big-endian.
    pub fn write_u16(&mut self, value: u16) -> &mut Self {
        self.buffer.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Append a 32-bit value, big-endian.
    pub fn write_u32(&mut self, value: u32) -> &mut Self {
        self.buffer.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Append a signed 64-bit value, big-endian.
    pub fn write_i64(&mut self, value: i64) -> &mut Self {
        self.buffer.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Append a length-prefixed byte string.
    ///
    /// The length prefix is what makes the encoding unambiguous: without it,
    /// the fields `("ab", "c")` and `("a", "bc")` would produce the same bytes
    /// and therefore the same digest.
    pub fn write_blob(&mut self, bytes: &[u8]) -> &mut Self {
        self.buffer
            .extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        self.buffer.extend_from_slice(bytes);
        self
    }

    /// Append a length-prefixed string.
    pub fn write_str(&mut self, value: &str) -> &mut Self {
        self.write_blob(value.as_bytes())
    }

    /// Append a nested canonical encoding, length-prefixed.
    pub fn write_section(&mut self, section: &CanonicalWriter) -> &mut Self {
        self.write_blob(section.as_bytes())
    }

    /// The encoded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Consume the writer and return the encoded bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }

    /// SHA-256 of the encoded bytes, hex encoded.
    pub fn digest_hex(&self) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&self.buffer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_section_name_separates_otherwise_identical_values() {
        let mut a = CanonicalWriter::new("tpm_quote");
        a.write_str("same");
        let mut b = CanonicalWriter::new("tee_quote");
        b.write_str("same");
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    /// The property length prefixing exists for: two different field splits
    /// must not collide into the same bytes.
    #[test]
    fn length_prefixes_make_field_boundaries_unambiguous() {
        let mut a = CanonicalWriter::new("s");
        a.write_str("ab").write_str("c");
        let mut b = CanonicalWriter::new("s");
        b.write_str("a").write_str("bc");
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn encoding_is_deterministic_across_writers() {
        let build = || {
            let mut w = CanonicalWriter::new("section");
            w.write_str("alpha")
                .write_u16(7)
                .write_blob(&[1, 2, 3])
                .write_i64(-42);
            w
        };
        assert_eq!(build().into_bytes(), build().into_bytes());
        assert_eq!(build().digest_hex(), build().digest_hex());
    }

    #[test]
    fn every_field_changes_the_digest() {
        let base = {
            let mut w = CanonicalWriter::new("s");
            w.write_str("a").write_u16(1).write_i64(2);
            w.digest_hex()
        };
        let changed_str = {
            let mut w = CanonicalWriter::new("s");
            w.write_str("b").write_u16(1).write_i64(2);
            w.digest_hex()
        };
        let changed_u16 = {
            let mut w = CanonicalWriter::new("s");
            w.write_str("a").write_u16(2).write_i64(2);
            w.digest_hex()
        };
        let changed_i64 = {
            let mut w = CanonicalWriter::new("s");
            w.write_str("a").write_u16(1).write_i64(3);
            w.digest_hex()
        };
        assert_ne!(base, changed_str);
        assert_ne!(base, changed_u16);
        assert_ne!(base, changed_i64);
    }

    #[test]
    fn integers_are_big_endian() {
        let mut w = CanonicalWriter::new("s");
        w.write_u32(0x0102_0304);
        let bytes = w.into_bytes();
        assert_eq!(&bytes[bytes.len() - 4..], &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn an_empty_blob_still_writes_its_length() {
        let mut w = CanonicalWriter::new("s");
        let before = w.as_bytes().len();
        w.write_blob(&[]);
        assert_eq!(w.as_bytes().len(), before + 4);
    }
}
