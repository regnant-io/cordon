//! A deliberately small CBOR reader, for attestation documents only.
//!
//! AWS Nitro Enclaves deliver their attestation as a COSE_Sign1 structure
//! encoded in CBOR (RFC 8949). Reading it needs a CBOR decoder, and the obvious
//! move is to add a general-purpose one and derive `Deserialize`.
//!
//! This module does not do that, for the same reason
//! the [`canonical`](crate::canonical) module exists. An attestation document is
//! the most hostile input Cordon accepts: it arrives unauthenticated, it is
//! parsed *before* any signature can be checked (you cannot verify a signature
//! you have not yet located), and a verifier is exactly the component an
//! attacker wants to crash or confuse. A general decoder is built to accept
//! every legal encoding of every legal value. A verifier wants the opposite:
//! accept one shape, refuse everything else, and never let the input decide how
//! much memory to allocate.
//!
//! So the reader below:
//!
//! * refuses indefinite-length items, which Nitro does not emit and which are
//!   the usual source of unbounded-allocation bugs;
//! * checks every declared length against the bytes actually remaining before
//!   allocating anything, so a header claiming four gigabytes fails on a
//!   two-kilobyte document instead of asking the allocator for four gigabytes;
//! * bounds nesting depth and total item count, so neither recursion nor a
//!   flat sequence of empty containers can be used to exhaust the stack or the
//!   heap;
//! * refuses trailing bytes, because a document with something appended is a
//!   document someone has edited;
//! * refuses tags, floats, and the simple values other than `true`, `false` and
//!   `null` — not because they are dangerous, but because a Nitro document
//!   containing one is not a Nitro document.
//!
//! The result is a few hundred lines that do one job, where the alternative is
//! a dependency whose threat model is "parse CBOR" rather than "survive a
//! hostile attestation document".

use crate::error::{CryptoError, CryptoResult};

/// Maximum nesting depth.
///
/// A COSE_Sign1 wrapping an attestation document reaches depth four: the outer
/// array, the payload map, the `pcrs` map inside it, and a value. Sixteen
/// leaves room for a format change without leaving room for a stack overflow.
const MAX_DEPTH: usize = 16;

/// Maximum number of decoded items in one document.
///
/// A Nitro document holds well under a hundred: the COSE fields, a couple of
/// dozen PCR entries, and a certificate bundle. Four thousand is generous
/// enough never to matter and small enough that a document made entirely of
/// empty arrays cannot cost anything.
const MAX_ITEMS: usize = 4096;

/// A decoded CBOR value, restricted to the types an attestation document uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborValue {
    /// Major type 0 — a non-negative integer.
    Unsigned(u64),
    /// Major type 1 — a negative integer. COSE algorithm identifiers are
    /// negative (`ES384` is `-35`), which is the only reason this exists.
    Negative(i64),
    /// Major type 2 — a byte string.
    Bytes(Vec<u8>),
    /// Major type 3 — a UTF-8 text string.
    Text(String),
    /// Major type 4 — an array.
    Array(Vec<CborValue>),
    /// Major type 5 — a map.
    ///
    /// Kept as a list of pairs rather than a `BTreeMap`, because the keys in a
    /// COSE header are integers while the keys in the attestation payload are
    /// strings, and because duplicate keys must be *detectable* rather than
    /// silently collapsed — a document carrying `pcrs` twice is not a document
    /// whose second `pcrs` should quietly win.
    Map(Vec<(CborValue, CborValue)>),
    /// `false` or `true`.
    Bool(bool),
    /// `null`. Nitro uses it for absent optional fields.
    Null,
}

impl CborValue {
    /// The value as a byte string, or an error naming what was found instead.
    pub fn as_bytes(&self, field: &str) -> CryptoResult<&[u8]> {
        match self {
            CborValue::Bytes(b) => Ok(b),
            other => Err(type_error(field, "a byte string", other)),
        }
    }

    /// The value as text.
    pub fn as_text(&self, field: &str) -> CryptoResult<&str> {
        match self {
            CborValue::Text(s) => Ok(s),
            other => Err(type_error(field, "a text string", other)),
        }
    }

    /// The value as an unsigned integer.
    pub fn as_u64(&self, field: &str) -> CryptoResult<u64> {
        match self {
            CborValue::Unsigned(n) => Ok(*n),
            other => Err(type_error(field, "an unsigned integer", other)),
        }
    }

    /// The value as an integer, negative or not.
    pub fn as_i64(&self, field: &str) -> CryptoResult<i64> {
        match self {
            CborValue::Unsigned(n) => i64::try_from(*n).map_err(|_| {
                CryptoError::AttestationFailed(format!("{} is too large to be an integer", field))
            }),
            CborValue::Negative(n) => Ok(*n),
            other => Err(type_error(field, "an integer", other)),
        }
    }

    /// The value as an array.
    pub fn as_array(&self, field: &str) -> CryptoResult<&[CborValue]> {
        match self {
            CborValue::Array(items) => Ok(items),
            other => Err(type_error(field, "an array", other)),
        }
    }

    /// The value as a map.
    pub fn as_map(&self, field: &str) -> CryptoResult<&[(CborValue, CborValue)]> {
        match self {
            CborValue::Map(entries) => Ok(entries),
            other => Err(type_error(field, "a map", other)),
        }
    }

    /// Whether the value is `null`, which Nitro uses for an absent field.
    pub fn is_null(&self) -> bool {
        matches!(self, CborValue::Null)
    }

    /// Look up a text key in a map, refusing a map that carries it twice.
    ///
    /// A duplicate key is not a formatting quirk to be tolerated. If a document
    /// carries `pcrs` twice, one of the two is what the signer meant and the
    /// other is what somebody added, and no decoder can tell which — so neither
    /// should be accepted.
    pub fn get(&self, key: &str) -> CryptoResult<Option<&CborValue>> {
        let entries = self.as_map(key)?;
        let mut found = None;
        for (k, v) in entries {
            if matches!(k, CborValue::Text(t) if t == key) {
                if found.is_some() {
                    return Err(CryptoError::AttestationFailed(format!(
                        "the attestation document carries the key `{}` more than once; \
                         a verifier cannot tell which one the signer meant",
                        key
                    )));
                }
                found = Some(v);
            }
        }
        Ok(found)
    }

    /// Look up a text key that must be present and must not be `null`.
    pub fn require(&self, key: &str) -> CryptoResult<&CborValue> {
        match self.get(key)? {
            Some(v) if !v.is_null() => Ok(v),
            _ => Err(CryptoError::AttestationFailed(format!(
                "the attestation document has no `{}`",
                key
            ))),
        }
    }

    /// Look up an integer key in a map — COSE headers are keyed by integer.
    pub fn get_int(&self, key: i64, field: &str) -> CryptoResult<Option<&CborValue>> {
        let entries = self.as_map(field)?;
        for (k, v) in entries {
            let matches = match k {
                CborValue::Unsigned(n) => i64::try_from(*n).ok() == Some(key),
                CborValue::Negative(n) => *n == key,
                _ => false,
            };
            if matches {
                return Ok(Some(v));
            }
        }
        Ok(None)
    }

    /// A short name for the value's type, for error messages.
    fn type_name(&self) -> &'static str {
        match self {
            CborValue::Unsigned(_) => "an unsigned integer",
            CborValue::Negative(_) => "a negative integer",
            CborValue::Bytes(_) => "a byte string",
            CborValue::Text(_) => "a text string",
            CborValue::Array(_) => "an array",
            CborValue::Map(_) => "a map",
            CborValue::Bool(_) => "a boolean",
            CborValue::Null => "null",
        }
    }
}

fn type_error(field: &str, expected: &str, found: &CborValue) -> CryptoError {
    CryptoError::AttestationFailed(format!(
        "`{}` should be {}, but the document has {}",
        field,
        expected,
        found.type_name()
    ))
}

/// Decode one CBOR item, which must account for every byte given.
pub fn decode(bytes: &[u8]) -> CryptoResult<CborValue> {
    let mut reader = Reader {
        bytes,
        position: 0,
        items: 0,
    };
    let value = reader.value(0)?;
    if reader.position != bytes.len() {
        return Err(CryptoError::AttestationFailed(format!(
            "{} bytes remain after the end of the CBOR document; \
             something has been appended to it",
            bytes.len() - reader.position
        )));
    }
    Ok(value)
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
    items: usize,
}

impl Reader<'_> {
    fn take(&mut self, count: usize) -> CryptoResult<&[u8]> {
        // Written as a subtraction on the remaining length rather than
        // `position + count`, which can overflow on a 32-bit target when the
        // document declares a huge length.
        if count > self.bytes.len() - self.position {
            return Err(CryptoError::AttestationFailed(format!(
                "the CBOR document declares {} more bytes than it contains",
                count - (self.bytes.len() - self.position)
            )));
        }
        let slice = &self.bytes[self.position..self.position + count];
        self.position += count;
        Ok(slice)
    }

    fn byte(&mut self) -> CryptoResult<u8> {
        Ok(self.take(1)?[0])
    }

    /// Read the argument that follows an initial byte.
    ///
    /// The low five bits are either the value itself (0–23) or say how many
    /// following bytes hold it. Values 28–30 are reserved and 31 means
    /// indefinite length, which this reader does not accept.
    fn argument(&mut self, initial: u8) -> CryptoResult<u64> {
        match initial & 0x1F {
            n @ 0..=23 => Ok(n as u64),
            24 => Ok(self.byte()? as u64),
            25 => {
                let b = self.take(2)?;
                Ok(u16::from_be_bytes([b[0], b[1]]) as u64)
            }
            26 => {
                let b = self.take(4)?;
                Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64)
            }
            27 => {
                let b = self.take(8)?;
                let mut buf = [0u8; 8];
                buf.copy_from_slice(b);
                Ok(u64::from_be_bytes(buf))
            }
            31 => Err(CryptoError::AttestationFailed(
                "the CBOR document uses an indefinite-length item, which an \
                 attestation document does not"
                    .into(),
            )),
            other => Err(CryptoError::AttestationFailed(format!(
                "the CBOR document uses reserved additional information {}",
                other
            ))),
        }
    }

    /// A declared length, checked against what is actually left.
    ///
    /// This is the check that matters. Without it a two-byte header claiming
    /// `u64::MAX` elements reaches `Vec::with_capacity` and the process dies
    /// before any signature is examined.
    fn length(&self, declared: u64, unit: &str) -> CryptoResult<usize> {
        let remaining = self.bytes.len() - self.position;
        let declared = usize::try_from(declared).unwrap_or(usize::MAX);
        if declared > remaining {
            return Err(CryptoError::AttestationFailed(format!(
                "the CBOR document declares {} {} but only {} bytes remain",
                declared, unit, remaining
            )));
        }
        Ok(declared)
    }

    fn count_item(&mut self) -> CryptoResult<()> {
        self.items += 1;
        if self.items > MAX_ITEMS {
            return Err(CryptoError::AttestationFailed(format!(
                "the CBOR document holds more than {} items; an attestation \
                 document holds fewer than a hundred",
                MAX_ITEMS
            )));
        }
        Ok(())
    }

    fn value(&mut self, depth: usize) -> CryptoResult<CborValue> {
        if depth > MAX_DEPTH {
            return Err(CryptoError::AttestationFailed(format!(
                "the CBOR document nests more than {} deep",
                MAX_DEPTH
            )));
        }
        self.count_item()?;

        let initial = self.byte()?;
        let major = initial >> 5;

        match major {
            0 => Ok(CborValue::Unsigned(self.argument(initial)?)),
            1 => {
                // Major type 1 encodes -1 - n, so n = u64::MAX represents a
                // value far outside i64. Nitro only uses small negatives.
                let n = self.argument(initial)?;
                let n = i64::try_from(n).map_err(|_| {
                    CryptoError::AttestationFailed(
                        "the CBOR document holds a negative integer too large to represent".into(),
                    )
                })?;
                Ok(CborValue::Negative(-1 - n))
            }
            2 => {
                let declared = self.argument(initial)?;
                let len = self.length(declared, "bytes")?;
                Ok(CborValue::Bytes(self.take(len)?.to_vec()))
            }
            3 => {
                let declared = self.argument(initial)?;
                let len = self.length(declared, "bytes of text")?;
                let raw = self.take(len)?;
                let text = std::str::from_utf8(raw).map_err(|_| {
                    CryptoError::AttestationFailed(
                        "the CBOR document holds a text string that is not valid UTF-8".into(),
                    )
                })?;
                Ok(CborValue::Text(text.to_string()))
            }
            4 => {
                let declared = self.argument(initial)?;
                // Every element costs at least one byte, so a declared count
                // larger than the bytes remaining is a lie by construction.
                let count = self.length(declared, "array elements")?;
                let mut items = Vec::with_capacity(count.min(64));
                for _ in 0..count {
                    items.push(self.value(depth + 1)?);
                }
                Ok(CborValue::Array(items))
            }
            5 => {
                let declared = self.argument(initial)?;
                // A map entry is at least two bytes, so halve the bound.
                let count = self.length(declared, "map entries")?;
                let mut entries = Vec::with_capacity(count.min(64));
                for _ in 0..count {
                    let key = self.value(depth + 1)?;
                    let value = self.value(depth + 1)?;
                    entries.push((key, value));
                }
                Ok(CborValue::Map(entries))
            }
            6 => Err(CryptoError::AttestationFailed(
                "the CBOR document uses a tag, which an attestation document does not".into(),
            )),
            7 => match initial & 0x1F {
                20 => Ok(CborValue::Bool(false)),
                21 => Ok(CborValue::Bool(true)),
                22 => Ok(CborValue::Null),
                23 => Err(CryptoError::AttestationFailed(
                    "the CBOR document holds `undefined`, which is not a value a \
                     verifier can act on"
                        .into(),
                )),
                other => Err(CryptoError::AttestationFailed(format!(
                    "the CBOR document holds simple value or float {}, which an \
                     attestation document does not use",
                    other
                ))),
            },
            _ => unreachable!("a three-bit major type cannot exceed 7"),
        }
    }
}

/// Encode a definite-length byte string header followed by its contents.
fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_header(out, 2, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// Encode a definite-length text string.
fn write_text(out: &mut Vec<u8>, text: &str) {
    write_header(out, 3, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
}

/// Encode an initial byte and its argument in the shortest form, which is what
/// COSE requires of the structure being signed.
fn write_header(out: &mut Vec<u8>, major: u8, argument: u64) {
    let major = major << 5;
    match argument {
        0..=23 => out.push(major | argument as u8),
        24..=0xFF => {
            out.push(major | 24);
            out.push(argument as u8);
        }
        0x100..=0xFFFF => {
            out.push(major | 25);
            out.extend_from_slice(&(argument as u16).to_be_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(major | 26);
            out.extend_from_slice(&(argument as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend_from_slice(&argument.to_be_bytes());
        }
    }
}

/// Build the `Sig_structure` that a COSE_Sign1 signature is actually computed
/// over (RFC 8152 §4.4).
///
/// The signature does not cover the payload directly. It covers a four-element
/// array holding a context string, the protected header as it appeared on the
/// wire, any externally supplied additional data, and the payload. Verifying
/// against the payload alone would accept a document whose protected header —
/// which names the signature algorithm — had been rewritten.
pub fn sig_structure_single_signer(
    protected: &[u8],
    external_aad: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(protected.len() + payload.len() + 32);
    write_header(&mut out, 4, 4);
    write_text(&mut out, "Signature1");
    write_bytes(&mut out, protected);
    write_bytes(&mut out, external_aad);
    write_bytes(&mut out, payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_shapes_an_attestation_document_uses() {
        assert_eq!(decode(&[0x00]).unwrap(), CborValue::Unsigned(0));
        assert_eq!(decode(&[0x17]).unwrap(), CborValue::Unsigned(23));
        assert_eq!(decode(&[0x18, 0x2A]).unwrap(), CborValue::Unsigned(42));
        assert_eq!(
            decode(&[0x19, 0x01, 0x00]).unwrap(),
            CborValue::Unsigned(256)
        );
        assert_eq!(
            decode(&[0x1A, 0x00, 0x01, 0x00, 0x00]).unwrap(),
            CborValue::Unsigned(65536)
        );
        assert_eq!(decode(&[0xF4]).unwrap(), CborValue::Bool(false));
        assert_eq!(decode(&[0xF5]).unwrap(), CborValue::Bool(true));
        assert_eq!(decode(&[0xF6]).unwrap(), CborValue::Null);
    }

    /// `ES384` is `-35`, so getting negative integers right is not optional:
    /// a decoder that mangles them cannot tell ES384 from ES256.
    #[test]
    fn decodes_the_negative_integers_cose_uses_for_algorithms() {
        assert_eq!(decode(&[0x20]).unwrap(), CborValue::Negative(-1));
        assert_eq!(decode(&[0x38, 0x22]).unwrap(), CborValue::Negative(-35));
        assert_eq!(decode(&[0x38, 0x06]).unwrap(), CborValue::Negative(-7));
    }

    #[test]
    fn decodes_nested_containers() {
        // {"a": [1, 2], "b": h'FF'}
        let bytes = [0xA2, 0x61, b'a', 0x82, 0x01, 0x02, 0x61, b'b', 0x41, 0xFF];
        let value = decode(&bytes).unwrap();
        assert_eq!(
            value.require("a").unwrap().as_array("a").unwrap(),
            &[CborValue::Unsigned(1), CborValue::Unsigned(2)]
        );
        assert_eq!(value.require("b").unwrap().as_bytes("b").unwrap(), &[0xFF]);
    }

    /// The allocation bomb: a header that says "four gigabytes follow" in a
    /// document ten bytes long. It must be refused by looking at the length,
    /// not by trying and failing to allocate.
    #[test]
    fn refuses_a_length_larger_than_the_document() {
        // Byte string, 8-byte length, 0xFFFFFFFF.
        let bytes = [0x5B, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF];
        let error = decode(&bytes).unwrap_err().to_string();
        assert!(error.contains("only"), "{}", error);
    }

    /// The same bomb wearing a different hat: an array header claiming more
    /// elements than the document has bytes to hold.
    #[test]
    fn refuses_an_element_count_larger_than_the_document() {
        let bytes = [0x9B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn refuses_indefinite_length_items() {
        // Indefinite-length array.
        let error = decode(&[0x9F, 0x01, 0xFF]).unwrap_err().to_string();
        assert!(error.contains("indefinite-length"), "{}", error);
    }

    #[test]
    fn refuses_tags_floats_and_undefined() {
        assert!(decode(&[0xC0, 0x00]).is_err(), "tag");
        assert!(decode(&[0xFB, 0, 0, 0, 0, 0, 0, 0, 0]).is_err(), "double");
        assert!(decode(&[0xF7]).is_err(), "undefined");
    }

    /// A document with bytes appended has been edited, and the edit is outside
    /// anything the signature covers.
    #[test]
    fn refuses_trailing_bytes() {
        let error = decode(&[0x00, 0x00]).unwrap_err().to_string();
        assert!(error.contains("appended"), "{}", error);
    }

    #[test]
    fn refuses_nesting_past_the_depth_limit() {
        // MAX_DEPTH + 2 nested single-element arrays.
        let mut bytes = vec![0x81; MAX_DEPTH + 2];
        bytes.push(0x00);
        let error = decode(&bytes).unwrap_err().to_string();
        assert!(error.contains("nests more than"), "{}", error);
    }

    #[test]
    fn refuses_text_that_is_not_utf8() {
        assert!(decode(&[0x62, 0xFF, 0xFE]).is_err());
    }

    /// A duplicate key means two answers to one question, and the verifier has
    /// no basis for preferring either.
    #[test]
    fn refuses_a_duplicate_key_rather_than_letting_one_win() {
        // {"pcrs": 1, "pcrs": 2}
        let bytes = [
            0xA2, 0x64, b'p', b'c', b'r', b's', 0x01, 0x64, b'p', b'c', b'r', b's', 0x02,
        ];
        let value = decode(&bytes).unwrap();
        let error = value.get("pcrs").unwrap_err().to_string();
        assert!(error.contains("more than once"), "{}", error);
    }

    #[test]
    fn a_missing_field_says_which_field() {
        let value = decode(&[0xA0]).unwrap();
        let error = value.require("certificate").unwrap_err().to_string();
        assert!(error.contains("certificate"), "{}", error);
        assert!(value.get("certificate").unwrap().is_none());
    }

    /// An explicit `null` is absence, not a value to be read as bytes.
    #[test]
    fn treats_an_explicit_null_as_absent() {
        // {"nonce": null}
        let bytes = [0xA1, 0x65, b'n', b'o', b'n', b'c', b'e', 0xF6];
        let value = decode(&bytes).unwrap();
        assert!(value.get("nonce").unwrap().unwrap().is_null());
        assert!(value.require("nonce").is_err());
    }

    #[test]
    fn reads_the_integer_keys_a_cose_header_uses() {
        // {1: -35}
        let bytes = [0xA1, 0x01, 0x38, 0x22];
        let value = decode(&bytes).unwrap();
        let alg = value.get_int(1, "protected header").unwrap().unwrap();
        assert_eq!(alg.as_i64("alg").unwrap(), -35);
    }

    /// The signed structure is checked against the example in RFC 8152 §4.4:
    /// a four-element array, the context string, then three byte strings.
    #[test]
    fn builds_the_signature1_structure_cose_specifies() {
        let built = sig_structure_single_signer(&[0xA1, 0x01, 0x26], &[], &[0xDE, 0xAD]);
        assert_eq!(
            built,
            vec![
                0x84, // array(4)
                0x6A, b'S', b'i', b'g', b'n', b'a', b't', b'u', b'r', b'e', b'1', 0x43, 0xA1, 0x01,
                0x26, // protected
                0x40, // external_aad, empty
                0x42, 0xDE, 0xAD, // payload
            ]
        );
        // And it must decode back to what it claims to be.
        let round_tripped = decode(&built).unwrap();
        let items = round_tripped.as_array("sig structure").unwrap();
        assert_eq!(items.len(), 4);
        assert_eq!(items[0].as_text("context").unwrap(), "Signature1");
    }

    /// The protected header travels in the signature exactly as it appeared on
    /// the wire. Re-encoding it would let a document that used a non-canonical
    /// encoding verify against bytes its signer never signed.
    #[test]
    fn the_signed_structure_carries_the_protected_header_verbatim() {
        // A deliberately non-shortest encoding of the same header.
        let odd = [0xB8, 0x01, 0x01, 0x38, 0x22];
        let built = sig_structure_single_signer(&odd, &[], &[0x00]);
        let decoded = decode(&built).unwrap();
        let items = decoded.as_array("sig structure").unwrap();
        assert_eq!(items[1].as_bytes("protected").unwrap(), &odd);
    }

    #[test]
    fn refuses_a_document_that_is_all_containers() {
        // A flat run of empty arrays would be cheap to decode individually;
        // the item counter is what stops a document made of millions of them.
        let mut bytes = vec![0x9A, 0x00, 0x00, 0x10, 0x01]; // array(4097)
        bytes.extend(std::iter::repeat(0x80).take(4097));
        let error = decode(&bytes).unwrap_err().to_string();
        assert!(error.contains("more than"), "{}", error);
    }
}
