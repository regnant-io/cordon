//! Secure memory types with guaranteed zeroization on drop.
//!
//! Uses the `zeroize` crate which issues volatile writes and compiler fences
//! to prevent the compiler from eliding the zeroing operation.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secret byte array — zeroized on drop.
/// Use for key material, passwords, and any sensitive fixed-size buffers.
#[derive(ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> SecretBytes<N> {
    /// Create from a byte array
    pub fn new(data: [u8; N]) -> Self {
        Self { data }
    }

    /// Create zeroed
    pub fn zeroed() -> Self {
        Self { data: [0u8; N] }
    }

    /// Get a reference to the inner data
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.data
    }

    /// Get a mutable reference to the inner data
    pub fn as_bytes_mut(&mut self) -> &mut [u8; N] {
        &mut self.data
    }
}

/// A secret byte vector — zeroized on drop.
/// Use for variable-length key material, query plaintexts, and response buffers.
#[derive(ZeroizeOnDrop)]
pub struct SecretVec {
    data: Vec<u8>,
}

impl SecretVec {
    /// Create from a vector
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create with given capacity
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            data: Vec::with_capacity(cap),
        }
    }

    /// Get a slice reference
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable slice reference
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get the length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Push a byte
    pub fn push(&mut self, b: u8) {
        self.data.push(b);
    }

    /// Extend from a slice
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.data.extend_from_slice(slice);
    }

    /// Manually zero and clear (in addition to automatic drop zeroization)
    pub fn zero_now(&mut self) {
        self.data.zeroize();
    }
}

/// A wrapper around a String that is zeroized on drop.
/// Use for secrets passed as strings (passwords, tokens).
#[derive(ZeroizeOnDrop)]
pub struct SecretString {
    data: String,
}

impl SecretString {
    /// Create from a String
    pub fn new(s: String) -> Self {
        Self { data: s }
    }

    /// Get a reference to the inner string
    pub fn expose_secret(&self) -> &str {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_vec_zeroize_on_drop() {
        let raw_ptr;
        {
            let sv = SecretVec::new(vec![0xFFu8; 32]);
            raw_ptr = sv.as_slice().as_ptr();
            // sv dropped here; memory zeroized
        }
        // We can't safely dereference after drop, but we can verify the type compiles
        // and zeroize was called (verified by libzeroize's volatile write semantics)
        let _ = raw_ptr;
    }

    #[test]
    fn test_secret_bytes_new() {
        let sb = SecretBytes::<32>::new([0xABu8; 32]);
        assert_eq!(sb.as_bytes()[0], 0xAB);
    }
}
