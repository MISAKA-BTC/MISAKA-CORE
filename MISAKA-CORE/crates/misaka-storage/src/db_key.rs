//! # Database Key — Prefix-Based Key Construction
//!
//! Kaspa-aligned `DbKey` with SmallVec optimization for the common case
//! of { prefix_byte || SHA3-256 hash (32 bytes) }.
//!
//! Keys are namespaced by store prefix to support multi-store layouts
//! within a single RocksDB instance.

use smallvec::SmallVec;
use std::fmt::{self, Debug, Display};

use crate::store_registry::StorePrefixes;

/// Separator byte between prefix and key.
pub const SEPARATOR: u8 = 0xFF;

/// Database key optimized for [prefix(1-2) + hash(32)] patterns.
#[derive(Clone)]
pub struct DbKey {
    /// The full key path (prefix + key bytes).
    path: SmallVec<[u8; 36]>,
    /// Length of the prefix portion.
    prefix_len: usize,
}

impl DbKey {
    /// Create a key from prefix and a typed key.
    pub fn new<K: AsRef<[u8]>>(prefix: &[u8], key: K) -> Self {
        let key_ref = key.as_ref();
        let mut path = SmallVec::with_capacity(prefix.len() + key_ref.len());
        path.extend_from_slice(prefix);
        path.extend_from_slice(key_ref);
        Self {
            path,
            prefix_len: prefix.len(),
        }
    }

    /// Create a key with an additional bucket level.
    pub fn new_with_bucket<K, B>(prefix: &[u8], bucket: B, key: K) -> Self
    where
        K: AsRef<[u8]>,
        B: AsRef<[u8]>,
    {
        let mut db_key = Self::prefix_only(prefix);
        db_key.add_bucket(bucket);
        db_key.add_key(key);
        db_key
    }

    /// Create a prefix-only key (for range iteration).
    pub fn prefix_only(prefix: &[u8]) -> Self {
        Self::new(prefix, [])
    }

    /// Append a bucket to the prefix.
    pub fn add_bucket<B: AsRef<[u8]>>(&mut self, bucket: B) {
        let b = bucket.as_ref();
        self.path.extend_from_slice(b);
        self.prefix_len += b.len();
    }

    /// Append key bytes.
    pub fn add_key<K: AsRef<[u8]>>(&mut self, key: K) {
        self.path.extend_from_slice(key.as_ref());
    }

    /// Length of the prefix portion.
    pub fn prefix_len(&self) -> usize {
        self.prefix_len
    }

    /// Full key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.path
    }
}

impl AsRef<[u8]> for DbKey {
    fn as_ref(&self) -> &[u8] {
        &self.path
    }
}

impl Display for DbKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.prefix_len > 0 {
            if let Ok(prefix) = StorePrefixes::try_from(self.path[0]) {
                write!(f, "{:?}/", prefix)?;
            } else {
                write!(f, "{:02x}/", self.path[0])?;
            }
        }
        let key_part = if self.prefix_len < self.path.len() {
            &self.path[self.prefix_len..]
        } else {
            &[]
        };
        write!(f, "{}", hex::encode(key_part))
    }
}

impl Debug for DbKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_construction() {
        let hash = [0xABu8; 32];
        let key = DbKey::new(&[0x01], hash);
        assert_eq!(key.prefix_len(), 1);
        assert_eq!(key.as_ref().len(), 33);
        assert_eq!(key.as_ref()[0], 0x01);
        assert_eq!(&key.as_ref()[1..], &hash);
    }

    #[test]
    fn test_prefix_only() {
        let key = DbKey::prefix_only(&[0x01, 0x02]);
        assert_eq!(key.prefix_len(), 2);
        assert_eq!(key.as_ref().len(), 2);
    }

    #[test]
    fn test_bucket_key() {
        let hash = [0xCD; 32];
        let key = DbKey::new_with_bucket(&[0x01], [0x05u8], hash);
        assert_eq!(key.as_ref()[0], 0x01);
        assert_eq!(key.as_ref()[1], 0x05);
        assert_eq!(&key.as_ref()[2..], &hash);
    }
}
