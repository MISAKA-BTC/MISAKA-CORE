//! Database key abstraction with prefix support.

use smallvec::SmallVec;
use std::fmt::{Debug, Display};

/// A database key composed of a prefix and a key portion.
///
/// Uses `SmallVec` optimized for the common case of prefix(1) + Hash(32).
#[derive(Clone)]
pub struct DbKey {
    path: SmallVec<[u8; 36]>,
    prefix_len: usize,
}

impl DbKey {
    pub fn new<TKey>(prefix: &[u8], key: TKey) -> Self
    where
        TKey: Clone + AsRef<[u8]>,
    {
        Self {
            path: prefix
                .iter()
                .chain(key.as_ref().iter())
                .copied()
                .collect(),
            prefix_len: prefix.len(),
        }
    }

    pub fn new_with_bucket<TKey, TBucket>(prefix: &[u8], bucket: TBucket, key: TKey) -> Self
    where
        TKey: Clone + AsRef<[u8]>,
        TBucket: Copy + AsRef<[u8]>,
    {
        let mut db_key = Self::prefix_only(prefix);
        db_key.add_bucket(bucket);
        db_key.add_key(key);
        db_key
    }

    pub fn prefix_only(prefix: &[u8]) -> Self {
        Self::new(prefix, [])
    }

    pub fn add_bucket<TBucket>(&mut self, bucket: TBucket)
    where
        TBucket: Copy + AsRef<[u8]>,
    {
        self.path.extend(bucket.as_ref().iter().copied());
        self.prefix_len += bucket.as_ref().len();
    }

    pub fn add_key<TKey>(&mut self, key: TKey)
    where
        TKey: Clone + AsRef<[u8]>,
    {
        self.path.extend(key.as_ref().iter().copied());
    }

    pub fn prefix_len(&self) -> usize {
        self.prefix_len
    }
}

impl AsRef<[u8]> for DbKey {
    fn as_ref(&self) -> &[u8] {
        &self.path
    }
}

impl Display for DbKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.path))
    }
}

impl Debug for DbKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}
