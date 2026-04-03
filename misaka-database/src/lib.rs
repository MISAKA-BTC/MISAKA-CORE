//! misaka-database — Database abstraction layer.
//!
//! Provides typed caching, batch/direct writers, and store primitives
//! modeled after Kaspa's database layer, adapted for MISAKA's
//! PQC-native architecture.

pub mod access;
pub mod cache;
pub mod db;
pub mod errors;
pub mod item;
pub mod key;
pub mod registry;
pub mod writer;

pub mod prelude {
    pub use super::access::CachedDbAccess;
    pub use super::cache::{Cache, CachePolicy, MemSizeEstimator};
    pub use super::db::{delete_db, ConnBuilder, DB};
    pub use super::errors::{
        StoreError, StoreErrorPredicates, StoreResult, StoreResultExt, StoreResultUnitExt,
    };
    pub use super::item::CachedDbItem;
    pub use super::key::DbKey;
    pub use super::writer::{BatchDbWriter, DbWriter, DirectDbWriter, DirectWriter, MemoryWriter};
}

/// Re-export rocksdb for downstream batch writing.
pub use rocksdb;
