//! # Store Error Types

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("RocksDB error: {0}")]
    RocksDb(String),

    #[error("serialization error: {0}")]
    SerializeError(String),

    #[error("deserialization error: {0}")]
    DeserializeError(String),

    #[error("data integrity error: {0}")]
    IntegrityError(String),

    #[error("store already exists: {0}")]
    AlreadyExists(String),

    #[error("pruning error: {0}")]
    PruningError(String),

    #[error("checkpoint error: {0}")]
    CheckpointError(String),
}

impl From<rocksdb::Error> for StoreError {
    fn from(e: rocksdb::Error) -> Self {
        StoreError::RocksDb(e.to_string())
    }
}

impl From<bincode::Error> for StoreError {
    fn from(e: bincode::Error) -> Self {
        StoreError::DeserializeError(e.to_string())
    }
}
