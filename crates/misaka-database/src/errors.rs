//! Store error types and result extensions.

use thiserror::Error;

/// Errors produced by typed stores.
#[derive(Error, Debug)]
pub enum StoreError {
    #[error("key {0} not found in store")]
    KeyNotFound(String),

    #[error("key already exists: {0}")]
    KeyAlreadyExists(String),

    #[error("hash already exists: {0}")]
    HashAlreadyExists(String),

    #[error("data inconsistency: {0}")]
    DataInconsistency(String),

    #[error("rocksdb error: {0}")]
    DbError(#[from] rocksdb::Error),

    #[error("bincode error: {0}")]
    DeserializationError(#[from] Box<bincode::ErrorKind>),
}

pub type StoreResult<T> = std::result::Result<T, StoreError>;

// ── Predicate traits ───────────────────────────────────────────

pub trait StoreErrorPredicates {
    fn is_key_not_found(&self) -> bool;
    fn is_already_exists(&self) -> bool;
}

impl StoreErrorPredicates for StoreError {
    fn is_key_not_found(&self) -> bool {
        matches!(self, StoreError::KeyNotFound(_))
    }

    fn is_already_exists(&self) -> bool {
        matches!(
            self,
            StoreError::KeyAlreadyExists(_) | StoreError::HashAlreadyExists(_)
        )
    }
}

/// Extension methods for `StoreResult<T>`.
pub trait StoreResultExt<T, E: StoreErrorPredicates> {
    /// Converts a "key not found" error into `Ok(None)`.
    fn optional(self) -> Result<Option<T>, E>;
}

impl<T, E: StoreErrorPredicates> StoreResultExt<T, E> for Result<T, E> {
    fn optional(self) -> Result<Option<T>, E> {
        match self {
            Ok(value) => Ok(Some(value)),
            Err(err) if err.is_key_not_found() => Ok(None),
            Err(err) => Err(err),
        }
    }
}

/// Extension methods for `StoreResult<()>`.
pub trait StoreResultUnitExt<E: StoreErrorPredicates> {
    /// Treats a duplicate-write error as success (idempotent).
    fn idempotent(self) -> Result<(), E>;
}

impl<E: StoreErrorPredicates> StoreResultUnitExt<E> for Result<(), E> {
    fn idempotent(self) -> Result<(), E> {
        match self {
            Ok(()) => Ok(()),
            Err(err) if err.is_already_exists() => Ok(()),
            Err(err) => Err(err),
        }
    }
}
