// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! On-disk schema version marker for the Kaspa-aligned misaka-storage DB.
//!
//! # Why
//!
//! The storage layer carries persisted data whose encoding is allowed to
//! change across node releases (e.g. v0.9.0 adds checkpoint and pruning
//! capabilities on top of the v0.8.8 on-disk layout). An unversioned DB
//! means a newer node cannot tell whether on-disk data is compatible with
//! its code; silent corruption or cryptic panics follow.
//!
//! This module persists a single `u32` marker under
//! `StorePrefixes::ChainInfo || "schema_version"`. On startup, the node
//! reads the marker and either:
//!
//! * boots normally (marker == [`CURRENT_STORAGE_SCHEMA_VERSION`]),
//! * refuses to boot and points the operator at `misaka-node migrate`
//!   (marker mismatches the current build), or
//! * refuses to boot (no marker: DB predates this scheme — a pre-v0.9.0
//!   database — and must be explicitly stamped or migrated).
//!
//! The marker is deliberately **not** tied to the semver crate version —
//! multiple releases can share one on-disk schema. Bump this constant
//! only when an on-disk format change lands.
//!
//! # Namespace collision
//!
//! Several other `schema_version` concepts exist elsewhere in the
//! codebase (genesis UTXO JSON, validator snapshots, `migrate_snapshot`
//! output). They describe file formats, not the storage DB. The
//! constants in this module are explicitly prefixed `STORAGE_SCHEMA_…`
//! to avoid confusion.
//!
//! # Scope
//!
//! This module handles only the marker read/write and the compatibility
//! check. It does **not** perform migrations — that lives in the
//! `misaka-node migrate` subcommand (Phase 2 R6).
//!
//! # Forward compatibility
//!
//! The marker key is written under `StorePrefixes::ChainInfo` rather
//! than a dedicated prefix so that a future migration can update the
//! marker atomically in the same `WriteBatch` as the bulk of the data
//! rewrite, without needing to allocate a new store prefix.

use std::sync::Arc;

use rocksdb::DB;

use crate::db_key::DbKey;
use crate::store_registry::StorePrefixes;

/// On-disk schema as shipped by v0.8.x. Pre-existed this module — a DB
/// with no marker is interpreted as v1.
pub const STORAGE_SCHEMA_VERSION_V088: u32 = 1;

/// On-disk schema introduced by v0.9.0. Adds:
/// * the schema-version marker itself,
/// * Phase-2 checkpoint + pruning capabilities,
/// * (future Phase-2 R1/R6) legacy-CF removal.
pub const STORAGE_SCHEMA_VERSION_V090: u32 = 2;

/// The schema version this build expects. Runtime refuses any DB whose
/// marker differs (subject to [`check_compatible`]'s `accept_unmarked`
/// flag).
pub const CURRENT_STORAGE_SCHEMA_VERSION: u32 = STORAGE_SCHEMA_VERSION_V090;

/// Sub-bucket suffix under [`StorePrefixes::ChainInfo`] that identifies
/// this key among other chain-info singletons. The literal is persisted
/// — do not rename without a migration.
const MARKER_BUCKET: &[u8] = b"schema_version";

/// Errors raised by [`check_compatible`], [`read_schema_version`], and
/// [`write_schema_version`].
#[derive(Debug, thiserror::Error)]
pub enum SchemaVersionError {
    /// The DB carries a version marker that does not match what the
    /// current build understands. The operator is expected to run the
    /// `misaka-node migrate` subcommand (Phase 2 R6) before retrying.
    #[error(
        "storage schema version mismatch: db = {db_version}, build expects = {expected}. \
         Run `misaka-node migrate --from {db_version} --to {expected}` to upgrade."
    )]
    Incompatible { db_version: u32, expected: u32 },

    /// The DB has no marker at all. Emitted only when `accept_unmarked`
    /// is `false` in [`check_compatible`]. Strictly a subset of
    /// `Incompatible` semantically, but reported separately so operators
    /// can distinguish a pre-marker DB from a known-older marker value.
    #[error(
        "storage schema version marker absent — this DB predates the v0.9.0 marker scheme. \
         Run `misaka-node migrate --from {STORAGE_SCHEMA_VERSION_V088} --to {expected}` to upgrade."
    )]
    MarkerAbsent { expected: u32 },

    /// The marker key exists but its value is not a 4-byte little-endian
    /// `u32`. This would indicate DB corruption or a concurrent writer
    /// with a different encoding convention.
    #[error("storage schema version value is corrupt: {0}")]
    Corrupt(String),

    /// Underlying RocksDB error.
    #[error(transparent)]
    Rocks(#[from] rocksdb::Error),
}

/// Build the marker's full DB key: `ChainInfo-prefix || "schema_version"`.
fn marker_key() -> DbKey {
    DbKey::new_with_bucket(
        &StorePrefixes::ChainInfo.prefix_bytes(),
        MARKER_BUCKET,
        [] as [u8; 0],
    )
}

/// Read the persisted schema version.
///
/// Returns `Ok(None)` when the marker is absent (treat as pre-v0.9.0 DB).
pub fn read_schema_version(db: &DB) -> Result<Option<u32>, SchemaVersionError> {
    let key = marker_key();
    match db.get_pinned(key.as_ref())? {
        None => Ok(None),
        Some(bytes) => {
            if bytes.len() != 4 {
                return Err(SchemaVersionError::Corrupt(format!(
                    "expected 4-byte u32 LE, got {} bytes",
                    bytes.len()
                )));
            }
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&bytes);
            Ok(Some(u32::from_le_bytes(buf)))
        }
    }
}

/// Write the schema version marker. Overwrites any existing value.
///
/// Intended callers:
/// * the `misaka-node migrate` tool on completion,
/// * first-open of a freshly-initialised DB (stamp with
///   [`CURRENT_STORAGE_SCHEMA_VERSION`]).
pub fn write_schema_version(db: &DB, version: u32) -> Result<(), SchemaVersionError> {
    let key = marker_key();
    db.put(key.as_ref(), version.to_le_bytes())?;
    Ok(())
}

/// Verify the DB's schema version is compatible with this build.
///
/// * `accept_unmarked = false` (recommended for production): an absent
///   marker triggers `MarkerAbsent` — operator must run the migration
///   tool or explicitly stamp the DB.
/// * `accept_unmarked = true`: an absent marker is treated as
///   [`STORAGE_SCHEMA_VERSION_V088`]. Used by the migration tool itself
///   to tolerate a pre-marker input DB.
///
/// On success returns the DB's version. On any mismatch returns the
/// appropriate error variant without mutating the DB.
pub fn check_compatible(db: &DB, accept_unmarked: bool) -> Result<u32, SchemaVersionError> {
    match read_schema_version(db)? {
        Some(v) if v == CURRENT_STORAGE_SCHEMA_VERSION => Ok(v),
        Some(v) => Err(SchemaVersionError::Incompatible {
            db_version: v,
            expected: CURRENT_STORAGE_SCHEMA_VERSION,
        }),
        None if accept_unmarked => Ok(STORAGE_SCHEMA_VERSION_V088),
        None => Err(SchemaVersionError::MarkerAbsent {
            expected: CURRENT_STORAGE_SCHEMA_VERSION,
        }),
    }
}

/// Convenience wrapper that accepts `Arc<DB>` — matches the `PruningStore`
/// / `ReachabilityStore` handle shape used throughout this crate.
pub fn check_compatible_arc(
    db: &Arc<DB>,
    accept_unmarked: bool,
) -> Result<u32, SchemaVersionError> {
    check_compatible(db.as_ref(), accept_unmarked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocksdb::{Options, DB as RocksDB};
    use tempfile::TempDir;

    fn open_tmp_db() -> (TempDir, Arc<RocksDB>) {
        let dir = TempDir::new().expect("tmpdir");
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = RocksDB::open(&opts, dir.path()).expect("rocksdb open");
        (dir, Arc::new(db))
    }

    #[test]
    fn marker_key_is_deterministic_and_under_chain_info() {
        let k1 = marker_key();
        let k2 = marker_key();
        assert_eq!(k1.as_ref(), k2.as_ref());
        // First byte must be the ChainInfo prefix.
        assert_eq!(k1.as_ref()[0], StorePrefixes::ChainInfo as u8);
        // The bucket literal follows.
        assert_eq!(&k1.as_ref()[1..1 + MARKER_BUCKET.len()], MARKER_BUCKET);
    }

    #[test]
    fn read_on_fresh_db_returns_none() {
        let (_dir, db) = open_tmp_db();
        let v = read_schema_version(&db).expect("read");
        assert!(v.is_none(), "fresh DB should have no marker");
    }

    #[test]
    fn write_then_read_roundtrips() {
        let (_dir, db) = open_tmp_db();
        write_schema_version(&db, STORAGE_SCHEMA_VERSION_V090).expect("write");
        let v = read_schema_version(&db).expect("read").expect("some");
        assert_eq!(v, STORAGE_SCHEMA_VERSION_V090);
    }

    #[test]
    fn write_overwrites_previous_value() {
        let (_dir, db) = open_tmp_db();
        write_schema_version(&db, STORAGE_SCHEMA_VERSION_V088).expect("write v1");
        write_schema_version(&db, STORAGE_SCHEMA_VERSION_V090).expect("write v2");
        let v = read_schema_version(&db).expect("read").expect("some");
        assert_eq!(v, STORAGE_SCHEMA_VERSION_V090);
    }

    #[test]
    fn corrupt_value_is_detected() {
        let (_dir, db) = open_tmp_db();
        // Write a 3-byte value directly — not a valid u32 LE.
        db.put(marker_key().as_ref(), b"bad").expect("put raw");
        let err = read_schema_version(&db).expect_err("should detect corruption");
        matches!(err, SchemaVersionError::Corrupt(_));
    }

    #[test]
    fn check_compatible_ok_when_marker_matches() {
        let (_dir, db) = open_tmp_db();
        write_schema_version(&db, CURRENT_STORAGE_SCHEMA_VERSION).expect("stamp");
        let v = check_compatible(&db, false).expect("ok");
        assert_eq!(v, CURRENT_STORAGE_SCHEMA_VERSION);
    }

    #[test]
    fn check_compatible_err_when_marker_mismatches() {
        let (_dir, db) = open_tmp_db();
        // Stamp a hypothetical future v3.
        write_schema_version(&db, 99).expect("stamp");
        let err = check_compatible(&db, false).expect_err("should refuse");
        match err {
            SchemaVersionError::Incompatible {
                db_version,
                expected,
            } => {
                assert_eq!(db_version, 99);
                assert_eq!(expected, CURRENT_STORAGE_SCHEMA_VERSION);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn check_compatible_err_when_marker_absent_and_strict() {
        let (_dir, db) = open_tmp_db();
        let err = check_compatible(&db, false).expect_err("strict refuses unmarked");
        match err {
            SchemaVersionError::MarkerAbsent { expected } => {
                assert_eq!(expected, CURRENT_STORAGE_SCHEMA_VERSION);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn check_compatible_accepts_unmarked_as_v1_when_opted_in() {
        let (_dir, db) = open_tmp_db();
        let v = check_compatible(&db, true).expect("accept_unmarked tolerates absence");
        assert_eq!(v, STORAGE_SCHEMA_VERSION_V088);
    }

    #[test]
    fn check_compatible_arc_wrapper_matches_plain() {
        let (_dir, db) = open_tmp_db();
        write_schema_version(&db, CURRENT_STORAGE_SCHEMA_VERSION).expect("stamp");
        let plain = check_compatible(&db, false).expect("plain");
        let via_arc = check_compatible_arc(&db, false).expect("arc");
        assert_eq!(plain, via_arc);
    }

    #[test]
    fn constants_are_monotone_and_current_is_latest() {
        assert!(STORAGE_SCHEMA_VERSION_V088 < STORAGE_SCHEMA_VERSION_V090);
        assert_eq!(CURRENT_STORAGE_SCHEMA_VERSION, STORAGE_SCHEMA_VERSION_V090);
    }
}
