// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Column family enumeration for the Narwhal consensus RocksDB store.
//!
//! See [`crate::narwhal_dag::rocksdb_store`] for the actual open path.
//! This module centralises the CF name registry so that adding a new
//! column family becomes a compiler-enforced change instead of three
//! manual edits scattered across `const` declarations, `cf_descriptors`
//! vectors, and every `cf_handle(...)` call site.
//!
//! The naming convention preserves the existing `narwhal_` prefix for
//! every CF so this module is a pure no-op refactor — database contents
//! are unchanged.

/// The set of RocksDB column families owned by the Narwhal consensus store.
///
/// The string values are **persisted** RocksDB column-family identifiers.
/// Changing a variant's `name()` orphans every existing database.
///
/// Adding a variant requires:
///   1. Register the canonical string in [`NarwhalCf::name`].
///   2. Include the variant in [`NarwhalCf::ALL`].
///   3. Add a `ColumnFamilyDescriptor` for it at DB open time
///      (see `rocksdb_store::open_with_sync`).
///   4. Update existing databases — variants are not retroactive.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum NarwhalCf {
    /// `BlockDigest` → `Block` (serialised).
    Blocks,
    /// `CommitIndex` → `CommittedSubDag` (serialised).
    Commits,
    /// Singleton keys (e.g. `last_committed_rounds`, `gc_round`).
    Meta,
    /// Per-authority last committed round, kept in a dedicated CF for
    /// hot-path reads.
    LastCommitted,
    /// `(round, author)` → equivocation evidence. Append-only; never
    /// deleted (slashing + post-mortem).
    EquivocationEvidence,
    /// Committed-tx filter snapshot.
    CommittedTxFilter,
    /// Transaction-hash → commit location index.
    TxIndex,
    /// Address → tx-hash prefix index (uses a fixed-64 prefix extractor).
    AddrIndex,
    /// Phase 3a A.1: Certificate V2 vote commitments.
    ///
    /// Key: cert digest (32 bytes — `CheckpointDigest` of the
    /// `CertificateV2` per its `digest()` method).
    /// Value: serde-JSON-serialised `(VoteCommitment,
    /// Option<AggregationProof>)` tuple. JSON is used for day-1
    /// consistency with the other narwhal value encodings
    /// (`Block`, `CommittedSubDag` both already use serde_json);
    /// a borsh migration is straightforward but needs manual
    /// `BorshSerialize` impls that preserve `#[repr(u8)]` tags,
    /// deferred to a follow-up session. The cert header/epoch are
    /// not stored here — they live in `Commits` alongside the rest
    /// of the subdag. This CF externalises signatures + commitment
    /// data so that the hot `Commits` CF stays compact.
    ///
    /// Tuning:
    /// * compression off (the payload is small, already hash-compressed,
    ///   and ZSTD overhead outweighs gains),
    /// * BlobDB threshold = 1024 bytes (any vote commitment whose
    ///   serialised form exceeds this is written to a `*.blob` file
    ///   instead of the LSM, matching the v0.8.9 BlobDB rationale).
    Votes,
}

impl NarwhalCf {
    /// All variants, in a stable order suitable for DB-open descriptor
    /// construction.
    pub const ALL: &'static [Self] = &[
        Self::Blocks,
        Self::Commits,
        Self::Meta,
        Self::LastCommitted,
        Self::EquivocationEvidence,
        Self::CommittedTxFilter,
        Self::TxIndex,
        Self::AddrIndex,
        Self::Votes,
    ];

    /// The canonical RocksDB column-family name.
    ///
    /// These strings are persisted — changing them breaks every
    /// existing database on disk.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Blocks => "narwhal_blocks",
            Self::Commits => "narwhal_commits",
            Self::Meta => "narwhal_meta",
            Self::LastCommitted => "narwhal_last_committed",
            Self::EquivocationEvidence => "narwhal_equivocation_evidence",
            Self::CommittedTxFilter => "narwhal_committed_tx_filter",
            Self::TxIndex => "narwhal_tx_index",
            Self::AddrIndex => "narwhal_addr_index",
            Self::Votes => "narwhal_votes",
        }
    }
}

impl AsRef<str> for NarwhalCf {
    fn as_ref(&self) -> &str {
        self.name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant appears exactly once in `ALL`. Guards the
    /// hand-written array against drift.
    #[test]
    fn all_is_exhaustive_and_unique() {
        // Update this when adding a CF; the assertion fails early
        // rather than surfacing as "column family missing" at DB open.
        const EXPECTED_COUNT: usize = 9;
        assert_eq!(
            NarwhalCf::ALL.len(),
            EXPECTED_COUNT,
            "NarwhalCf::ALL is missing or has duplicate variants"
        );

        let mut names: Vec<&str> = NarwhalCf::ALL.iter().map(|c| c.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            EXPECTED_COUNT,
            "NarwhalCf::ALL contains duplicate CF names"
        );
    }

    /// The on-disk names must match the pre-refactor string literals
    /// that shipped with `rocksdb_store.rs`. Drift here orphans every
    /// existing Narwhal RocksDB.
    #[test]
    fn names_match_pre_refactor_literals() {
        assert_eq!(NarwhalCf::Blocks.name(), "narwhal_blocks");
        assert_eq!(NarwhalCf::Commits.name(), "narwhal_commits");
        assert_eq!(NarwhalCf::Meta.name(), "narwhal_meta");
        assert_eq!(NarwhalCf::LastCommitted.name(), "narwhal_last_committed");
        assert_eq!(
            NarwhalCf::EquivocationEvidence.name(),
            "narwhal_equivocation_evidence"
        );
        assert_eq!(
            NarwhalCf::CommittedTxFilter.name(),
            "narwhal_committed_tx_filter"
        );
        assert_eq!(NarwhalCf::TxIndex.name(), "narwhal_tx_index");
        assert_eq!(NarwhalCf::AddrIndex.name(), "narwhal_addr_index");
        assert_eq!(NarwhalCf::Votes.name(), "narwhal_votes");
    }

    /// Every variant's name starts with the `narwhal_` prefix — this
    /// distinguishes Narwhal CFs from storage CFs inside a single
    /// RocksDB instance if they ever share one.
    #[test]
    fn all_names_have_narwhal_prefix() {
        for cf in NarwhalCf::ALL {
            assert!(
                cf.name().starts_with("narwhal_"),
                "{:?} missing narwhal_ prefix: {}",
                cf,
                cf.name()
            );
        }
    }

    #[test]
    fn as_ref_str_matches_name() {
        for cf in NarwhalCf::ALL {
            assert_eq!(AsRef::<str>::as_ref(cf), cf.name());
        }
    }
}
