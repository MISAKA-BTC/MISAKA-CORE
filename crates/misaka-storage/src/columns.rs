// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Column family enumeration for `misaka-storage`'s block store RocksDB.
//!
//! # Why
//!
//! String literals (`const CF_UTXOS: &str = "utxos"`) are the source of
//! two classes of bug that have bitten this codebase repeatedly:
//!
//! 1. **Silent drift**: adding a new CF means touching ≥ 3 places
//!    (const definition, `cf_descriptors`, every `cf_handle(...)` call
//!    site). Missing one site compiles and only fails at runtime.
//! 2. **Typo safety**: `cf_handle("utxo")` vs `"utxos"` is a runtime
//!    error, not a compile error.
//!
//! Gathering CFs into an enum moves both classes into the compiler's
//! exhaustiveness check. Adding a variant forces every `match` on
//! [`StorageCf`] to handle it.
//!
//! # Scope
//!
//! This enum is the **name registry** only — it does not take ownership
//! of how CFs are opened, tuned, or migrated. Open paths still pass a
//! `ColumnFamilyDescriptor` slice to RocksDB; this module just supplies
//! the canonical name string for each variant.
//!
//! The string values MUST NOT change — they are persisted RocksDB
//! column-family identifiers. Renaming a variant's `name()` breaks
//! every existing database on disk. Anchoring them in the enum makes
//! the invariant loud instead of buried in a `const`.

/// The set of RocksDB column families owned by `misaka-storage`'s
/// block store (see `block_store.rs`).
///
/// Adding a variant here requires:
///   1. Register the canonical string in [`StorageCf::name`].
///   2. Include the variant in [`StorageCf::ALL`].
///   3. Add a `ColumnFamilyDescriptor` for it at DB open time.
///   4. Update existing databases — variants are not retroactive.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum StorageCf {
    /// UTXO set. Key: `tx_hash(32) || output_index(4 LE)`.
    Utxos,
    /// Spent identifiers ("key images"). Key: `tag(32)`.
    SpentTags,
    /// Ring-member resolution bytes. Key: matches [`StorageCf::Utxos`].
    SpendingKeys,
    /// Per-height block metadata. Key: `height(8 LE)`.
    BlockMeta,
    /// Singleton state entries (chain tip height, state root).
    State,
}

impl StorageCf {
    /// All variants, in a stable order suitable for DB-open descriptor
    /// construction.
    pub const ALL: &'static [Self] = &[
        Self::Utxos,
        Self::SpentTags,
        Self::SpendingKeys,
        Self::BlockMeta,
        Self::State,
    ];

    /// The canonical RocksDB column-family name.
    ///
    /// These strings are **persisted** — changing them breaks every
    /// existing database on disk.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Utxos => "utxos",
            Self::SpentTags => "spent_tags",
            Self::SpendingKeys => "spending_keys",
            Self::BlockMeta => "block_meta",
            Self::State => "state",
        }
    }
}

impl AsRef<str> for StorageCf {
    fn as_ref(&self) -> &str {
        self.name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant appears exactly once in `ALL`. The `match` in
    /// `name()` already guarantees exhaustiveness for variants — this
    /// test guards the hand-written `ALL` array against drift.
    #[test]
    fn all_is_exhaustive_and_unique() {
        // Expected count = every variant currently defined. Update the
        // constant when adding a CF; the mismatch panics here instead of
        // surfacing as a silent RocksDB "missing column family" at open.
        const EXPECTED_COUNT: usize = 5;
        assert_eq!(
            StorageCf::ALL.len(),
            EXPECTED_COUNT,
            "StorageCf::ALL is missing or has duplicate variants"
        );

        let mut names: Vec<&str> = StorageCf::ALL.iter().map(|c| c.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            EXPECTED_COUNT,
            "StorageCf::ALL contains duplicate CF names"
        );
    }

    /// The on-disk names must match the pre-refactor string literals
    /// that shipped with `block_store.rs`. Any drift here would silently
    /// orphan every existing database.
    #[test]
    fn names_match_pre_refactor_literals() {
        assert_eq!(StorageCf::Utxos.name(), "utxos");
        assert_eq!(StorageCf::SpentTags.name(), "spent_tags");
        assert_eq!(StorageCf::SpendingKeys.name(), "spending_keys");
        assert_eq!(StorageCf::BlockMeta.name(), "block_meta");
        assert_eq!(StorageCf::State.name(), "state");
    }

    #[test]
    fn as_ref_str_matches_name() {
        for cf in StorageCf::ALL {
            assert_eq!(AsRef::<str>::as_ref(cf), cf.name());
        }
    }
}
