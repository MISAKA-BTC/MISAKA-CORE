// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! RocksDB-backed ConsensusStore for production deployment.
//!
//! Feature-gated behind `rocksdb` to avoid linking RocksDB in dev builds.
//!
//! Column families:
//! - `CF_BLOCKS`: BlockDigest -> Block (serialized JSON)
//! - `CF_COMMITS`: CommitIndex -> CommittedSubDag (serialized JSON)
//! - `CF_META`: singleton keys (last_committed_rounds, gc_round, etc.)
//! - `CF_LAST_COMMITTED`: per-authority last committed round (separate CF
//!    for hot-path reads without scanning CF_META)
//! - `CF_EQUIVOCATION_EVIDENCE`: (round, author) -> equivocation evidence
//!    for slashing and post-mortem analysis

#[cfg(feature = "rocksdb")]
use std::path::Path;
#[cfg(feature = "rocksdb")]
use std::sync::Arc;

#[cfg(feature = "rocksdb")]
use super::dag_state::DagWriteBatch;
#[cfg(feature = "rocksdb")]
use super::store::{ConsensusStore, StoreError};
#[cfg(feature = "rocksdb")]
use crate::narwhal_types::block::*;
#[cfg(feature = "rocksdb")]
use crate::narwhal_types::commit::*;

// ─── Column family names ─────────────────────────────────────
//
// CF names live in `super::columns::NarwhalCf`. The aliases below keep
// existing call sites compiling without churn; the enum owns the
// canonical source of truth and is tested against these literals.
#[cfg(feature = "rocksdb")]
use super::columns::NarwhalCf;
#[cfg(feature = "rocksdb")]
const CF_BLOCKS: &str = NarwhalCf::Blocks.name();
#[cfg(feature = "rocksdb")]
const CF_COMMITS: &str = NarwhalCf::Commits.name();
#[cfg(feature = "rocksdb")]
const CF_META: &str = NarwhalCf::Meta.name();
#[cfg(feature = "rocksdb")]
const CF_LAST_COMMITTED: &str = NarwhalCf::LastCommitted.name();
#[cfg(feature = "rocksdb")]
const CF_EQUIVOCATION_EVIDENCE: &str = NarwhalCf::EquivocationEvidence.name();
#[cfg(feature = "rocksdb")]
const CF_COMMITTED_TX_FILTER: &str = NarwhalCf::CommittedTxFilter.name();
#[cfg(feature = "rocksdb")]
const CF_TX_INDEX: &str = NarwhalCf::TxIndex.name();
#[cfg(feature = "rocksdb")]
const CF_ADDR_INDEX: &str = NarwhalCf::AddrIndex.name();
/// Phase 3a A.1: Certificate V2 vote commitments + optional
/// aggregation proofs. See `columns::NarwhalCf::Votes` rustdoc.
const CF_VOTES: &str = NarwhalCf::Votes.name();
/// Phase 3a A.5: Certificate v1 ↔ v2 digest mapping. See
/// `columns::NarwhalCf::CertMapping` rustdoc.
const CF_CERT_MAPPING: &str = NarwhalCf::CertMapping.name();
/// Phase 3a Part C: epoch-boundary round-config audit log. See
/// `columns::NarwhalCf::RoundConfigAudit` rustdoc.
const CF_ROUND_CONFIG_AUDIT: &str = NarwhalCf::RoundConfigAudit.name();

// ─── Meta keys ───────────────────────────────────────────────
#[cfg(feature = "rocksdb")]
const KEY_LAST_COMMITTED_ROUNDS: &[u8] = b"last_committed_rounds";
#[cfg(feature = "rocksdb")]
const KEY_GC_ROUND: &[u8] = b"gc_round";
#[cfg(feature = "rocksdb")]
const KEY_TX_FILTER_SNAPSHOT: &[u8] = b"tx_filter_snapshot";
/// BLOCKER G: schema-version singleton in `narwhal_meta`.
///
/// * Absent + CF empty → fresh install, written as
///   `CURRENT_SCHEMA_VERSION` at open time.
/// * Absent + CF non-empty → legacy v0.8.8 testnet DB that predates
///   versioning. Implicitly upgraded to `CURRENT_SCHEMA_VERSION` at
///   open time (the on-disk format did not change, only the meta
///   key is new).
/// * Present + matches `CURRENT_SCHEMA_VERSION` → normal boot.
/// * Present + mismatches → hard refusal via
///   [`StoreError::SchemaVersionMismatch`]. The operator must either
///   run the binary matching that version or drop the DB.
#[cfg(feature = "rocksdb")]
const KEY_SCHEMA_VERSION: &[u8] = b"schema_version";

/// BLOCKER G: schema version the current binary expects on disk.
///
/// Bump when the physical layout of any CF or meta key changes in a
/// way that older binaries cannot read correctly. A bump MUST ship
/// alongside a migration routine (added to `ensure_schema_version`)
/// or the node will fail closed on every restart.
#[cfg(feature = "rocksdb")]
pub const CURRENT_SCHEMA_VERSION: u32 = 1;
/// BLOCKER H: last-committed-index marker stamped atomically with
/// every commit-loop index write. Used on recovery to detect whether
/// a crash left any `tx_index` / `addr_index` entries partially
/// persisted and to log the commit delta between the DAG store and
/// the UTXO snapshot.
#[cfg(feature = "rocksdb")]
const KEY_LAST_COMMITTED_INDEX: &[u8] = b"last_committed_index";

/// RocksDB-backed consensus store.
///
/// This is the ONLY production-grade store. `JsonFileStore` is dev/test only.
///
/// ## fsync Policy
///
/// By default, `sync_writes = true` for safety. This means every `WriteBatch`
/// is fsync'd to disk before returning. For benchmarking, use `open_with_sync(path, false)`.
#[cfg(feature = "rocksdb")]
pub struct RocksDbConsensusStore {
    db: Arc<rocksdb::DB>,
    /// If true, all writes are fsynced (production default).
    sync_writes: bool,
}

#[cfg(feature = "rocksdb")]
impl RocksDbConsensusStore {
    /// Open or create a RocksDB store at the given path.
    ///
    /// Default: `sync_writes = true` (production safe).
    /// Creates all 6 column families if missing.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        Self::open_with_sync(path, true)
    }

    /// BLOCKER M: build a Column Family option set tuned for MISAKA's
    /// narwhal workload. ZSTD (level 3) replaces Snappy for a 2-3×
    /// on-disk reduction on metadata / TX-payload bytes; the 60-70%
    /// of the database that is ML-DSA-65 signatures is still near the
    /// incompressibility floor but the remainder (refs, headers, TX
    /// envelopes, index keys) benefits substantially.
    ///
    /// `bottommost_compression_type` is set to ZSTD so the biggest
    /// layer of the LSM tree — which is where old commits accumulate
    /// — gets the best compression ratio without paying the ZSTD cost
    /// on hot levels. `compression_opts` uses level 3 (default ZSTD
    /// "fast" mode); higher levels trade more CPU for marginal ratio
    /// improvement and are not worth it for this write volume.
    fn cf_opts() -> rocksdb::Options {
        let mut o = rocksdb::Options::default();
        o.set_compression_type(rocksdb::DBCompressionType::Zstd);
        o.set_bottommost_compression_type(rocksdb::DBCompressionType::Zstd);
        // rocksdb::Options::set_compression_options arguments are
        // (window_bits, level, strategy, max_dict_bytes). ZSTD accepts
        // level 1-22; 3 matches the fast mode used by most Cosmos /
        // Sui deployments. window_bits = -14 is the default ZSTD raw
        // window. strategy = 0 and max_dict_bytes = 0 leave both
        // disabled which is correct for CF data (no shared dictionary
        // across keys).
        o.set_compression_options(-14, 3, 0, 0);
        o
    }

    /// BLOCKER M: `cf_opts` plus BlobDB. Large values (≥ 512 B —
    /// every ML-DSA-65 signature is 3309 B, certs are 10-23 KB, so
    /// virtually every block / commit entry qualifies) are split out
    /// of the LSM tree into separate `.blob` files. This has three
    /// wins for the narwhal workload:
    ///
    /// 1. **Write amplification**: LSM level-0 SSTs no longer carry
    ///    multi-KB signature payloads, so the compaction pipeline
    ///    moves far fewer bytes on every level-up.
    /// 2. **Compression locality**: the blob file itself is
    ///    ZSTD-compressed as a single unit, letting ZSTD build a
    ///    per-file window over long sequences of similar-shape
    ///    sigs — better ratio than row-level compression in SSTs.
    /// 3. **GC hook**: `set_enable_blob_gc(true)` lets the eventual
    ///    pruning API (BLOCKER G) reclaim space from orphan blobs
    ///    without rewriting whole SSTs.
    ///
    /// Use this for `CF_BLOCKS`, `CF_COMMITS`, `CF_EQUIVOCATION_EVIDENCE`
    /// — the three CFs that actually hold signature-bearing values.
    /// For tx index / filter / addr CFs the values are small (< 256 B
    /// typical) and BlobDB would add overhead without benefit.
    fn cf_opts_with_blob() -> rocksdb::Options {
        let mut o = Self::cf_opts();
        o.set_enable_blob_files(true);
        // 512 B threshold: any ML-DSA signature, cert, or encoded
        // block-body envelope goes to the blob tier. Short index
        // keys and metadata rows stay in the LSM SSTs where point
        // lookups are cheapest.
        o.set_min_blob_size(512);
        // Blob files share ZSTD with SSTs for consistency. If a
        // future profiling pass shows blob files dominate the
        // working set and want faster decompression, LZ4 is a
        // drop-in alternative — but 6 GB/day → 2 GB/day is the
        // first-order objective, not latency.
        o.set_blob_compression_type(rocksdb::DBCompressionType::Zstd);
        o.set_enable_blob_gc(true);
        // The two GC knobs balance foreground work vs storage
        // reclaim rate:
        //   age_cutoff        — blobs in files whose last-modified
        //                       time is older than 25% of the
        //                       newest blob file get compacted.
        //   force_threshold   — when a blob file has > 75% garbage
        //                       bytes, it is unconditionally
        //                       rewritten during the next GC pass.
        // 0.25 / 0.75 is the RocksDB-recommended default for
        // write-heavy workloads like ours.
        o.set_blob_gc_age_cutoff(0.25);
        o.set_blob_gc_force_threshold(0.75);
        o
    }

    /// Open with explicit fsync policy.
    ///
    /// - `sync_writes = true`: every WriteBatch is fsynced (production default, safe)
    /// - `sync_writes = false`: no explicit fsync (benchmark mode, NOT crash-safe)
    pub fn open_with_sync(path: &Path, sync_writes: bool) -> Result<Self, StoreError> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        // Production tuning: WAL + fsync for crash safety
        opts.set_wal_recovery_mode(rocksdb::DBRecoveryMode::AbsoluteConsistency);
        if sync_writes {
            // Sync WAL on every write for maximum durability
            opts.set_bytes_per_sync(0); // 0 = fsync every write
        }

        // BLOCKER M (WAL tuning): the write-ahead log dominates disk
        // traffic between flushes. Two knobs tame it:
        //
        //   set_wal_compression_type(Zstd) — compresses records
        //     in-log. Same 2-3× ratio benefit as SST ZSTD applied
        //     to the hot write path, at negligible latency cost
        //     (WAL writes are small and compression is streaming).
        //
        //   set_max_total_wal_size(512 MiB) — bounds the sum of
        //     all WAL files. Beyond this cap, RocksDB force-flushes
        //     the memtables that are holding back old WAL files
        //     from deletion, so WALs never accumulate indefinitely.
        //     512 MiB matches Sui's mainnet value; small enough to
        //     fit on cheap VPS disks, big enough to batch flushes
        //     under bursty load.
        opts.set_wal_compression_type(rocksdb::DBCompressionType::Zstd);
        opts.set_max_total_wal_size(512 * 1024 * 1024);

        // BLOCKER M: all data-bearing CFs share the ZSTD-tuned options
        // via `cf_opts()`. `meta` and `last_committed` stay at the
        // RocksDB default because they are tiny (single-row CFs) and
        // compressing them would add setup cost with no saving.
        //
        // Signature-bearing CFs (`blocks`, `commits`, `equivocation`)
        // also get BlobDB via `cf_opts_with_blob()` — see that helper
        // for the rationale.
        let block_opts = Self::cf_opts_with_blob();
        let commit_opts = Self::cf_opts_with_blob();
        let meta_opts = rocksdb::Options::default();
        let last_committed_opts = rocksdb::Options::default();
        let equivocation_opts = Self::cf_opts_with_blob();
        let tx_filter_opts = Self::cf_opts();
        let tx_index_opts = Self::cf_opts();
        let addr_index_opts = {
            let mut o = Self::cf_opts();
            o.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(64));
            o
        };
        // Phase 3a A.1: `votes` CF tuning.
        // - compression = None: payload is small (≤ a few hundred bytes
        //   per cert), already high-entropy (hash + bitvec), ZSTD cost
        //   dominates gain.
        // - BlobDB with min_blob_size = 1024: any cert whose serialised
        //   (VoteCommitment, Option<AggregationProof>) exceeds 1 KiB is
        //   redirected to a `*.blob` file. Future AggregationProof
        //   payloads (real ZK proofs) will easily exceed this. Below
        //   1 KiB stays in the LSM for point-read speed.
        let votes_opts = {
            let mut o = rocksdb::Options::default();
            o.set_compression_type(rocksdb::DBCompressionType::None);
            o.set_enable_blob_files(true);
            o.set_min_blob_size(1024);
            o
        };
        // Phase 3a A.5: `cert_mapping` CF tuning. 32-byte key + 32-byte
        // value per entry — compression off (poor ratio on hashes), no
        // BlobDB (values never exceed the LSM threshold).
        let cert_mapping_opts = {
            let mut o = rocksdb::Options::default();
            o.set_compression_type(rocksdb::DBCompressionType::None);
            o
        };
        // Phase 3a Part C: `round_config_audit` CF tuning. Small
        // JSON payloads (~200 bytes) with repeated field names —
        // Snappy compresses well and is cheap.
        let round_config_audit_opts = {
            let mut o = rocksdb::Options::default();
            o.set_compression_type(rocksdb::DBCompressionType::Snappy);
            o
        };

        let cfs = vec![
            rocksdb::ColumnFamilyDescriptor::new(CF_BLOCKS, block_opts),
            rocksdb::ColumnFamilyDescriptor::new(CF_COMMITS, commit_opts),
            rocksdb::ColumnFamilyDescriptor::new(CF_META, meta_opts),
            rocksdb::ColumnFamilyDescriptor::new(CF_LAST_COMMITTED, last_committed_opts),
            rocksdb::ColumnFamilyDescriptor::new(CF_EQUIVOCATION_EVIDENCE, equivocation_opts),
            rocksdb::ColumnFamilyDescriptor::new(CF_COMMITTED_TX_FILTER, tx_filter_opts),
            rocksdb::ColumnFamilyDescriptor::new(CF_TX_INDEX, tx_index_opts),
            rocksdb::ColumnFamilyDescriptor::new(CF_ADDR_INDEX, addr_index_opts),
            rocksdb::ColumnFamilyDescriptor::new(CF_VOTES, votes_opts),
            rocksdb::ColumnFamilyDescriptor::new(CF_CERT_MAPPING, cert_mapping_opts),
            rocksdb::ColumnFamilyDescriptor::new(CF_ROUND_CONFIG_AUDIT, round_config_audit_opts),
        ];

        let db = rocksdb::DB::open_cf_descriptors(&opts, path, cfs)
            .map_err(|e| StoreError::Corrupted(format!("RocksDB open failed: {}", e)))?;

        let store = Self {
            db: Arc::new(db),
            sync_writes,
        };

        // BLOCKER G: schema-version gate. Runs BEFORE any read / write
        // against the opened DB. A version mismatch is a hard refusal;
        // a fresh or pre-versioning DB is upgraded in place.
        store.ensure_schema_version()?;

        Ok(store)
    }

    /// BLOCKER G: enforce [`KEY_SCHEMA_VERSION`] on open.
    ///
    /// See the [`KEY_SCHEMA_VERSION`] doc-comment for the branch
    /// matrix. Returns [`StoreError::SchemaVersionMismatch`] on a
    /// present-but-wrong version; all other outcomes Ok(()).
    fn ensure_schema_version(&self) -> Result<(), StoreError> {
        let cf_meta = self.cf_meta()?;
        let raw = self.db.get_cf(cf_meta, KEY_SCHEMA_VERSION).map_err(|e| {
            StoreError::Corrupted(format!("RocksDB get schema_version failed: {}", e))
        })?;

        match raw {
            Some(bytes) => {
                if bytes.len() != 4 {
                    return Err(StoreError::Corrupted(format!(
                        "schema_version: unexpected value length {}",
                        bytes.len()
                    )));
                }
                let got = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                if got != CURRENT_SCHEMA_VERSION {
                    return Err(StoreError::SchemaVersionMismatch {
                        got,
                        expected: CURRENT_SCHEMA_VERSION,
                    });
                }
                Ok(())
            }
            None => {
                // Absent → fresh or pre-versioning. Either way, stamp
                // `CURRENT_SCHEMA_VERSION` so subsequent opens take
                // the fast-path above. We do NOT distinguish fresh
                // vs legacy here because v0 and v1 are on-disk
                // identical — only the meta key is new.
                let value = CURRENT_SCHEMA_VERSION.to_le_bytes();
                self.db
                    .put_cf(cf_meta, KEY_SCHEMA_VERSION, value)
                    .map_err(|e| {
                        StoreError::Corrupted(format!("RocksDB put schema_version failed: {}", e))
                    })?;
                Ok(())
            }
        }
    }

    /// Read the persisted schema version. Returns `Ok(None)` if the
    /// key has not been written yet — useful for pre-`ensure_schema_version`
    /// tests only. Production callers should never see None because
    /// `open` always stamps a version.
    pub fn read_schema_version(&self) -> Result<Option<u32>, StoreError> {
        let cf_meta = self.cf_meta()?;
        let raw = self.db.get_cf(cf_meta, KEY_SCHEMA_VERSION).map_err(|e| {
            StoreError::Corrupted(format!("RocksDB get schema_version failed: {}", e))
        })?;
        Ok(raw.and_then(|v| {
            if v.len() == 4 {
                Some(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
            } else {
                None
            }
        }))
    }

    // ─── CF handle accessors ─────────────────────────────────

    fn cf_blocks(&self) -> Result<&rocksdb::ColumnFamily, StoreError> {
        self.db.cf_handle(CF_BLOCKS).ok_or_else(|| {
            StoreError::Corrupted(format!(
                "column family '{}' missing — DB may be corrupted",
                CF_BLOCKS
            ))
        })
    }

    fn cf_commits(&self) -> Result<&rocksdb::ColumnFamily, StoreError> {
        self.db.cf_handle(CF_COMMITS).ok_or_else(|| {
            StoreError::Corrupted(format!(
                "column family '{}' missing — DB may be corrupted",
                CF_COMMITS
            ))
        })
    }

    fn cf_meta(&self) -> Result<&rocksdb::ColumnFamily, StoreError> {
        self.db.cf_handle(CF_META).ok_or_else(|| {
            StoreError::Corrupted(format!(
                "column family '{}' missing — DB may be corrupted",
                CF_META
            ))
        })
    }

    fn cf_last_committed(&self) -> Result<&rocksdb::ColumnFamily, StoreError> {
        self.db.cf_handle(CF_LAST_COMMITTED).ok_or_else(|| {
            StoreError::Corrupted(format!(
                "column family '{}' missing — DB may be corrupted",
                CF_LAST_COMMITTED
            ))
        })
    }

    fn cf_equivocation_evidence(&self) -> Result<&rocksdb::ColumnFamily, StoreError> {
        self.db.cf_handle(CF_EQUIVOCATION_EVIDENCE).ok_or_else(|| {
            StoreError::Corrupted(format!(
                "column family '{}' missing — DB may be corrupted",
                CF_EQUIVOCATION_EVIDENCE
            ))
        })
    }

    fn cf_committed_tx_filter(&self) -> Result<&rocksdb::ColumnFamily, StoreError> {
        self.db.cf_handle(CF_COMMITTED_TX_FILTER).ok_or_else(|| {
            StoreError::Corrupted(format!(
                "column family '{}' missing — DB may be corrupted",
                CF_COMMITTED_TX_FILTER
            ))
        })
    }

    fn cf_tx_index(&self) -> Result<&rocksdb::ColumnFamily, StoreError> {
        self.db.cf_handle(CF_TX_INDEX).ok_or_else(|| {
            StoreError::Corrupted(format!(
                "column family '{}' missing — DB may be corrupted",
                CF_TX_INDEX
            ))
        })
    }

    fn cf_addr_index(&self) -> Result<&rocksdb::ColumnFamily, StoreError> {
        self.db.cf_handle(CF_ADDR_INDEX).ok_or_else(|| {
            StoreError::Corrupted(format!(
                "column family '{}' missing — DB may be corrupted",
                CF_ADDR_INDEX
            ))
        })
    }

    fn cf_votes(&self) -> Result<&rocksdb::ColumnFamily, StoreError> {
        self.db.cf_handle(CF_VOTES).ok_or_else(|| {
            StoreError::Corrupted(format!(
                "column family '{}' missing — DB may be corrupted",
                CF_VOTES
            ))
        })
    }

    fn cf_cert_mapping(&self) -> Result<&rocksdb::ColumnFamily, StoreError> {
        self.db.cf_handle(CF_CERT_MAPPING).ok_or_else(|| {
            StoreError::Corrupted(format!(
                "column family '{}' missing — DB may be corrupted",
                CF_CERT_MAPPING
            ))
        })
    }

    fn cf_round_config_audit(&self) -> Result<&rocksdb::ColumnFamily, StoreError> {
        self.db.cf_handle(CF_ROUND_CONFIG_AUDIT).ok_or_else(|| {
            StoreError::Corrupted(format!(
                "column family '{}' missing — DB may be corrupted",
                CF_ROUND_CONFIG_AUDIT
            ))
        })
    }

    // ─── TX index persistence ─────────────────────────────────

    /// Store a committed transaction detail (JSON bytes).
    /// Expose the underlying `Arc<DB>` handle.
    ///
    /// Added for Phase 2 Path X R1 step 2: the node's Kaspa-aligned
    /// `startup_integrity` persistence writes the committed chain tip
    /// under `StorePrefixes::VirtualState` inside this same RocksDB
    /// instance. Sharing the single DB keeps the schema-version marker,
    /// the tip snapshot, and the Narwhal consensus state in one
    /// file for crash-atomicity and backup simplicity.
    ///
    /// Callers outside the consensus-store module MUST only write to
    /// `StorePrefixes::*` keyspaces they own — touching Narwhal CFs
    /// through this handle bypasses all the invariants `RocksDbConsensusStore`
    /// enforces.
    pub fn raw_db(&self) -> &Arc<rocksdb::DB> {
        &self.db
    }

    pub fn put_tx_detail(&self, tx_hash: &[u8; 32], detail: &[u8]) -> Result<(), StoreError> {
        self.db
            .put_cf(self.cf_tx_index()?, tx_hash, detail)
            .map_err(|e| StoreError::Corrupted(format!("RocksDB put tx_index failed: {}", e)))
    }

    /// Retrieve a committed transaction detail by hash.
    pub fn get_tx_detail(&self, tx_hash: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError> {
        self.db
            .get_cf(self.cf_tx_index()?, tx_hash)
            .map_err(|e| StoreError::Corrupted(format!("RocksDB get tx_index failed: {}", e)))
    }

    // ─── Phase 3a A.2 / A.3: Certificate V2 vote persistence ─────

    /// Phase 3a A.2 — persist a [`CertificateV2`]'s vote commitment +
    /// optional aggregation proof under the certificate's digest.
    ///
    /// Key: `cert_digest.0` (32 bytes — the return value of
    /// `CertificateV2::digest()`).
    /// Value: serde-JSON of `(VoteCommitment, Option<AggregationProof>)`.
    ///
    /// Stored in the `votes` CF tuned with compression off + BlobDB
    /// (min_blob_size = 1024) so large aggregation proofs end up in
    /// `*.blob` files rather than the LSM. See
    /// `columns::NarwhalCf::Votes` rustdoc.
    ///
    /// **Note**: this method does NOT enforce the Phase 3a invariant
    /// that `aggregation_slot` must be `None`. The verify path owns
    /// that check. The store intentionally accepts any shape so that
    /// a future Phase 3b verify-off migration tool can stage proofs
    /// before enabling them in consensus.
    pub fn put_cert_v2_votes(
        &self,
        cert_digest: &[u8; 32],
        vote_commitment: &crate::narwhal_finality::cert_v2::VoteCommitment,
        aggregation_slot: &Option<crate::narwhal_finality::cert_v2::AggregationProof>,
    ) -> Result<(), StoreError> {
        let payload = (vote_commitment, aggregation_slot);
        let bytes = serde_json::to_vec(&payload)?;
        self.db
            .put_cf(self.cf_votes()?, cert_digest, bytes)
            .map_err(|e| StoreError::Corrupted(format!("RocksDB put votes failed: {}", e)))
    }

    /// Phase 3a A.3 — read back a persisted vote commitment + optional
    /// aggregation proof for a cert.
    ///
    /// Returns `Ok(None)` when no record exists (fresh cert or
    /// pre-A.2-write-path DB). Returns `Err(StoreError::Corrupted)` on
    /// underlying RocksDB failure, and propagates serde errors through
    /// the pre-existing `From<serde_json::Error> for StoreError` path.
    pub fn get_cert_v2_votes(
        &self,
        cert_digest: &[u8; 32],
    ) -> Result<
        Option<(
            crate::narwhal_finality::cert_v2::VoteCommitment,
            Option<crate::narwhal_finality::cert_v2::AggregationProof>,
        )>,
        StoreError,
    > {
        match self.db.get_cf(self.cf_votes()?, cert_digest) {
            Ok(None) => Ok(None),
            Ok(Some(bytes)) => {
                let (vc, agg) = serde_json::from_slice(&bytes)?;
                Ok(Some((vc, agg)))
            }
            Err(e) => Err(StoreError::Corrupted(format!(
                "RocksDB get votes failed: {}",
                e
            ))),
        }
    }

    // ─── Phase 3a A.5: Cert v1 ↔ v2 digest mapping ───────────────

    /// Phase 3a A.5 — record that a v1 cert with digest `v1_digest`
    /// corresponds to a v2 cert with digest `v2_digest`. Written
    /// during cross-over epoch processing; consumers can resolve
    /// v1-referenced certs to their v2 shape via
    /// [`get_cert_mapping_v1_to_v2`](Self::get_cert_mapping_v1_to_v2).
    ///
    /// Idempotent: re-writing with the same digests is a no-op.
    /// Overwriting with a different `v2_digest` is allowed but
    /// callers SHOULD NOT do it — the mapping is intended to be
    /// 1:1 within one cert's lifetime.
    pub fn put_cert_mapping(
        &self,
        v1_digest: &[u8; 32],
        v2_digest: &[u8; 32],
    ) -> Result<(), StoreError> {
        self.db
            .put_cf(self.cf_cert_mapping()?, v1_digest, v2_digest)
            .map_err(|e| StoreError::Corrupted(format!("RocksDB put cert_mapping failed: {}", e)))
    }

    /// Phase 3a A.5 — resolve a v1 cert digest to its v2 counterpart.
    ///
    /// Returns `Ok(None)` on miss (either no mapping written or the
    /// cert pre-dates the cross-over). Returns
    /// `Err(StoreError::Corrupted)` if a record exists but its
    /// length is not 32 bytes (DB tampering).
    pub fn get_cert_mapping_v1_to_v2(
        &self,
        v1_digest: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, StoreError> {
        match self.db.get_cf(self.cf_cert_mapping()?, v1_digest) {
            Ok(None) => Ok(None),
            Ok(Some(bytes)) => {
                if bytes.len() != 32 {
                    return Err(StoreError::Corrupted(format!(
                        "cert_mapping value length {} != 32",
                        bytes.len()
                    )));
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                Ok(Some(out))
            }
            Err(e) => Err(StoreError::Corrupted(format!(
                "RocksDB get cert_mapping failed: {}",
                e
            ))),
        }
    }

    // ─── Phase 3a Part C: round-config audit log ─────────────────

    /// Phase 3a Part C — append an audit entry for an
    /// epoch-boundary `RoundSchedulerConfig` adjustment.
    ///
    /// Key: `entry.applied_from_epoch` as u64 big-endian so the
    /// natural RocksDB iterator order matches chronological order.
    /// Value: serde-JSON of the entry (~200 bytes, Snappy-compressed
    /// at the CF level).
    ///
    /// Idempotent on identical re-writes. Overwrite-with-different
    /// is accepted (caller SHOULD NOT do it — the epoch boundary
    /// is a one-shot adjustment).
    pub fn put_round_config_audit(
        &self,
        entry: &crate::narwhal_dag::round_config_adjust::RoundConfigAuditEntry,
    ) -> Result<(), StoreError> {
        let key = entry.applied_from_epoch.to_be_bytes();
        let bytes = serde_json::to_vec(entry)?;
        self.db
            .put_cf(self.cf_round_config_audit()?, key, bytes)
            .map_err(|e| {
                StoreError::Corrupted(format!("RocksDB put round_config_audit failed: {}", e))
            })
    }

    /// Phase 3a Part C — read back the audit entry for a specific
    /// epoch. Returns `Ok(None)` when no entry is recorded for
    /// that epoch; propagates serde errors; wraps RocksDB failures
    /// as `StoreError::Corrupted`.
    pub fn get_round_config_audit(
        &self,
        applied_from_epoch: u64,
    ) -> Result<Option<crate::narwhal_dag::round_config_adjust::RoundConfigAuditEntry>, StoreError>
    {
        let key = applied_from_epoch.to_be_bytes();
        match self.db.get_cf(self.cf_round_config_audit()?, key) {
            Ok(None) => Ok(None),
            Ok(Some(bytes)) => {
                let entry = serde_json::from_slice(&bytes)?;
                Ok(Some(entry))
            }
            Err(e) => Err(StoreError::Corrupted(format!(
                "RocksDB get round_config_audit failed: {}",
                e
            ))),
        }
    }

    /// Phase 3a Part C — list every audit entry in epoch order.
    /// Intended for ops / dashboard use; for a running node the
    /// per-epoch `get_round_config_audit` is enough. Iteration is
    /// cheap because the CF is append-once-per-epoch.
    pub fn list_round_config_audit(
        &self,
    ) -> Result<Vec<crate::narwhal_dag::round_config_adjust::RoundConfigAuditEntry>, StoreError>
    {
        let cf = self.cf_round_config_audit()?;
        let mut out = Vec::new();
        for item in self.db.iterator_cf(cf, rocksdb::IteratorMode::Start) {
            let (_k, v) = item.map_err(|e| {
                StoreError::Corrupted(format!("round_config_audit iter failed: {}", e))
            })?;
            let entry: crate::narwhal_dag::round_config_adjust::RoundConfigAuditEntry =
                serde_json::from_slice(&v)?;
            out.push(entry);
        }
        Ok(out)
    }

    /// Store an address index entry. Key format: `{address_hex}:{height_be8}:{tx_hash_hex}`.
    pub fn put_addr_entry(&self, key: &[u8], entry: &[u8]) -> Result<(), StoreError> {
        self.db
            .put_cf(self.cf_addr_index()?, key, entry)
            .map_err(|e| StoreError::Corrupted(format!("RocksDB put addr_index failed: {}", e)))
    }

    /// Retrieve all address index entries for a given address (prefix scan).
    pub fn get_addr_entries(&self, address_hex: &str) -> Result<Vec<Vec<u8>>, StoreError> {
        let cf = self.cf_addr_index()?;
        let prefix = address_hex.as_bytes();
        let mut results = Vec::new();
        let iter = self.db.prefix_iterator_cf(cf, prefix);
        for item in iter {
            match item {
                Ok((k, v)) => {
                    if !k.starts_with(prefix) {
                        break;
                    }
                    results.push(v.to_vec());
                }
                Err(e) => {
                    return Err(StoreError::Corrupted(format!(
                        "RocksDB addr_index iterator failed: {}",
                        e
                    )));
                }
            }
        }
        Ok(results)
    }

    // ─── BLOCKER H: atomic commit-boundary index batch ───────
    //
    // The commit loop (main.rs) previously issued `put_tx_detail` /
    // `put_addr_entry` per-transaction. Because each is a separate
    // `db.put_cf` call, a node crash mid-loop could leave some
    // transactions indexed and others not — an explorer would
    // present an inconsistent view of a committed sub-dag until the
    // next run "filled in" the missing entries by chance.
    //
    // `write_commit_indexes` packs every tx_index / addr_index
    // `put_cf` plus the `last_committed_index` meta-key update into
    // ONE `rocksdb::WriteBatch`. RocksDB guarantees an atomic write
    // across all CFs in a single handle, so either every entry from
    // this commit lands or none of them do. On recovery,
    // `get_last_committed_index` tells the node which commit was
    // the last fully-persisted one.
    //
    // Out of scope for this batch: UTXO snapshot (separate JSON
    // artifact, atomic-via-rename in its own right) and DAG
    // `narwhal_blocks` / `narwhal_commits` (written by the consensus
    // runtime on a different cadence). A cross-artifact transaction
    // would require merging those stores into a single RocksDB
    // handle; that is a dedicated follow-up.

    /// Atomically persist a commit's tx_index + addr_index entries
    /// together with the `last_committed_index` meta marker.
    ///
    /// Either every entry lands or none does. The write honours the
    /// store's `sync_writes` policy — when enabled (production
    /// default) the WAL is fsynced before returning.
    pub fn write_commit_indexes(
        &self,
        commit_index: u64,
        tx_details: &[([u8; 32], Vec<u8>)],
        addr_entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), StoreError> {
        let cf_tx = self.cf_tx_index()?;
        let cf_addr = self.cf_addr_index()?;
        let cf_meta = self.cf_meta()?;

        let mut batch = rocksdb::WriteBatch::default();
        for (hash, detail) in tx_details {
            batch.put_cf(cf_tx, hash, detail);
        }
        for (key, entry) in addr_entries {
            batch.put_cf(cf_addr, key, entry);
        }
        batch.put_cf(
            cf_meta,
            KEY_LAST_COMMITTED_INDEX,
            commit_index.to_le_bytes(),
        );

        let mut opts = rocksdb::WriteOptions::default();
        if self.sync_writes {
            opts.set_sync(true);
        }
        self.db.write_opt(batch, &opts).map_err(|e| {
            StoreError::Corrupted(format!(
                "RocksDB write_commit_indexes atomic batch failed: {}",
                e
            ))
        })?;
        Ok(())
    }

    /// Read the `last_committed_index` marker written by the most
    /// recent [`write_commit_indexes`]. Returns `Ok(None)` on a DB
    /// that has never processed a commit (fresh install or a
    /// pre-BLOCKER-H v0.8.8 testnet DB).
    pub fn get_last_committed_index(&self) -> Result<Option<u64>, StoreError> {
        let raw = self
            .db
            .get_cf(self.cf_meta()?, KEY_LAST_COMMITTED_INDEX)
            .map_err(|e| {
                StoreError::Corrupted(format!("RocksDB get last_committed_index failed: {}", e))
            })?;
        Ok(raw.and_then(|v| {
            if v.len() == 8 {
                Some(u64::from_le_bytes([
                    v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7],
                ]))
            } else {
                None
            }
        }))
    }

    // ─── Committed TX filter persistence ─────────────────────

    /// Save a committed TX filter snapshot.
    pub fn save_tx_filter_snapshot(&self, data: &[u8]) -> Result<(), StoreError> {
        self.db
            .put_cf(self.cf_committed_tx_filter()?, KEY_TX_FILTER_SNAPSHOT, data)
            .map_err(|e| StoreError::Corrupted(format!("RocksDB put tx filter failed: {}", e)))?;
        Ok(())
    }

    /// Load the most recent committed TX filter snapshot.
    pub fn load_tx_filter_snapshot(&self) -> Result<Option<Vec<u8>>, StoreError> {
        match self
            .db
            .get_cf(self.cf_committed_tx_filter()?, KEY_TX_FILTER_SNAPSHOT)
        {
            Ok(v) => Ok(v),
            Err(e) => Err(StoreError::Corrupted(format!(
                "RocksDB get tx filter failed: {}",
                e
            ))),
        }
    }

    // ─── Equivocation evidence ───────────────────────────────

    /// Store equivocation evidence for a (round, author) slot.
    ///
    /// Evidence is append-only: once stored, it is never overwritten.
    /// Used for slashing proposals and post-mortem analysis.
    pub fn store_equivocation_evidence(
        &self,
        round: Round,
        author: AuthorityIndex,
        evidence: &[u8],
    ) -> Result<(), StoreError> {
        let key = equivocation_key(round, author);
        self.db
            .put_cf(self.cf_equivocation_evidence()?, key, evidence)
            .map_err(|e| {
                StoreError::Corrupted(format!("RocksDB put equivocation failed: {}", e))
            })?;
        Ok(())
    }

    /// Read equivocation evidence for a (round, author) slot.
    pub fn read_equivocation_evidence(
        &self,
        round: Round,
        author: AuthorityIndex,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = equivocation_key(round, author);
        match self.db.get_cf(self.cf_equivocation_evidence()?, key) {
            Ok(v) => Ok(v),
            Err(e) => Err(StoreError::Corrupted(format!(
                "RocksDB get equivocation failed: {}",
                e
            ))),
        }
    }

    /// Read all equivocation evidence.
    pub fn read_all_equivocation_evidence(
        &self,
    ) -> Result<Vec<(Round, AuthorityIndex, Vec<u8>)>, StoreError> {
        let mut results = Vec::new();
        let iter = self.db.iterator_cf(
            self.cf_equivocation_evidence()?,
            rocksdb::IteratorMode::Start,
        );
        for item in iter {
            let (key, value) =
                item.map_err(|e| StoreError::Corrupted(format!("RocksDB iterator error: {}", e)))?;
            if key.len() == 8 {
                let round = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);
                let author = u32::from_be_bytes([key[4], key[5], key[6], key[7]]);
                results.push((round, author, value.to_vec()));
            }
        }
        Ok(results)
    }

    // ─── GC round persistence ────────────────────────────────

    /// Persist the current GC round to meta.
    pub fn set_gc_round(&self, round: Round) -> Result<(), StoreError> {
        let value = round.to_le_bytes();
        self.db
            .put_cf(self.cf_meta()?, KEY_GC_ROUND, value)
            .map_err(|e| StoreError::Corrupted(format!("RocksDB put gc_round failed: {}", e)))?;
        Ok(())
    }

    /// Read the persisted GC round.
    pub fn get_gc_round(&self) -> Result<Option<Round>, StoreError> {
        match self.db.get_cf(self.cf_meta()?, KEY_GC_ROUND) {
            Ok(Some(value)) if value.len() == 4 => Ok(Some(u32::from_le_bytes([
                value[0], value[1], value[2], value[3],
            ]))),
            Ok(Some(_)) => Err(StoreError::Corrupted(
                "gc_round: unexpected value length".into(),
            )),
            Ok(None) => Ok(None),
            Err(e) => Err(StoreError::Corrupted(format!(
                "RocksDB get gc_round failed: {}",
                e
            ))),
        }
    }
}

/// Encode (round, author) as a big-endian 8-byte key for sorted iteration.
#[cfg(feature = "rocksdb")]
fn equivocation_key(round: Round, author: AuthorityIndex) -> [u8; 8] {
    let mut key = [0u8; 8];
    key[..4].copy_from_slice(&round.to_be_bytes());
    key[4..].copy_from_slice(&author.to_be_bytes());
    key
}

#[cfg(feature = "rocksdb")]
impl ConsensusStore for RocksDbConsensusStore {
    fn write_batch(&self, batch: &DagWriteBatch) -> Result<(), StoreError> {
        let mut wb = rocksdb::WriteBatch::default();

        for block in &batch.blocks {
            let key = block.digest().0;
            let value = serde_json::to_vec(block.inner()).map_err(StoreError::Serde)?;
            wb.put_cf(self.cf_blocks()?, key, value);
        }

        for commit in &batch.commits {
            let key = commit.index.to_le_bytes();
            let value = serde_json::to_vec(commit).map_err(StoreError::Serde)?;
            wb.put_cf(self.cf_commits()?, key, value);
        }

        if let Some(rounds) = &batch.last_committed_rounds {
            // Write to both CF_META (legacy) and CF_LAST_COMMITTED (hot-path)
            let value = serde_json::to_vec(rounds).map_err(StoreError::Serde)?;
            wb.put_cf(self.cf_meta()?, KEY_LAST_COMMITTED_ROUNDS, &value);
            wb.put_cf(self.cf_last_committed()?, KEY_LAST_COMMITTED_ROUNDS, &value);
        }

        // Atomic write: all CF mutations in a single WriteBatch
        if self.sync_writes {
            let mut write_opts = rocksdb::WriteOptions::default();
            write_opts.set_sync(true);
            self.db
                .write_opt(wb, &write_opts)
                .map_err(|e| StoreError::Corrupted(format!("RocksDB write failed: {}", e)))?;
        } else {
            self.db
                .write(wb)
                .map_err(|e| StoreError::Corrupted(format!("RocksDB write failed: {}", e)))?;
        }

        Ok(())
    }

    fn read_all_blocks(&self) -> Result<Vec<(BlockRef, Block)>, StoreError> {
        let mut blocks = Vec::new();
        let iter = self
            .db
            .iterator_cf(self.cf_blocks()?, rocksdb::IteratorMode::Start);

        for item in iter {
            let (_, value) =
                item.map_err(|e| StoreError::Corrupted(format!("RocksDB iterator error: {}", e)))?;
            let block: Block = serde_json::from_slice(&value).map_err(StoreError::Serde)?;
            let block_ref = block.reference();
            blocks.push((block_ref, block));
        }

        Ok(blocks)
    }

    fn read_all_commits(&self) -> Result<Vec<CommittedSubDag>, StoreError> {
        let mut commits = Vec::new();
        let iter = self
            .db
            .iterator_cf(self.cf_commits()?, rocksdb::IteratorMode::Start);

        for item in iter {
            let (_, value) =
                item.map_err(|e| StoreError::Corrupted(format!("RocksDB iterator error: {}", e)))?;
            let commit: CommittedSubDag =
                serde_json::from_slice(&value).map_err(StoreError::Serde)?;
            commits.push(commit);
        }

        // Sort by index (LE key encoding means iterator order matches)
        commits.sort_by_key(|c| c.index);
        Ok(commits)
    }

    fn read_last_committed_rounds(&self) -> Result<Option<Vec<Round>>, StoreError> {
        // Prefer CF_LAST_COMMITTED (hot-path), fall back to CF_META
        let result = self
            .db
            .get_cf(self.cf_last_committed()?, KEY_LAST_COMMITTED_ROUNDS);
        match result {
            Ok(Some(value)) => {
                let rounds: Vec<Round> =
                    serde_json::from_slice(&value).map_err(StoreError::Serde)?;
                Ok(Some(rounds))
            }
            Ok(None) => {
                // Fall back to legacy CF_META
                match self.db.get_cf(self.cf_meta()?, KEY_LAST_COMMITTED_ROUNDS) {
                    Ok(Some(value)) => {
                        let rounds: Vec<Round> =
                            serde_json::from_slice(&value).map_err(StoreError::Serde)?;
                        Ok(Some(rounds))
                    }
                    Ok(None) => Ok(None),
                    Err(e) => Err(StoreError::Corrupted(format!("RocksDB get failed: {}", e))),
                }
            }
            Err(e) => Err(StoreError::Corrupted(format!("RocksDB get failed: {}", e))),
        }
    }

    fn sync_wal(&self) -> Result<(), StoreError> {
        self.db
            .flush()
            .map_err(|e| StoreError::Corrupted(format!("RocksDB flush failed: {}", e)))?;
        Ok(())
    }

    fn gc_below_round(&self, round: Round) -> Result<u64, StoreError> {
        let mut deleted = 0u64;
        let mut to_delete = Vec::new();

        let iter = self
            .db
            .iterator_cf(self.cf_blocks()?, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, value) =
                item.map_err(|e| StoreError::Corrupted(format!("RocksDB iterator error: {}", e)))?;
            match serde_json::from_slice::<Block>(&value) {
                Ok(block) if block.round < round => {
                    to_delete.push(key.to_vec());
                }
                Ok(_) => {} // block.round >= round, keep
                Err(e) => {
                    // R7 L-9: Log and delete corrupt entries instead of silently skipping
                    tracing::warn!(
                        "gc_below_round: corrupt block entry (key={} bytes), deleting: {}",
                        key.len(),
                        e
                    );
                    to_delete.push(key.to_vec());
                }
            }
        }

        // Use WriteBatch for atomic GC
        if !to_delete.is_empty() {
            let mut wb = rocksdb::WriteBatch::default();
            for key in &to_delete {
                wb.delete_cf(self.cf_blocks()?, key);
            }
            self.db
                .write(wb)
                .map_err(|e| StoreError::Corrupted(format!("RocksDB gc delete failed: {}", e)))?;
            deleted = to_delete.len() as u64;
        }

        // Persist GC watermark
        self.set_gc_round(round)?;

        Ok(deleted)
    }

    // ─── BLOCKER G: point-get + counts (efficient overrides) ────────
    //
    // The default trait impls fall back to `read_all_blocks()` which
    // scans the entire CF. RocksDB supports O(log n) `get_cf` and
    // cheap iterator-count so we override with CF-direct accessors.

    fn get_block(&self, digest: &BlockDigest) -> Result<Option<Block>, StoreError> {
        let raw = self
            .db
            .get_cf(self.cf_blocks()?, digest.0.as_slice())
            .map_err(|e| StoreError::Corrupted(format!("RocksDB get block failed: {}", e)))?;
        match raw {
            None => Ok(None),
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        }
    }

    fn block_count(&self) -> Result<u64, StoreError> {
        // There is no constant-time `count` in RocksDB; iterate keys
        // only (values skipped, no deserialization cost). Good enough
        // for operator metrics; if a future hot-path needs sub-ms
        // counts, cache this in `narwhal_meta` on every write batch.
        let mut count: u64 = 0;
        let iter = self
            .db
            .iterator_cf(self.cf_blocks()?, rocksdb::IteratorMode::Start);
        for item in iter {
            item.map_err(|e| StoreError::Corrupted(format!("RocksDB block_count iter: {}", e)))?;
            count += 1;
        }
        Ok(count)
    }

    fn commit_count(&self) -> Result<u64, StoreError> {
        let mut count: u64 = 0;
        let iter = self
            .db
            .iterator_cf(self.cf_commits()?, rocksdb::IteratorMode::Start);
        for item in iter {
            item.map_err(|e| StoreError::Corrupted(format!("RocksDB commit_count iter: {}", e)))?;
            count += 1;
        }
        Ok(count)
    }
}

// ─── Tests ────────────────────────────────────────────────────────

#[cfg(all(test, feature = "rocksdb"))]
mod tests {
    use super::*;
    use crate::narwhal_finality::cert_v2::{
        AggregationProof, CommitmentScheme, ProofSystem, VoteCommitment,
    };
    use tempfile::TempDir;

    fn open_tmp() -> (TempDir, RocksDbConsensusStore) {
        let dir = TempDir::new().expect("tmpdir");
        // sync_writes=false: test-only, OOM/IO-cheap.
        let store =
            RocksDbConsensusStore::open_with_sync(dir.path(), false).expect("open consensus store");
        (dir, store)
    }

    fn sample_vc() -> VoteCommitment {
        let ids = [[0x01u8; 32], [0x02u8; 32], [0x03u8; 32]];
        VoteCommitment::with_blake3(&ids, vec![0b0000_0111])
    }

    fn sample_agg() -> AggregationProof {
        AggregationProof {
            system: ProofSystem::ReservedV1,
            proof: vec![0xAA, 0xBB, 0xCC],
            public_inputs: vec![0xDE, 0xAD],
            generated_at: 1_700_000_000_000,
        }
    }

    // ── A.1: CF registration ──────────────────────────────────────

    #[test]
    fn a1_votes_cf_is_registered_on_open() {
        // Opening the store with the new Votes CF listed in the
        // descriptor slice must succeed. If the ALL list and the cf
        // descriptors drift, this test panics.
        let (_d, store) = open_tmp();
        // Can get a handle.
        store.cf_votes().expect("votes CF accessible");
    }

    // ── A.2/A.3: write / read roundtrip ──────────────────────────

    #[test]
    fn a2_a3_put_then_get_roundtrips_without_agg() {
        let (_d, store) = open_tmp();
        let digest = [0xA0u8; 32];
        let vc = sample_vc();
        store.put_cert_v2_votes(&digest, &vc, &None).expect("put");
        let got = store
            .get_cert_v2_votes(&digest)
            .expect("get")
            .expect("some");
        assert_eq!(got.0, vc);
        assert!(got.1.is_none());
    }

    #[test]
    fn a2_a3_put_then_get_roundtrips_with_agg() {
        let (_d, store) = open_tmp();
        let digest = [0xA1u8; 32];
        let vc = sample_vc();
        let agg = sample_agg();
        store
            .put_cert_v2_votes(&digest, &vc, &Some(agg.clone()))
            .expect("put");
        let got = store
            .get_cert_v2_votes(&digest)
            .expect("get")
            .expect("some");
        assert_eq!(got.0, vc);
        assert_eq!(got.1, Some(agg));
    }

    // ── A.3: fresh read returns None ─────────────────────────────

    #[test]
    fn a3_get_on_missing_key_returns_none() {
        let (_d, store) = open_tmp();
        let got = store
            .get_cert_v2_votes(&[0xFFu8; 32])
            .expect("get returns Ok(None) on missing key");
        assert!(got.is_none());
    }

    // ── A.2: overwrite replaces previous value ───────────────────

    #[test]
    fn a2_put_overwrites_previous_value() {
        let (_d, store) = open_tmp();
        let digest = [0xA2u8; 32];
        let vc1 = sample_vc();
        let vc2 = VoteCommitment::with_blake3(&[[0x09u8; 32]], vec![0b1]);
        store
            .put_cert_v2_votes(&digest, &vc1, &None)
            .expect("put 1");
        store
            .put_cert_v2_votes(&digest, &vc2, &None)
            .expect("put 2");
        let got = store
            .get_cert_v2_votes(&digest)
            .expect("get")
            .expect("some");
        assert_eq!(got.0, vc2);
    }

    // ── A.1: independence from other CFs ─────────────────────────

    #[test]
    fn a1_write_to_votes_does_not_affect_tx_index() {
        let (_d, store) = open_tmp();
        let hash = [0xB0u8; 32];
        // Write to tx_index (existing CF).
        store.put_tx_detail(&hash, b"original").expect("put tx");
        // Write to votes under the same key bytes.
        store
            .put_cert_v2_votes(&hash, &sample_vc(), &None)
            .expect("put votes");
        // Original tx_index value is preserved.
        let got = store.get_tx_detail(&hash).expect("get tx").expect("some");
        assert_eq!(got, b"original");
    }

    // ── Scheme tag preserved through roundtrip ───────────────────

    #[test]
    fn a3_roundtrip_preserves_scheme_tag() {
        let (_d, store) = open_tmp();
        let digest = [0xA3u8; 32];
        let vc = sample_vc();
        store.put_cert_v2_votes(&digest, &vc, &None).expect("put");
        let got = store
            .get_cert_v2_votes(&digest)
            .expect("get")
            .expect("some");
        assert_eq!(got.0.scheme, CommitmentScheme::Blake3MerkleV1);
        assert_eq!(got.0.scheme.tag(), 0x01);
    }

    // ── A.5: cert mapping CF ─────────────────────────────────────

    #[test]
    fn a5_cert_mapping_cf_is_registered_on_open() {
        let (_d, store) = open_tmp();
        store.cf_cert_mapping().expect("cert_mapping CF accessible");
    }

    #[test]
    fn a5_put_then_get_cert_mapping_roundtrips() {
        let (_d, store) = open_tmp();
        let v1 = [0xC0u8; 32];
        let v2 = [0xC1u8; 32];
        store.put_cert_mapping(&v1, &v2).expect("put");
        let got = store
            .get_cert_mapping_v1_to_v2(&v1)
            .expect("get")
            .expect("some");
        assert_eq!(got, v2);
    }

    #[test]
    fn a5_get_on_missing_v1_returns_none() {
        let (_d, store) = open_tmp();
        let got = store
            .get_cert_mapping_v1_to_v2(&[0xFFu8; 32])
            .expect("get returns Ok(None)");
        assert!(got.is_none());
    }

    #[test]
    fn a5_mapping_idempotent_on_rewrite() {
        let (_d, store) = open_tmp();
        let v1 = [0xC2u8; 32];
        let v2 = [0xC3u8; 32];
        store.put_cert_mapping(&v1, &v2).expect("put 1");
        store.put_cert_mapping(&v1, &v2).expect("put 2 identical");
        let got = store
            .get_cert_mapping_v1_to_v2(&v1)
            .expect("get")
            .expect("some");
        assert_eq!(got, v2);
    }

    #[test]
    fn a5_mapping_overwrite_replaces() {
        let (_d, store) = open_tmp();
        let v1 = [0xC4u8; 32];
        let v2_first = [0xC5u8; 32];
        let v2_second = [0xC6u8; 32];
        store.put_cert_mapping(&v1, &v2_first).expect("put 1");
        store.put_cert_mapping(&v1, &v2_second).expect("put 2");
        let got = store
            .get_cert_mapping_v1_to_v2(&v1)
            .expect("get")
            .expect("some");
        assert_eq!(got, v2_second);
    }

    #[test]
    fn a5_mapping_independent_of_votes_cf() {
        // Shared digest bytes across CFs must not collide — each CF
        // has its own keyspace.
        let (_d, store) = open_tmp();
        let key = [0xC7u8; 32];
        store
            .put_cert_v2_votes(&key, &sample_vc(), &None)
            .expect("put votes");
        store
            .put_cert_mapping(&key, &[0xC8u8; 32])
            .expect("put mapping");
        // Both reads return their respective values.
        assert!(store.get_cert_v2_votes(&key).expect("get votes").is_some());
        assert_eq!(
            store
                .get_cert_mapping_v1_to_v2(&key)
                .expect("get mapping")
                .expect("some"),
            [0xC8u8; 32]
        );
    }

    // ── Part C: round-config audit log ───────────────────────────

    fn sample_audit(epoch: u64) -> crate::narwhal_dag::round_config_adjust::RoundConfigAuditEntry {
        use crate::narwhal_dag::round_config_adjust::{EpochStats, RoundConfigAuditEntry};
        use crate::narwhal_dag::round_scheduler::RoundSchedulerConfig;
        RoundConfigAuditEntry {
            applied_from_epoch: epoch,
            previous_config: RoundSchedulerConfig {
                min_interval_ms: 100,
                max_interval_ms: 2000,
            },
            new_config: RoundSchedulerConfig {
                min_interval_ms: 150,
                max_interval_ms: 1800,
            },
            stats: EpochStats {
                epoch: epoch.saturating_sub(1),
                max_observed_rtt_ms: 75,
                total_rounds: 8640,
                non_empty_rounds: 4320,
                leader_timeout_ms: 1000,
            },
            timestamp_ms: 1_700_000_000_000 + epoch,
        }
    }

    #[test]
    fn partc_audit_cf_is_registered_on_open() {
        let (_d, store) = open_tmp();
        store
            .cf_round_config_audit()
            .expect("round_config_audit CF accessible");
    }

    #[test]
    fn partc_put_then_get_audit_roundtrips() {
        let (_d, store) = open_tmp();
        let entry = sample_audit(7);
        store.put_round_config_audit(&entry).expect("put");
        let got = store.get_round_config_audit(7).expect("get").expect("some");
        assert_eq!(got, entry);
    }

    #[test]
    fn partc_get_on_missing_epoch_returns_none() {
        let (_d, store) = open_tmp();
        let got = store
            .get_round_config_audit(999)
            .expect("get returns Ok(None)");
        assert!(got.is_none());
    }

    #[test]
    fn partc_list_preserves_epoch_order() {
        // Insert out of order; list() must return ascending epoch.
        // Big-endian u64 keys guarantee natural byte order matches
        // chronological order.
        let (_d, store) = open_tmp();
        store
            .put_round_config_audit(&sample_audit(10))
            .expect("put 10");
        store
            .put_round_config_audit(&sample_audit(3))
            .expect("put 3");
        store
            .put_round_config_audit(&sample_audit(7))
            .expect("put 7");
        let all = store.list_round_config_audit().expect("list");
        let epochs: Vec<u64> = all.iter().map(|e| e.applied_from_epoch).collect();
        assert_eq!(epochs, vec![3, 7, 10]);
    }

    #[test]
    fn partc_idempotent_rewrite_of_same_entry() {
        let (_d, store) = open_tmp();
        let entry = sample_audit(5);
        store.put_round_config_audit(&entry).expect("put 1");
        store
            .put_round_config_audit(&entry)
            .expect("put 2 identical");
        let all = store.list_round_config_audit().expect("list");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], entry);
    }
}
