// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Persistence layer for Narwhal DAG state.
//!
//! Sui equivalent: consensus/core/store.rs (~600 lines)
//!
//! Provides a `ConsensusStore` trait and a JSON-file implementation
//! for testnet. Production uses RocksDB (behind feature flag).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::dag_state::DagWriteBatch;
use crate::narwhal_types::block::*;
use crate::narwhal_types::commit::*;

// ═══════════════════════════════════════════════════════════
//  Store trait
// ═══════════════════════════════════════════════════════════

/// Persistence interface for the consensus DAG.
///
/// All writes go through `write_batch()` for atomicity.
/// Implementations: `JsonFileStore` (testnet), RocksDB (production).
pub trait ConsensusStore: Send + Sync {
    /// Write a batch of blocks and commits atomically.
    fn write_batch(&self, batch: &DagWriteBatch) -> Result<(), StoreError>;

    /// Read all blocks for recovery.
    fn read_all_blocks(&self) -> Result<Vec<(BlockRef, Block)>, StoreError>;

    /// Read all commits for recovery.
    fn read_all_commits(&self) -> Result<Vec<CommittedSubDag>, StoreError>;

    /// Read last committed rounds per authority.
    fn read_last_committed_rounds(&self) -> Result<Option<Vec<Round>>, StoreError>;

    /// Flush WAL to stable storage.
    fn sync_wal(&self) -> Result<(), StoreError>;

    /// Delete blocks below a given round (GC).
    fn gc_below_round(&self, round: Round) -> Result<u64, StoreError>;
}

/// Store error.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Store corrupted: {0}")]
    Corrupted(String),
}

// ═══════════════════════════════════════════════════════════
//  WAL (Write-Ahead Log) — JSON-based, dev/test only
// ═══════════════════════════════════════════════════════════

/// WAL entry types.
#[cfg(any(test, feature = "json-store-dev"))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
enum WalEntry {
    Block(Block),
    Commit(CommittedSubDag),
    LastCommittedRounds(Vec<Round>),
}

/// Simple append-only WAL for crash recovery (JSON-based, dev/test only).
///
/// Each entry is a JSON line. On recovery, replay all entries
/// to reconstruct the DagState.
///
/// Production uses `RocksDbConsensusStore` which has its own WAL via RocksDB.
#[cfg(any(test, feature = "json-store-dev"))]
pub struct WriteAheadLog {
    path: PathBuf,
    tmp_path: PathBuf,
}

#[cfg(any(test, feature = "json-store-dev"))]
impl WriteAheadLog {
    pub fn new(path: PathBuf) -> Self {
        let tmp_path = path.with_extension("tmp");
        Self { path, tmp_path }
    }

    /// Append a write batch to the WAL.
    pub fn append_batch(&self, batch: &DagWriteBatch) -> Result<(), StoreError> {
        use std::io::Write;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;

        for block in &batch.blocks {
            let entry = WalEntry::Block(block.inner().clone());
            let line = serde_json::to_string(&entry)?;
            writeln!(file, "{}", line)?;
        }

        for commit in &batch.commits {
            let entry = WalEntry::Commit(commit.clone());
            let line = serde_json::to_string(&entry)?;
            writeln!(file, "{}", line)?;
        }

        if let Some(rounds) = &batch.last_committed_rounds {
            let entry = WalEntry::LastCommittedRounds(rounds.clone());
            let line = serde_json::to_string(&entry)?;
            writeln!(file, "{}", line)?;
        }

        file.sync_all()?;
        Ok(())
    }

    /// Replay the WAL and return all entries.
    pub fn replay(
        &self,
    ) -> Result<(Vec<Block>, Vec<CommittedSubDag>, Option<Vec<Round>>), StoreError> {
        let mut blocks = Vec::new();
        let mut commits = Vec::new();
        let mut last_rounds = None;

        if !self.path.exists() {
            return Ok((blocks, commits, last_rounds));
        }

        let content = std::fs::read_to_string(&self.path)?;
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<WalEntry>(line) {
                Ok(WalEntry::Block(block)) => blocks.push(block),
                Ok(WalEntry::Commit(commit)) => commits.push(commit),
                Ok(WalEntry::LastCommittedRounds(rounds)) => last_rounds = Some(rounds),
                Err(e) => {
                    tracing::warn!("WAL: skipping corrupt entry: {}", e);
                }
            }
        }

        Ok((blocks, commits, last_rounds))
    }

    /// Truncate WAL after successful checkpoint.
    pub fn truncate(&self) -> Result<(), StoreError> {
        // Atomic truncate: write empty tmp, rename over WAL
        std::fs::write(&self.tmp_path, "")?;
        std::fs::rename(&self.tmp_path, &self.path)?;
        Ok(())
    }

    /// WAL file size in bytes.
    pub fn size_bytes(&self) -> u64 {
        std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0)
    }
}

// ═══════════════════════════════════════════════════════════
//  JSON file store (testnet/dev only — NOT for production)
// ═══════════════════════════════════════════════════════════

/// JSON-file backed store for testnet/dev only.
///
/// **WARNING**: This store is NOT crash-safe, NOT fsync-guaranteed, and
/// MUST NOT be used in production. Use `RocksDbConsensusStore` instead.
///
/// Gated behind `#[cfg(any(test, feature = "json-store-dev"))]`.
#[cfg(any(test, feature = "json-store-dev"))]
pub struct JsonFileStore {
    /// Base directory for storage.
    base_dir: PathBuf,
    /// Write-ahead log.
    wal: WriteAheadLog,
}

#[cfg(any(test, feature = "json-store-dev"))]
impl JsonFileStore {
    pub fn new(base_dir: PathBuf) -> Result<Self, StoreError> {
        std::fs::create_dir_all(&base_dir)?;
        let wal_path = base_dir.join("narwhal_wal.jsonl");
        Ok(Self {
            base_dir,
            wal: WriteAheadLog::new(wal_path),
        })
    }

    /// Recover state from WAL + snapshot.
    pub fn recover(
        &self,
    ) -> Result<(Vec<Block>, Vec<CommittedSubDag>, Option<Vec<Round>>), StoreError> {
        // First try snapshot
        let snapshot_path = self.base_dir.join("narwhal_snapshot.json");
        let mut blocks = Vec::new();
        let mut commits = Vec::new();
        let mut last_rounds = None;

        if snapshot_path.exists() {
            let content = std::fs::read_to_string(&snapshot_path)?;
            if let Ok(snapshot) = serde_json::from_str::<Snapshot>(&content) {
                blocks = snapshot.blocks;
                commits = snapshot.commits;
                last_rounds = snapshot.last_committed_rounds;
            }
        }

        // Then replay WAL on top.
        //
        // SECURITY (C5 fix): Deduplicate blocks and commits after merging.
        // Without this, blocks present in BOTH the snapshot and the WAL
        // would be applied twice, causing DagState divergence on crash recovery.
        let (wal_blocks, wal_commits, wal_rounds) = self.wal.replay()?;

        // Dedup blocks by digest (snapshot blocks take precedence)
        let existing_digests: std::collections::HashSet<_> =
            blocks.iter().map(|b| b.digest()).collect();
        for wb in wal_blocks {
            if !existing_digests.contains(&wb.digest()) {
                blocks.push(wb);
            }
        }

        // Dedup commits by index (snapshot commits take precedence)
        let existing_commit_indices: std::collections::HashSet<_> =
            commits.iter().map(|c| c.index).collect();
        for wc in wal_commits {
            if !existing_commit_indices.contains(&wc.index) {
                commits.push(wc);
            }
        }

        if wal_rounds.is_some() {
            last_rounds = wal_rounds;
        }

        Ok((blocks, commits, last_rounds))
    }

    /// Create a snapshot and truncate WAL.
    pub fn checkpoint(
        &self,
        blocks: &[Block],
        commits: &[CommittedSubDag],
        last_committed_rounds: &[Round],
    ) -> Result<(), StoreError> {
        let snapshot = Snapshot {
            blocks: blocks.to_vec(),
            commits: commits.to_vec(),
            last_committed_rounds: Some(last_committed_rounds.to_vec()),
        };

        let tmp_path = self.base_dir.join("narwhal_snapshot.json.tmp");
        let snapshot_path = self.base_dir.join("narwhal_snapshot.json");

        let content = serde_json::to_string_pretty(&snapshot)?;
        std::fs::write(&tmp_path, &content)?;
        std::fs::rename(&tmp_path, &snapshot_path)?;

        // Truncate WAL after successful snapshot
        self.wal.truncate()?;

        Ok(())
    }
}

#[cfg(any(test, feature = "json-store-dev"))]
impl ConsensusStore for JsonFileStore {
    fn write_batch(&self, batch: &DagWriteBatch) -> Result<(), StoreError> {
        self.wal.append_batch(batch)
    }

    fn read_all_blocks(&self) -> Result<Vec<(BlockRef, Block)>, StoreError> {
        let (blocks, _, _) = self.recover()?;
        Ok(blocks
            .into_iter()
            .map(|b| {
                let block_ref = b.reference();
                (block_ref, b)
            })
            .collect())
    }

    fn read_all_commits(&self) -> Result<Vec<CommittedSubDag>, StoreError> {
        let (_, commits, _) = self.recover()?;
        Ok(commits)
    }

    fn read_last_committed_rounds(&self) -> Result<Option<Vec<Round>>, StoreError> {
        let (_, _, rounds) = self.recover()?;
        Ok(rounds)
    }

    fn sync_wal(&self) -> Result<(), StoreError> {
        // WAL is synced on each write (sync_all in append_batch)
        Ok(())
    }

    fn gc_below_round(&self, _round: Round) -> Result<u64, StoreError> {
        // GC is handled at checkpoint time
        Ok(0)
    }
}

/// Snapshot format for JSON persistence.
#[cfg(any(test, feature = "json-store-dev"))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct Snapshot {
    blocks: Vec<Block>,
    commits: Vec<CommittedSubDag>,
    last_committed_rounds: Option<Vec<Round>>,
}

// ═══════════════════════════════════════════════════════════
//  DagState recovery
// ═══════════════════════════════════════════════════════════

use super::dag_state::{DagState, DagStateConfig};
use crate::narwhal_types::committee::Committee;

/// Recover DagState from a store.
///
/// If `verifier` is provided, each recovered block is re-verified before
/// acceptance. This protects against corrupted or tampered store data
/// (SEC-FIX: recovery path previously trusted all store data without
/// re-verification).
///
/// Pass `None` for `verifier` only if the store is integrity-protected
/// by other means (e.g., authenticated snapshot with Merkle root check).
pub fn recover_dag_state(
    store: &dyn ConsensusStore,
    committee: Committee,
    config: DagStateConfig,
    verifier: Option<&super::block_verifier::BlockVerifier>,
) -> Result<DagState, StoreError> {
    let mut dag_state = DagState::new(committee, config);

    // Recover blocks
    let blocks = store.read_all_blocks()?;
    let mut block_count = 0;
    let mut rejected_count = 0;
    for (_block_ref, block) in blocks {
        // SEC-FIX: Re-verify recovered blocks if verifier is available.
        if let Some(v) = verifier {
            if let Err(e) = v.verify(&block) {
                tracing::warn!(
                    "Recovery: rejecting corrupted block round={} author={}: {}",
                    block.round,
                    block.author,
                    e
                );
                rejected_count += 1;
                continue;
            }
        }
        let vb = VerifiedBlock::new_verified(block);
        dag_state.accept_block(vb);
        block_count += 1;
    }
    if rejected_count > 0 {
        tracing::error!(
            "Recovery: rejected {} corrupted blocks out of {} total",
            rejected_count,
            block_count + rejected_count
        );
    }

    // Recover commits
    let commits = store.read_all_commits()?;
    let commit_count = commits.len();
    for commit in commits {
        dag_state.record_commit(commit);
    }

    // Clear the write batch generated by recovery
    let _ = dag_state.take_write_batch();

    tracing::info!(
        "DAG state recovered: {} blocks, {} commits",
        block_count,
        commit_count
    );

    Ok(dag_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_test_block(round: Round, author: AuthorityIndex) -> Block {
        Block {
            epoch: 0,
            round,
            author,
            timestamp_ms: round as u64 * 1000,
            ancestors: vec![],
            transactions: vec![vec![author as u8]],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            state_root_smt: [0u8; 32],
            signature: vec![0xAA; 64],
        }
    }

    #[test]
    fn test_wal_write_and_replay() {
        let dir = TempDir::new().unwrap();
        let wal = WriteAheadLog::new(dir.path().join("test.wal"));

        let block = make_test_block(1, 0);
        let mut batch = DagWriteBatch::new();
        batch.add_block(VerifiedBlock::new_for_test(block.clone()));

        wal.append_batch(&batch).unwrap();

        let (blocks, commits, rounds) = wal.replay().unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].round, 1);
        assert!(commits.is_empty());
        assert!(rounds.is_none());
    }

    #[test]
    fn test_wal_truncate() {
        let dir = TempDir::new().unwrap();
        let wal = WriteAheadLog::new(dir.path().join("test.wal"));

        let mut batch = DagWriteBatch::new();
        batch.add_block(VerifiedBlock::new_for_test(make_test_block(1, 0)));
        wal.append_batch(&batch).unwrap();

        assert!(wal.size_bytes() > 0);
        wal.truncate().unwrap();

        let (blocks, _, _) = wal.replay().unwrap();
        assert!(blocks.is_empty());
    }

    #[test]
    fn test_json_store_write_and_recover() {
        let dir = TempDir::new().unwrap();
        let store = JsonFileStore::new(dir.path().join("store")).unwrap();

        // Write a batch
        let mut batch = DagWriteBatch::new();
        batch.add_block(VerifiedBlock::new_for_test(make_test_block(1, 0)));
        batch.add_block(VerifiedBlock::new_for_test(make_test_block(1, 1)));
        batch.set_last_committed_rounds(vec![0, 0, 0, 0]);
        store.write_batch(&batch).unwrap();

        // Recover
        let blocks = store.read_all_blocks().unwrap();
        assert_eq!(blocks.len(), 2);

        let rounds = store.read_last_committed_rounds().unwrap();
        assert_eq!(rounds, Some(vec![0, 0, 0, 0]));
    }

    #[test]
    fn test_checkpoint_and_truncate_wal() {
        let dir = TempDir::new().unwrap();
        let store = JsonFileStore::new(dir.path().join("store")).unwrap();

        // Write initial data via WAL
        let block1 = make_test_block(1, 0);
        let mut batch1 = DagWriteBatch::new();
        batch1.add_block(VerifiedBlock::new_for_test(block1.clone()));
        store.write_batch(&batch1).unwrap();

        // Checkpoint: snapshot + truncate WAL
        store.checkpoint(&[block1.clone()], &[], &[1, 0]).unwrap();

        // Write more data after checkpoint
        let block2 = make_test_block(2, 0);
        let mut batch2 = DagWriteBatch::new();
        batch2.add_block(VerifiedBlock::new_for_test(block2));
        store.write_batch(&batch2).unwrap();

        // Recover: should have snapshot (1 block) + WAL (1 block)
        let blocks = store.read_all_blocks().unwrap();
        assert_eq!(blocks.len(), 2);
    }

    #[test]
    fn test_recover_dag_state() {
        let dir = TempDir::new().unwrap();
        let store = JsonFileStore::new(dir.path().join("store")).unwrap();

        // Write blocks
        let mut batch = DagWriteBatch::new();
        for author in 0..4u32 {
            batch.add_block(VerifiedBlock::new_for_test(make_test_block(1, author)));
        }
        store.write_batch(&batch).unwrap();

        // Recover
        let committee = Committee::new_for_test(4);
        let dag = recover_dag_state(&store, committee, DagStateConfig::default(), None).unwrap();
        assert_eq!(dag.num_blocks(), 4);
        assert_eq!(dag.highest_accepted_round(), 1);
    }
}
