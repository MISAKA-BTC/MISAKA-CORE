//! Block archive types. Stored in RocksDB column families.

use borsh::{BorshDeserialize, BorshSerialize};

/// Metadata for a committed sub-DAG ("block" in Bitcoin RPC terms).
///
/// In Narwhal consensus, a "block" at the RPC layer maps to a committed
/// sub-DAG. The `hash` is the leader block's BLAKE3 digest.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct BlockMetadata {
    /// Leader block digest (BLAKE3, 32 bytes). Used as "block hash" in RPC.
    pub hash: [u8; 32],
    /// Leader block round.
    pub round: u32,
    /// Leader block author (AuthorityIndex).
    pub author: u32,
    /// Commit timestamp (milliseconds since epoch).
    pub timestamp_ms: u64,
    /// Commit index (used as "block height" in RPC).
    pub commit_index: u64,
    /// Number of transactions in this commit.
    pub tx_count: u32,
    /// Post-execution state root (MuHash3072 v4).
    pub state_root: [u8; 32],
    /// All block references in this committed sub-DAG.
    pub block_refs: Vec<BlockRefEntry>,
}

/// A block reference within a committed sub-DAG.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct BlockRefEntry {
    pub digest: [u8; 32],
    pub round: u32,
    pub author: u32,
}

/// Reference to a transaction within a block (commit).
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct TxRef {
    /// Transaction hash.
    pub tx_hash: [u8; 32],
    /// Position within the commit's transaction list.
    pub position: u32,
}

/// Location of a transaction in the archive.
#[derive(Clone, Copy, Debug, BorshSerialize, BorshDeserialize)]
pub struct TxLocation {
    /// The "block hash" (leader digest) of the commit containing this tx.
    pub block_hash: [u8; 32],
    /// Commit index.
    pub commit_index: u64,
    /// Position within the commit's transaction list.
    pub position: u32,
}

/// Statistics from a pruning operation.
#[derive(Debug, Default)]
pub struct PruneStats {
    pub commits_removed: u64,
    pub tx_records_removed: u64,
}
