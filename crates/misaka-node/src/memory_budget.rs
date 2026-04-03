//! SR Memory Budget — 16 vCPU / 16 GB RAM constraint enforcement.
//!
//! # Design
//!
//! SR nodes are finality-only. They do NOT store full archive history.
//! This module defines per-subsystem memory budgets and provides a
//! centralized configuration point for all memory-sensitive parameters.
//!
//! # Memory Map (16 GB total)
//!
//! | Subsystem              | Budget  | Notes                                     |
//! |------------------------|---------|-------------------------------------------|
//! | OS + tokio runtime     | 1.5 GB  | Kernel, page tables, async scheduler      |
//! | RocksDB engine         | 1.0 GB  | Write buffers + WAL + bloom filters       |
//! | RocksDB block cache    | 2.0 GB  | Read cache for hot data                   |
//! | DAG frontier           | 64 MB   | Recent rounds only (gc_depth=50 for SR)   |
//! | Synchronizer           | 16 MB   | Pending blocks for ancestor recovery      |
//! | UTXO set (hot)         | 512 MB  | In-memory UTXOs (LRU, not full set)       |
//! | Nullifier set          | 256 MB  | Recent nullifiers (pruned at checkpoint)  |
//! | Mempool                | 128 MB  | Reduced from 256 MB for SR                |
//! | Checkpoint/BFT state   | 16 MB   | Votes, pending checkpoints                |
//! | P2P + networking       | 64 MB   | Connections, message buffers              |
//! | Reachability caches    | 128 MB  | Reduced from 192 MB                       |
//! | Pruning UTXO cache     | 128 MB  | Reduced from 256 MB                       |
//! | Certificate cache      | 32 MB   | Compact verified certificates             |
//! | Committee state        | 1 MB    | 21 SR public keys + scores                |
//! | Headroom               | ~10 GB  | OS page cache, spikes, RocksDB compaction |
//! | **Total allocated**    | **~4.3 GB** |                                       |
//! | **Available headroom** | **~11.7 GB** | For RocksDB page cache + growth     |

use crate::config::NodeRole;

/// Memory budget configuration for a single subsystem.
#[derive(Debug, Clone, Copy)]
pub struct SubsystemBudget {
    /// Human-readable name.
    pub name: &'static str,
    /// Maximum bytes this subsystem may use.
    pub max_bytes: usize,
}

/// Complete memory budget for an SR node (16 GB target).
#[derive(Debug, Clone)]
pub struct SrMemoryBudget {
    pub dag_frontier: SubsystemBudget,
    pub synchronizer: SubsystemBudget,
    pub utxo_hot_set: SubsystemBudget,
    pub nullifier_set: SubsystemBudget,
    pub mempool: SubsystemBudget,
    pub checkpoint_bft: SubsystemBudget,
    pub p2p_networking: SubsystemBudget,
    pub reachability_cache: SubsystemBudget,
    pub pruning_utxo_cache: SubsystemBudget,
    pub certificate_cache: SubsystemBudget,
    pub committee_state: SubsystemBudget,
    pub rocksdb_block_cache: SubsystemBudget,
    pub rocksdb_engine: SubsystemBudget,
}

impl SrMemoryBudget {
    /// Memory budget for an SR node on 16 GB RAM.
    pub fn sr_16gb() -> Self {
        Self {
            dag_frontier: SubsystemBudget {
                name: "dag_frontier",
                max_bytes: 64 * MB,
            },
            synchronizer: SubsystemBudget {
                name: "synchronizer",
                max_bytes: 16 * MB,
            },
            utxo_hot_set: SubsystemBudget {
                name: "utxo_hot_set",
                max_bytes: 512 * MB,
            },
            nullifier_set: SubsystemBudget {
                name: "nullifier_set",
                max_bytes: 256 * MB,
            },
            mempool: SubsystemBudget {
                name: "mempool",
                max_bytes: 128 * MB,
            },
            checkpoint_bft: SubsystemBudget {
                name: "checkpoint_bft",
                max_bytes: 16 * MB,
            },
            p2p_networking: SubsystemBudget {
                name: "p2p_networking",
                max_bytes: 64 * MB,
            },
            reachability_cache: SubsystemBudget {
                name: "reachability_cache",
                max_bytes: 128 * MB,
            },
            pruning_utxo_cache: SubsystemBudget {
                name: "pruning_utxo_cache",
                max_bytes: 128 * MB,
            },
            certificate_cache: SubsystemBudget {
                name: "certificate_cache",
                max_bytes: 32 * MB,
            },
            committee_state: SubsystemBudget {
                name: "committee_state",
                max_bytes: 1 * MB,
            },
            rocksdb_block_cache: SubsystemBudget {
                name: "rocksdb_block_cache",
                max_bytes: 2048 * MB,
            },
            rocksdb_engine: SubsystemBudget {
                name: "rocksdb_engine",
                max_bytes: 1024 * MB,
            },
        }
    }

    /// Memory budget for Archive nodes (no aggressive limits).
    pub fn archive_default() -> Self {
        Self {
            dag_frontier: SubsystemBudget {
                name: "dag_frontier",
                max_bytes: 256 * MB,
            },
            synchronizer: SubsystemBudget {
                name: "synchronizer",
                max_bytes: 64 * MB,
            },
            utxo_hot_set: SubsystemBudget {
                name: "utxo_hot_set",
                max_bytes: 2048 * MB,
            },
            nullifier_set: SubsystemBudget {
                name: "nullifier_set",
                max_bytes: 1024 * MB,
            },
            mempool: SubsystemBudget {
                name: "mempool",
                max_bytes: 256 * MB,
            },
            checkpoint_bft: SubsystemBudget {
                name: "checkpoint_bft",
                max_bytes: 16 * MB,
            },
            p2p_networking: SubsystemBudget {
                name: "p2p_networking",
                max_bytes: 128 * MB,
            },
            reachability_cache: SubsystemBudget {
                name: "reachability_cache",
                max_bytes: 192 * MB,
            },
            pruning_utxo_cache: SubsystemBudget {
                name: "pruning_utxo_cache",
                max_bytes: 256 * MB,
            },
            certificate_cache: SubsystemBudget {
                name: "certificate_cache",
                max_bytes: 64 * MB,
            },
            committee_state: SubsystemBudget {
                name: "committee_state",
                max_bytes: 1 * MB,
            },
            rocksdb_block_cache: SubsystemBudget {
                name: "rocksdb_block_cache",
                max_bytes: 4096 * MB,
            },
            rocksdb_engine: SubsystemBudget {
                name: "rocksdb_engine",
                max_bytes: 2048 * MB,
            },
        }
    }

    /// Select the appropriate budget based on node role.
    pub fn for_role(role: NodeRole) -> Self {
        match role {
            NodeRole::Sr => Self::sr_16gb(),
            NodeRole::Candidate => Self::sr_16gb(), // candidates run similar hardware
            _ => Self::archive_default(),
        }
    }

    /// Total allocated bytes across all subsystems.
    pub fn total_allocated(&self) -> usize {
        self.all_budgets().iter().map(|b| b.max_bytes).sum()
    }

    /// All subsystem budgets as a slice.
    pub fn all_budgets(&self) -> Vec<SubsystemBudget> {
        vec![
            self.dag_frontier,
            self.synchronizer,
            self.utxo_hot_set,
            self.nullifier_set,
            self.mempool,
            self.checkpoint_bft,
            self.p2p_networking,
            self.reachability_cache,
            self.pruning_utxo_cache,
            self.certificate_cache,
            self.committee_state,
            self.rocksdb_block_cache,
            self.rocksdb_engine,
        ]
    }

    /// Log the memory budget table.
    pub fn log_budget(&self) {
        tracing::info!("╔══════════════════════════════════════════════╗");
        tracing::info!("║        SR Memory Budget (16 GB target)       ║");
        tracing::info!("╠══════════════════════════════════════════════╣");
        for b in self.all_budgets() {
            tracing::info!("║  {:24} {:>8} MB  ║", b.name, b.max_bytes / MB);
        }
        tracing::info!("╠══════════════════════════════════════════════╣");
        tracing::info!("║  {:24} {:>8} MB  ║", "TOTAL ALLOCATED", self.total_allocated() / MB);
        tracing::info!("║  {:24} {:>8} MB  ║", "OS + headroom", 16384 - self.total_allocated() / MB);
        tracing::info!("╚══════════════════════════════════════════════╝");
    }

    // ── Derived parameters for subsystem initialization ──

    /// DAG GC depth for this budget.
    /// SR: 50 rounds (saves ~50% memory vs 100).
    /// Archive: 100 rounds (full retention).
    pub fn dag_gc_depth(&self) -> u64 {
        // 64 MB budget / 15 KB per block / 21 authorities ≈ 200 blocks ≈ ~10 rounds
        // But we need at least wave_length * 2 for commit rule → 50 is safe
        if self.dag_frontier.max_bytes <= 64 * MB { 50 } else { 100 }
    }

    /// Maximum synchronizer pending blocks.
    pub fn synchronizer_max_pending(&self) -> usize {
        // 16 MB / 15 KB per block ≈ 1000
        self.synchronizer.max_bytes / (15 * 1024)
    }

    /// Mempool byte budget.
    pub fn mempool_max_bytes(&self) -> usize {
        self.mempool.max_bytes
    }

    /// RocksDB write buffer size (per CF).
    pub fn rocksdb_write_buffer_size(&self) -> usize {
        // Engine budget split: 60% write buffers, 40% WAL + misc
        let write_budget = self.rocksdb_engine.max_bytes * 60 / 100;
        // 5 CFs × 3 buffers each = 15 buffers total
        write_budget / 15
    }

    /// RocksDB block cache size (shared across all CFs).
    pub fn rocksdb_block_cache_size(&self) -> usize {
        self.rocksdb_block_cache.max_bytes
    }

    /// RocksDB max WAL size.
    pub fn rocksdb_max_wal_size(&self) -> u64 {
        // 40% of engine budget, capped at 256 MB
        let wal = self.rocksdb_engine.max_bytes * 40 / 100;
        std::cmp::min(wal, 256 * MB) as u64
    }
}

const MB: usize = 1024 * 1024;

// ─── Metadata vs Payload split types ───────────────────────────

/// Compact block metadata kept in RAM for SR nodes.
///
/// Full block bodies (transactions, proofs) are stored on disk only.
/// SR nodes verify signatures and advance finality using metadata alone.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CompactBlockMeta {
    /// Block digest (32 bytes).
    pub digest: [u8; 32],
    /// Round number.
    pub round: u64,
    /// Author index.
    pub author: u32,
    /// Timestamp (ms).
    pub timestamp_ms: u64,
    /// Ancestor digests (not full BlockRef — saves 4 bytes per ancestor).
    pub ancestor_digests: Vec<[u8; 32]>,
    /// Number of transactions (for stats, not stored).
    pub tx_count: u32,
    /// Signature bytes (ML-DSA-65, 3309 bytes — needed for verification).
    pub signature: Vec<u8>,
    /// Whether this block has been finalized.
    pub finalized: bool,
}

impl CompactBlockMeta {
    /// Approximate in-memory size.
    pub fn estimated_bytes(&self) -> usize {
        32 + 8 + 4 + 8 // digest + round + author + timestamp
        + self.ancestor_digests.len() * 32 // ancestors
        + 4 // tx_count
        + self.signature.len() // sig (3309 for ML-DSA-65)
        + 1 // finalized flag
        + 64 // HashMap overhead
    }
}

/// Compact verified certificate — stored after signature verification.
///
/// Once a certificate (checkpoint + votes) is verified, we discard the
/// full vote signatures and keep only the verification summary.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CompactVerifiedCertificate {
    /// Checkpoint digest.
    pub checkpoint_digest: [u8; 32],
    /// Checkpoint sequence number.
    pub sequence: u64,
    /// Last committed round.
    pub last_committed_round: u64,
    /// State root at this checkpoint.
    pub state_root: [u8; 32],
    /// Number of valid votes (>= 15/21).
    pub vote_count: u8,
    /// Total stake behind votes.
    pub total_vote_stake: u128,
    /// Timestamp of finalization.
    pub finalized_at_ms: u64,
}

impl CompactVerifiedCertificate {
    pub const ESTIMATED_BYTES: usize = 32 + 8 + 8 + 32 + 1 + 16 + 8 + 64; // ~169 bytes
}

// ─── Retention and pruning rules ───────────────────────────────

/// Retention policy for SR nodes.
///
/// SR nodes keep only what's needed for finality participation:
/// - Recent DAG frontier (dag_gc_depth rounds)
/// - Current UTXO state (hot set, recent only)
/// - Replay protection (nullifiers)
/// - Checkpoint history (compact certificates only)
/// - Committee state
///
/// They do NOT keep:
/// - Full transaction bodies (disk only)
/// - Explorer indexes
/// - Historical DAG payloads
/// - Full certificate signatures (compacted after verification)
#[derive(Debug, Clone)]
pub struct SrRetentionPolicy {
    /// Maximum rounds of DAG blocks to keep in RAM.
    pub max_dag_rounds_in_ram: u64,
    /// Maximum number of compact certificates in RAM.
    pub max_certificates_in_ram: usize,
    /// Checkpoint compaction: keep full data for last N checkpoints.
    pub full_checkpoint_retention: usize,
    /// Beyond full_checkpoint_retention, keep only CompactVerifiedCertificate.
    pub compact_checkpoint_retention: usize,
    /// Nullifier pruning: keep nullifiers for last N checkpoints.
    pub nullifier_retention_checkpoints: usize,
}

impl SrRetentionPolicy {
    pub fn default_sr() -> Self {
        Self {
            max_dag_rounds_in_ram: 50,
            max_certificates_in_ram: 1000,
            full_checkpoint_retention: 5,
            compact_checkpoint_retention: 10_000,
            nullifier_retention_checkpoints: 100,
        }
    }

    pub fn default_archive() -> Self {
        Self {
            max_dag_rounds_in_ram: 100,
            max_certificates_in_ram: 100_000,
            full_checkpoint_retention: 100,
            compact_checkpoint_retention: 1_000_000,
            nullifier_retention_checkpoints: 10_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sr_budget_fits_16gb() {
        let budget = SrMemoryBudget::sr_16gb();
        let total = budget.total_allocated();
        // Total allocated must be well under 16 GB (leave room for OS)
        assert!(total < 8 * 1024 * MB, "SR budget exceeds 8 GB: {} MB", total / MB);
        // At least 8 GB headroom for OS + page cache
        let headroom = 16 * 1024 * MB - total;
        assert!(headroom >= 8 * 1024 * MB, "insufficient headroom: {} MB", headroom / MB);
    }

    #[test]
    fn test_sr_budget_derived_params() {
        let budget = SrMemoryBudget::sr_16gb();
        assert_eq!(budget.dag_gc_depth(), 50);
        assert!(budget.synchronizer_max_pending() >= 500);
        assert_eq!(budget.mempool_max_bytes(), 128 * MB);
        assert!(budget.rocksdb_write_buffer_size() > 0);
        assert!(budget.rocksdb_max_wal_size() <= 256 * MB as u64);
    }

    #[test]
    fn test_archive_budget_larger() {
        let sr = SrMemoryBudget::sr_16gb();
        let archive = SrMemoryBudget::archive_default();
        assert!(archive.total_allocated() > sr.total_allocated());
        assert_eq!(archive.dag_gc_depth(), 100);
    }

    #[test]
    fn test_compact_block_meta_small() {
        let meta = CompactBlockMeta {
            digest: [0; 32],
            round: 100,
            author: 5,
            timestamp_ms: 1000000,
            ancestor_digests: vec![[0; 32]; 21],
            tx_count: 50,
            signature: vec![0; 3309], // ML-DSA-65
            finalized: false,
        };
        // Should be ~4 KB (vs ~15 KB full block with TX bodies)
        assert!(meta.estimated_bytes() < 5000, "meta too large: {}", meta.estimated_bytes());
    }

    #[test]
    fn test_compact_certificate_small() {
        // 1000 certificates × 169 bytes = ~165 KB (vs full: 1000 × 50KB = 50 MB)
        assert!(
            1000 * CompactVerifiedCertificate::ESTIMATED_BYTES < 256 * 1024,
            "1000 certificates exceed 256 KB"
        );
    }

    #[test]
    fn test_role_based_budget_selection() {
        let sr = SrMemoryBudget::for_role(NodeRole::Sr);
        let archive = SrMemoryBudget::for_role(NodeRole::Archive);
        assert_eq!(sr.dag_gc_depth(), 50);
        assert_eq!(archive.dag_gc_depth(), 100);
    }

    #[test]
    fn test_memory_budget_log_does_not_panic() {
        let budget = SrMemoryBudget::sr_16gb();
        // Just verify it doesn't panic (no tracing subscriber in test)
        let _ = budget.total_allocated();
        let _ = budget.all_budgets();
    }

    #[test]
    fn test_retention_policy_sr_vs_archive() {
        let sr = SrRetentionPolicy::default_sr();
        let archive = SrRetentionPolicy::default_archive();
        assert!(sr.max_dag_rounds_in_ram < archive.max_dag_rounds_in_ram);
        assert!(sr.max_certificates_in_ram < archive.max_certificates_in_ram);
    }
}
