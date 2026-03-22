//! Block Processing Pipeline — O(1) per-block, deterministic.
//!
//! # Phase 1.1: ParentSortKey 統一
//!
//! `ParentSortKey` と `select_canonical_parents()` は
//! `parent_selection.rs` に集約された。このモジュールは re-export のみ行う。
//!
//! # Complexity Guarantee
//!
//! When the DAG contains N blocks, processing a NEW block takes:
//!
//! ```text
//! validate_header_topology()  → O(|parents|) = O(MAX_PARENTS) = O(1)
//! reachability.add_child()    → O(1) amortized (interval allocation)
//! ghostdag.calculate()        → O(|parents| × depth_walk) where depth_walk ≤ PRUNING_WINDOW
//!                             → O(MAX_PARENTS × PRUNING_WINDOW) = O(1) constant
//! virtual_state.update()      → O(reorg_depth) where reorg_depth ≤ MAX_REORG_DEPTH = O(1)
//! ```
//!
//! Total: O(1) per block, regardless of |DAG| = N.

use crate::dag_block::{DagBlockHeader, GhostDagData, Hash, ZERO_HASH};
use crate::ghostdag::{DagStore, GhostDagEngine, StakeWeightProvider, validate_header_topology};
use crate::reachability::ReachabilityStore;

// ── Re-export from parent_selection (Single Source of Truth) ──
pub use crate::parent_selection::{
    ParentSortKey, canonical_compare,
    select_canonical_parents,
};

// ═══════════════════════════════════════════════════════════════
//  Block Processing Pipeline
// ═══════════════════════════════════════════════════════════════

/// Result of processing a new block through the O(1) pipeline.
#[derive(Debug)]
pub struct BlockProcessResult {
    pub block_hash: Hash,
    pub ghostdag_data: GhostDagData,
    pub selected_parent: Hash,
    pub blue_score: u64,
    pub is_new_tip: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum BlockProcessError {
    #[error("header topology: {0}")]
    HeaderTopology(String),
    #[error("reachability: {0}")]
    Reachability(String),
    #[error("ghostdag: {0}")]
    GhostDag(String),
    #[error("duplicate block")]
    Duplicate,
    /// header.blue_score と GhostDAG 再計算値の不一致。
    /// header の値は wire-level 参考値であり、consensus 内部では
    /// 必ず recomputed ghostdag_data.blue_score を SSOT とする。
    #[error("blue_score mismatch: header={declared}, computed={computed}")]
    BlueScoreMismatch { declared: u64, computed: u64 },
    /// DAA bits (difficulty) が期待値と不一致。
    #[error("DAA bits mismatch: declared=0x{declared:08x}, expected=0x{expected:08x}")]
    DaaBitsMismatch { declared: u32, expected: u32 },
    /// Timestamp が DAG context で無効。
    #[error("bad timestamp: {0}")]
    BadTimestamp(String),
}

/// Process a new block through the O(1) pipeline.
///
/// # Pipeline Steps (all O(1) or O(constant)):
///
/// 1. **Dedup check**: O(1) hash lookup
/// 2. **Header topology validation**: O(|parents|) ≤ O(MAX_PARENTS)
/// 3. **Reachability index update**: O(1) amortized (interval allocation)
/// 4. **GhostDAG calculation**: O(1) via reachability + BFS on bounded mergeset
pub fn process_new_block<S, W>(
    block_hash: &Hash,
    header: &DagBlockHeader,
    store: &S,
    reachability: &mut ReachabilityStore,
    engine: &GhostDagEngine,
    stake: &W,
) -> Result<BlockProcessResult, BlockProcessError>
where
    S: DagStore,
    W: StakeWeightProvider,
{
    // ── Step 1: Dedup ──
    if store.get_header(block_hash).is_some() {
        return Err(BlockProcessError::Duplicate);
    }

    // ── Step 2: Header topology validation (O(MAX_PARENTS)) ──
    validate_header_topology(&header.parents, header.blue_score, store)
        .map_err(|e| BlockProcessError::HeaderTopology(e.to_string()))?;

    // ── Step 3: Reachability index update (O(1) amortized) ──
    //
    // Canonical parent selection via parent_selection module
    let selected_parent = engine.select_parent_public(&header.parents, store);
    reachability.add_child(selected_parent, *block_hash)
        .map_err(|e| BlockProcessError::Reachability(e))?;

    // ── Step 4: GhostDAG calculation — Fail-Closed (Task 2.1) ──
    //
    // Uses try_calculate: mergeset overflow → block rejected as Invalid.
    let ghostdag_data = engine.try_calculate(
        block_hash,
        &header.parents,
        store,
        reachability,
        stake,
    ).map_err(|e| BlockProcessError::GhostDag(e.to_string()))?;

    // ── Step 4.1: blue_score SSOT — header は参考値、computed が真実 ──
    //
    // Kaspa 準拠: "header に書いてある score" と "ノードが再計算した score" の
    // どちらが真実かを曖昧にしない。consensus 内部では常に recomputed value を使用。
    //
    // header.blue_score はネットワーク上の light node ヒント (wire-level field) であり、
    // consensus-critical な判定には使わない。不一致時はブロックを reject する。
    let computed_blue_score = ghostdag_data.blue_score;
    if header.blue_score != computed_blue_score && !header.is_genesis() {
        return Err(BlockProcessError::BlueScoreMismatch {
            declared: header.blue_score,
            computed: computed_blue_score,
        });
    }

    // ── Step 4.2: DAA bits 検証 ──
    //
    // header.bits が DAA から算出される期待値と一致するか検証。
    // genesis や DAA window 不足時はスキップ。
    if !header.is_genesis() {
        use crate::daa;
        let tip_for_daa = ghostdag_data.selected_parent;
        let existing_bits = store.get_header(&tip_for_daa)
            .map(|h| h.bits)
            .unwrap_or(daa::INITIAL_BITS);
        let expected_bits = daa::compute_next_bits(&tip_for_daa, store, existing_bits);
        // DAA window が不十分な場合 (compute_next_bits が current を返す) はスキップ
        if header.bits != expected_bits {
            return Err(BlockProcessError::DaaBitsMismatch {
                declared: header.bits,
                expected: expected_bits,
            });
        }
    }

    // ── Step 4.3: DAG-context timestamp 検証 ──
    //
    // past median time (親群の中央値) との比較。
    // block_processor 側でも検証し、validation の漏れを防ぐ。
    if !header.is_genesis() {
        use crate::daa::{validate_timestamp, TimestampCheck};
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        match validate_timestamp(header.timestamp_ms, &header.parents, store, now_ms) {
            TimestampCheck::Valid => {},
            TimestampCheck::TooOld { block_ms, past_median_ms } => {
                return Err(BlockProcessError::BadTimestamp(
                    format!("timestamp {}ms < past_median_time {}ms", block_ms, past_median_ms)
                ));
            }
            TimestampCheck::TooFuture { block_ms, max_ms } => {
                return Err(BlockProcessError::BadTimestamp(
                    format!("timestamp {}ms > max_allowed {}ms", block_ms, max_ms)
                ));
            }
        }
    }

    let is_new_tip = computed_blue_score > store.get_tips()
        .iter()
        .filter_map(|t| store.get_ghostdag_data(t))
        .map(|d| d.blue_score)
        .max()
        .unwrap_or(0);

    Ok(BlockProcessResult {
        block_hash: *block_hash,
        ghostdag_data,
        selected_parent,
        // SSOT: consensus 内部では常に recomputed blue_score を使用。
        // header.blue_score は wire-level 参考値。
        blue_score: computed_blue_score,
        is_new_tip,
    })
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn test_parent_sort_key_total_order() {
        let a = ParentSortKey {
            blue_work: 100, blue_score: 10,
            proposer_id: [0xAA; 32], block_hash: [1; 32],
        };
        let b = ParentSortKey {
            blue_work: 100, blue_score: 10,
            proposer_id: [0xAA; 32], block_hash: [2; 32],
        };
        assert_ne!(canonical_compare(&a, &b), Ordering::Equal);
    }

    #[test]
    fn test_parent_sort_key_blue_work_priority() {
        let high = ParentSortKey {
            blue_work: 200, blue_score: 5,
            proposer_id: [0; 32], block_hash: [1; 32],
        };
        let low = ParentSortKey {
            blue_work: 100, blue_score: 10,
            proposer_id: [0xFF; 32], block_hash: [0xFF; 32],
        };
        // higher blue_work sorts first (descending) → Less
        assert_eq!(canonical_compare(&high, &low), Ordering::Less);
    }

    #[test]
    fn test_parent_sort_deterministic() {
        let keys = vec![
            ParentSortKey { blue_work: 50, blue_score: 5, proposer_id: [0; 32], block_hash: [3; 32] },
            ParentSortKey { blue_work: 100, blue_score: 10, proposer_id: [0; 32], block_hash: [1; 32] },
            ParentSortKey { blue_work: 75, blue_score: 7, proposer_id: [0; 32], block_hash: [2; 32] },
        ];
        let mut sorted1 = keys.clone();
        sorted1.sort_by(|a, b| canonical_compare(a, b));

        let mut sorted2 = vec![keys[2].clone(), keys[0].clone(), keys[1].clone()];
        sorted2.sort_by(|a, b| canonical_compare(a, b));

        assert_eq!(sorted1, sorted2, "sort must be deterministic regardless of input order");
    }
}
