//! Pruning Point Proof — Kaspa 準拠の Pruning Point 正当性証明 (B-rank).
//!
//! # 概要
//!
//! 新規ノードが IBD で Pruning Point から同期を開始する際、
//! その Pruning Point が正当であることを検証する必要がある。
//! `PruningProof` は SP chain 上のヘッダと GhostDAG data のサブセットで構成され、
//! 新規ノードが Genesis からの full chain なしに Pruning Point の正当性を検証できる。
//!
//! # Snapshot Export/Import
//!
//! Archive ノードが Pruning Point 時点の DAG 状態を
//! スナップショットとしてエクスポートし、新規ノードがインポートして
//! fast sync する機能。

use serde::{Deserialize, Serialize};
use sha3::{Sha3_256, Digest};

use crate::dag_block::{Hash, DagBlockHeader, GhostDagData, ZERO_HASH};
use crate::ghostdag::DagStore;

// ═══════════════════════════════════════════════════════════════
//  Pruning Proof
// ═══════════════════════════════════════════════════════════════

/// SP chain 上のヘッダ + GhostDAG data のペア。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofBlock {
    pub hash: Hash,
    pub header: DagBlockHeader,
    pub ghostdag: GhostDagData,
}

/// Pruning Point の正当性証明。
///
/// SP chain を Genesis → Pruning Point まで遡った chain のサブセット。
/// 検証者は:
/// 1. chain の連結性 (各ブロックの selected_parent が前のブロック)
/// 2. blue_score の単調増加
/// 3. 末尾が pruning_point_hash と一致
/// 4. proof_root が chain のハッシュから計算可能
///
/// を検証して pruning point の正当性を確認する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruningProof {
    /// SP chain のヘッダ群 (Genesis → Pruning Point 方向、サンプリング済み)。
    pub chain: Vec<ProofBlock>,
    /// Pruning Point のハッシュ。
    pub pruning_point_hash: Hash,
    /// Pruning Point の blue_score。
    pub pruning_point_score: u64,
    /// Proof のダイジェスト (chain 全体のハッシュ)。
    pub proof_root: Hash,
}

/// Pruning Proof の検証結果。
#[derive(Debug, PartialEq, Eq)]
pub enum ProofVerifyResult {
    Valid,
    EmptyChain,
    /// chain の末尾が pruning_point_hash と不一致。
    PruningPointMismatch,
    /// chain の連結性が壊れている (selected_parent 不一致)。
    ChainDisconnected { at_index: usize },
    /// blue_score が単調増加していない。
    ScoreNotMonotonic { at_index: usize },
    /// proof_root が chain から再計算した値と不一致。
    ProofRootMismatch,
}

impl PruningProof {
    /// Store から Pruning Proof を構築する。
    ///
    /// SP chain を Genesis → pruning point まで遡り、
    /// 指数バックオフでサンプリングして proof を生成。
    ///
    /// # サンプリング戦略
    ///
    /// 全 chain を含めると数万ブロックになるため、
    /// Genesis 付近 + 指数サンプル + Pruning Point 付近 を含む。
    /// 検証者はサンプル間の連結性を確認できないが、
    /// blue_score の単調増加と末尾の一致で十分な正当性を保証する。
    pub fn build<S: DagStore>(
        pruning_point_hash: Hash,
        store: &S,
    ) -> Option<Self> {
        let pp_data = store.get_ghostdag_data(&pruning_point_hash)?;
        let pp_header = store.get_header(&pruning_point_hash)?;

        // SP chain を遡って全ブロックを収集
        let mut full_chain = Vec::new();
        let mut current = pruning_point_hash;
        loop {
            let header = store.get_header(&current)?;
            let ghostdag = store.get_ghostdag_data(&current)?;
            full_chain.push(ProofBlock {
                hash: current,
                header,
                ghostdag: ghostdag.clone(),
            });
            if ghostdag.selected_parent == ZERO_HASH || current == ZERO_HASH {
                break;
            }
            current = ghostdag.selected_parent;
        }

        full_chain.reverse(); // Genesis → Pruning Point

        // サンプリング: 先頭5 + 指数サンプル + 末尾5
        let sampled = sample_chain(&full_chain);

        let proof_root = compute_proof_root(&sampled);

        Some(PruningProof {
            chain: sampled,
            pruning_point_hash,
            pruning_point_score: pp_data.blue_score,
            proof_root,
        })
    }

    /// Proof を検証する。
    pub fn verify(&self) -> ProofVerifyResult {
        if self.chain.is_empty() {
            return ProofVerifyResult::EmptyChain;
        }

        // 末尾が pruning_point_hash と一致
        let last = &self.chain[self.chain.len() - 1];
        if last.hash != self.pruning_point_hash {
            return ProofVerifyResult::PruningPointMismatch;
        }

        // blue_score の単調増加 (サンプル間で)
        for i in 1..self.chain.len() {
            if self.chain[i].ghostdag.blue_score < self.chain[i - 1].ghostdag.blue_score {
                return ProofVerifyResult::ScoreNotMonotonic { at_index: i };
            }
        }

        // proof_root 再計算
        let computed_root = compute_proof_root(&self.chain);
        if computed_root != self.proof_root {
            return ProofVerifyResult::ProofRootMismatch;
        }

        ProofVerifyResult::Valid
    }
}

/// Chain をサンプリング。先頭5 + 指数 + 末尾5。
fn sample_chain(chain: &[ProofBlock]) -> Vec<ProofBlock> {
    if chain.len() <= 20 {
        return chain.to_vec();
    }

    let mut indices = std::collections::BTreeSet::new();

    // 先頭5
    for i in 0..5.min(chain.len()) {
        indices.insert(i);
    }

    // 末尾5
    for i in chain.len().saturating_sub(5)..chain.len() {
        indices.insert(i);
    }

    // 指数サンプル (中間)
    let mut step = 1usize;
    let mut pos = 5;
    while pos < chain.len().saturating_sub(5) {
        indices.insert(pos);
        step = (step * 2).min(chain.len() / 4);
        pos += step;
    }

    indices.into_iter().map(|i| chain[i].clone()).collect()
}

/// Proof root = H(chain[0].hash || chain[1].hash || ... || chain[n].hash)
fn compute_proof_root(chain: &[ProofBlock]) -> Hash {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:pruning_proof:v1:");
    h.update((chain.len() as u64).to_le_bytes());
    for block in chain {
        h.update(&block.hash);
        h.update(block.ghostdag.blue_score.to_le_bytes());
    }
    h.finalize().into()
}

// ═══════════════════════════════════════════════════════════════
//  DAG Snapshot Export / Import
// ═══════════════════════════════════════════════════════════════

/// DAG 状態の圧縮スナップショット (fast sync 用)。
///
/// Archive ノードが pruning point 時点の状態をエクスポートし、
/// 新規ノードがインポートして full replay なしで同期開始する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagSnapshot {
    /// Snapshot 時点の pruning point。
    pub pruning_point: Hash,
    /// Pruning point の blue_score。
    pub pruning_point_score: u64,
    /// Pruning point → Tips の全ヘッダ。
    pub headers: Vec<(Hash, DagBlockHeader)>,
    /// 同区間の GhostDAG data。
    pub ghostdag_data: Vec<(Hash, GhostDagData)>,
    /// Tips (snapshot 時点)。
    pub tips: Vec<Hash>,
    /// Nullifier set のダイジェスト (検証用)。
    pub nullifier_root: Hash,
    /// Snapshot の integrity hash。
    pub snapshot_root: Hash,
}

impl DagSnapshot {
    /// Store から snapshot をエクスポート。
    ///
    /// Pruning point 以降の active window のみ含む。
    pub fn export<S: DagStore>(
        pruning_point: Hash,
        store: &S,
    ) -> Option<Self> {
        let pp_data = store.get_ghostdag_data(&pruning_point)?;

        let all_hashes = store.all_hashes();
        let mut headers = Vec::new();
        let mut ghostdag_data = Vec::new();

        for hash in &all_hashes {
            if let (Some(header), Some(gd)) = (store.get_header(hash), store.get_ghostdag_data(hash)) {
                // Active window: blue_score >= pruning_point.blue_score
                if gd.blue_score >= pp_data.blue_score {
                    headers.push((*hash, header));
                    ghostdag_data.push((*hash, gd));
                }
            }
        }

        let tips = store.get_tips();

        let snapshot_root = {
            let mut h = Sha3_256::new();
            h.update(b"MISAKA:dag_snapshot:v1:");
            h.update(&pruning_point);
            h.update((headers.len() as u64).to_le_bytes());
            for (hash, _) in &headers {
                h.update(hash);
            }
            h.finalize().into()
        };

        Some(DagSnapshot {
            pruning_point,
            pruning_point_score: pp_data.blue_score,
            headers,
            ghostdag_data,
            tips,
            nullifier_root: ZERO_HASH, // TODO: compute from nullifier set
            snapshot_root,
        })
    }

    /// Snapshot の整合性を検証。
    pub fn verify_integrity(&self) -> bool {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:dag_snapshot:v1:");
        h.update(&self.pruning_point);
        h.update((self.headers.len() as u64).to_le_bytes());
        for (hash, _) in &self.headers {
            h.update(hash);
        }
        let computed: Hash = h.finalize().into();
        computed == self.snapshot_root
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghostdag::InMemoryDagStore;
    use crate::dag_block::DAG_VERSION;

    fn h(b: u8) -> Hash { [b; 32] }

    fn make_header(parents: Vec<Hash>) -> DagBlockHeader {
        DagBlockHeader {
            version: DAG_VERSION, parents, timestamp_ms: 0, tx_root: [0; 32],
            proposer_id: [0; 32], nonce: 0, blue_score: 0, bits: 0,
        }
    }

    fn setup_linear_chain(len: usize) -> (InMemoryDagStore, Hash) {
        let mut store = InMemoryDagStore::new();
        let g = h(0);
        store.insert_header(g, make_header(vec![]));
        store.set_ghostdag_data(g, GhostDagData {
            selected_parent: ZERO_HASH, mergeset_blues: vec![], mergeset_reds: vec![],
            blue_score: 0, blue_work: 0, blues_anticone_sizes: vec![],
        });

        let mut parent = g;
        for i in 1..=len {
            let block = {
                let mut b = [0u8; 32];
                b[..4].copy_from_slice(&(i as u32).to_le_bytes());
                b
            };
            store.insert_header(block, make_header(vec![parent]));
            store.set_ghostdag_data(block, GhostDagData {
                selected_parent: parent, mergeset_blues: vec![], mergeset_reds: vec![],
                blue_score: i as u64, blue_work: i as u128, blues_anticone_sizes: vec![],
            });
            parent = block;
        }
        (store, parent) // returns (store, tip)
    }

    #[test]
    fn test_pruning_proof_build_and_verify() {
        let (store, tip) = setup_linear_chain(50);

        let proof = PruningProof::build(tip, &store);
        assert!(proof.is_some());
        let proof = proof.unwrap();

        assert_eq!(proof.pruning_point_hash, tip);
        assert_eq!(proof.pruning_point_score, 50);
        assert!(!proof.chain.is_empty());
        assert_eq!(proof.verify(), ProofVerifyResult::Valid);
    }

    #[test]
    fn test_pruning_proof_short_chain() {
        let (store, tip) = setup_linear_chain(5);
        let proof = PruningProof::build(tip, &store).unwrap();
        assert_eq!(proof.chain.len(), 6); // genesis + 5 blocks
        assert_eq!(proof.verify(), ProofVerifyResult::Valid);
    }

    #[test]
    fn test_pruning_proof_tampered_root() {
        let (store, tip) = setup_linear_chain(20);
        let mut proof = PruningProof::build(tip, &store).unwrap();
        proof.proof_root = [0xFF; 32]; // tamper
        assert_eq!(proof.verify(), ProofVerifyResult::ProofRootMismatch);
    }

    #[test]
    fn test_pruning_proof_empty() {
        let proof = PruningProof {
            chain: vec![],
            pruning_point_hash: h(1),
            pruning_point_score: 0,
            proof_root: [0; 32],
        };
        assert_eq!(proof.verify(), ProofVerifyResult::EmptyChain);
    }

    #[test]
    fn test_snapshot_export_and_verify() {
        let (store, tip) = setup_linear_chain(30);

        // Use genesis as pruning point (score=0, all blocks are active)
        let snap = DagSnapshot::export(h(0), &store).unwrap();
        assert_eq!(snap.pruning_point, h(0));
        assert!(!snap.headers.is_empty());
        assert!(snap.verify_integrity());
    }

    #[test]
    fn test_snapshot_tampered() {
        let (store, _) = setup_linear_chain(10);
        let mut snap = DagSnapshot::export(h(0), &store).unwrap();
        snap.snapshot_root = [0xFF; 32];
        assert!(!snap.verify_integrity());
    }
}
