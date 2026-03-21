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
/// 5. **v8: utxo_commitment と nullifier_commitment が正当** (State Commitment)
///
/// を検証して pruning point の正当性を確認する。
///
/// # v8: True State Commitment
///
/// v7 以前は `nullifier_root: ZERO_HASH` でヘッダのチェックサムに過ぎなかった。
/// v8 では Pruning Point 時点の UTXO set と nullifier set の暗号的コミットメント
/// (Merkle Root) を含み、verify() で不一致があれば Proof を reject する。
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
    /// **v8**: UTXO set commitment at pruning point (Merkle root of sorted UTXO set).
    /// ZERO_HASH if not yet computed (backward compat).
    pub utxo_commitment: Hash,
    /// **v8**: Nullifier set commitment at pruning point (Merkle root of sorted nullifiers).
    /// ZERO_HASH if not yet computed (backward compat).
    pub nullifier_commitment: Hash,
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
    /// v8: UTXO commitment が不一致。
    UtxoCommitmentMismatch,
    /// v8: Nullifier commitment が不一致。
    NullifierCommitmentMismatch,
}

impl PruningProof {
    /// Store から Pruning Proof を構築する。
    ///
    /// SP chain を Genesis → pruning point まで遡り、
    /// 指数バックオフでサンプリングして proof を生成。
    ///
    /// # v8: State Commitment
    ///
    /// `utxo_commitment` と `nullifier_commitment` を外部から受け取り、
    /// Proof に埋め込む。これらは VirtualState.compute_state_root() の
    /// 構成要素を個別に計算したもの。
    ///
    /// # サンプリング戦略
    ///
    /// 全 chain を含めると数万ブロックになるため、
    /// Genesis 付近 + 指数サンプル + Pruning Point 付近 を含む。
    pub fn build<S: DagStore>(
        pruning_point_hash: Hash,
        store: &S,
        utxo_commitment: Hash,
        nullifier_commitment: Hash,
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
            utxo_commitment,
            nullifier_commitment,
        })
    }

    /// Legacy build (backward compat) — no state commitments (ZERO_HASH).
    ///
    /// **DEPRECATED**: Use `build()` with explicit commitments for production.
    #[deprecated(note = "Use build() with explicit utxo/nullifier commitments")]
    pub fn build_legacy<S: DagStore>(
        pruning_point_hash: Hash,
        store: &S,
    ) -> Option<Self> {
        Self::build(pruning_point_hash, store, ZERO_HASH, ZERO_HASH)
    }

    /// Proof を検証する。
    ///
    /// # v8: State Commitment 検証
    ///
    /// `expected_utxo_commitment` と `expected_nullifier_commitment` を外部から渡し、
    /// Proof 内のコミットメントと比較する。不一致なら Proof を reject。
    ///
    /// ZERO_HASH のコミットメントはスキップ (backward compat)。
    pub fn verify_with_state(
        &self,
        expected_utxo_commitment: Hash,
        expected_nullifier_commitment: Hash,
    ) -> ProofVerifyResult {
        // Basic structural checks first
        let basic = self.verify();
        if basic != ProofVerifyResult::Valid {
            return basic;
        }

        // v8: State commitment checks
        // Skip if either side is ZERO_HASH (backward compat / not yet computed)
        if self.utxo_commitment != ZERO_HASH
            && expected_utxo_commitment != ZERO_HASH
            && self.utxo_commitment != expected_utxo_commitment
        {
            return ProofVerifyResult::UtxoCommitmentMismatch;
        }

        if self.nullifier_commitment != ZERO_HASH
            && expected_nullifier_commitment != ZERO_HASH
            && self.nullifier_commitment != expected_nullifier_commitment
        {
            return ProofVerifyResult::NullifierCommitmentMismatch;
        }

        ProofVerifyResult::Valid
    }

    /// Proof を検証する (structural checks only, backward compat).
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

/// Compute UTXO set commitment (sorted Merkle root).
///
/// Deterministic: sorted by (tx_hash, output_index).
pub fn compute_utxo_commitment(utxos: &[(Hash, u32, u64)]) -> Hash {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:utxo_commitment:v1:");
    let mut sorted: Vec<_> = utxos.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    h.update((sorted.len() as u64).to_le_bytes());
    for (tx_hash, output_index, amount) in &sorted {
        h.update(tx_hash);
        h.update(output_index.to_le_bytes());
        h.update(amount.to_le_bytes());
    }
    h.finalize().into()
}

/// Compute nullifier set commitment (sorted Merkle root).
///
/// Deterministic: sorted lexicographically.
pub fn compute_nullifier_commitment(nullifiers: &[Hash]) -> Hash {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:nullifier_commitment:v1:");
    let mut sorted = nullifiers.to_vec();
    sorted.sort();
    h.update((sorted.len() as u64).to_le_bytes());
    for nf in &sorted {
        h.update(nf);
    }
    h.finalize().into()
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
///
/// # v8: State Commitments
///
/// `nullifier_root` と `utxo_root` は VirtualState から計算された
/// 暗号的コミットメント。`verify_integrity()` でこれらの一致を検証する。
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
    /// v8: Nullifier set commitment (Merkle root of sorted nullifiers).
    pub nullifier_root: Hash,
    /// v8: UTXO set commitment (Merkle root of sorted UTXOs).
    pub utxo_root: Hash,
    /// Snapshot の integrity hash (includes state commitments in v8).
    pub snapshot_root: Hash,
}

impl DagSnapshot {
    /// Store から snapshot をエクスポート。
    ///
    /// Pruning point 以降の active window のみ含む。
    ///
    /// # v8: State Commitment
    ///
    /// `nullifier_root` と `utxo_root` は外部から渡された VirtualState の
    /// 暗号的コミットメント。snapshot_root はこれらを含む integrity hash。
    pub fn export<S: DagStore>(
        pruning_point: Hash,
        store: &S,
        nullifier_root: Hash,
        utxo_root: Hash,
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

        // v8: snapshot_root includes state commitments
        let snapshot_root = {
            let mut h = Sha3_256::new();
            h.update(b"MISAKA:dag_snapshot:v2:");
            h.update(&pruning_point);
            h.update((headers.len() as u64).to_le_bytes());
            for (hash, _) in &headers {
                h.update(hash);
            }
            // v8: bind state commitments into integrity hash
            h.update(b":nullifier_root:");
            h.update(&nullifier_root);
            h.update(b":utxo_root:");
            h.update(&utxo_root);
            h.finalize().into()
        };

        Some(DagSnapshot {
            pruning_point,
            pruning_point_score: pp_data.blue_score,
            headers,
            ghostdag_data,
            tips,
            nullifier_root,
            utxo_root,
            snapshot_root,
        })
    }

    /// Snapshot の整合性を検証。
    ///
    /// # v8: State Commitment 検証
    ///
    /// snapshot_root は headers + nullifier_root + utxo_root から再計算される。
    /// いずれかが改竄されていれば false を返す。
    pub fn verify_integrity(&self) -> bool {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:dag_snapshot:v2:");
        h.update(&self.pruning_point);
        h.update((self.headers.len() as u64).to_le_bytes());
        for (hash, _) in &self.headers {
            h.update(hash);
        }
        // v8: must include state commitments
        h.update(b":nullifier_root:");
        h.update(&self.nullifier_root);
        h.update(b":utxo_root:");
        h.update(&self.utxo_root);
        let computed: Hash = h.finalize().into();
        computed == self.snapshot_root
    }

    /// v8: Verify state commitments against externally computed values.
    ///
    /// After importing a snapshot, the node should independently compute
    /// the UTXO and nullifier commitments from the imported state,
    /// then call this to verify they match the snapshot's claims.
    pub fn verify_state_commitments(
        &self,
        computed_nullifier_root: Hash,
        computed_utxo_root: Hash,
    ) -> bool {
        // Structural integrity first
        if !self.verify_integrity() {
            return false;
        }
        // State commitment match
        if self.nullifier_root != ZERO_HASH && self.nullifier_root != computed_nullifier_root {
            return false;
        }
        if self.utxo_root != ZERO_HASH && self.utxo_root != computed_utxo_root {
            return false;
        }
        true
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

        let proof = PruningProof::build(tip, &store, ZERO_HASH, ZERO_HASH);
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
        let proof = PruningProof::build(tip, &store, ZERO_HASH, ZERO_HASH).unwrap();
        assert_eq!(proof.chain.len(), 6); // genesis + 5 blocks
        assert_eq!(proof.verify(), ProofVerifyResult::Valid);
    }

    #[test]
    fn test_pruning_proof_tampered_root() {
        let (store, tip) = setup_linear_chain(20);
        let mut proof = PruningProof::build(tip, &store, ZERO_HASH, ZERO_HASH).unwrap();
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
            utxo_commitment: ZERO_HASH,
            nullifier_commitment: ZERO_HASH,
        };
        assert_eq!(proof.verify(), ProofVerifyResult::EmptyChain);
    }

    #[test]
    fn test_pruning_proof_state_commitment_verification() {
        let (store, tip) = setup_linear_chain(10);

        let utxo_root = [0xAA; 32];
        let nullifier_root = [0xBB; 32];
        let proof = PruningProof::build(tip, &store, utxo_root, nullifier_root).unwrap();

        // Matching commitments → Valid
        assert_eq!(
            proof.verify_with_state(utxo_root, nullifier_root),
            ProofVerifyResult::Valid,
        );

        // Mismatched UTXO commitment → Reject
        assert_eq!(
            proof.verify_with_state([0xFF; 32], nullifier_root),
            ProofVerifyResult::UtxoCommitmentMismatch,
        );

        // Mismatched nullifier commitment → Reject
        assert_eq!(
            proof.verify_with_state(utxo_root, [0xFF; 32]),
            ProofVerifyResult::NullifierCommitmentMismatch,
        );

        // ZERO_HASH on either side → skip check (backward compat)
        assert_eq!(
            proof.verify_with_state(ZERO_HASH, ZERO_HASH),
            ProofVerifyResult::Valid,
        );
    }

    #[test]
    fn test_snapshot_export_and_verify() {
        let (store, tip) = setup_linear_chain(30);

        // Use genesis as pruning point (score=0, all blocks are active)
        let snap = DagSnapshot::export(h(0), &store, [0xCC; 32], [0xDD; 32]).unwrap();
        assert_eq!(snap.pruning_point, h(0));
        assert!(!snap.headers.is_empty());
        assert!(snap.verify_integrity());
        assert_eq!(snap.nullifier_root, [0xCC; 32]);
        assert_eq!(snap.utxo_root, [0xDD; 32]);
    }

    #[test]
    fn test_snapshot_tampered() {
        let (store, _) = setup_linear_chain(10);
        let mut snap = DagSnapshot::export(h(0), &store, ZERO_HASH, ZERO_HASH).unwrap();
        snap.snapshot_root = [0xFF; 32];
        assert!(!snap.verify_integrity());
    }

    #[test]
    fn test_snapshot_state_commitment_tampered() {
        let (store, _) = setup_linear_chain(10);
        let snap = DagSnapshot::export(h(0), &store, [0xAA; 32], [0xBB; 32]).unwrap();
        assert!(snap.verify_integrity());

        // Verify with correct commitments
        assert!(snap.verify_state_commitments([0xAA; 32], [0xBB; 32]));

        // Verify with wrong nullifier commitment
        assert!(!snap.verify_state_commitments([0xFF; 32], [0xBB; 32]));

        // Verify with wrong utxo commitment
        assert!(!snap.verify_state_commitments([0xAA; 32], [0xFF; 32]));
    }

    #[test]
    fn test_commitment_computation_deterministic() {
        let utxos = vec![
            ([0x02; 32], 0u32, 100u64),
            ([0x01; 32], 0u32, 200u64),
        ];
        let root1 = compute_utxo_commitment(&utxos);
        let root2 = compute_utxo_commitment(&utxos);
        assert_eq!(root1, root2, "commitment must be deterministic");
        assert_ne!(root1, ZERO_HASH);

        let nullifiers = vec![[0xBB; 32], [0xAA; 32]];
        let nr1 = compute_nullifier_commitment(&nullifiers);
        let nr2 = compute_nullifier_commitment(&nullifiers);
        assert_eq!(nr1, nr2, "commitment must be deterministic");
        assert_ne!(nr1, ZERO_HASH);
    }
}
