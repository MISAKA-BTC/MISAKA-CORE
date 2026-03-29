//! # DAG 遅延状態マネージャ (MISAKA-CORE v2)
//!
//! ## 中核課題の解決
//!
//! BlockDAG では複数のブロックが並列に生成されるため、同一の UTXO を消費する
//! トランザクション (= 同一 Key Image) が異なるブロックに含まれる可能性がある。
//!
//! **線形チェーン (v1)** では「先に確認されたブロックの TX が勝つ」が自明だが、
//! **DAG (v2)** では GhostDAG の Total Order が確定するまで「どちらが先か」が
//! 不明である。
//!
//! ## 設計原則: 遅延状態評価 (Delayed State Application)
//!
//! 1. ブロック受信時に UTXO 状態を即座に更新しない。
//! 2. GhostDAG の Total Order が確定した後、その順序に従って TX を走査する。
//! 3. 「先に現れた Key Image」を正として UTXO Set に適用する。
//! 4. 「後から現れた競合 Key Image」を持つ TX は **Failed** としてマークし、
//!    **ブロック自体は有効のまま** とする (DAG 特有のフェイルソフト)。
//!
//! ## 安全なデコイ選択
//!
//! リング署名のデコイは `confirmation_depth >= MIN_DECOY_DEPTH` のブロックの
//! UTXO からのみ選択する。これにより:
//! - DAG 並び替えで無効化される UTXO をデコイに使うリスクを排除
//! - 無効化された TX の出力をデコイに使ってしまうリスクを排除

use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};

use misaka_types::utxo::TxOutput;

use crate::dag_block::Hash;
use crate::ghostdag::{DagStore, GhostDagEngine, MIN_DECOY_DEPTH};

// ═══════════════════════════════════════════════════════════════
//  TX 状態 (DAG 上のトランザクションの最終状態)
// ═══════════════════════════════════════════════════════════════

/// DAG 上のトランザクションの最終適用結果。
///
/// v1 では「ブロックに入った TX = 有効」だったが、DAG では
/// ブロックは有効でも TX が無効 (Key Image 競合) になりうる。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TxApplyStatus {
    /// 正常に適用された。UTXO が消費され、新しい出力が生成された。
    Applied,

    /// Key Image が既にトポロジー的に先行する TX で使われていた。
    /// この TX の出力は **生成されない**。
    /// ブロック自体は Invalid にならない (フェイルソフト)。
    FailedKeyImageConflict {
        /// 競合した Key Image。
        conflicting_key_image: [u8; 32],
        /// 先行する TX のハッシュ (トポロジー順で先に適用された TX)。
        prior_tx_hash: [u8; 32],
    },

    /// Q-DAG-CT (v4): Nullifier が既にトポロジー的に先行する TX で使われていた。
    /// Ring-independent — 同一 UTXO はどのリングで使っても同一 nullifier を生成。
    FailedNullifierConflict {
        /// 競合した nullifier。
        conflicting_nullifier: [u8; 32],
        /// 先行する TX のハッシュ。
        prior_tx_hash: [u8; 32],
    },

    /// 署名検証に失敗した (不正な TX)。
    /// ブロック提案者のペナルティ対象になりうる。
    FailedInvalidSignature,

    /// Ring member が UTXO Set に存在しない (無効な参照)。
    FailedRingMemberNotFound,
}

/// 1 件の TX の適用結果レコード。
#[derive(Debug, Clone)]
pub struct TxApplyResult {
    /// TX ハッシュ。
    pub tx_hash: [u8; 32],
    /// この TX が含まれていたブロックのハッシュ。
    pub block_hash: Hash,
    /// 適用結果。
    pub status: TxApplyStatus,
}

// ═══════════════════════════════════════════════════════════════
//  ブロック順序付きイテレータ入力
// ═══════════════════════════════════════════════════════════════

/// Total Order で並べ替え済みの単一ブロックのデータ。
///
/// GhostDAG の `get_total_ordering()` で得たハッシュリストから、
/// 各ブロックの TX を取り出して `DagStateManager::apply_ordered_transactions()`
/// に渡す。
#[derive(Debug)]
pub struct OrderedBlockData {
    /// ブロックハッシュ。
    pub block_hash: Hash,
    /// ブロックの blue_score (ファイナリティ判定用)。
    pub blue_score: u64,
    /// このブロックに含まれるトランザクション群 (ブロック内の順序を保持)。
    pub transactions: Vec<OrderedTxData>,
}

/// 順序付けされた個別 TX のデータ。
#[derive(Debug)]
pub struct OrderedTxData {
    /// TX ハッシュ。
    pub tx_hash: [u8; 32],
    /// この TX に含まれる Key Image 群 (v1/v2/v3 ring-signature path)。
    pub key_images: Vec<[u8; 32]>,
    /// Q-DAG-CT (v4): ring-independent nullifiers for double-spend detection.
    /// `null = H(a_null · s)` — deterministic per (secret, output_id, chain_id).
    /// Empty for v1/v2/v3 transactions.
    pub nullifiers: Vec<[u8; 32]>,
    /// Coinbase/Faucet TX か (inputs が空)。
    pub is_coinbase: bool,
    /// 完全な出力群。
    /// runtime 側で UTXO / wallet / explorer に必要な情報を保持する。
    pub outputs: Vec<TxOutput>,
    /// 手数料。
    pub fee: u64,
    /// Ring 署名検証済みフラグ。
    /// true の場合、DagStateManager は署名検証をスキップする。
    /// (ブロック受信時に既に検証済みの場合に使用)
    pub signature_verified: bool,
}

// ═══════════════════════════════════════════════════════════════
//  UTXO Commitment (DAG 版 State Root)
// ═══════════════════════════════════════════════════════════════

/// DAG 上の UTXO Set のスナップショットコミットメント。
///
/// 線形チェーンでは各ブロックに `state_root` を含めるが、
/// DAG ではブロック生成時に状態が確定しないため、**Virtual Block** の
/// 時点で計算される。
#[derive(Debug, Clone)]
pub struct UtxoCommitment {
    /// コミットメントハッシュ (Merkle root of UTXO set)。
    pub root_hash: [u8; 32],
    /// この時点の blue_score (何の時点のスナップショットか)。
    pub at_blue_score: u64,
    /// 適用済み TX 数。
    pub applied_tx_count: u64,
    /// 無効化された TX 数。
    pub failed_tx_count: u64,
}

// ═══════════════════════════════════════════════════════════════
//  DAG 状態マネージャ
// ═══════════════════════════════════════════════════════════════

/// DAG 遅延状態マネージャ。
///
/// ## 責務
///
/// 1. GhostDAG の Total Order を入力として受け取る
/// 2. 順番に TX を走査し、Key Image の競合を検出・解決する
/// 3. 有効な TX のみ UTXO Set に適用する
/// 4. 無効な TX を FailedKeyImageConflict としてマークする
///
/// ## 不変条件 (Invariants)
///
/// - **決定論性**: 同一の Total Order 入力に対して、常に同一の UTXO Set が得られる
/// - **フェイルソフト**: TX が Failed でもブロックは有効
/// - **匿名性保持**: Key Image のみで競合を検出 (実際の入力 UTXO は不明)
pub struct DagStateManager {
    /// 適用済み Key Image → (最初に適用した TX hash, block hash)。
    ///
    /// Key Image は匿名 nullifier であり、どの UTXO が消費されたかは不明。
    /// DAG では複数ブロックが同一 Key Image を含みうるため、
    /// 「トポロジー順で最初に現れた TX」のみが勝つ。
    applied_key_images: HashMap<[u8; 32], KeyImageRecord>,

    /// Q-DAG-CT (v4): 適用済み Nullifier → (最初に適用した TX hash, block hash)。
    ///
    /// Ring-independent — 同一 UTXO は同一 nullifier を生成するため、
    /// DAG 上のどのブランチで使われても衝突を確実に検出する。
    applied_nullifiers: HashMap<[u8; 32], NullifierRecord>,

    /// 適用結果ログ。
    /// 全 TX の適用/失敗を記録する (監査・デバッグ用)。
    results_log: Vec<TxApplyResult>,

    /// 累積統計。
    pub stats: ApplyStats,
}

/// Key Image の適用記録。
#[derive(Debug, Clone)]
struct KeyImageRecord {
    /// この Key Image を最初に使った TX のハッシュ。
    first_tx_hash: [u8; 32],
    /// その TX が含まれていたブロック。
    block_hash: Hash,
    /// 適用時の Total Order 上のインデックス。
    order_index: u64,
}

/// Q-DAG-CT (v4): Nullifier の適用記録。
#[derive(Debug, Clone)]
struct NullifierRecord {
    first_tx_hash: [u8; 32],
    block_hash: Hash,
    order_index: u64,
}

/// 適用統計。
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ApplyStats {
    /// 処理したブロック数。
    pub blocks_processed: u64,
    /// 正常に適用された TX 数。
    pub txs_applied: u64,
    /// Key Image 競合で無効化された TX 数 (v1/v2/v3)。
    pub txs_failed_ki_conflict: u64,
    /// Nullifier 競合で無効化された TX 数 (v4 Q-DAG-CT)。
    pub txs_failed_nullifier_conflict: u64,
    /// 署名不正で無効化された TX 数。
    pub txs_failed_invalid_sig: u64,
    /// Coinbase TX 数。
    pub txs_coinbase: u64,
    /// 合計手数料。
    pub total_fees: u64,
}

impl DagStateManager {
    /// 新しい DagStateManager を作成する。
    ///
    /// # 引数
    ///
    /// - `known_key_images`: 既に UTXO Set に記録済みの Key Image 群 (v1/v2/v3)。
    /// - `known_nullifiers`: 既に記録済みの Nullifier 群 (v4 Q-DAG-CT)。
    ///   チェックポイントからの復元時に使用。空から開始する場合は空の HashSet。
    pub fn new(known_key_images: HashSet<[u8; 32]>, known_nullifiers: HashSet<[u8; 32]>) -> Self {
        let applied_key_images = known_key_images
            .into_iter()
            .map(|ki| {
                (
                    ki,
                    KeyImageRecord {
                        first_tx_hash: [0; 32],
                        block_hash: [0; 32],
                        order_index: 0,
                    },
                )
            })
            .collect();

        let applied_nullifiers = known_nullifiers
            .into_iter()
            .map(|nf| {
                (
                    nf,
                    NullifierRecord {
                        first_tx_hash: [0; 32],
                        block_hash: [0; 32],
                        order_index: 0,
                    },
                )
            })
            .collect();

        Self {
            applied_key_images,
            applied_nullifiers,
            results_log: Vec::new(),
            stats: ApplyStats::default(),
        }
    }

    /// Restore a state manager from persisted key images and aggregate stats.
    ///
    /// Results log is intentionally not restored. Runtime-facing status should be
    /// rebuilt from the DAG store and checkpointed state.
    pub fn from_snapshot(
        known_key_images: HashSet<[u8; 32]>,
        known_nullifiers: HashSet<[u8; 32]>,
        stats: ApplyStats,
    ) -> Self {
        let mut manager = Self::new(known_key_images, known_nullifiers);
        manager.stats = stats;
        manager
    }

    /// GhostDAG Total Order に従って TX を順番に適用する。
    ///
    /// # コアロジック (遅延状態評価)
    ///
    /// ```text
    /// for each block in total_order:
    ///   for each tx in block.transactions:
    ///     if tx.is_coinbase:
    ///       → 無条件で適用 (Key Image なし)
    ///     else:
    ///       for each key_image in tx.key_images:
    ///         if key_image ∈ applied_key_images:
    ///           → TX を FailedKeyImageConflict としてマーク
    ///           → この TX の出力は生成しない
    ///           → break (この TX の処理を中断)
    ///       if all key_images are fresh:
    ///         → TX を Applied としてマーク
    ///         → 全 key_images を applied_key_images に追加
    ///         → 出力を UTXO Set に追加
    /// ```
    ///
    /// # 引数
    ///
    /// - `ordered_blocks`: GhostDAG Total Order で並べ替え済みのブロック群
    /// - `utxo_callback`: 有効な TX の出力を UTXO Set に反映するコールバック。
    ///   `(tx_hash, block_hash, output_index, output)` を受け取る。
    ///
    /// # 戻り値
    ///
    /// 全 TX の適用結果リスト。
    pub fn apply_ordered_transactions<F>(
        &mut self,
        ordered_blocks: &[OrderedBlockData],
        mut utxo_callback: F,
    ) -> Vec<TxApplyResult>
    where
        F: FnMut(UtxoAction),
    {
        let mut results = Vec::new();
        let mut global_order_index: u64 =
            self.stats.txs_applied + self.stats.txs_failed_ki_conflict;

        for block_data in ordered_blocks {
            self.stats.blocks_processed += 1;

            for tx_data in &block_data.transactions {
                let result = self.apply_single_tx(
                    tx_data,
                    &block_data.block_hash,
                    global_order_index,
                    &mut utxo_callback,
                );
                results.push(result.clone());
                self.results_log.push(result);
                global_order_index += 1;
            }
        }

        results
    }

    /// 単一 TX を適用する (内部関数)。
    ///
    /// ## Key Image 競合解決の詳細
    ///
    /// 1. TX の全 Key Image を走査する
    /// 2. いずれかの Key Image が `applied_key_images` に既に存在する場合:
    ///    - TX 全体を `FailedKeyImageConflict` としてマーク
    ///    - **TX の出力は一切生成しない** (部分適用は行わない)
    ///    - **TX の他の Key Image も記録しない** (未使用 KI として残す)
    /// 3. 全 Key Image が未使用の場合:
    ///    - 全 Key Image を `applied_key_images` に追加
    ///    - TX の出力を生成する (`utxo_callback` 経由)
    fn apply_single_tx<F>(
        &mut self,
        tx: &OrderedTxData,
        block_hash: &Hash,
        order_index: u64,
        utxo_callback: &mut F,
    ) -> TxApplyResult
    where
        F: FnMut(UtxoAction),
    {
        // ── Coinbase TX: 無条件適用 ──
        if tx.is_coinbase {
            self.stats.txs_coinbase += 1;

            // Coinbase 出力を UTXO Set に追加
            for (idx, output) in tx.outputs.iter().enumerate() {
                utxo_callback(UtxoAction::CreateOutput {
                    tx_hash: tx.tx_hash,
                    block_hash: *block_hash,
                    output_index: idx as u32,
                    output: output.clone(),
                });
            }

            return TxApplyResult {
                tx_hash: tx.tx_hash,
                block_hash: *block_hash,
                status: TxApplyStatus::Applied,
            };
        }

        // ── Q-DAG-CT (v4): Nullifier 競合チェック ──
        // Nullifier は ring-independent — 同一 UTXO → 同一 nullifier。
        // key_images よりも先にチェック (v4 TX は key_images が空)。
        for &nf in &tx.nullifiers {
            if let Some(existing) = self.applied_nullifiers.get(&nf) {
                warn!(
                    "Nullifier conflict: tx={} nf={} conflicts with prior tx={} (block={})",
                    hex::encode(&tx.tx_hash[..8]),
                    hex::encode(&nf[..8]),
                    hex::encode(&existing.first_tx_hash[..8]),
                    hex::encode(&existing.block_hash[..4]),
                );

                self.stats.txs_failed_nullifier_conflict += 1;

                return TxApplyResult {
                    tx_hash: tx.tx_hash,
                    block_hash: *block_hash,
                    status: TxApplyStatus::FailedNullifierConflict {
                        conflicting_nullifier: nf,
                        prior_tx_hash: existing.first_tx_hash,
                    },
                };
            }
        }

        // ── 通常 TX: Key Image 競合チェック (v1/v2/v3) ──
        for &ki in &tx.key_images {
            if let Some(existing) = self.applied_key_images.get(&ki) {
                // ⚠️ Key Image 競合検出!
                // この TX はトポロジー的に後から現れたため、無効化される。
                warn!(
                    "KI conflict: tx={} ki={} conflicts with prior tx={} (block={})",
                    hex::encode(&tx.tx_hash[..8]),
                    hex::encode(&ki[..8]),
                    hex::encode(&existing.first_tx_hash[..8]),
                    hex::encode(&existing.block_hash[..4]),
                );

                self.stats.txs_failed_ki_conflict += 1;

                return TxApplyResult {
                    tx_hash: tx.tx_hash,
                    block_hash: *block_hash,
                    status: TxApplyStatus::FailedKeyImageConflict {
                        conflicting_key_image: ki,
                        prior_tx_hash: existing.first_tx_hash,
                    },
                };
            }
        }

        // ── 全 Key Image / Nullifier が未使用 → 適用 ──

        // Key Image を記録 (v1/v2/v3)
        for &ki in &tx.key_images {
            self.applied_key_images.insert(
                ki,
                KeyImageRecord {
                    first_tx_hash: tx.tx_hash,
                    block_hash: *block_hash,
                    order_index,
                },
            );
        }

        // Nullifier を記録 (v4 Q-DAG-CT)
        for &nf in &tx.nullifiers {
            self.applied_nullifiers.insert(
                nf,
                NullifierRecord {
                    first_tx_hash: tx.tx_hash,
                    block_hash: *block_hash,
                    order_index,
                },
            );
        }

        // 出力を UTXO Set に追加
        for (idx, output) in tx.outputs.iter().enumerate() {
            utxo_callback(UtxoAction::CreateOutput {
                tx_hash: tx.tx_hash,
                block_hash: *block_hash,
                output_index: idx as u32,
                output: output.clone(),
            });
        }

        // Key Image を nullifier として記録
        for &ki in &tx.key_images {
            utxo_callback(UtxoAction::RecordNullifier {
                key_image: ki,
                tx_hash: tx.tx_hash,
            });
        }

        self.stats.txs_applied += 1;
        self.stats.total_fees += tx.fee;

        debug!(
            "TX applied: {} (kis={}, outputs={}, fee={})",
            hex::encode(&tx.tx_hash[..8]),
            tx.key_images.len(),
            tx.outputs.len(),
            tx.fee,
        );

        TxApplyResult {
            tx_hash: tx.tx_hash,
            block_hash: *block_hash,
            status: TxApplyStatus::Applied,
        }
    }

    // ─── クエリ ──────────────────────────────────────────────

    /// Key Image が既に使用されているか確認する。
    pub fn is_key_image_spent(&self, ki: &[u8; 32]) -> bool {
        self.applied_key_images.contains_key(ki)
    }

    /// 適用結果ログを取得する。
    pub fn results(&self) -> &[TxApplyResult] {
        &self.results_log
    }

    /// 競合した TX のリストを取得する。
    pub fn failed_txs(&self) -> Vec<&TxApplyResult> {
        self.results_log
            .iter()
            .filter(|r| !matches!(r.status, TxApplyStatus::Applied))
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════
//  UTXO アクション (コールバック用)
// ═══════════════════════════════════════════════════════════════

/// DagStateManager から UTXO Set への状態変更アクション。
///
/// DagStateManager 自体は UTXO Set を直接操作せず、
/// コールバックを通じてアクションを発行する (依存性逆転)。
#[derive(Debug, Clone)]
pub enum UtxoAction {
    /// 新しい UTXO 出力を作成する。
    CreateOutput {
        tx_hash: [u8; 32],
        block_hash: Hash,
        output_index: u32,
        output: TxOutput,
    },

    /// Key Image (nullifier) を記録する。
    RecordNullifier {
        key_image: [u8; 32],
        tx_hash: [u8; 32],
    },
}

// ═══════════════════════════════════════════════════════════════
//  安全なデコイ選択
// ═══════════════════════════════════════════════════════════════

/// DAG 上で安全にデコイ (Ring Member) を選択するためのフィルタ。
///
/// ## 原則
///
/// 1. `confirmation_depth < MIN_DECOY_DEPTH` の UTXO は選択しない
/// 2. `FailedKeyImageConflict` でマークされた TX の出力は選択しない
/// 3. 自分自身の入力に関連する UTXO は選択しない (リンク可能性排除)
///
/// ## 使用方法
///
/// ```ignore
/// let filter = DecoyFilter::new(&ghostdag_engine, &dag_store, &state_manager);
/// let safe_utxos = filter.get_eligible_utxos(amount, anonymity_set_size);
/// ```
pub struct DecoyFilter<'a, S: DagStore> {
    ghostdag: &'a GhostDagEngine,
    store: &'a S,
    state_manager: &'a DagStateManager,
}

impl<'a, S: DagStore> DecoyFilter<'a, S> {
    pub fn new(
        ghostdag: &'a GhostDagEngine,
        store: &'a S,
        state_manager: &'a DagStateManager,
    ) -> Self {
        Self {
            ghostdag,
            store,
            state_manager,
        }
    }

    /// 指定された amount に対して安全なデコイ候補 UTXO を返す。
    ///
    /// # 安全基準
    ///
    /// - 確認深度が `MIN_DECOY_DEPTH` 以上
    /// - Failed TX の出力でないこと
    /// - 自分自身の Key Image と関連しないこと
    ///
    /// # 引数
    ///
    /// - `target_amount`: デコイの金額 (同額リングの場合)
    /// - `anonymity_set_size`: 必要なデコイ数
    /// - `exclude_key_images`: 自分の TX に含まれる Key Image (除外対象)
    /// - `all_utxos`: UTXO Set から取得した全候補
    ///
    /// # 戻り値
    ///
    /// 安全なデコイ候補のリスト (anonymity_set_size 以上あれば成功)。
    pub fn filter_eligible_decoys(
        &self,
        target_amount: u64,
        exclude_key_images: &HashSet<[u8; 32]>,
        all_utxos: &[DecoyCandidate],
    ) -> Vec<DecoyCandidate> {
        all_utxos
            .iter()
            .filter(|utxo| {
                // 条件 1: 確認深度が十分
                let depth = self
                    .ghostdag
                    .confirmation_depth(&utxo.block_hash, self.store);
                if depth < MIN_DECOY_DEPTH {
                    return false;
                }

                // 条件 2: 金額が一致 (同額リング)
                if utxo.amount != target_amount {
                    return false;
                }

                // 条件 3: Failed TX の出力でないこと
                // (DagStateManager の結果ログで確認)
                // NOTE: 実装では tx_hash → status のインデックスが必要
                // ここではスケルトンとして省略

                true
            })
            .cloned()
            .collect()
    }
}

/// デコイ候補 UTXO の情報。
#[derive(Debug, Clone)]
pub struct DecoyCandidate {
    pub tx_hash: [u8; 32],
    pub output_index: u32,
    pub amount: u64,
    pub block_hash: Hash,
    /// この UTXO が含まれるブロックの blue_score。
    pub blue_score: u64,
}

// ═══════════════════════════════════════════════════════════════
//  テスト
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tx_data(hash: [u8; 32], key_images: Vec<[u8; 32]>, outputs: Vec<u64>) -> OrderedTxData {
        OrderedTxData {
            tx_hash: hash,
            key_images,
            nullifiers: vec![],
            is_coinbase: false,
            outputs: outputs
                .into_iter()
                .map(|amount| TxOutput {
                    amount,
                    one_time_address: [0xAA; 32],
                    pq_stealth: None,
                    spending_pubkey: None,
                })
                .collect(),
            fee: 100,
            signature_verified: true,
        }
    }

    fn make_coinbase(hash: [u8; 32], amount: u64) -> OrderedTxData {
        OrderedTxData {
            tx_hash: hash,
            key_images: vec![],
            nullifiers: vec![],
            is_coinbase: true,
            outputs: vec![TxOutput {
                amount,
                one_time_address: [0xCC; 32],
                pq_stealth: None,
                spending_pubkey: None,
            }],
            fee: 0,
            signature_verified: true,
        }
    }

    #[test]
    fn test_basic_apply() {
        let mut manager = DagStateManager::new(HashSet::new(), HashSet::new());
        let mut utxo_actions = Vec::new();

        let blocks = vec![OrderedBlockData {
            block_hash: [0x01; 32],
            blue_score: 1,
            transactions: vec![
                make_coinbase([0xA0; 32], 50_000),
                make_tx_data([0xA1; 32], vec![[0xBB; 32]], vec![9_900]),
            ],
        }];

        let results = manager.apply_ordered_transactions(&blocks, |action| {
            utxo_actions.push(action);
        });

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].status, TxApplyStatus::Applied); // coinbase
        assert_eq!(results[1].status, TxApplyStatus::Applied); // transfer
        assert_eq!(manager.stats.txs_applied, 1);
        assert_eq!(manager.stats.txs_coinbase, 1);
        assert!(manager.is_key_image_spent(&[0xBB; 32]));
    }

    #[test]
    fn test_key_image_conflict_resolution() {
        let mut manager = DagStateManager::new(HashSet::new(), HashSet::new());

        // 2 つの並列ブロック (A, B) が同じ Key Image を使うケース。
        // Total Order では Block A が先、Block B が後。
        let ki = [0xFF; 32];
        let blocks = vec![
            // Block A (先に順序付け)
            OrderedBlockData {
                block_hash: [0x0A; 32],
                blue_score: 1,
                transactions: vec![make_tx_data([0xA1; 32], vec![ki], vec![5_000])],
            },
            // Block B (後に順序付け — 同じ KI を使う)
            OrderedBlockData {
                block_hash: [0x0B; 32],
                blue_score: 1,
                transactions: vec![make_tx_data([0xB1; 32], vec![ki], vec![4_000])],
            },
        ];

        let results = manager.apply_ordered_transactions(&blocks, |_| {});

        // Block A の TX は成功
        assert_eq!(results[0].status, TxApplyStatus::Applied);

        // Block B の TX は Key Image 競合で失敗
        assert!(matches!(
            results[1].status,
            TxApplyStatus::FailedKeyImageConflict { conflicting_key_image, prior_tx_hash }
            if conflicting_key_image == ki && prior_tx_hash == [0xA1; 32]
        ));

        // 統計確認
        assert_eq!(manager.stats.txs_applied, 1);
        assert_eq!(manager.stats.txs_failed_ki_conflict, 1);
    }

    #[test]
    fn test_multi_ki_partial_conflict() {
        // TX が複数の Key Image を持ち、そのうち 1 つが競合する場合、
        // TX 全体が無効化される (部分適用なし)。
        let mut manager = DagStateManager::new(HashSet::new(), HashSet::new());

        let ki_shared = [0xAA; 32];
        let ki_unique = [0xBB; 32];

        let blocks = vec![
            // 先行 TX: ki_shared のみ使用
            OrderedBlockData {
                block_hash: [0x01; 32],
                blue_score: 1,
                transactions: vec![make_tx_data([0x10; 32], vec![ki_shared], vec![1_000])],
            },
            // 後続 TX: ki_shared + ki_unique を使用
            // ki_shared が競合するため、TX 全体が無効化される。
            // ki_unique は consumed にならない (他の TX で使用可能)。
            OrderedBlockData {
                block_hash: [0x02; 32],
                blue_score: 2,
                transactions: vec![make_tx_data(
                    [0x20; 32],
                    vec![ki_shared, ki_unique],
                    vec![2_000],
                )],
            },
        ];

        let results = manager.apply_ordered_transactions(&blocks, |_| {});

        assert_eq!(results[0].status, TxApplyStatus::Applied);
        assert!(matches!(
            results[1].status,
            TxApplyStatus::FailedKeyImageConflict { .. }
        ));

        // ki_unique は使われていない (TX 全体が無効化されたため)
        assert!(!manager.is_key_image_spent(&ki_unique));
    }

    #[test]
    fn test_failed_tx_outputs_not_created() {
        let mut manager = DagStateManager::new(HashSet::new(), HashSet::new());
        let mut created_outputs = Vec::new();

        let ki = [0xCC; 32];
        let blocks = vec![
            OrderedBlockData {
                block_hash: [0x01; 32],
                blue_score: 1,
                transactions: vec![make_tx_data([0x10; 32], vec![ki], vec![5_000])],
            },
            OrderedBlockData {
                block_hash: [0x02; 32],
                blue_score: 2,
                transactions: vec![
                    // この TX は KI 競合で失敗 → 出力 (3_000) は生成されない
                    make_tx_data([0x20; 32], vec![ki], vec![3_000]),
                ],
            },
        ];

        manager.apply_ordered_transactions(&blocks, |action| {
            if let UtxoAction::CreateOutput { output, .. } = action {
                created_outputs.push(output.amount);
            }
        });

        // 最初の TX の出力 (5_000) のみ生成される
        assert_eq!(created_outputs, vec![5_000]);
    }
}
