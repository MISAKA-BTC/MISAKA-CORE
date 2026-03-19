//! # DAG P2P プロトコルメッセージ (MISAKA-CORE v2)
//!
//! ## v1 → v2 の P2P 変更点
//!
//! | v1 メッセージ     | v2 メッセージ             | 変更理由                         |
//! |------------------|--------------------------|----------------------------------|
//! | `NewBlock`       | `NewDagBlock`            | parents[] + blue_score           |
//! | `GetBlocks`      | `GetDagBlocks`           | ハッシュ指定 (高さなし)          |
//! | (なし)           | `GetDagHeaders`          | ヘッダのみ同期 (軽量)           |
//! | (なし)           | `DagAnticone`            | 並行ブロック通知                 |
//! | (なし)           | `GetDagTips`             | DAG Tips 要求                    |
//!
//! ## DAG 同期プロトコル
//!
//! 線形チェーンでは `height` で同期位置を特定できたが、DAG では
//! 「最新の共通祖先」を特定するために以下のフローを使う:
//!
//! ```text
//! 1. 接続時に互いの Tips を交換 (DagHello)
//! 2. 相手の Tips のうち自分が知らないものを特定
//! 3. 知らない Tips の ancestors を BFS で要求 (GetDagBlocks)
//! 4. 共通祖先に到達したら同期完了
//! ```

use serde::{Serialize, Deserialize};

use crate::dag_block::{Hash, ZERO_HASH};

// ═══════════════════════════════════════════════════════════════
//  P2P メッセージ型
// ═══════════════════════════════════════════════════════════════

/// DAG P2P メッセージ — v1 `P2pMessage` の v2 後継。
///
/// v1 のメッセージとは互換性がない (wire format が異なる)。
/// v1/v2 ノード間の通信はゲートウェイノードが中継する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DagP2pMessage {
    // ─── Handshake ───

    /// DAG ノードの初期ハンドシェイク。
    /// v1 の `Hello` に相当するが、`height` の代わりに `blue_score` と `tips` を含む。
    DagHello {
        /// チェーン ID (v1 と同じ)。
        chain_id: u32,
        /// DAG プロトコルバージョン。
        dag_version: u8,
        /// 自分の DAG の最大 blue_score。
        blue_score: u64,
        /// 自分の DAG の Tips (最新の葉ノード群)。
        tips: Vec<Hash>,
        /// ノード名。
        node_name: String,
        /// 動作モード ("public", "hidden", "seed")。
        mode: String,
        /// 外部アドレス (peer discovery 用)。
        listen_addr: Option<String>,
    },

    // ─── Block Announcement ───

    /// 新しい DAG ブロックの通知。
    ///
    /// v1 `NewBlock` との違い:
    /// - `parent_hash` → `parents: Vec<Hash>` (複数親)
    /// - `height` → `blue_score` (DAG 論理高度)
    /// - `merge_depth` 追加 (このブロックが合流するブランチの深さ)
    NewDagBlock {
        /// ブロックハッシュ。
        hash: Hash,
        /// 親ブロック群。
        parents: Vec<Hash>,
        /// GhostDAG blue score。
        blue_score: u64,
        /// ブロック生成時刻。
        timestamp_ms: u64,
        /// 含まれる TX 数。
        tx_count: usize,
        /// プロポーザー ID。
        proposer_id: [u8; 32],
    },

    // ─── Block Data ───

    /// DAG ブロックの完全なデータ (ヘッダ + TX)。
    DagBlockData {
        /// ブロックハッシュ。
        hash: Hash,
        /// シリアライズされたブロックヘッダ (JSON)。
        header_json: Vec<u8>,
        /// シリアライズされた TX 群 (JSON array)。
        txs_json: Vec<u8>,
    },

    // ─── Sync Requests ───

    /// DAG ブロックの要求 (ハッシュ指定)。
    ///
    /// 線形チェーンの `GetBlocks(from_height, to_height)` と異なり、
    /// DAG では特定のハッシュ群を指定して要求する。
    GetDagBlocks {
        /// 要求するブロックハッシュ群。
        hashes: Vec<Hash>,
    },

    /// DAG ヘッダのみの要求 (軽量同期用)。
    GetDagHeaders {
        /// 要求するブロックハッシュ群。
        hashes: Vec<Hash>,
    },

    /// ヘッダ応答。
    DagHeaders {
        /// シリアライズされたヘッダ群 (JSON array)。
        headers_json: Vec<u8>,
    },

    /// DAG Tips 要求。
    GetDagTips,

    /// DAG Tips 応答。
    DagTips {
        tips: Vec<Hash>,
        max_blue_score: u64,
    },

    // ─── Anti-Entropy ───

    /// 自分が持つブロックハッシュのブルームフィルタを送信。
    /// 相手が持っていないブロックを特定するために使用。
    DagInventory {
        /// blue_score 範囲 (この範囲のブロックのハッシュを含む)。
        from_blue_score: u64,
        to_blue_score: u64,
        /// ブロックハッシュ群 (この範囲内の全ブロック)。
        block_hashes: Vec<Hash>,
    },

    // ─── TX ───

    /// 新しい TX のブロードキャスト (v1 と同一)。
    NewTx {
        tx_hash: [u8; 32],
        fee: u64,
        size: usize,
    },

    /// TX データ要求。
    GetTx {
        tx_hash: [u8; 32],
    },

    /// TX データ応答。
    TxData {
        tx_json: Vec<u8>,
    },
}

// ═══════════════════════════════════════════════════════════════
//  DAG 同期状態マシン
// ═══════════════════════════════════════════════════════════════

/// DAG 同期の状態。
///
/// 新しいピアに接続した際に、互いの DAG を同期させるための状態マシン。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DagSyncState {
    /// ハンドシェイク中。Tips を交換する。
    Handshaking,

    /// Tips 比較中。相手の Tips のうち自分が知らないものを特定する。
    ComparingTips {
        /// 相手の Tips。
        remote_tips: Vec<Hash>,
        /// 相手の max blue_score。
        remote_blue_score: u64,
    },

    /// ブロック取得中。不足ブロックを BFS でダウンロードする。
    Downloading {
        /// 要求中のブロックハッシュ群。
        pending: Vec<Hash>,
        /// 取得済みブロック数。
        received: u64,
    },

    /// 同期完了。通常のブロック受信モードに移行。
    Synced,
}

/// DAG 同期マネージャ。
///
/// 各ピアごとに 1 つの `DagSyncManager` インスタンスが存在する。
pub struct DagSyncManager {
    /// 現在の同期状態。
    pub state: DagSyncState,

    /// ローカルに存在するブロックハッシュの集合。
    /// (実際の実装では DagStore への参照で代替)
    local_known: std::collections::HashSet<Hash>,
}

impl DagSyncManager {
    pub fn new() -> Self {
        Self {
            state: DagSyncState::Handshaking,
            local_known: std::collections::HashSet::new(),
        }
    }

    /// ハンドシェイク完了後、相手の Tips を受け取って比較を開始する。
    ///
    /// # 返り値
    ///
    /// 要求すべきブロックハッシュのリスト (自分が知らない Tips)。
    pub fn on_remote_tips(
        &mut self,
        remote_tips: Vec<Hash>,
        remote_blue_score: u64,
    ) -> Vec<Hash> {
        let unknown: Vec<Hash> = remote_tips.iter()
            .filter(|h| !self.local_known.contains(h))
            .copied()
            .collect();

        if unknown.is_empty() {
            self.state = DagSyncState::Synced;
        } else {
            self.state = DagSyncState::Downloading {
                pending: unknown.clone(),
                received: 0,
            };
        }

        unknown
    }

    /// ブロック受信時の処理。
    ///
    /// # 返り値
    ///
    /// 追加で要求すべきブロックハッシュ (受信ブロックの parents のうち未知のもの)。
    pub fn on_block_received(
        &mut self,
        block_hash: Hash,
        parents: &[Hash],
    ) -> Vec<Hash> {
        self.local_known.insert(block_hash);

        // parents のうち未知のものを追加要求
        let new_requests: Vec<Hash> = parents.iter()
            .filter(|p| **p != ZERO_HASH && !self.local_known.contains(p))
            .copied()
            .collect();

        if let DagSyncState::Downloading { pending, received } = &mut self.state {
            pending.retain(|h| h != &block_hash);
            *received += 1;
            pending.extend(&new_requests);

            if pending.is_empty() {
                self.state = DagSyncState::Synced;
            }
        }

        new_requests
    }

    /// 同期が完了しているか。
    pub fn is_synced(&self) -> bool {
        matches!(self.state, DagSyncState::Synced)
    }
}

// ═══════════════════════════════════════════════════════════════
//  テスト
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_manager_basic_flow() {
        let mut sync = DagSyncManager::new();

        // Peer reports tips that we don't know
        let unknown_tip = [0xFF; 32];
        let requests = sync.on_remote_tips(vec![unknown_tip], 100);
        assert_eq!(requests, vec![unknown_tip]);
        assert!(matches!(sync.state, DagSyncState::Downloading { .. }));

        // Receive the block — its parent is genesis which we know
        let parent = ZERO_HASH;
        sync.local_known.insert(parent); // we know genesis
        let more = sync.on_block_received(unknown_tip, &[parent]);
        assert!(more.is_empty()); // no more unknowns
        assert!(sync.is_synced());
    }

    #[test]
    fn test_sync_manager_chain_download() {
        let mut sync = DagSyncManager::new();
        let genesis = [0x00; 32];
        sync.local_known.insert(genesis);

        // Peer's tip is C, which we don't know
        let c_hash = [0x0C; 32];
        let requests = sync.on_remote_tips(vec![c_hash], 3);
        assert_eq!(requests, vec![c_hash]);

        // Receive C — parents are A and B (unknown)
        let a_hash = [0x0A; 32];
        let b_hash = [0x0B; 32];
        let more = sync.on_block_received(c_hash, &[a_hash, b_hash]);
        assert_eq!(more.len(), 2);
        assert!(!sync.is_synced());

        // Receive A — parent is genesis (known)
        let more = sync.on_block_received(a_hash, &[genesis]);
        assert!(more.is_empty());
        assert!(!sync.is_synced()); // still waiting for B

        // Receive B — parent is genesis (known)
        let more = sync.on_block_received(b_hash, &[genesis]);
        assert!(more.is_empty());
        assert!(sync.is_synced()); // all done
    }
}
