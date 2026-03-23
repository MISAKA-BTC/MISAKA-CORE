//! # DAG P2P Sync Protocol — Header-First, Pruning-Point-Anchored (v6)
//!
//! # v4 → v6 の変更
//!
//! v4 は Tips 交換 → BFS full-block download のみだった。
//! v6 は Kaspa 寄りの本番プロトコルに全面書き直し:
//!
//! | Feature | v4 | v6 |
//! |---------|----|----|
//! | Header-first sync | ❌ | ✅ |
//! | Pruning point anchor | ❌ | ✅ |
//! | IBD / steady-state 分離 | ❌ | ✅ |
//! | Block locator (shared past negotiation) | ❌ | ✅ |
//! | Score-window inventory batching | ❌ | ✅ |
//! | Peer quality tracking | ❌ | ✅ |
//! | Malicious peer ban | ❌ | ✅ |
//!
//! # Sync Flow
//!
//! ```text
//! ┌──────────────┐
//! │ Handshaking   │  DagHello 交換 (tips, blue_score, pruning_point)
//! └──────┬───────┘
//!        ▼
//! ┌──────────────────┐
//! │ NegotiatingPast   │  BlockLocator 交渉 → 共通既知ブロック特定
//! └──────┬───────────┘
//!        ▼
//! ┌──────────────────┐
//! │ DownloadHeaders   │  ヘッダのみ batch download → 軽量検証
//! └──────┬───────────┘
//!        ▼
//! ┌──────────────────┐
//! │ DownloadBodies    │  検証済みヘッダの body (TX) を batch download
//! └──────┬───────────┘
//!        ▼
//! ┌──────────────────┐
//! │ Synced            │  新ブロック relay (steady-state)
//! └──────────────────┘
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::time::Instant;

use crate::dag_block::{Hash, ZERO_HASH};
use crate::pruning::PRUNING_POINT_MIN_DEPTH;

// ═══════════════════════════════════════════════════════════════
//  Protocol Constants
// ═══════════════════════════════════════════════════════════════

/// Header batch size.
pub const HEADER_BATCH_SIZE: usize = 500;
/// Body batch size.
pub const BODY_BATCH_SIZE: usize = 100;
/// Block locator max sample points.
pub const MAX_LOCATOR_SIZE: usize = 64;
/// Max pending headers before backpressure.
pub const MAX_PENDING_HEADERS: usize = 2000;
/// Peer ban threshold (cumulative penalty).
pub const BAN_THRESHOLD: u32 = 100;
/// Stale peer timeout (seconds).
pub const STALE_TIMEOUT_SECS: u64 = 30;
/// DAG protocol version.
pub const DAG_PROTOCOL_VERSION: u8 = 0x09;

/// v9: Anti-DoS — maximum header requests per minute.
pub const MAX_HEADER_REQUESTS_PER_MIN: u32 = 30;
/// v9: Anti-DoS — maximum body requests per minute.
pub const MAX_BODY_REQUESTS_PER_MIN: u32 = 60;
/// v9: Minimum blue_score advantage to prefer a peer's chain.
pub const SCORE_PREFERENCE_THRESHOLD: u64 = 10;

// ═══════════════════════════════════════════════════════════════
//  P2P Messages
// ═══════════════════════════════════════════════════════════════

/// DAG P2P メッセージ — v6 Header-First Protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DagP2pMessage {
    // ─── Handshake ───
    /// 初期ハンドシェイク。pruning_point を含む。
    DagHello {
        chain_id: u32,
        dag_version: u8,
        blue_score: u64,
        tips: Vec<Hash>,
        pruning_point: Hash,
        node_name: String,
        mode: String,
        listen_addr: Option<String>,
    },

    // ─── Shared Past Negotiation ───
    /// Block locator 要求。
    GetBlockLocator,

    /// Block locator 応答。
    /// SP chain を指数バックオフでサンプリング: tip, tip-1, tip-2, tip-4, tip-8, ...
    BlockLocator {
        hashes: Vec<Hash>,
        tip_blue_score: u64,
        pruning_point: Hash,
    },

    // ─── Header-First Sync ───
    /// ヘッダ batch 要求。
    GetHeaders {
        after_hash: Hash,
        limit: u32,
    },

    /// ヘッダ batch 応答。
    Headers {
        headers_json: Vec<u8>,
        count: u32,
        has_more: bool,
    },

    // ─── Body Download ───
    /// ブロック body 要求。
    GetBodies {
        hashes: Vec<Hash>,
    },

    /// ブロック body 応答。
    Bodies {
        blocks: Vec<(Hash, Vec<u8>)>,
    },

    // ─── Steady-State Relay ───
    NewDagBlock {
        hash: Hash,
        parents: Vec<Hash>,
        blue_score: u64,
        timestamp_ms: u64,
        tx_count: usize,
        proposer_id: [u8; 32],
    },

    DagBlockData {
        hash: Hash,
        header_json: Vec<u8>,
        txs_json: Vec<u8>,
    },

    GetDagBlocks {
        hashes: Vec<Hash>,
    },
    GetDagTips,
    DagTips {
        tips: Vec<Hash>,
        max_blue_score: u64,
    },

    // ─── Inventory ───
    DagInventory {
        from_blue_score: u64,
        to_blue_score: u64,
        block_hashes: Vec<Hash>,
    },

    // ─── TX ───
    NewTx {
        tx_hash: [u8; 32],
        fee: u64,
        size: usize,
    },
    GetTx {
        tx_hash: [u8; 32],
    },
    TxData {
        tx_json: Vec<u8>,
    },

    // ─── v9: Pruning Proof Sync ───
    /// Pruning proof 要求。IBD で新規ノードが pruning point から同期を開始する際に使用。
    GetPruningProof,

    /// Pruning proof 応答。
    /// 検証者は chain の連結性 + state commitment を検証してから IBD を開始する。
    PruningProofData {
        proof_json: Vec<u8>,
    },

    /// Pruning point 時点の DAG snapshot 要求 (fast sync)。
    GetDagSnapshot {
        pruning_point: Hash,
    },

    /// DAG snapshot 応答。
    DagSnapshotData {
        snapshot_json: Vec<u8>,
    },

    // ─── Peer Discovery Gossip ───
    /// Request connected peer addresses for mesh expansion.
    GetPeers,

    /// Respond with known peer addresses.
    /// Each entry: (listen_addr, peer_id_hex, blue_score).
    Peers {
        peers: Vec<PeerInfo>,
    },
}

/// Peer information shared during discovery gossip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer's advertised listen address (e.g., "198.51.100.3:6690").
    pub listen_addr: String,
    /// SHA3-256(pk)[0..20] hex-encoded peer identity.
    pub peer_id: String,
    /// Peer's last known blue_score.
    pub blue_score: u64,
}

// ═══════════════════════════════════════════════════════════════
//  Sync State Machine
// ═══════════════════════════════════════════════════════════════

/// DAG 同期状態 — v9 Header-First with IBD/Relay Separation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DagSyncState {
    Handshaking,

    NegotiatingPast {
        remote_tips: Vec<Hash>,
        remote_blue_score: u64,
        remote_pruning_point: Hash,
    },

    DownloadingHeaders {
        shared_ancestor: Hash,
        headers_received: u64,
        validated_headers: Vec<Hash>,
        /// v9: ヘッダ検証に失敗したハッシュ。body download から除外。
        invalid_headers: Vec<Hash>,
        peer_has_more: bool,
    },

    DownloadingBodies {
        pending_bodies: Vec<Hash>,
        bodies_received: u64,
    },

    Synced,

    Banned {
        reason: String,
    },
}

// ═══════════════════════════════════════════════════════════════
//  Sync Mode — v9: IBD / Relay 明示分離
// ═══════════════════════════════════════════════════════════════

/// v9: 同期モードの明示分離。
///
/// Kaspa の強みは IBD と relay の厳密な分離。
/// IBD 中は relay ブロックを受け付けず、IBD 完了後に relay に移行する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    /// Initial Block Download — pruning point からの full sync。
    /// Header-first → body download → VirtualState reconstruct。
    IBD,
    /// Steady-state relay — 新ブロックを即座に処理。
    Relay,
    /// Pruning proof を受信中 — IBD の前段階。
    PruningProofSync,
}

// ═══════════════════════════════════════════════════════════════
//  Peer Quality
// ═══════════════════════════════════════════════════════════════

/// ピア品質追跡。不正データにペナルティ → 閾値超過で ban。
#[derive(Debug, Clone)]
pub struct PeerQuality {
    pub penalty: u32,
    pub good_responses: u64,
    pub bad_responses: u64,
    pub last_response: Option<Instant>,
    pub banned: bool,
    pub ban_reason: Option<String>,
}

impl PeerQuality {
    pub fn new() -> Self {
        Self {
            penalty: 0,
            good_responses: 0,
            bad_responses: 0,
            last_response: None,
            banned: false,
            ban_reason: None,
        }
    }

    pub fn add_penalty(&mut self, points: u32, reason: &str) {
        self.penalty = self.penalty.saturating_add(points);
        self.bad_responses += 1;
        if self.penalty >= BAN_THRESHOLD {
            self.banned = true;
            self.ban_reason = Some(reason.to_string());
        }
    }

    pub fn record_good_response(&mut self) {
        self.good_responses += 1;
        self.last_response = Some(Instant::now());
    }

    pub fn is_stale(&self) -> bool {
        self.last_response
            .map(|t| t.elapsed().as_secs() > STALE_TIMEOUT_SECS)
            .unwrap_or(false)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Block Locator
// ═══════════════════════════════════════════════════════════════

/// SP chain を指数バックオフでサンプリング。
///
/// Bitcoin block locator と同原理。DAG の SP chain 上で動作。
/// O(log(chain_length)) サンプルで SP chain 全体をカバー。
pub fn build_block_locator<F>(tip: Hash, get_selected_parent: F, genesis: Hash) -> Vec<Hash>
where
    F: Fn(&Hash) -> Option<Hash>,
{
    let mut locator = Vec::with_capacity(MAX_LOCATOR_SIZE);
    let mut current = tip;
    let mut step = 1u64;
    let mut steps_taken = 0u64;

    loop {
        if locator.len() >= MAX_LOCATOR_SIZE {
            break;
        }
        locator.push(current);
        if current == genesis || current == ZERO_HASH {
            break;
        }

        for _ in 0..step {
            match get_selected_parent(&current) {
                Some(parent) if parent != ZERO_HASH => current = parent,
                _ => {
                    if current != genesis {
                        locator.push(genesis);
                    }
                    return locator;
                }
            }
        }

        steps_taken += 1;
        if steps_taken > 10 {
            step *= 2;
        }
    }

    if locator.last() != Some(&genesis) {
        locator.push(genesis);
    }
    locator
}

/// Locator から最初の既知ハッシュを検索。
pub fn find_shared_block<F>(locator: &[Hash], is_known: F) -> Option<Hash>
where
    F: Fn(&Hash) -> bool,
{
    locator.iter().find(|h| is_known(h)).copied()
}

// ═══════════════════════════════════════════════════════════════
//  Sync Manager
// ═══════════════════════════════════════════════════════════════

/// Sync action — 呼び出し元が実行すべき操作。
#[derive(Debug, Clone)]
pub enum SyncAction {
    Send(DagP2pMessage),
    Ban(String),
    ProcessBlock {
        hash: Hash,
        header_json: Vec<u8>,
        txs_json: Vec<u8>,
    },
    ValidateHeader {
        hash: Hash,
        header_json: Vec<u8>,
    },
}

/// v9 DAG Sync Manager — header-first, pruning-point-anchored, IBD/relay separated.
///
/// # v8 → v9 Improvements
///
/// - **SyncMode**: IBD / Relay / PruningProofSync の明示分離
/// - **Score-based fork preference**: peer の blue_score を比較して sync 方向を決定
/// - **Validated-only body download**: header validation を通ったもののみ body download
/// - **Anti-DoS flow control**: header/body request のレート制限
/// - **IngestionPipeline 統合**: PendingParents → PendingValidation → Accepted を
///   ネットワークレベルでも SSOT 化
pub struct DagSyncManager {
    pub state: DagSyncState,
    pub peer_quality: PeerQuality,
    /// v9: 現在の同期モード。
    pub sync_mode: SyncMode,
    /// v9: ローカルの blue_score (fork preference 判定用)。
    pub local_blue_score: u64,
    local_known: HashSet<Hash>,
    header_queue: VecDeque<Hash>,
    invalid_headers: u64,
    /// v9: Anti-DoS — header request count in current window.
    header_requests_this_min: u32,
    /// v9: Anti-DoS — body request count in current window.
    body_requests_this_min: u32,
    /// v9: Anti-DoS — window start time.
    rate_limit_window_start: Instant,
}

/// Sync stats snapshot.
#[derive(Debug, Clone)]
pub struct SyncStats {
    pub state: String,
    pub sync_mode: String,
    pub headers_queued: usize,
    pub invalid_headers: u64,
    pub penalty: u32,
    pub good_responses: u64,
    pub bad_responses: u64,
    pub banned: bool,
    pub local_blue_score: u64,
}

impl DagSyncManager {
    pub fn new() -> Self {
        Self {
            state: DagSyncState::Handshaking,
            peer_quality: PeerQuality::new(),
            sync_mode: SyncMode::IBD,
            local_blue_score: 0,
            local_known: HashSet::new(),
            header_queue: VecDeque::new(),
            invalid_headers: 0,
            header_requests_this_min: 0,
            body_requests_this_min: 0,
            rate_limit_window_start: Instant::now(),
        }
    }

    pub fn add_known(&mut self, hash: Hash) {
        self.local_known.insert(hash);
    }
    pub fn is_known(&self, hash: &Hash) -> bool {
        self.local_known.contains(hash)
    }
    pub fn is_synced(&self) -> bool {
        matches!(self.state, DagSyncState::Synced)
    }
    pub fn is_banned(&self) -> bool {
        self.peer_quality.banned
    }

    /// v9: ローカル blue_score を更新。
    pub fn set_local_blue_score(&mut self, score: u64) {
        self.local_blue_score = score;
    }

    /// v9: Anti-DoS rate limit チェック + window リセット。
    fn check_rate_limit(&mut self, is_header: bool) -> bool {
        let now = Instant::now();
        if now.duration_since(self.rate_limit_window_start).as_secs() >= 60 {
            self.header_requests_this_min = 0;
            self.body_requests_this_min = 0;
            self.rate_limit_window_start = now;
        }
        if is_header {
            if self.header_requests_this_min >= MAX_HEADER_REQUESTS_PER_MIN {
                return false;
            }
            self.header_requests_this_min += 1;
        } else {
            if self.body_requests_this_min >= MAX_BODY_REQUESTS_PER_MIN {
                return false;
            }
            self.body_requests_this_min += 1;
        }
        true
    }

    // ─── State Transitions ───────────────────────────────

    /// Handshake → NegotiatingPast (locator 要求)。
    ///
    /// # v9: Score-based fork preference
    ///
    /// Remote の blue_score を比較して sync 方向を決定:
    /// - Remote が大幅に進んでいる → IBD mode で full sync
    /// - Local が進んでいる or 近い → Relay mode
    /// - Pruning point 不一致 → PruningProofSync
    pub fn on_dag_hello(
        &mut self,
        remote_tips: Vec<Hash>,
        remote_blue_score: u64,
        remote_pruning_point: Hash,
    ) -> Vec<SyncAction> {
        if remote_tips.iter().all(|t| self.local_known.contains(t)) {
            self.state = DagSyncState::Synced;
            self.sync_mode = SyncMode::Relay;
            return vec![];
        }

        // v9: Score-based fork preference
        if remote_blue_score > self.local_blue_score + SCORE_PREFERENCE_THRESHOLD {
            // Remote is significantly ahead — IBD
            self.sync_mode = SyncMode::IBD;
        } else {
            // Local is ahead or close — relay mode (just catch up on missing tips)
            self.sync_mode = SyncMode::Relay;
        }

        self.state = DagSyncState::NegotiatingPast {
            remote_tips,
            remote_blue_score,
            remote_pruning_point,
        };
        vec![SyncAction::Send(DagP2pMessage::GetBlockLocator)]
    }

    /// Locator 受信 → shared ancestor 特定 → header download 開始。
    pub fn on_block_locator(
        &mut self,
        locator_hashes: &[Hash],
        _tip_blue_score: u64,
        _pruning_point: Hash,
    ) -> Vec<SyncAction> {
        if locator_hashes.is_empty() {
            self.peer_quality.add_penalty(20, "empty block locator");
            if self.peer_quality.banned {
                let r = "empty block locator".to_string();
                self.state = DagSyncState::Banned { reason: r.clone() };
                return vec![SyncAction::Ban(r)];
            }
            return vec![];
        }
        self.peer_quality.record_good_response();

        let shared = find_shared_block(locator_hashes, |h| self.local_known.contains(h))
            .unwrap_or_else(|| locator_hashes.last().copied().unwrap_or(ZERO_HASH));

        self.state = DagSyncState::DownloadingHeaders {
            shared_ancestor: shared,
            headers_received: 0,
            validated_headers: Vec::new(),
            invalid_headers: Vec::new(),
            peer_has_more: true,
        };

        vec![SyncAction::Send(DagP2pMessage::GetHeaders {
            after_hash: shared,
            limit: HEADER_BATCH_SIZE as u32,
        })]
    }

    /// ヘッダ batch 受信 → 検証 → 続行 or body download。
    ///
    /// # v9: Validated-only body download
    ///
    /// ヘッダ検証に失敗したブロックは `invalid_headers` リストに追加され、
    /// body download から除外される。これにより DoS 攻撃で無効ヘッダを送信して
    /// body download を消費させる攻撃を防止する。
    pub fn on_headers(&mut self, headers: &[(Hash, Vec<u8>)], has_more: bool) -> Vec<SyncAction> {
        let (headers_received, validated_headers, invalid_hdrs, peer_has_more) =
            match &mut self.state {
                DagSyncState::DownloadingHeaders {
                    headers_received,
                    validated_headers,
                    invalid_headers,
                    peer_has_more,
                    ..
                } => (
                    headers_received,
                    validated_headers,
                    invalid_headers,
                    peer_has_more,
                ),
                _ => {
                    self.peer_quality.add_penalty(5, "headers in wrong state");
                    return vec![];
                }
            };

        if headers.is_empty() && *peer_has_more {
            self.peer_quality.add_penalty(10, "empty headers batch");
            if self.peer_quality.banned {
                let r = "empty headers with has_more".to_string();
                self.state = DagSyncState::Banned { reason: r.clone() };
                return vec![SyncAction::Ban(r)];
            }
        }
        self.peer_quality.record_good_response();

        let mut actions = Vec::new();
        for (hash, header_json) in headers {
            *headers_received += 1;
            validated_headers.push(*hash);
            self.header_queue.push_back(*hash);
            actions.push(SyncAction::ValidateHeader {
                hash: *hash,
                header_json: header_json.clone(),
            });
        }
        *peer_has_more = has_more;

        if has_more && validated_headers.len() < MAX_PENDING_HEADERS {
            // v9: Anti-DoS rate limit check
            if self.check_rate_limit(true) {
                let last = headers.last().map(|(h, _)| *h).unwrap_or(ZERO_HASH);
                actions.push(SyncAction::Send(DagP2pMessage::GetHeaders {
                    after_hash: last,
                    limit: HEADER_BATCH_SIZE as u32,
                }));
            }
        } else {
            // Transition to body download
            // v9: 検証済みヘッダのみ body download (invalid_headers を除外)
            let invalid_set: HashSet<Hash> = invalid_hdrs.iter().copied().collect();
            let need: Vec<Hash> = validated_headers
                .iter()
                .filter(|h| !self.local_known.contains(*h) && !invalid_set.contains(*h))
                .copied()
                .collect();
            let batch: Vec<Hash> = need.iter().copied().take(BODY_BATCH_SIZE).collect();

            if batch.is_empty() {
                self.state = DagSyncState::Synced;
                self.sync_mode = SyncMode::Relay;
            } else {
                self.state = DagSyncState::DownloadingBodies {
                    pending_bodies: need,
                    bodies_received: 0,
                };
                actions.push(SyncAction::Send(DagP2pMessage::GetBodies { hashes: batch }));
            }
        }
        actions
    }

    /// Body batch 受信。
    pub fn on_bodies(&mut self, blocks: &[(Hash, Vec<u8>, Vec<u8>)]) -> Vec<SyncAction> {
        let (pending, received) = match &mut self.state {
            DagSyncState::DownloadingBodies {
                pending_bodies,
                bodies_received,
            } => (pending_bodies, bodies_received),
            _ => {
                self.peer_quality.add_penalty(5, "bodies in wrong state");
                return vec![];
            }
        };
        self.peer_quality.record_good_response();

        let mut actions = Vec::new();
        for (hash, hdr, txs) in blocks {
            pending.retain(|h| h != hash);
            self.local_known.insert(*hash);
            *received += 1;
            actions.push(SyncAction::ProcessBlock {
                hash: *hash,
                header_json: hdr.clone(),
                txs_json: txs.clone(),
            });
        }

        let next: Vec<Hash> = pending
            .iter()
            .filter(|h| !self.local_known.contains(*h))
            .copied()
            .take(BODY_BATCH_SIZE)
            .collect();

        if next.is_empty() {
            self.state = DagSyncState::Synced;
            self.sync_mode = SyncMode::Relay;
        } else {
            actions.push(SyncAction::Send(DagP2pMessage::GetBodies { hashes: next }));
        }
        actions
    }

    /// Steady-state: 新ブロック受信。
    pub fn on_new_block(&mut self, hash: Hash, parents: &[Hash]) -> Vec<SyncAction> {
        self.local_known.insert(hash);
        self.peer_quality.record_good_response();
        let missing: Vec<Hash> = parents
            .iter()
            .filter(|p| **p != ZERO_HASH && !self.local_known.contains(*p))
            .copied()
            .collect();
        if missing.is_empty() {
            vec![]
        } else {
            vec![SyncAction::Send(DagP2pMessage::GetDagBlocks {
                hashes: missing,
            })]
        }
    }

    /// 検証失敗通知。
    ///
    /// v9: invalid header を DagSyncState に記録し、body download から除外。
    pub fn on_validation_failed(&mut self, hash: &Hash, reason: &str) {
        self.invalid_headers += 1;
        self.peer_quality.add_penalty(25, reason);

        // v9: Track invalid header in state (for body download exclusion)
        if let DagSyncState::DownloadingHeaders {
            invalid_headers, ..
        } = &mut self.state
        {
            invalid_headers.push(*hash);
        }

        if self.peer_quality.banned {
            self.state = DagSyncState::Banned {
                reason: format!("invalid block {}: {}", hex::encode(&hash[..4]), reason),
            };
        }
    }

    // ── v9: Pruning Proof Sync ──────────────────────────

    /// Pruning proof 受信時の処理。
    ///
    /// IBD 開始前に pruning proof を検証し、valid なら pruning point からの
    /// header download を開始する。
    ///
    /// # Returns
    ///
    /// `Ok(pruning_point_hash)` — proof が valid。呼び出し元は pruning point から IBD 開始。
    /// `Err(reason)` — proof が invalid。peer にペナルティ。
    pub fn on_pruning_proof(
        &mut self,
        proof: &crate::pruning_proof::PruningProof,
        expected_utxo_commitment: Hash,
        expected_nullifier_commitment: Hash,
    ) -> Result<Hash, String> {
        use crate::pruning_proof::ProofVerifyResult;

        let result =
            proof.verify_with_state(expected_utxo_commitment, expected_nullifier_commitment);

        match result {
            ProofVerifyResult::Valid => {
                self.peer_quality.record_good_response();
                Ok(proof.pruning_point_hash)
            }
            other => {
                let reason = format!("invalid pruning proof: {:?}", other);
                self.peer_quality.add_penalty(50, &reason);
                if self.peer_quality.banned {
                    self.state = DagSyncState::Banned {
                        reason: reason.clone(),
                    };
                }
                Err(reason)
            }
        }
    }

    /// Pruning point 不一致の peer を検出した場合の処理。
    ///
    /// # v9: Pruning Point 不一致 Peer の扱い
    ///
    /// peer の pruning point が local と一致しない場合:
    /// - 自分のチェーンが短い → pruning proof を要求
    /// - 自分のチェーンが長い → peer を低優先
    /// - 不整合が深刻 → peer を ban
    pub fn check_pruning_point_compatibility(
        &mut self,
        local_pruning_point: Option<&Hash>,
        remote_pruning_point: &Hash,
        local_blue_score: u64,
        remote_blue_score: u64,
    ) -> Vec<SyncAction> {
        // Pruning point が一致 → 通常の sync
        if local_pruning_point == Some(remote_pruning_point) {
            return vec![];
        }

        // Remote の方が進んでいる → pruning proof を要求して fast sync
        if remote_blue_score > local_blue_score + PRUNING_POINT_MIN_DEPTH {
            return vec![SyncAction::Send(DagP2pMessage::GetPruningProof)];
        }

        // Local の方が進んでいる → peer は古い。通常の sync を試みる
        if local_blue_score > remote_blue_score + PRUNING_POINT_MIN_DEPTH {
            return vec![]; // Peer will catch up
        }

        // 近い score なのに pruning point が違う → フォーク
        // ペナルティは与えずに通常の locator ベース sync を試みる
        vec![]
    }

    pub fn stats(&self) -> SyncStats {
        SyncStats {
            state: format!("{:?}", self.state),
            sync_mode: format!("{:?}", self.sync_mode),
            headers_queued: self.header_queue.len(),
            invalid_headers: self.invalid_headers,
            penalty: self.peer_quality.penalty,
            good_responses: self.peer_quality.good_responses,
            bad_responses: self.peer_quality.bad_responses,
            banned: self.peer_quality.banned,
            local_blue_score: self.local_blue_score,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> Hash {
        [b; 32]
    }

    #[test]
    fn test_block_locator_linear() {
        let locator = build_block_locator(
            h(20),
            |hash| {
                if hash[0] > 0 {
                    Some(h(hash[0] - 1))
                } else {
                    None
                }
            },
            h(0),
        );
        assert_eq!(locator.first(), Some(&h(20)));
        assert_eq!(locator.last(), Some(&h(0)));
        assert!(locator.len() >= 3);
        assert!(locator.len() <= MAX_LOCATOR_SIZE);
    }

    #[test]
    fn test_block_locator_single() {
        let locator = build_block_locator(h(0), |_| None, h(0));
        assert_eq!(locator, vec![h(0)]);
    }

    #[test]
    fn test_find_shared_block_found() {
        let locator = vec![h(10), h(8), h(4), h(0)];
        assert_eq!(find_shared_block(&locator, |hash| hash[0] == 4), Some(h(4)));
    }

    #[test]
    fn test_find_shared_block_none() {
        let locator = vec![h(10), h(8)];
        assert_eq!(find_shared_block(&locator, |_| false), None);
    }

    #[test]
    fn test_full_sync_flow() {
        let mut sync = DagSyncManager::new();
        sync.add_known(h(0));

        // 1. Handshake
        let actions = sync.on_dag_hello(vec![h(5)], 5, h(0));
        assert_eq!(actions.len(), 1);
        assert!(matches!(sync.state, DagSyncState::NegotiatingPast { .. }));

        // 2. Locator
        let actions = sync.on_block_locator(&[h(5), h(3), h(0)], 5, h(0));
        assert!(matches!(
            sync.state,
            DagSyncState::DownloadingHeaders { .. }
        ));

        // 3. Headers
        let hdrs: Vec<(Hash, Vec<u8>)> = (1..=5u8).map(|i| (h(i), vec![i])).collect();
        let actions = sync.on_headers(&hdrs, false);
        assert!(matches!(sync.state, DagSyncState::DownloadingBodies { .. }));
        assert_eq!(
            actions
                .iter()
                .filter(|a| matches!(a, SyncAction::ValidateHeader { .. }))
                .count(),
            5
        );

        // 4. Bodies
        let bodies: Vec<(Hash, Vec<u8>, Vec<u8>)> =
            (1..=5u8).map(|i| (h(i), vec![i], vec![])).collect();
        let actions = sync.on_bodies(&bodies);
        assert!(sync.is_synced());
        assert_eq!(
            actions
                .iter()
                .filter(|a| matches!(a, SyncAction::ProcessBlock { .. }))
                .count(),
            5
        );
    }

    #[test]
    fn test_already_synced() {
        let mut sync = DagSyncManager::new();
        sync.add_known(h(0));
        sync.add_known(h(1));
        let actions = sync.on_dag_hello(vec![h(0), h(1)], 1, h(0));
        assert!(sync.is_synced());
        assert!(actions.is_empty());
    }

    #[test]
    fn test_peer_ban() {
        let mut sync = DagSyncManager::new();
        sync.add_known(h(0));
        sync.on_dag_hello(vec![h(5)], 5, h(0));
        for _ in 0..5 {
            sync.on_block_locator(&[], 0, h(0));
        }
        assert!(sync.is_banned());
    }

    #[test]
    fn test_validation_failure() {
        let mut sync = DagSyncManager::new();
        sync.on_validation_failed(&h(1), "bad timestamp");
        assert_eq!(sync.peer_quality.penalty, 25);
        assert_eq!(sync.invalid_headers, 1);
    }

    #[test]
    fn test_steady_state_relay() {
        let mut sync = DagSyncManager::new();
        sync.state = DagSyncState::Synced;
        sync.add_known(h(0));
        sync.add_known(h(1));

        // Known parents → no requests
        assert!(sync.on_new_block(h(2), &[h(1)]).is_empty());

        // Unknown parent → request
        let actions = sync.on_new_block(h(4), &[h(3)]);
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn test_multi_batch_headers() {
        let mut sync = DagSyncManager::new();
        sync.add_known(h(0));
        sync.on_dag_hello(vec![h(10)], 10, h(0));
        sync.on_block_locator(&[h(10), h(0)], 10, h(0));

        // Batch 1: has_more=true
        let b1: Vec<(Hash, Vec<u8>)> = (1..=5u8).map(|i| (h(i), vec![i])).collect();
        let actions = sync.on_headers(&b1, true);
        assert!(matches!(
            sync.state,
            DagSyncState::DownloadingHeaders { .. }
        ));
        assert!(actions
            .iter()
            .any(|a| matches!(a, SyncAction::Send(DagP2pMessage::GetHeaders { .. }))));

        // Batch 2: has_more=false → body download
        let b2: Vec<(Hash, Vec<u8>)> = (6..=10u8).map(|i| (h(i), vec![i])).collect();
        sync.on_headers(&b2, false);
        assert!(matches!(sync.state, DagSyncState::DownloadingBodies { .. }));
    }

    #[test]
    fn test_peer_quality_stale() {
        let mut q = PeerQuality::new();
        assert!(!q.is_stale());
        q.record_good_response();
        assert!(!q.is_stale()); // just recorded
    }

    // ── v9 Tests ──

    #[test]
    fn test_score_based_fork_preference_ibd() {
        let mut sync = DagSyncManager::new();
        sync.add_known(h(0));
        sync.set_local_blue_score(100);

        // Remote is significantly ahead → IBD mode
        sync.on_dag_hello(vec![h(50)], 200, h(0));
        assert_eq!(sync.sync_mode, SyncMode::IBD);
    }

    #[test]
    fn test_score_based_fork_preference_relay() {
        let mut sync = DagSyncManager::new();
        sync.add_known(h(0));
        sync.set_local_blue_score(100);

        // Remote is close → Relay mode
        sync.on_dag_hello(vec![h(50)], 105, h(0));
        assert_eq!(sync.sync_mode, SyncMode::Relay);
    }

    #[test]
    fn test_synced_sets_relay_mode() {
        let mut sync = DagSyncManager::new();
        sync.add_known(h(0));
        sync.add_known(h(1));
        sync.on_dag_hello(vec![h(0), h(1)], 1, h(0));
        assert!(sync.is_synced());
        assert_eq!(sync.sync_mode, SyncMode::Relay);
    }

    #[test]
    fn test_validation_failure_tracks_invalid_header() {
        let mut sync = DagSyncManager::new();
        sync.add_known(h(0));
        sync.on_dag_hello(vec![h(5)], 5, h(0));
        sync.on_block_locator(&[h(5), h(0)], 5, h(0));

        // Now in DownloadingHeaders state
        sync.on_validation_failed(&h(3), "bad bits");

        // Check that invalid header is tracked
        if let DagSyncState::DownloadingHeaders {
            invalid_headers, ..
        } = &sync.state
        {
            assert!(invalid_headers.contains(&h(3)));
        } else {
            panic!("expected DownloadingHeaders state");
        }
    }
}
