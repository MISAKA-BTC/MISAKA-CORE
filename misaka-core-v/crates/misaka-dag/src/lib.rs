//! # MISAKA-DAG: Privacy BlockDAG (LogRing + GhostDAG)
//!
//! ## アーキテクチャ概要 (Architecture Overview)
//!
//! ```text
//!  ┌─────────────────────────────────────────────────────────────────┐
//!  │                     MISAKA-CORE v2 Layer Cake                   │
//!  ├─────────────────────────────────────────────────────────────────┤
//!  │                                                                 │
//!  │  ┌──────────────────┐    ┌────────────────────────────────┐    │
//!  │  │   P2P Network     │───▶│  DAG Block Pool (Unordered)    │    │
//!  │  │  (libp2p relay)   │    │  dag_block.rs                  │    │
//!  │  └──────────────────┘    └──────────────┬─────────────────┘    │
//!  │                                          │                      │
//!  │                                          ▼                      │
//!  │  ┌──────────────────────────────────────────────────────┐      │
//!  │  │           GhostDAG Consensus Engine                   │      │
//!  │  │           ghostdag.rs                                 │      │
//!  │  │                                                       │      │
//!  │  │  • Selected Parent Chain 構築                         │      │
//!  │  │  • Blue set / Red set 分類                            │      │
//!  │  │  • Total Order (決定論的線形化)                       │      │
//!  │  │  • Confirmation Depth 算出                            │      │
//!  │  └────────────────────────┬─────────────────────────────┘      │
//!  │                           │                                     │
//!  │                           │ Total Order                         │
//!  │                           ▼                                     │
//!  │  ┌──────────────────────────────────────────────────────┐      │
//!  │  │         DAG State Manager (遅延状態評価)              │      │
//!  │  │         dag_state_manager.rs                          │      │
//!  │  │                                                       │      │
//!  │  │  • Key Image 競合検出・解決                           │      │
//!  │  │  • フェイルソフト TX 無効化                           │      │
//!  │  │  • UTXO Set 更新 (コールバック)                      │      │
//!  │  │  • 安全なデコイ選択フィルタ                           │      │
//!  │  └────────────────────────┬─────────────────────────────┘      │
//!  │                           │                                     │
//!  │                           │ UtxoAction callbacks                │
//!  │                           ▼                                     │
//!  │  ┌──────────────────────────────────────────────────────┐      │
//!  │  │            UTXO Set (misaka-storage)                  │      │
//!  │  │  ┌───────────────────────────────────────────┐       │      │
//!  │  │  │  unspent: HashMap<OutputRef, UtxoEntry>    │       │      │
//!  │  │  │  key_images: HashSet<[u8; 32]>             │       │      │
//!  │  │  │  spending_pubkeys: HashMap<OutputRef, Poly> │       │      │
//!  │  │  └───────────────────────────────────────────┘       │      │
//!  │  └──────────────────────────────────────────────────────┘      │
//!  │                                                                 │
//!  │  ┌──────────────────────────────────────────────────────┐      │
//!  │  │         LogRing / PQC Layer (misaka-pqc)              │      │
//!  │  │  • LogRing O(log n) ring signatures                   │      │
//!  │  │  • Key Image correctness proofs                       │      │
//!  │  │  • Falcon-512 polynomial arithmetic                   │      │
//!  │  └──────────────────────────────────────────────────────┘      │
//!  └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## モジュール構成
//!
//! | モジュール            | 責務                                                  |
//! |-----------------------|------------------------------------------------------|
//! | `dag_block`           | DAG ブロックヘッダ (multi-parent) + GhostDagData      |
//! | `ghostdag`            | GhostDAG コンセンサス: Blue/Red 分類, Total Order     |
//! | `dag_state_manager`   | 遅延状態評価: KI 競合解決, フェイルソフト TX, デコイ   |
//!
//! ## 設計上の重要な判断
//!
//! ### 1. コンセンサス層と状態遷移層の分離
//!
//! `ghostdag.rs` はブロックの順序付けのみを担当し、UTXO 状態には一切触れない。
//! `dag_state_manager.rs` は順序付けの結果を受け取り、状態遷移を行う。
//! これにより:
//! - コンセンサスアルゴリズムの変更が状態遷移に影響しない
//! - 状態遷移ロジックのテストがコンセンサスなしで可能
//! - v1 の `UtxoSet` をそのまま再利用できる
//!
//! ### 2. v1 型の再利用
//!
//! `UtxoTransaction`, `RingInput`, `TxOutput`, `OutputRef` は v1 と同一。
//! DAG レイヤーはトランザクション形式に依存しない。
//!
//! ### 3. フェイルソフトな TX 無効化
//!
//! v1 では「ブロック内の TX が不正 → ブロック全体が不正」だったが、
//! v2 では「TX が競合 → TX のみ無効、ブロックは有効」。
//! これは DAG の並列ブロック生成が善意のノードでも起こりうるため必須。

// ─── Phase 1: データ構造とコンセンサス ───
pub mod dag_block;
pub mod ghostdag;
pub mod dag_state_manager;

// ─── Phase 2: インフラストラクチャ ───
pub mod dag_store;
pub mod dag_block_producer;
pub mod dag_p2p;
pub mod dag_finality;

// ═══════════════════════════════════════════════════════════════
//  Re-exports — Phase 1: Core
// ═══════════════════════════════════════════════════════════════

pub use dag_block::{DagBlockHeader, DagBlock, GhostDagData, Hash, ZERO_HASH};
pub use ghostdag::{GhostDagManager, DagStore, InMemoryDagStore, MIN_DECOY_DEPTH};
pub use dag_state_manager::{
    DagStateManager, TxApplyStatus, TxApplyResult,
    OrderedBlockData, OrderedTxData, UtxoAction,
    DecoyFilter, DecoyCandidate,
};

// ═══════════════════════════════════════════════════════════════
//  Re-exports — Phase 2: Infrastructure
// ═══════════════════════════════════════════════════════════════

pub use dag_store::{ThreadSafeDagStore, DagStoreSnapshot};
pub use dag_block_producer::{
    DagNodeState, DagMempool,
    assemble_dag_block, run_dag_block_producer,
    utxo_tx_to_ordered, build_ordered_block_data,
};
pub use dag_p2p::{DagP2pMessage, DagSyncState, DagSyncManager};
pub use dag_finality::{
    FinalityManager, DagCheckpoint, VirtualBlock,
    FINALITY_DEPTH, PRUNING_DEPTH,
};
