//! MISAKA Network — ZK-based Shielded Transfer Module
//!
//! # Summary
//!
//! transparent DAG L1 に opt-in で乗せる note-based shielded pool 実装。
//!
//! - [`types`]:           Note, Nullifier, NoteCommitment, TreeRoot, EncryptedNote, ViewKey
//! - [`commitment_tree`]: Incremental Merkle tree (depth-32, Blake3)
//! - [`nullifier_set`]:   Double-spend 防止 (confirmed + mempool reservation)
//! - [`proof_backend`]:   ProofBackend trait + StubBackend (P0) + Groth16 shell (P1)
//! - [`tx_types`]:        ShieldDepositTx, ShieldedTransferTx, ShieldWithdrawTx
//! - [`shielded_state`]:  ShieldedState — validate / apply の中核
//! - [`storage`]:         DB CF 定義と WriteBatch ヘルパー
//! - [`wallet_scanner`]:  Monero-style note scanner + PaymentProof
//! - [`rpc_types`]:       Wallet ↔ Node RPC 型定義
//!
//! # Privacy-by-Default 禁止
//!
//! この crate は privacy-by-default を一切実装しない。
//! transparent が標準経路であり、shielded は明示的 opt-in のみ。
//!
//! # Feature Flags
//!
//! - (デフォルト): 全機能有効
//! - 将来: `groth16`, `plonk` フィーチャーで proving backend を選択可能にする
//!
//! # CEX Compatibility
//!
//! CEX ノードは `ShieldedConfig::disabled()` を使い、
//! shielded module を完全無効化できる。
//! transparent transfer は shielded module に非依存で常に動作する。

pub mod commitment_tree;
pub mod nullifier_set;
pub mod proof_backend;
pub mod rpc_types;
pub mod shielded_state;
pub mod storage;
pub mod tx_types;
pub mod types;
pub mod wallet_scanner;
pub mod sha3_proof;

// ─── re-exports ───────────────────────────────────────────────────────────────

pub use commitment_tree::CommitmentTree;
pub use nullifier_set::NullifierSet;
pub use proof_backend::{CircuitRegistry, ProofBackend, ProofError, StubProofBackend, Sha3MerkleProofBackend};
pub use sha3_proof::{Sha3TransferProofBackend, Sha3TransferProofBuilder};
pub use shielded_state::{
    new_shared_state, SharedShieldedState, ShieldedConfig, ShieldedError, ShieldedReceipt,
    ShieldedState, ShieldedWriteSet, StoredEncryptedNote, TransparentCredit, TransparentDebit,
};
pub use storage::{
    write_shield_set_to_batch, ShieldedBatch, ALL_SHIELDED_CFS,
    CF_SHIELD_CIRCUIT_VKEYS, CF_SHIELD_COMMITMENTS, CF_SHIELD_FRONTIER,
    CF_SHIELD_NOTES_ENC, CF_SHIELD_NULLIFIERS, CF_SHIELD_ROOTS,
};
pub use tx_types::{
    ShieldDepositTx, ShieldWithdrawTx, ShieldedTransferTx, ShieldedTxError,
    MAX_NULLIFIERS_PER_TX, MAX_OUTPUTS_PER_TX, MIN_SHIELDED_FEE,
};
pub use types::{
    CircuitVersion, DecryptError, EncryptError, EncryptedNote, FullViewKey, IncomingViewKey,
    MerkleWitness, Note, NoteCommitment, Nullifier, NullifierKey, ShieldedProof,
    ShieldedPublicInputs, SpentRecord, TreeRoot,
};
pub use wallet_scanner::{
    LocalNullifierCache, NoteScanner, NullifierChecker, PaymentProof, ScannedBlock, ScannedNote,
    ScanStats, WalletScanError,
};
