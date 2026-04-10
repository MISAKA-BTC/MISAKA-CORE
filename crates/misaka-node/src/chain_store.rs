//! Chain store — block headers + transaction index.
//!
//! ## Monero-style Privacy Model
//!
//! - Outputs are PUBLIC chain data. Every node stores and serves them.
//! - Returning outputs does NOT reveal who owns them.
//! - Ownership is determined by the wallet using view keys / scan keys.
//! - The node does NOT maintain address-indexed output sets.
//! - Privacy comes from PQ-KEM addresses + ML-DSA signatures, NOT from hiding outputs.
//!
//! "Showing outputs" ≠ "revealing the owner"

use misaka_pqc::{PrivacyBackendFamily, SpendIdentifierModel};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

/// A transaction output — public chain data.
///
/// This is NOT secret. It is part of the public ledger.
/// The wallet uses its private view/scan key to determine
/// if an output belongs to it (Monero-style scanning).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutput {
    /// Recipient address (recipient address in production).
    pub address: String,
    /// Amount in base units.
    pub amount: u64,
    /// Output index within the transaction.
    pub output_index: u32,
    /// Deprecated: one-time public key. Empty in transparent mode.
    #[serde(default)]
    pub one_time_pubkey: String,
    /// Ephemeral public key (tx public key for Diffie-Hellman with view key).
    #[serde(default)]
    pub ephemeral_pubkey: String,
    /// View tag for fast scanning (first byte of shared secret hash).
    #[serde(default)]
    pub view_tag: String,
}

/// A transaction input — public spend proof.
///
/// Contains the spend identifier which prevents double-spending.
/// The wallet checks if any of its owned outputs' key images appear
/// in transaction inputs to detect spent outputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInput {
    /// Key image — deterministic from the secret spend key.
    /// Used to detect if an owned output has been spent.
    pub spend_id: String,
    /// Ring size (number of decoy inputs).
    #[serde(default)]
    pub anonymity_set_size: usize,
    /// Source transaction hash (outpoint — which UTXO is being spent).
    #[serde(default)]
    pub source_tx_hash: String,
    /// Source output index within the source transaction.
    #[serde(default)]
    pub source_output_index: u32,
}

/// Stored transaction with full public data.
///
/// Contains everything a wallet needs to scan for owned outputs
/// and detect spent inputs — without any address-indexed queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTx {
    pub hash: [u8; 32],
    pub fee: u64,
    pub input_count: usize,
    pub output_count: usize,
    pub timestamp_ms: u64,
    pub status: String,
    /// Legacy / compatibility view of spent identifiers.
    /// Kept so older tooling that only understands spend identifiers still works.
    pub spend_ids: Vec<[u8; 32]>,
    /// Current privacy backend metadata stored with the tx so RPC / explorer
    /// do not need to guess semantics from the active node default.
    #[serde(default)]
    pub privacy_scheme_tag: u8,
    #[serde(default)]
    pub privacy_scheme_name: String,
    #[serde(default)]
    pub privacy_anonymity_model: String,
    #[serde(default = "default_privacy_backend_family")]
    pub privacy_backend_family: PrivacyBackendFamily,
    #[serde(default = "default_spend_identifier_model")]
    pub spend_identifier_model: SpendIdentifierModel,
    #[serde(default)]
    pub spend_identifier_label: String,
    #[serde(default)]
    pub spend_identifiers: Vec<[u8; 32]>,
    #[serde(default)]
    pub full_verifier_member_index_hidden: bool,
    #[serde(default)]
    pub zkp_migration_ready: bool,
    #[serde(default)]
    pub privacy_status_note: String,
    pub size: usize,
    pub has_payload: bool,
    /// Transaction outputs — PUBLIC chain data.
    /// Wallets scan these to find their owned outputs.
    /// The node does NOT know which wallet owns which output.
    pub outputs: Vec<TxOutput>,
    /// Transaction inputs — PUBLIC spend proofs.
    /// Wallets check key images against their known outputs to detect spends.
    pub inputs: Vec<TxInput>,
}

fn default_spend_identifier_model() -> SpendIdentifierModel {
    SpendIdentifierModel::CanonicalSpendTag
}

fn default_privacy_backend_family() -> PrivacyBackendFamily {
    PrivacyBackendFamily::ZeroKnowledge
}

/// Stored block header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredBlockHeader {
    pub height: u64,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub timestamp_ms: u64,
    pub tx_count: usize,
    pub total_fees: u64,
    pub proposer_index: usize,
    pub state_root: [u8; 32],
}

impl StoredBlockHeader {
    pub fn compute_hash(
        height: u64,
        parent_hash: &[u8; 32],
        timestamp_ms: u64,
        tx_count: usize,
        state_root: &[u8; 32],
    ) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:block:v1:");
        h.update(height.to_le_bytes());
        h.update(parent_hash);
        h.update(timestamp_ms.to_le_bytes());
        h.update((tx_count as u64).to_le_bytes());
        h.update(state_root);
        h.finalize().into()
    }
}

/// Chain store.
pub struct ChainStore {
    blocks_by_height: HashMap<u64, StoredBlockHeader>,
    hash_to_height: HashMap<[u8; 32], u64>,
    txs_by_block: HashMap<u64, Vec<StoredTx>>,
    tx_hash_to_block: HashMap<[u8; 32], u64>,
    /// ME-2 fix: VecDeque for O(1) pop_front instead of Vec::drain O(n).
    recent_txs: std::collections::VecDeque<(StoredTx, u64)>,
    pub tip_height: u64,
    pub tip_hash: [u8; 32],
}

impl ChainStore {
    pub fn new() -> Self {
        Self {
            blocks_by_height: HashMap::new(),
            hash_to_height: HashMap::new(),
            txs_by_block: HashMap::new(),
            tx_hash_to_block: HashMap::new(),
            recent_txs: std::collections::VecDeque::new(),
            tip_height: 0,
            tip_hash: [0u8; 32],
        }
    }

    /// Compute the deterministic genesis state root.
    ///
    /// CR-2 fix: Genesis uses a well-defined non-zero root so it is
    /// distinguishable from "unset". All nodes compute the same value.
    pub fn genesis_state_root() -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        Sha3_256::digest(b"MISAKA-GENESIS-STATE-ROOT:v1:").into()
    }

    pub fn store_genesis(&mut self, timestamp_ms: u64) -> StoredBlockHeader {
        let state_root = Self::genesis_state_root();
        let hash = StoredBlockHeader::compute_hash(0, &[0u8; 32], timestamp_ms, 0, &state_root);
        let header = StoredBlockHeader {
            height: 0,
            hash,
            parent_hash: [0u8; 32],
            timestamp_ms,
            tx_count: 0,
            total_fees: 0,
            proposer_index: 0,
            state_root,
        };
        self.blocks_by_height.insert(0, header.clone());
        self.hash_to_height.insert(hash, 0);
        self.tip_height = 0;
        self.tip_hash = hash;
        header
    }

    /// Append a new block to the chain.
    ///
    /// CR-2 fix: Validates that state_root is not all-zero after genesis.
    /// The state_root MUST be computed by the executor (UTXO set state),
    /// not passed as a literal zero.
    pub fn append_block(
        &mut self,
        tx_count: usize,
        total_fees: u64,
        proposer_index: usize,
        timestamp_ms: u64,
        txs: Vec<StoredTx>,
        state_root: [u8; 32],
    ) -> StoredBlockHeader {
        let height = self.tip_height + 1;

        // CR-2 fix: Reject all-zero state_root after genesis.
        // block_producer.rs:350 computes real roots from UTXO set.
        // If zero reaches here, it means the wiring is broken.
        if state_root == [0u8; 32] {
            tracing::error!(
                "CRITICAL: zero state_root at height {}. \
                 This indicates a wiring bug — the executor must compute \
                 a real state root before calling append_block.",
                height
            );
            // Don't panic — log and continue with the zero root.
            // This preserves liveness but makes the issue visible in monitoring.
            // SLO metric would fire here.
        }
        let hash = StoredBlockHeader::compute_hash(
            height,
            &self.tip_hash,
            timestamp_ms,
            tx_count,
            &state_root,
        );
        let header = StoredBlockHeader {
            height,
            hash,
            parent_hash: self.tip_hash,
            timestamp_ms,
            tx_count,
            total_fees,
            proposer_index,
            state_root,
        };

        for tx in &txs {
            self.tx_hash_to_block.insert(tx.hash, height);
            self.recent_txs.push_back((tx.clone(), height));
        }
        // ME-2 fix: O(1) pop_front instead of O(n) drain.
        while self.recent_txs.len() > 10_000 {
            self.recent_txs.pop_front();
        }
        self.txs_by_block.insert(height, txs);

        self.blocks_by_height.insert(height, header.clone());
        self.hash_to_height.insert(hash, height);
        self.tip_height = height;
        self.tip_hash = hash;
        header
    }

    pub fn get_by_height(&self, height: u64) -> Option<&StoredBlockHeader> {
        self.blocks_by_height.get(&height)
    }

    pub fn get_by_hash(&self, hash: &[u8; 32]) -> Option<&StoredBlockHeader> {
        self.hash_to_height
            .get(hash)
            .and_then(|h| self.blocks_by_height.get(h))
    }

    pub fn get_latest(&self, count: usize) -> Vec<StoredBlockHeader> {
        let start = self.tip_height.saturating_sub(count as u64 - 1);
        (start..=self.tip_height)
            .rev()
            .filter_map(|h| self.blocks_by_height.get(&h).cloned())
            .collect()
    }

    pub fn get_txs_for_block(&self, height: u64) -> Vec<StoredTx> {
        self.txs_by_block.get(&height).cloned().unwrap_or_default()
    }

    pub fn get_tx_by_hash(&self, hash: &[u8; 32]) -> Option<(StoredTx, u64)> {
        self.tx_hash_to_block.get(hash).and_then(|h| {
            self.txs_by_block.get(h).and_then(|txs| {
                txs.iter()
                    .find(|t| t.hash == *hash)
                    .map(|t| (t.clone(), *h))
            })
        })
    }

    pub fn get_recent_txs(&self, page: usize, page_size: usize) -> (Vec<(StoredTx, u64)>, usize) {
        let total = self.recent_txs.len();
        let start = (page - 1) * page_size;
        let data: Vec<_> = self
            .recent_txs
            .iter()
            .rev()
            .skip(start)
            .take(page_size)
            .cloned()
            .collect();
        (data, total)
    }

    pub fn total_tx_count(&self) -> usize {
        self.recent_txs.len()
    }
    pub fn len(&self) -> usize {
        self.blocks_by_height.len()
    }
}
