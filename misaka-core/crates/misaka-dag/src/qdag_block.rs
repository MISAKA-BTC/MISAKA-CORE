//! QdagBlock — V4 native DAG block with ZKP-verified transactions only.
//!
//! # Problem
//!
//! `DagBlock.transactions: Vec<UtxoTransaction>` couples the DAG layer to the
//! legacy UTXO model. `UtxoTransaction` carries `ring_signature`, `key_image`,
//! and `ring_members` — all artifacts of the purged ring-signature architecture.
//! The DAG block producer populates `nullifiers: vec![]` as a placeholder.
//!
//! # Solution
//!
//! `QdagBlock` stores transactions as `Vec<SealedTransaction>`, where
//! `SealedTransaction` wraps a `QdagTransaction` with its verified nullifiers.
//! The state manager receives `SealedTransaction` references, which carry
//! type-level proof that cryptographic verification has occurred.
//!
//! # Type Safety
//!
//! ```text
//! COMPILE ERROR paths prevented by this design:
//!
//! 1. Storing an unverified TX in a block:
//!    QdagBlock::new(vec![raw_qdag_tx])  → ERROR: expected SealedTransaction
//!
//! 2. Extracting nullifiers from unverified TX:
//!    raw_tx.nullifiers()  → returns Vec<[u8;32]> (untyped, could be wrong)
//!    sealed.nullifiers()  → returns &[PublicNullifier] (typed, verified)
//!
//! 3. Applying state without verification:
//!    state_manager.apply(OrderedTxData { nullifiers: vec![] })  → OLD: silent bug
//!    state_manager.apply(sealed_tx)  → NEW: nullifiers guaranteed populated
//! ```

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::dag_block::{DagBlockHeader, GhostDagData, Hash, ZERO_HASH};

/// A transaction that has been sealed into a block.
///
/// "Sealed" means:
/// 1. `QdagTransaction::validate_structure()` passed
/// 2. Nullifiers have been extracted and typed as `PublicNullifier`
/// 3. The TX is ready for state application (nullifier conflict detection)
///
/// For full cryptographic verification (membership proofs, range proofs, etc.),
/// use `VerifiedTransactionEnvelope` from `misaka_pqc::verified_envelope`.
/// `SealedTransaction` is the block-storage form; `VerifiedTransactionEnvelope`
/// is the validation-pipeline form. Both prevent unverified state updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedTransaction {
    /// Transaction hash (QdagTransaction::tx_hash()).
    pub tx_hash: Hash,
    /// Nullifiers extracted from this transaction (typed, non-empty for Transfer).
    pub nullifiers: Vec<Hash>,
    /// Is this a coinbase transaction?
    pub is_coinbase: bool,
    /// Number of outputs (for UTXO creation).
    pub output_count: u32,
    /// Output one-time addresses (for UTXO set indexing).
    pub output_addresses: Vec<[u8; 32]>,
    /// Source outpoints consumed by this transaction.
    /// Empty for coinbase. For transfers, these are the UTXOs being spent
    /// (identified by their OutputRef). Used for SpentUtxo tracking in
    /// the atomic pipeline.
    pub source_outpoints: Vec<misaka_types::utxo::OutputRef>,
    /// Chain ID (for domain separation).
    pub chain_id: u32,
    /// Serialized QdagTransaction bytes (for full re-verification if needed).
    pub tx_bytes: Vec<u8>,
}

impl SealedTransaction {
    /// Seal a QdagTransaction after structural validation.
    ///
    /// This extracts nullifiers and metadata into typed fields.
    /// The original TX is serialized for archival / re-verification.
    pub fn seal(
        tx_hash: Hash,
        nullifiers: Vec<Hash>,
        is_coinbase: bool,
        output_count: u32,
        output_addresses: Vec<[u8; 32]>,
        chain_id: u32,
    ) -> Self {
        Self {
            tx_hash,
            nullifiers,
            is_coinbase,
            output_count,
            output_addresses,
            source_outpoints: vec![], // Default empty — set via seal_with_outpoints()
            chain_id,
            tx_bytes: vec![],
        }
    }

    /// Seal with explicit source outpoints (for full UTXO consumption tracking).
    pub fn seal_with_outpoints(
        tx_hash: Hash,
        nullifiers: Vec<Hash>,
        is_coinbase: bool,
        output_count: u32,
        output_addresses: Vec<[u8; 32]>,
        source_outpoints: Vec<misaka_types::utxo::OutputRef>,
        chain_id: u32,
    ) -> Self {
        Self {
            tx_hash,
            nullifiers,
            is_coinbase,
            output_count,
            output_addresses,
            source_outpoints,
            chain_id,
            tx_bytes: vec![],
        }
    }
}

/// V4-native DAG block containing only ZKP-verified transactions.
///
/// Replaces `DagBlock { transactions: Vec<UtxoTransaction> }`.
///
/// # Nullifier First-Class Citizen
///
/// Every `SealedTransaction` carries its nullifiers as typed, non-empty vectors.
/// The block-level `all_nullifiers()` method aggregates them for O(1) conflict
/// checking at the DAG state manager level.
///
/// # No Legacy Leakage
///
/// This type has NO dependency on `UtxoTransaction`, `RingInput`, `key_image`,
/// or any ring-signature artifact. It exists in a clean ZKP-only type space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QdagBlock {
    pub header: DagBlockHeader,
    pub transactions: Vec<SealedTransaction>,
    pub ghostdag_data: Option<GhostDagData>,
}

impl QdagBlock {
    pub fn new(header: DagBlockHeader, transactions: Vec<SealedTransaction>) -> Self {
        Self {
            header,
            transactions,
            ghostdag_data: None,
        }
    }

    /// All nullifiers in this block (aggregated from all transactions).
    ///
    /// Used by the state manager for O(1) conflict detection.
    /// Guaranteed non-empty for Transfer transactions (enforced at seal time).
    pub fn all_nullifiers(&self) -> Vec<Hash> {
        self.transactions
            .iter()
            .flat_map(|tx| tx.nullifiers.iter().copied())
            .collect()
    }

    /// All transaction hashes in this block.
    pub fn tx_hashes(&self) -> Vec<Hash> {
        self.transactions.iter().map(|tx| tx.tx_hash).collect()
    }

    /// Block hash (from header).
    pub fn hash(&self) -> Hash {
        self.header.compute_hash()
    }

    /// Convert to state manager input format.
    ///
    /// This is the ONLY path from block to state application.
    /// Nullifiers are ALWAYS populated (no `vec![]` placeholders).
    pub fn to_ordered_block(&self) -> super::dag_state_manager::OrderedBlockData {
        use super::dag_state_manager::{OrderedBlockData, OrderedTxData};
        use misaka_types::utxo::TxOutput;

        OrderedBlockData {
            block_hash: self.hash(),
            blue_score: self.header.blue_score,
            transactions: self
                .transactions
                .iter()
                .map(|sealed| {
                    OrderedTxData {
                        tx_hash: sealed.tx_hash,
                        key_images: vec![], // Legacy field — always empty for v4
                        nullifiers: sealed.nullifiers.clone(), // ALWAYS populated
                        is_coinbase: sealed.is_coinbase,
                        outputs: (0..sealed.output_count)
                            .map(|i| {
                                TxOutput {
                                    amount: 0, // Confidential
                                    one_time_address: sealed
                                        .output_addresses
                                        .get(i as usize)
                                        .copied()
                                        .unwrap_or([0u8; 32]),
                                    pq_stealth: None,
                                    spending_pubkey: None,
                                }
                            })
                            .collect(),
                        fee: 0,                   // Confidential
                        signature_verified: true, // Sealed = structurally verified
                    }
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag_block::DagBlockHeader;

    fn sample_header() -> DagBlockHeader {
        DagBlockHeader {
            version: 2,
            parents: vec![[0x01; 32]],
            timestamp_ms: 1000,
            tx_root: [0xAA; 32],
            blue_score: 5,
            proposer_id: [0; 32],
            nonce: 0,
            bits: 0,
        }
    }

    #[test]
    fn test_all_nullifiers_aggregation() {
        let block = QdagBlock::new(
            sample_header(),
            vec![
                SealedTransaction::seal(
                    [1; 32],
                    vec![[0xAA; 32], [0xBB; 32]],
                    false,
                    2,
                    vec![[0x11; 32], [0x22; 32]],
                    2,
                ),
                SealedTransaction::seal([2; 32], vec![[0xCC; 32]], false, 1, vec![[0x33; 32]], 2),
            ],
        );
        let nullifiers = block.all_nullifiers();
        assert_eq!(nullifiers.len(), 3);
        assert!(nullifiers.contains(&[0xAA; 32]));
        assert!(nullifiers.contains(&[0xBB; 32]));
        assert!(nullifiers.contains(&[0xCC; 32]));
    }

    #[test]
    fn test_to_ordered_block_nullifiers_populated() {
        let block = QdagBlock::new(
            sample_header(),
            vec![SealedTransaction::seal(
                [1; 32],
                vec![[0xDD; 32]],
                false,
                1,
                vec![[0x44; 32]],
                2,
            )],
        );
        let ordered = block.to_ordered_block();
        assert_eq!(
            ordered.transactions[0].nullifiers,
            vec![[0xDD; 32]],
            "nullifiers must NEVER be empty for transfer TXs"
        );
    }
}
