//! Block application — full UTXO state transition.
//!
//! Orchestrates: validation → UTXO spend → UTXO create → key image commit.
//! This is the single entry point for block execution.

use misaka_consensus::block_validation::{self, BlockCandidate, BlockError};
use misaka_consensus::validator_set::ValidatorSet;
use misaka_storage::utxo_set::{BlockDelta, UtxoSet};

// 必要な型を misaka-types からインポート
/// Full block execution result.
#[derive(Debug)]
pub struct BlockResult {
    pub height: u64,
    pub tx_count: usize,
    pub total_fees: u64,
    pub utxos_created: usize,
    pub utxos_spent: usize,
    // Phase 2c-B D4c: spend_ids_added deleted
}

/// Execute a block: validate all txs, apply state changes, return result.
///
/// This is the ONLY way to modify the UTXO set from block data.
///
/// # Proposer Verification Responsibility
///
/// ALL validation (including proposer sig, block hash binding, tx validation)
/// is delegated to `validate_and_apply_block`. This function does NOT
/// duplicate any checks — it is a thin orchestration layer.
#[allow(deprecated)]
pub fn execute_block(
    block: &BlockCandidate,
    utxo_set: &mut UtxoSet,
    validator_set: Option<&ValidatorSet>,
) -> Result<BlockResult, BlockError> {
    // γ-2: pass `None` for staking_registry — the legacy block_apply path does
    // not carry a registry reference. The DAG-mode utxo_executor (γ-3) wires
    // the registry through so that StakeDeposit / StakeWithdraw txs get their
    // signature + state verified before the validator account is mutated.
    let delta =
        block_validation::validate_and_apply_block(block, utxo_set, validator_set, None)?;

    // SEC-FIX: Use checked_add to prevent silent overflow in release builds.
    // 256 txs with fee near u64::MAX would wrap to a small number.
    let total_fees: u64 = block
        .transactions
        .iter()
        .map(|vtx| vtx.tx.fee)
        .try_fold(0u64, |acc, fee| acc.checked_add(fee))
        .ok_or(BlockError::FeeOverflow)?;

    Ok(BlockResult {
        height: block.height,
        tx_count: block.transactions.len(),
        total_fees,
        utxos_created: delta.created.len(),
        utxos_spent: delta.spent.len(),
    })
}

/// Undo the last block (for SPC switch only).
///
/// This is NOT a protocol-level rollback. Used exclusively during
/// shallow Selected Parent Chain switches. Finality boundary check
/// MUST be performed by the caller before invoking this.
pub fn undo_last_block(utxo_set: &mut UtxoSet) -> Result<BlockDelta, BlockError> {
    block_validation::undo_last_block(utxo_set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_consensus::block_validation::{VerifiedProof, VerifiedTx};
    use misaka_pqc::key_derivation::{derive_public_param, Poly, SpendingKeypair, DEFAULT_A_SEED};
    use misaka_pqc::pq_sign::MlDsaKeypair;
    use misaka_types::utxo::*;

    fn setup() -> (UtxoSet, Vec<SpendingKeypair>, Poly) {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let mut utxo_set = UtxoSet::new(100);
        let wallets: Vec<SpendingKeypair> = (0..6)
            .map(|_| {
                let kp = MlDsaKeypair::generate();
                let pk_bytes = kp.public_key.as_bytes().to_vec();
                SpendingKeypair::from_ml_dsa_pair(kp.secret_key, pk_bytes).unwrap()
            })
            .collect();
        for (i, w) in wallets.iter().enumerate() {
            let outref = OutputRef {
                tx_hash: [(i + 1) as u8; 32],
                output_index: 0,
            };
            utxo_set
                .add_output(
                    outref.clone(),
                    TxOutput {
                        amount: 10_000,
                        address: [0xAA; 32],
                        spending_pubkey: Some(w.ml_dsa_pk().to_vec()),
                    },
                    0,
                    false,
                )
                .unwrap();
            utxo_set
                .register_spending_key(outref, w.ml_dsa_pk().to_vec())
                .expect("test: register_spending_key");
        }
        (utxo_set, wallets, a)
    }

    fn make_vtx(wallets: &[SpendingKeypair], amount: u64, fee: u64) -> VerifiedTx {
        let ring_pks: Vec<Poly> = vec![wallets[0].public_poly.clone()];

        // D4b: spend-tag field removed from TxInput

        let tx = UtxoTransaction {
            tx_type: TxType::TransparentTransfer,
            version: UTXO_TX_VERSION,
            inputs: vec![TxInput {
                utxo_refs: vec![OutputRef {
                    tx_hash: [1u8; 32],
                    output_index: 0,
                }],
                proof: vec![], // will be filled with ML-DSA sig
            }],
            outputs: vec![
                TxOutput {
                    amount,
                    address: [0xCC; 32],
                    spending_pubkey: None,
                },
                TxOutput {
                    amount: 10_000 - amount - fee,
                    address: [0xCC; 32],
                    spending_pubkey: None,
                },
            ],
            fee,
            extra: vec![],
            expiry: 0,
        };

        // Sign with ML-DSA-65
        // Phase 2c-B: signing_digest deleted; use tx_hash for v1 compat
        let digest = tx.tx_hash();
        let sig = misaka_pqc::ml_dsa_sign_raw(&wallets[0].ml_dsa_sk, &digest).unwrap();

        let mut tx_final = tx;
        tx_final.inputs[0].proof = sig.as_bytes().to_vec();

        VerifiedTx {
            tx: tx_final,
            ring_pubkeys: vec![ring_pks],
            raw_spending_keys: vec![wallets[0].ml_dsa_pk().to_vec()],
            ring_amounts: vec![vec![10_000]],
            ring_proofs: vec![VerifiedProof::Transparent {
                raw_sig: sig.as_bytes().to_vec(),
            }],
        }
    }

    #[test]
    fn test_execute_block_ok() {
        let (mut utxo_set, wallets, _a) = setup();
        let vtx = make_vtx(&wallets, 7000, 100);
        let block = BlockCandidate {
            height: 1,
            slot: 1,
            parent_hash: [0; 32],
            transactions: vec![vtx],
            proposer_signature: None,
        };
        let result = execute_block(&block, &mut utxo_set, None).unwrap();
        assert_eq!(result.tx_count, 1);
        assert_eq!(result.total_fees, 100);
        assert_eq!(result.utxos_created, 2);
        assert_eq!(result.utxos_spent, 1);
    }

    #[test]
    fn test_execute_and_rollback() {
        let (mut utxo_set, wallets, _a) = setup();
        let _initial = utxo_set.len();
        let vtx = make_vtx(&wallets, 7000, 100);
        let block = BlockCandidate {
            height: 1,
            slot: 1,
            parent_hash: [0; 32],
            transactions: vec![vtx],
            proposer_signature: None,
        };
        execute_block(&block, &mut utxo_set, None).unwrap();
        assert_eq!(utxo_set.height, 1);
        undo_last_block(&mut utxo_set).unwrap();
        assert_eq!(utxo_set.height, 0);
    }
}
