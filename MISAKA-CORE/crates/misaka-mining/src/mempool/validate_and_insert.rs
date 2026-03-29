//! Transaction validation and insertion pipeline.

use crate::errors::{MiningError, MiningResult};
use crate::mempool::Mempool;
use crate::mempool::model::tx::MempoolTransaction;
use crate::mempool::tx::{Orphan, Priority, RbfPolicy};
use crate::mempool::check_transaction_standard::check_transaction_standard;
use crate::model::tx_insert::TransactionInsertion;

/// Validate and insert a transaction into the mempool.
pub fn validate_and_insert_transaction(
    mempool: &mut Mempool,
    tx: MempoolTransaction,
    orphan_policy: Orphan,
    priority: Priority,
    rbf_policy: RbfPolicy,
) -> MiningResult<TransactionInsertion> {
    let tx_id = tx.tx_id;

    // Check if already in mempool
    if mempool.contains(&tx_id) {
        return Err(MiningError::TxAlreadyExists(hex::encode(tx_id)));
    }

    // Standard transaction checks
    if priority != Priority::High {
        check_transaction_standard(&tx).map_err(MiningError::MempoolRule)?;
    }

    // Check for double-spends
    let mut replaced_tx = None;
    for outpoint in &tx.input_outpoints {
        if let Some(conflicting) = mempool.spending_tx(outpoint) {
            match rbf_policy {
                RbfPolicy::Forbidden => {
                    return Err(MiningError::MempoolRule(
                        crate::errors::MempoolRuleError::DoubleSpend(hex::encode(outpoint))
                    ));
                }
                RbfPolicy::Allowed | RbfPolicy::FullRbf => {
                    if let Some(existing) = mempool.get(&conflicting) {
                        if tx.fee <= existing.fee {
                            return Err(MiningError::MempoolRule(
                                crate::errors::MempoolRuleError::RbfInsufficientFee {
                                    old: existing.fee,
                                    new: tx.fee,
                                    min_increment: (existing.fee as f64 * 0.25) as u64,
                                }
                            ));
                        }
                    }
                    replaced_tx = Some(conflicting);
                }
            }
        }
    }

    // Remove conflicting transaction if RBF
    if let Some(replaced) = replaced_tx {
        mempool.remove(&replaced);
    }

    // Insert into mempool
    mempool.insert(tx)?;

    // Try to resolve orphans
    let unorphaned_txs = mempool.try_resolve_orphans(&tx_id);
    let unorphaned: Vec<[u8; 32]> = unorphaned_txs.iter().map(|t| t.tx_id).collect();

    // Insert resolved orphans
    for resolved_tx in unorphaned_txs {
        let _ = mempool.insert(resolved_tx);
    }

    Ok(TransactionInsertion {
        accepted: true,
        tx_id,
        replaced_tx,
        unorphaned,
    })
}
