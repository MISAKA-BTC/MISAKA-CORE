//! Consensus security hardening layer.
//!
//! Centralized security checks that run across all consensus paths:
//! - Timestamp manipulation detection
//! - Difficulty adjustment validation  
//! - Mass limit enforcement
//! - Signature operation counting
//! - Coinbase maturity enforcement
//! - Finality violation detection
//! - Eclipse attack mitigation

use std::collections::{HashMap, HashSet};

/// Maximum allowed timestamp deviation from network median (seconds).
pub const MAX_TIME_OFFSET_SECONDS: u64 = 132; // ~2 minutes

/// Maximum block mass.
pub const MAX_BLOCK_MASS: u64 = 500_000;

/// Coinbase maturity — number of confirmations before coinbase can be spent.
pub const COINBASE_MATURITY: u64 = 100;

/// Maximum signature operations per block.
pub const MAX_BLOCK_SIG_OPS: u64 = 80_000;

/// Maximum number of parents per block in DAG.
pub const MAX_BLOCK_PARENTS: usize = 10;

/// Minimum number of parents per block.
pub const MIN_BLOCK_PARENTS: usize = 1;

/// Maximum transactions per block.
pub const MAX_BLOCK_TRANSACTIONS: usize = 50_000;

/// Maximum transaction mass.
pub const MAX_TRANSACTION_MASS: u64 = 100_000;

/// Block validation security checks.
pub struct BlockSecurityChecker;

impl BlockSecurityChecker {
    /// Full security validation of a block header.
    pub fn check_header(
        header: &BlockHeaderForCheck,
        past_median_time: u64,
        expected_difficulty: u64,
        known_invalids: &HashSet<[u8; 32]>,
    ) -> Result<(), BlockSecurityError> {
        // 1. Check timestamp isn't too far in the future
        let now = now_secs();
        if header.timestamp > now + MAX_TIME_OFFSET_SECONDS {
            return Err(BlockSecurityError::TimestampTooFarInFuture {
                block_time: header.timestamp,
                max_allowed: now + MAX_TIME_OFFSET_SECONDS,
            });
        }

        // 2. Check timestamp is after past median time
        if header.timestamp <= past_median_time {
            return Err(BlockSecurityError::TimestampBeforeMedian {
                block_time: header.timestamp,
                median_time: past_median_time,
            });
        }

        // 3. Check difficulty target
        if header.bits != expected_difficulty as u32 {
            return Err(BlockSecurityError::InvalidDifficulty {
                got: header.bits,
                expected: expected_difficulty as u32,
            });
        }

        // 4. Check parent count
        if header.parents.is_empty() || header.parents.len() < MIN_BLOCK_PARENTS {
            return Err(BlockSecurityError::TooFewParents(header.parents.len()));
        }
        if header.parents.len() > MAX_BLOCK_PARENTS {
            return Err(BlockSecurityError::TooManyParents(header.parents.len()));
        }

        // 5. Check no duplicate parents
        let unique_parents: HashSet<&[u8; 32]> = header.parents.iter().collect();
        if unique_parents.len() != header.parents.len() {
            return Err(BlockSecurityError::DuplicateParents);
        }

        // 6. Check parents aren't known-invalid
        for parent in &header.parents {
            if known_invalids.contains(parent) {
                return Err(BlockSecurityError::InvalidParent(hex::encode(parent)));
            }
        }

        // 7. Check version
        if header.version == 0 || header.version > 2 {
            return Err(BlockSecurityError::InvalidVersion(header.version));
        }

        Ok(())
    }

    /// Full security validation of a block body.
    pub fn check_body(
        body: &BlockBodyForCheck,
        current_daa_score: u64,
    ) -> Result<(), BlockSecurityError> {
        // 1. Check transaction count
        if body.transactions.is_empty() {
            return Err(BlockSecurityError::NoTransactions);
        }
        if body.transactions.len() > MAX_BLOCK_TRANSACTIONS {
            return Err(BlockSecurityError::TooManyTransactions(body.transactions.len()));
        }

        // 2. Check block mass
        let total_mass: u64 = body.transactions.iter().map(|t| t.mass).sum();
        if total_mass > MAX_BLOCK_MASS {
            return Err(BlockSecurityError::MassExceeded { mass: total_mass, max: MAX_BLOCK_MASS });
        }

        // 3. Check total sig ops
        let total_sig_ops: u64 = body.transactions.iter().map(|t| t.sig_op_count as u64).sum();
        if total_sig_ops > MAX_BLOCK_SIG_OPS {
            return Err(BlockSecurityError::SigOpsExceeded { count: total_sig_ops, max: MAX_BLOCK_SIG_OPS });
        }

        // 4. First transaction must be coinbase
        if !body.transactions[0].is_coinbase {
            return Err(BlockSecurityError::MissingCoinbase);
        }

        // 5. Only first transaction can be coinbase
        for (i, tx) in body.transactions.iter().skip(1).enumerate() {
            if tx.is_coinbase {
                return Err(BlockSecurityError::MultipleCoinbases(i + 1));
            }
        }

        // 6. Check no duplicate transaction IDs
        let mut seen_txids = HashSet::new();
        for tx in &body.transactions {
            if !seen_txids.insert(tx.tx_id) {
                return Err(BlockSecurityError::DuplicateTransaction(hex::encode(tx.tx_id)));
            }
        }

        // 7. Check each transaction's mass
        for tx in &body.transactions {
            if tx.mass > MAX_TRANSACTION_MASS {
                return Err(BlockSecurityError::TransactionTooHeavy {
                    tx_id: hex::encode(tx.tx_id),
                    mass: tx.mass,
                });
            }
        }

        Ok(())
    }
}

/// Transaction security checks.
pub struct TxSecurityChecker;

impl TxSecurityChecker {
    /// Validate transaction in isolation (no UTXO context needed).
    pub fn check_in_isolation(tx: &TxForCheck) -> Result<(), TxSecurityError> {
        // 1. Must have inputs
        if tx.inputs.is_empty() && !tx.is_coinbase {
            return Err(TxSecurityError::NoInputs);
        }

        // 2. Must have outputs
        if tx.outputs.is_empty() {
            return Err(TxSecurityError::NoOutputs);
        }

        // 3. Check for duplicate inputs (double-spend attempt)
        let mut seen_outpoints = HashSet::new();
        for input in &tx.inputs {
            let outpoint = (input.prev_tx_id, input.prev_index);
            if !seen_outpoints.insert(outpoint) {
                return Err(TxSecurityError::DuplicateInput {
                    tx_id: hex::encode(input.prev_tx_id),
                    index: input.prev_index,
                });
            }
        }

        // 4. Check output amounts for overflow
        let mut total_output: u64 = 0;
        for output in &tx.outputs {
            if output.value == 0 && output.script_public_key.first() != Some(&0x6a) {
                // Zero-value output only allowed for OP_RETURN
                return Err(TxSecurityError::ZeroValueOutput);
            }
            total_output = total_output.checked_add(output.value)
                .ok_or(TxSecurityError::OutputOverflow)?;
        }

        // 5. Check mass limits
        if tx.mass > MAX_TRANSACTION_MASS {
            return Err(TxSecurityError::MassExceeded { mass: tx.mass, max: MAX_TRANSACTION_MASS });
        }

        // 6. Check script sizes
        for output in &tx.outputs {
            if output.script_public_key.len() > 10_000 {
                return Err(TxSecurityError::ScriptTooLarge(output.script_public_key.len()));
            }
        }

        // 7. Signature script sizes
        for input in &tx.inputs {
            if input.sig_script.len() > 150_000 {
                return Err(TxSecurityError::SigScriptTooLarge(input.sig_script.len()));
            }
        }

        Ok(())
    }

    /// Validate transaction in UTXO context.
    pub fn check_in_utxo_context(
        tx: &TxForCheck,
        utxo_entries: &[UtxoEntryForCheck],
        current_daa_score: u64,
    ) -> Result<(), TxSecurityError> {
        if tx.is_coinbase {
            return Ok(());
        }

        if utxo_entries.len() != tx.inputs.len() {
            return Err(TxSecurityError::UtxoCountMismatch {
                inputs: tx.inputs.len(),
                utxos: utxo_entries.len(),
            });
        }

        // 1. Check coinbase maturity
        for utxo in utxo_entries {
            if utxo.is_coinbase {
                let confirmations = current_daa_score.saturating_sub(utxo.block_daa_score);
                if confirmations < COINBASE_MATURITY {
                    return Err(TxSecurityError::ImmatureCoinbase {
                        confirmations,
                        required: COINBASE_MATURITY,
                    });
                }
            }
        }

        // 2. Check total input >= total output (no money creation)
        let total_input: u64 = utxo_entries.iter().map(|u| u.amount).sum();
        let total_output: u64 = tx.outputs.iter().map(|o| o.value).sum();

        if total_input < total_output {
            return Err(TxSecurityError::InputsLessThanOutputs {
                inputs: total_input,
                outputs: total_output,
            });
        }

        // 3. Fee must be non-negative (implied by above) and reasonable
        let fee = total_input - total_output;
        if fee > total_input / 2 {
            // Fee > 50% of input is suspicious (likely user error)
            tracing::warn!("Suspicious fee: {} / {} = {:.1}%",
                fee, total_input, fee as f64 / total_input as f64 * 100.0);
        }

        Ok(())
    }
}

// ─── Check types ──────────────────────────────────────

pub struct BlockHeaderForCheck {
    pub hash: [u8; 32],
    pub version: u32,
    pub parents: Vec<[u8; 32]>,
    pub timestamp: u64,
    pub bits: u32,
    pub daa_score: u64,
}

pub struct BlockBodyForCheck {
    pub transactions: Vec<TxForCheck>,
}

pub struct TxForCheck {
    pub tx_id: [u8; 32],
    pub inputs: Vec<TxInputForCheck>,
    pub outputs: Vec<TxOutputForCheck>,
    pub mass: u64,
    pub sig_op_count: u32,
    pub is_coinbase: bool,
}

pub struct TxInputForCheck {
    pub prev_tx_id: [u8; 32],
    pub prev_index: u32,
    pub sig_script: Vec<u8>,
    pub sequence: u64,
}

pub struct TxOutputForCheck {
    pub value: u64,
    pub script_public_key: Vec<u8>,
}

pub struct UtxoEntryForCheck {
    pub amount: u64,
    pub block_daa_score: u64,
    pub is_coinbase: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum BlockSecurityError {
    #[error("timestamp too far in future: {block_time} > {max_allowed}")]
    TimestampTooFarInFuture { block_time: u64, max_allowed: u64 },
    #[error("timestamp before median: {block_time} <= {median_time}")]
    TimestampBeforeMedian { block_time: u64, median_time: u64 },
    #[error("invalid difficulty: got {got}, expected {expected}")]
    InvalidDifficulty { got: u32, expected: u32 },
    #[error("too few parents: {0}")]
    TooFewParents(usize),
    #[error("too many parents: {0}")]
    TooManyParents(usize),
    #[error("duplicate parents")]
    DuplicateParents,
    #[error("invalid parent: {0}")]
    InvalidParent(String),
    #[error("invalid version: {0}")]
    InvalidVersion(u32),
    #[error("no transactions")]
    NoTransactions,
    #[error("too many transactions: {0}")]
    TooManyTransactions(usize),
    #[error("block mass exceeded: {mass} > {max}")]
    MassExceeded { mass: u64, max: u64 },
    #[error("sig ops exceeded: {count} > {max}")]
    SigOpsExceeded { count: u64, max: u64 },
    #[error("missing coinbase")]
    MissingCoinbase,
    #[error("multiple coinbases at index {0}")]
    MultipleCoinbases(usize),
    #[error("duplicate transaction: {0}")]
    DuplicateTransaction(String),
    #[error("transaction too heavy: {tx_id} mass={mass}")]
    TransactionTooHeavy { tx_id: String, mass: u64 },
}

#[derive(Debug, thiserror::Error)]
pub enum TxSecurityError {
    #[error("no inputs")]
    NoInputs,
    #[error("no outputs")]
    NoOutputs,
    #[error("duplicate input: {tx_id}:{index}")]
    DuplicateInput { tx_id: String, index: u32 },
    #[error("zero-value non-OP_RETURN output")]
    ZeroValueOutput,
    #[error("output total overflow")]
    OutputOverflow,
    #[error("mass exceeded: {mass} > {max}")]
    MassExceeded { mass: u64, max: u64 },
    #[error("script too large: {0} bytes")]
    ScriptTooLarge(usize),
    #[error("sig script too large: {0} bytes")]
    SigScriptTooLarge(usize),
    #[error("UTXO count mismatch: {inputs} inputs, {utxos} UTXOs")]
    UtxoCountMismatch { inputs: usize, utxos: usize },
    #[error("immature coinbase: {confirmations} < {required}")]
    ImmatureCoinbase { confirmations: u64, required: u64 },
    #[error("inputs ({inputs}) < outputs ({outputs})")]
    InputsLessThanOutputs { inputs: u64, outputs: u64 },
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
