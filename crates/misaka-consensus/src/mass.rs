//! Consensus mass calculation — canonical mass rules enforced by all nodes.
//!
//! Mass is MISAKA's equivalent of Kaspa's mass/Bitcoin's vSize. It accounts for:
//! - Serialized transaction size (same weight as Kaspa: 1 mass/byte)
//! - Signature operation cost (same as Kaspa for PQ: normalized by MAX_BLOCK_MASS increase)
//! - UTXO creation/consumption costs (same as Kaspa)
//! - Script complexity (same as Kaspa)
//!
//! # Kaspa→MISAKA Mass Mapping
//!
//! ML-DSA-65 signatures are ~51× larger than Schnorr, but we compensate by
//! increasing MAX_BLOCK_MASS from 500K to 2M (4×). The per-byte mass rate
//! remains identical to Kaspa, so the effective "TX slots per block" is:
//!
//! | | Kaspa | MISAKA |
//! |---|---|---|
//! | Std TX size | ~220 bytes | ~5,500 bytes |
//! | Std TX mass | ~2,500 | ~8,000 |
//! | Max block mass | 500,000 | 2,000,000 |
//! | TXs/block | ~200 | ~250 |
//! | BPS | 1 | 10 |
//! | **Effective TPS** | **~200** | **~2,500** |

/// Consensus mass parameters — identical weighting to Kaspa.
/// The PQ signature size increase is absorbed by MAX_BLOCK_MASS increase.
pub const MASS_PER_TX_BYTE: u64 = 1; // Same as Kaspa
pub const MASS_PER_SCRIPT_PUB_KEY_BYTE: u64 = 10; // Same as Kaspa
pub const MASS_PER_SIG_OP: u64 = 1000; // Same as Kaspa (classic)
pub const MASS_PER_INPUT: u64 = 100; // Same as Kaspa
pub const MASS_PER_OUTPUT: u64 = 50; // Same as Kaspa
pub const BASE_MASS: u64 = 100; // Same as Kaspa
pub const MASS_PER_PQ_SIG_OP: u64 = 1000; // Same as classic (normalized by block mass)
pub const MAX_TX_MASS: u64 = 200_000; // 2× Kaspa (PQ sigs larger)
pub const MAX_BLOCK_MASS: u64 = 2_000_000; // 4× Kaspa (absorbs PQ size)

/// Transaction data for consensus mass calculation.
pub struct ConsensusTxData<'a> {
    pub raw_bytes: &'a [u8],
    pub inputs: &'a [ConsensusInput],
    pub outputs: &'a [ConsensusOutput],
}

pub struct ConsensusInput {
    pub sig_script_len: usize,
    pub sig_op_count: u32,
    pub is_pq: bool,
}

pub struct ConsensusOutput {
    pub script_pub_key_len: usize,
}

/// Calculate consensus mass for a transaction.
pub fn calculate_consensus_mass(tx: &ConsensusTxData) -> u64 {
    let mut mass = BASE_MASS;
    mass += tx.raw_bytes.len() as u64 * MASS_PER_TX_BYTE;

    for input in tx.inputs {
        mass += MASS_PER_INPUT;
        if input.is_pq {
            mass += input.sig_op_count as u64 * MASS_PER_PQ_SIG_OP;
        } else {
            mass += input.sig_op_count as u64 * MASS_PER_SIG_OP;
        }
    }

    for output in tx.outputs {
        mass += MASS_PER_OUTPUT;
        mass += output.script_pub_key_len as u64 * MASS_PER_SCRIPT_PUB_KEY_BYTE;
    }

    mass
}

/// Validate that a transaction's mass is within limits.
pub fn validate_tx_mass(mass: u64) -> Result<(), MassError> {
    if mass > MAX_TX_MASS {
        Err(MassError::TxMassExceeded {
            mass,
            max: MAX_TX_MASS,
        })
    } else {
        Ok(())
    }
}

/// Validate that a block's total mass is within limits.
pub fn validate_block_mass(total_mass: u64) -> Result<(), MassError> {
    if total_mass > MAX_BLOCK_MASS {
        Err(MassError::BlockMassExceeded {
            mass: total_mass,
            max: MAX_BLOCK_MASS,
        })
    } else {
        Ok(())
    }
}

/// Dust policy — minimum output value based on output size.
pub fn is_dust(value: u64, script_pub_key_len: usize) -> bool {
    if value == 0 {
        return true;
    }
    // Minimum value = 3 * (serialized_size_to_spend) to ensure
    // the output is economically viable to spend
    let spend_cost = 3 * (script_pub_key_len as u64 + 200);
    value < spend_cost.max(546)
}

/// Dust threshold for a standard PQ P2PKH output.
pub fn standard_dust_threshold() -> u64 {
    // Standard PQ P2PKH script is 37 bytes
    // Spend size: ~3400 bytes (PQ sig) + ~200 bytes overhead
    // At fee rate 1.0: 3600 mass → 3600 fee
    // Dust = 3 * 3600 = 10800
    // But we cap at a reasonable minimum
    1000
}

#[derive(Debug, thiserror::Error)]
pub enum MassError {
    #[error("transaction mass {mass} exceeds limit {max}")]
    TxMassExceeded { mass: u64, max: u64 },
    #[error("block mass {mass} exceeds limit {max}")]
    BlockMassExceeded { mass: u64, max: u64 },
}

/// Past median time calculation.
pub fn calculate_past_median_time(timestamps: &[u64]) -> u64 {
    if timestamps.is_empty() {
        return 0;
    }
    let mut sorted = timestamps.to_vec();
    sorted.sort();
    sorted[sorted.len() / 2]
}

/// Timestamp validation.
pub fn validate_timestamp(
    block_time: u64,
    past_median_time: u64,
    max_future_offset: u64,
) -> Result<(), TimestampError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if block_time <= past_median_time {
        return Err(TimestampError::BeforeMedian {
            block_time,
            median: past_median_time,
        });
    }
    if block_time > now + max_future_offset {
        return Err(TimestampError::TooFarFuture {
            block_time,
            max: now + max_future_offset,
        });
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum TimestampError {
    #[error("timestamp {block_time} <= median {median}")]
    BeforeMedian { block_time: u64, median: u64 },
    #[error("timestamp {block_time} > max allowed {max}")]
    TooFarFuture { block_time: u64, max: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dust_policy() {
        assert!(is_dust(0, 37));
        assert!(is_dust(100, 37));
        assert!(!is_dust(100_000, 37));
    }

    #[test]
    fn test_past_median_time() {
        let times = vec![100, 200, 300, 400, 500];
        assert_eq!(calculate_past_median_time(&times), 300);
    }
}
