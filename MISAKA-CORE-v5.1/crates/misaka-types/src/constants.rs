//! Network-wide constants.

/// Chain ID for MISAKA mainnet.
pub const MAINNET_CHAIN_ID: u32 = 1;
/// Chain ID for testnet.
pub const TESTNET_CHAIN_ID: u32 = 2;
/// Maximum transaction size in bytes.
pub const MAX_TX_SIZE: usize = 128 * 1024; // 128 KiB (increased for PQ sigs)
/// Maximum gas per transaction.
pub const MAX_GAS_PER_TX: u64 = 50_000_000;
/// Base fee per gas unit.
pub const BASE_GAS_PRICE: u64 = 1;
/// Block time target (seconds).
pub const BLOCK_TIME_SECS: u64 = 60;
/// Maximum transactions per block.
pub const MAX_TXS_PER_BLOCK: usize = 1000;
/// Epoch length in checkpoints.
pub const EPOCH_LENGTH: u64 = 720; // ~12 hours at 60s blocks
/// Minimum validators for liveness.
pub const MIN_VALIDATORS: usize = 4;
/// BFT quorum threshold (basis points, 6667 = 2/3).
pub const QUORUM_THRESHOLD_BPS: u16 = 6667;
/// ML-DSA-65 signature overhead per TX (bytes).
pub const PQ_SIG_OVERHEAD: usize = 3309 + 1952; // sig + pk
