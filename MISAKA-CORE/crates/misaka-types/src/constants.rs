//! Network-wide constants — 21 SR DPoS + Dual-Lane BlockDAG + Post-Quantum
//!
//! # 設計原則
//!
//! 1. **21 SR (Super Representative)**: 固定21ノードがラウンドロビンで提案
//! 2. **Dual-Lane Block Production**:
//!    - Fast lane (通常送金): 2秒/block
//!    - ZKP lane  (匿名送金): 30秒/block
//! 3. **時間基準の保持設計**: wall-clock 時間で定義し、レーンごとに depth 変換
//! 4. **暗号方式**: ML-DSA-65 (FIPS 204) — 量子耐性
//!
//! # トランザクションレーン
//!
//! | Wall-Clock | Fast Lane (2s) | ZKP Lane (30s) |
//! |------------|----------------|----------------|
//! | 1分        | 30 blocks      | 2 blocks       |
//! | 1時間      | 1,800 blocks   | 120 blocks     |
//! | 6時間      | 10,800 blocks  | 720 blocks     |
//! | 24時間     | 43,200 blocks  | 2,880 blocks   |
//! | 7日        | 302,400 blocks | 20,160 blocks  |
//!
//! # 21 SR ラウンドロビン
//!
//! ```text
//! SR_0 → SR_1 → SR_2 → ... → SR_20 → SR_0 → SR_1 → ...
//! 1ラウンド = 21ブロック = 42秒 (Fast lane)
//! ```

// ═══ Network Identity ═══
pub const MAINNET_CHAIN_ID: u32 = 0x4D534B01;
pub const TESTNET_CHAIN_ID: u32 = 0x4D534B02;
pub const SIMNET_CHAIN_ID: u32 = 0x4D534BFF;
pub const MAINNET_NETWORK_ID: &str = "misaka-mainnet";
pub const TESTNET_NETWORK_ID: &str = "misaka-testnet-1";
pub const PROTOCOL_VERSION: u32 = 2;

// ═══ 21 SR Consensus ═══
pub const NUM_SUPER_REPRESENTATIVES: usize = 21;
pub const MAX_ACTIVE_VALIDATORS: usize = NUM_SUPER_REPRESENTATIVES;
pub const MIN_VALIDATORS: usize = 4;
pub const QUORUM_THRESHOLD_BPS: u16 = 6667; // 2/3 (15 of 21)
pub const SR_ROUND_SIZE: u64 = NUM_SUPER_REPRESENTATIVES as u64;

// ═══ Dual-Lane Block Timing ═══
pub const FAST_LANE_BLOCK_TIME_SECS: u64 = 2;
pub const ZKP_LANE_BLOCK_TIME_SECS: u64 = 30;
pub const DEFAULT_BPS: u64 = 1;
pub const TARGET_BLOCK_INTERVAL_MS: u64 = FAST_LANE_BLOCK_TIME_SECS * 1000;

// ═══ Time-Based → Depth Conversion ═══
pub const TIME_1_MIN: u64 = 60;
pub const TIME_10_MIN: u64 = 600;
pub const TIME_1_HOUR: u64 = 3_600;
pub const TIME_6_HOURS: u64 = 21_600;
pub const TIME_24_HOURS: u64 = 86_400;
pub const TIME_7_DAYS: u64 = 604_800;

pub const fn fast_depth(wall_secs: u64) -> u64 {
    wall_secs / FAST_LANE_BLOCK_TIME_SECS
}
pub const fn zkp_depth(wall_secs: u64) -> u64 {
    wall_secs / ZKP_LANE_BLOCK_TIME_SECS
}

// ═══ Finality & Maturity (time-based) ═══
pub const FINALITY_TIME_SECS: u64 = TIME_1_MIN;
pub const FINALITY_DEPTH_FAST: u64 = fast_depth(FINALITY_TIME_SECS);   // 30
pub const FINALITY_DEPTH_ZKP: u64 = zkp_depth(FINALITY_TIME_SECS);     // 2
pub const MATURITY_TIME_SECS: u64 = TIME_10_MIN;
pub const COINBASE_MATURITY_FAST: u64 = fast_depth(MATURITY_TIME_SECS); // 300
pub const COINBASE_MATURITY_ZKP: u64 = zkp_depth(MATURITY_TIME_SECS);   // 20
pub const FINALITY_DEPTH: u64 = FINALITY_DEPTH_FAST;
pub const COINBASE_MATURITY: u64 = COINBASE_MATURITY_FAST;

// ═══ DAA & Recovery Windows (time-based) ═══
pub const DAA_WINDOW_TIME_SECS: u64 = TIME_1_HOUR;
pub const DIFFICULTY_WINDOW_SIZE: u64 = fast_depth(DAA_WINDOW_TIME_SECS); // 1800
pub const MEDIAN_TIME_WINDOW_SIZE: u64 = fast_depth(TIME_10_MIN);         // 300
pub const RECOVERY_TIME_SECS: u64 = TIME_6_HOURS;
pub const RECOVERY_DEPTH_FAST: u64 = fast_depth(RECOVERY_TIME_SECS); // 10800
pub const RECOVERY_DEPTH_ZKP: u64 = zkp_depth(RECOVERY_TIME_SECS);   // 720

// ═══ Pruning & Epoch (time-based) ═══
pub const PRUNING_TIME_SECS: u64 = TIME_7_DAYS;
pub const PRUNING_DEPTH: u64 = fast_depth(PRUNING_TIME_SECS); // 302400
pub const EPOCH_TIME_SECS: u64 = TIME_24_HOURS;
pub const EPOCH_LENGTH: u64 = fast_depth(EPOCH_TIME_SECS); // 43200

// ═══ Shielded Anchor Age (time-based) ═══
pub const SHIELDED_ANCHOR_AGE_TIME_SECS: u64 = TIME_1_HOUR;
pub const SHIELDED_ANCHOR_AGE_FAST: u64 = fast_depth(SHIELDED_ANCHOR_AGE_TIME_SECS);
pub const SHIELDED_ANCHOR_AGE_ZKP: u64 = zkp_depth(SHIELDED_ANCHOR_AGE_TIME_SECS);

// ═══ GhostDAG ═══
pub const GHOSTDAG_K: u64 = 18;
pub const MAX_BLOCK_PARENTS: usize = 10;
pub const MAX_MERGESET_SIZE: usize = 512;
pub const MAX_TXS_PER_BLOCK: usize = 50_000;

// ═══ Block Mass ═══
pub const MAX_BLOCK_MASS: u64 = 2_000_000;
pub const MAX_TX_MASS: u64 = 200_000;
pub const MAX_BLOCK_SIG_OPS: u64 = 80_000;
pub const MAX_TX_SIZE: usize = 256 * 1024;
pub const MASS_PER_TX_BYTE: u64 = 1;
pub const MASS_PER_SCRIPT_PUB_KEY_BYTE: u64 = 10;
pub const MASS_PER_SIG_OP: u64 = 1000;
pub const MASS_PER_INPUT: u64 = 100;
pub const MASS_PER_OUTPUT: u64 = 50;
pub const BASE_TX_MASS: u64 = 100;

// ═══ Cryptography — ML-DSA-65 (FIPS 204) ═══
pub const PQ_PK_SIZE: usize = 1_952;
pub const PQ_SIG_SIZE: usize = 3_309;
pub const PQ_SK_SIZE: usize = 4_032;
pub const KEM_PK_SIZE: usize = 1_184;
pub const KEM_CT_SIZE: usize = 1_088;
pub const HASH_SIZE: usize = 32;
pub const PQ_SIG_OVERHEAD: usize = PQ_SIG_SIZE + PQ_PK_SIZE;
pub const NIST_SECURITY_LEVEL: u8 = 3;

// ═══ Validator / PoS ═══
pub const MIN_STAKE: u64 = 10_000_000 * 1_000_000_000; // 10,000,000 MISAKA

// ═══ Tokenomics ═══
pub const MAX_SUPPLY: u128 = 10_000_000_000 * 1_000_000_000;
pub const DECIMALS: u32 = 9;
pub const INITIAL_BLOCK_REWARD: u64 = 50 * 1_000_000_000;

// ═══ Address ═══
pub const ADDRESS_PREFIX: &str = "misaka1";
pub const TESTNET_ADDRESS_PREFIX: &str = "misakatest1";

// ═══ Script Engine ═══
pub const MAX_SCRIPT_SIZE: usize = 10_000;
pub const MAX_STACK_SIZE: usize = 1000;
pub const MAX_OPS_PER_SCRIPT: usize = 201;
pub const MAX_SIG_OPS_PER_SCRIPT: usize = 20;
pub const MAX_MULTISIG_KEYS: usize = 20;
pub const DUST_THRESHOLD: u64 = 1_000;

// ═══ P2P ═══
pub const DEFAULT_P2P_PORT: u16 = 16111;
pub const DEFAULT_RPC_PORT: u16 = 16110;
pub const DEFAULT_WRPC_PORT: u16 = 17110;
pub const DEFAULT_GRPC_PORT: u16 = 16210;
pub const MAX_OUTBOUND_PEERS: usize = 8;
pub const MAX_INBOUND_PEERS: usize = 117;
pub const MAX_P2P_MESSAGE_SIZE: usize = 32 * 1024 * 1024;

// ═══ TPS Summary ═══
pub const ESTIMATED_STD_TX_MASS: u64 = 8_000;
pub const ESTIMATED_TXS_PER_BLOCK: u64 = MAX_BLOCK_MASS / ESTIMATED_STD_TX_MASS;
pub const ESTIMATED_FAST_TPS: u64 = ESTIMATED_TXS_PER_BLOCK / FAST_LANE_BLOCK_TIME_SECS;
pub const ESTIMATED_ZKP_TPS: u64 = ESTIMATED_TXS_PER_BLOCK / ZKP_LANE_BLOCK_TIME_SECS;

// ═══ Compile-Time Safety ═══
const _: () = {
    assert!(NUM_SUPER_REPRESENTATIVES == 21);
    assert!(FINALITY_DEPTH > 0);
    assert!(PRUNING_DEPTH > FINALITY_DEPTH);
    assert!(COINBASE_MATURITY > FINALITY_DEPTH);
    assert!(RECOVERY_DEPTH_FAST > COINBASE_MATURITY);
    assert!(MAX_BLOCK_MASS > ESTIMATED_STD_TX_MASS * 10);
    assert!(MAX_TX_MASS < MAX_BLOCK_MASS);
    assert!(PQ_SIG_OVERHEAD < MAX_TX_SIZE);
    assert!(FINALITY_DEPTH_FAST == 30);
    assert!(FINALITY_DEPTH_ZKP == 2);
    assert!(COINBASE_MATURITY_FAST == 300);
    assert!(fast_depth(TIME_24_HOURS) == 43200);
    assert!(zkp_depth(TIME_24_HOURS) == 2880);
    assert!(fast_depth(TIME_7_DAYS) == 302400);
    assert!(zkp_depth(TIME_7_DAYS) == 20160);
};
