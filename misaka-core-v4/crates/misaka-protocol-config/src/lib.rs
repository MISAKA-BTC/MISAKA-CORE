// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! # MISAKA Protocol Configuration — Sui-style versioned constants
//!
//! **Single Source of Truth** for all protocol-level constants.
//!
//! Follows the [Sui Protocol Config pattern](https://github.com/MystenLabs/sui/blob/main/crates/sui-protocol-config/src/lib.rs):
//! - All constants are `Option<T>` — `None` means "not available in this version"
//! - Accessor methods panic if the value is `None` (version mismatch)
//! - Feature flags are a separate `FeatureFlags` struct with `bool` fields
//! - Each version builds on the previous, overriding only changed values
//! - `ProtocolConfig::get_for_version(v)` is deterministic
//!
//! ## Usage
//!
//! ```rust
//! use misaka_protocol_config::{ProtocolConfig, ProtocolVersion};
//!
//! let config = ProtocolConfig::get_for_version(ProtocolVersion::V1);
//! assert_eq!(config.num_validators(), 21);
//! assert_eq!(config.quorum_threshold_bps(), 6667);
//! assert_eq!(config.ml_dsa_sig_len(), 3309);
//! assert!(config.feature_flags.transparent_only());
//! ```

use serde::{Deserialize, Serialize};

/// Minimum and maximum supported protocol versions.
const MIN_PROTOCOL_VERSION: u64 = 1;
const MAX_PROTOCOL_VERSION: u64 = 1;

// ═══════════════════════════════════════════════════════════════
//  Protocol Version
// ═══════════════════════════════════════════════════════════════

/// Protocol version — monotonically increasing. Each hard fork or
/// parameter change bumps this. Values returned by older versions
/// are immutable.
#[derive(Copy, Clone, Debug, Hash, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtocolVersion(u64);

impl ProtocolVersion {
    pub const MIN: Self = Self(MIN_PROTOCOL_VERSION);
    pub const MAX: Self = Self(MAX_PROTOCOL_VERSION);

    pub const fn new(v: u64) -> Self { Self(v) }
    pub const fn as_u64(&self) -> u64 { self.0 }

    /// Convenience aliases.
    pub const V1: Self = Self(1);
}

impl From<u64> for ProtocolVersion {
    fn from(v: u64) -> Self { Self::new(v) }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}", self.0)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Feature Flags (Sui pattern: bool fields, declarative)
// ═══════════════════════════════════════════════════════════════

/// Boolean feature flags that may vary per protocol version.
///
/// Sui equivalent: `FeatureFlags` struct with `ProtocolConfigFeatureFlagsGetters`.
/// We implement getters manually since we don't use proc macros.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeatureFlags {
    /// Chain operates in transparent-only mode (no privacy/ZK).
    transparent_only: bool,
    /// Solana bridge enabled.
    bridge_enabled: bool,
    /// Testnet faucet enabled.
    faucet_enabled: bool,
    /// Narwhal/Bullshark DAG consensus (vs legacy linear chain).
    dag_consensus: bool,
    /// ML-DSA-65 domain separation enforced at network edge.
    enforce_domain_separation_at_edge: bool,
    /// Equivocation detection with ledger-based quorum exclusion.
    equivocation_quorum_exclusion: bool,
}

impl FeatureFlags {
    pub fn transparent_only(&self) -> bool { self.transparent_only }
    pub fn bridge_enabled(&self) -> bool { self.bridge_enabled }
    pub fn faucet_enabled(&self) -> bool { self.faucet_enabled }
    pub fn dag_consensus(&self) -> bool { self.dag_consensus }
    pub fn enforce_domain_separation_at_edge(&self) -> bool { self.enforce_domain_separation_at_edge }
    pub fn equivocation_quorum_exclusion(&self) -> bool { self.equivocation_quorum_exclusion }

    /// Lookup a feature flag by string name.
    pub fn lookup(&self, name: &str) -> Option<bool> {
        match name {
            "transparent_only" => Some(self.transparent_only),
            "bridge_enabled" => Some(self.bridge_enabled),
            "faucet_enabled" => Some(self.faucet_enabled),
            "dag_consensus" => Some(self.dag_consensus),
            "enforce_domain_separation_at_edge" => Some(self.enforce_domain_separation_at_edge),
            "equivocation_quorum_exclusion" => Some(self.equivocation_quorum_exclusion),
            _ => None,
        }
    }

    /// Get all feature flags as a map.
    pub fn as_map(&self) -> std::collections::BTreeMap<String, bool> {
        let mut m = std::collections::BTreeMap::new();
        m.insert("transparent_only".into(), self.transparent_only);
        m.insert("bridge_enabled".into(), self.bridge_enabled);
        m.insert("faucet_enabled".into(), self.faucet_enabled);
        m.insert("dag_consensus".into(), self.dag_consensus);
        m.insert("enforce_domain_separation_at_edge".into(), self.enforce_domain_separation_at_edge);
        m.insert("equivocation_quorum_exclusion".into(), self.equivocation_quorum_exclusion);
        m
    }
}

// ═══════════════════════════════════════════════════════════════
//  Protocol Config (Sui pattern: Option<T> fields + accessors)
// ═══════════════════════════════════════════════════════════════

/// Complete protocol configuration.
///
/// All fields are `Option<T>` following the Sui pattern:
/// - `None` = not available in this protocol version
/// - `Some(x)` = the value for this version
///
/// Accessor methods (e.g., `num_validators()`) unwrap the Option and
/// panic if the value is None — this is intentional, as calling a
/// config value that doesn't exist in the current version is a bug.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ProtocolConfig {
    pub version: ProtocolVersion,
    pub feature_flags: FeatureFlags,

    // ─── BFT / Consensus ─────────────────────────────────
    num_validators: Option<u32>,
    min_validators: Option<u32>,
    /// BFT quorum threshold in basis points (6667 = 2/3 = 15 of 21).
    quorum_threshold_bps: Option<u16>,

    // ─── Block Structure ─────────────────────────────────
    max_block_mass: Option<u64>,
    max_tx_mass: Option<u64>,
    max_txs_per_block: Option<u32>,
    max_block_parents: Option<u32>,
    max_block_sig_ops: Option<u64>,
    max_tx_size: Option<u64>,
    max_mergeset_size: Option<u32>,

    // ─── Block Timing ────────────────────────────────────
    target_block_interval_ms: Option<u64>,
    epoch_length_blocks: Option<u64>,
    finality_depth: Option<u64>,
    coinbase_maturity: Option<u64>,
    pruning_depth: Option<u64>,

    // ─── GhostDAG / DAG ──────────────────────────────────
    ghostdag_k: Option<u64>,
    blocks_per_second: Option<u64>,
    /// Narwhal leader round wave (distance between leader rounds).
    leader_round_wave: Option<u32>,

    // ─── Cryptography (ML-DSA-65 / ML-KEM-768) ──────────
    ml_dsa_pk_len: Option<u64>,
    ml_dsa_sk_len: Option<u64>,
    ml_dsa_sig_len: Option<u64>,
    ml_kem_pk_len: Option<u64>,
    ml_kem_ct_len: Option<u64>,
    nist_security_level: Option<u8>,

    // ─── Tokenomics ──────────────────────────────────────
    max_supply: Option<u128>,
    decimals: Option<u32>,
    initial_block_reward: Option<u64>,
    min_stake: Option<u64>,
    dust_threshold: Option<u64>,

    // ─── Broadcaster / Subscriber (PQ-aware) ──────────────
    /// Max blocks per broadcast batch.
    /// Sui default ~20; PQ setting lower (larger blocks due to 3.3KB sigs).
    broadcaster_batch_size: Option<u32>,
    /// Max concurrent in-flight batches per peer.
    /// Sui default ~10; PQ setting lower.
    broadcaster_window_size: Option<u32>,
    /// Back-pressure threshold in bytes — broadcaster pauses when pending
    /// bytes to any peer exceed this. Default 64 MiB (~20,000 ML-DSA-65 sigs).
    broadcaster_max_pending_bytes: Option<u64>,
    /// Max delay (ms) before flushing a partial batch.
    broadcaster_max_batch_delay_ms: Option<u64>,
    /// Block subscriber buffer capacity (number of blocks).
    block_subscriber_buffer_capacity: Option<u32>,

    // ─── Network ─────────────────────────────────────────
    max_p2p_message_size: Option<u64>,
    max_inbound_peers: Option<u64>,
    max_outbound_peers: Option<u64>,
    default_p2p_port: Option<u16>,
    default_rpc_port: Option<u16>,

    // ─── Script Engine ───────────────────────────────────
    max_script_size: Option<u64>,
    max_stack_size: Option<u64>,
    max_ops_per_script: Option<u64>,

    // ─── Chain Identity ──────────────────────────────────
    mainnet_chain_id: Option<u32>,
    testnet_chain_id: Option<u32>,
}

// ─── Accessor macros (Sui pattern without proc macro) ────────
//
// Each accessor unwraps the Option, panicking if None.
// This is intentional: calling a config value not present in
// the current version is a programming error.

#[allow(unused_macros)]
macro_rules! config_accessor {
    ($name:ident, $t:ty) => {
        pub fn $name(&self) -> $t {
            self.$name.expect(Self::ERR_MSG)
        }
        paste::item! {
            pub fn [< $name _as_option >](&self) -> Option<$t> {
                self.$name
            }
        }
    };
}

// We don't have the `paste` crate, so implement manually:
impl ProtocolConfig {
    const ERR_MSG: &'static str =
        "protocol config value not present in current protocol version";

    // BFT
    pub fn num_validators(&self) -> u32 { self.num_validators.expect(Self::ERR_MSG) }
    pub fn min_validators(&self) -> u32 { self.min_validators.expect(Self::ERR_MSG) }
    pub fn quorum_threshold_bps(&self) -> u16 { self.quorum_threshold_bps.expect(Self::ERR_MSG) }

    // Block
    pub fn max_block_mass(&self) -> u64 { self.max_block_mass.expect(Self::ERR_MSG) }
    pub fn max_tx_mass(&self) -> u64 { self.max_tx_mass.expect(Self::ERR_MSG) }
    pub fn max_txs_per_block(&self) -> u32 { self.max_txs_per_block.expect(Self::ERR_MSG) }
    pub fn max_block_parents(&self) -> u32 { self.max_block_parents.expect(Self::ERR_MSG) }
    pub fn max_block_sig_ops(&self) -> u64 { self.max_block_sig_ops.expect(Self::ERR_MSG) }
    pub fn max_tx_size(&self) -> u64 { self.max_tx_size.expect(Self::ERR_MSG) }
    pub fn max_mergeset_size(&self) -> u32 { self.max_mergeset_size.expect(Self::ERR_MSG) }

    // Timing
    pub fn target_block_interval_ms(&self) -> u64 { self.target_block_interval_ms.expect(Self::ERR_MSG) }
    pub fn epoch_length_blocks(&self) -> u64 { self.epoch_length_blocks.expect(Self::ERR_MSG) }
    pub fn finality_depth(&self) -> u64 { self.finality_depth.expect(Self::ERR_MSG) }
    pub fn coinbase_maturity(&self) -> u64 { self.coinbase_maturity.expect(Self::ERR_MSG) }
    pub fn pruning_depth(&self) -> u64 { self.pruning_depth.expect(Self::ERR_MSG) }

    // DAG
    pub fn ghostdag_k(&self) -> u64 { self.ghostdag_k.expect(Self::ERR_MSG) }
    pub fn blocks_per_second(&self) -> u64 { self.blocks_per_second.expect(Self::ERR_MSG) }
    pub fn leader_round_wave(&self) -> u32 { self.leader_round_wave.expect(Self::ERR_MSG) }

    // Crypto
    pub fn ml_dsa_pk_len(&self) -> u64 { self.ml_dsa_pk_len.expect(Self::ERR_MSG) }
    pub fn ml_dsa_sk_len(&self) -> u64 { self.ml_dsa_sk_len.expect(Self::ERR_MSG) }
    pub fn ml_dsa_sig_len(&self) -> u64 { self.ml_dsa_sig_len.expect(Self::ERR_MSG) }
    pub fn ml_kem_pk_len(&self) -> u64 { self.ml_kem_pk_len.expect(Self::ERR_MSG) }
    pub fn ml_kem_ct_len(&self) -> u64 { self.ml_kem_ct_len.expect(Self::ERR_MSG) }
    pub fn nist_security_level(&self) -> u8 { self.nist_security_level.expect(Self::ERR_MSG) }

    // Tokenomics
    pub fn max_supply(&self) -> u128 { self.max_supply.expect(Self::ERR_MSG) }
    pub fn decimals(&self) -> u32 { self.decimals.expect(Self::ERR_MSG) }
    pub fn initial_block_reward(&self) -> u64 { self.initial_block_reward.expect(Self::ERR_MSG) }
    pub fn min_stake(&self) -> u64 { self.min_stake.expect(Self::ERR_MSG) }
    pub fn dust_threshold(&self) -> u64 { self.dust_threshold.expect(Self::ERR_MSG) }

    // Broadcaster / Subscriber (PQ-aware)
    pub fn broadcaster_batch_size(&self) -> u32 { self.broadcaster_batch_size.expect(Self::ERR_MSG) }
    pub fn broadcaster_window_size(&self) -> u32 { self.broadcaster_window_size.expect(Self::ERR_MSG) }
    pub fn broadcaster_max_pending_bytes(&self) -> u64 { self.broadcaster_max_pending_bytes.expect(Self::ERR_MSG) }
    pub fn broadcaster_max_batch_delay_ms(&self) -> u64 { self.broadcaster_max_batch_delay_ms.expect(Self::ERR_MSG) }
    pub fn block_subscriber_buffer_capacity(&self) -> u32 { self.block_subscriber_buffer_capacity.expect(Self::ERR_MSG) }

    // Network
    pub fn max_p2p_message_size(&self) -> u64 { self.max_p2p_message_size.expect(Self::ERR_MSG) }
    pub fn max_inbound_peers(&self) -> u64 { self.max_inbound_peers.expect(Self::ERR_MSG) }
    pub fn max_outbound_peers(&self) -> u64 { self.max_outbound_peers.expect(Self::ERR_MSG) }
    pub fn default_p2p_port(&self) -> u16 { self.default_p2p_port.expect(Self::ERR_MSG) }
    pub fn default_rpc_port(&self) -> u16 { self.default_rpc_port.expect(Self::ERR_MSG) }

    // Script
    pub fn max_script_size(&self) -> u64 { self.max_script_size.expect(Self::ERR_MSG) }
    pub fn max_stack_size(&self) -> u64 { self.max_stack_size.expect(Self::ERR_MSG) }
    pub fn max_ops_per_script(&self) -> u64 { self.max_ops_per_script.expect(Self::ERR_MSG) }

    // Chain identity
    pub fn mainnet_chain_id(&self) -> u32 { self.mainnet_chain_id.expect(Self::ERR_MSG) }
    pub fn testnet_chain_id(&self) -> u32 { self.testnet_chain_id.expect(Self::ERR_MSG) }

    /// Lookup any config attribute by string name.
    pub fn lookup_attr(&self, name: &str) -> Option<String> {
        match name {
            "num_validators" => self.num_validators.map(|v| v.to_string()),
            "quorum_threshold_bps" => self.quorum_threshold_bps.map(|v| v.to_string()),
            "max_block_mass" => self.max_block_mass.map(|v| v.to_string()),
            "target_block_interval_ms" => self.target_block_interval_ms.map(|v| v.to_string()),
            "finality_depth" => self.finality_depth.map(|v| v.to_string()),
            "ml_dsa_sig_len" => self.ml_dsa_sig_len.map(|v| v.to_string()),
            "max_supply" => self.max_supply.map(|v| v.to_string()),
            _ => None,
        }
    }

    /// Lookup a feature flag by string name.
    pub fn lookup_feature(&self, name: &str) -> Option<bool> {
        self.feature_flags.lookup(name)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Version Definitions
// ═══════════════════════════════════════════════════════════════

impl ProtocolConfig {
    /// Get config for a specific version. Deterministic.
    pub fn get_for_version(version: ProtocolVersion) -> Self {
        let v = version.as_u64();
        assert!(
            v >= MIN_PROTOCOL_VERSION && v <= MAX_PROTOCOL_VERSION,
            "unsupported protocol version {v} (supported: {MIN_PROTOCOL_VERSION}..={MAX_PROTOCOL_VERSION})"
        );

        let mut cfg = Self::default_for(version);

        // Apply version-specific overrides.
        // Each version builds on the previous — only changed values are set.
        match v {
            1 => Self::apply_v1(&mut cfg),
            _ => unreachable!(),
        }

        cfg
    }

    /// Convenience: get the latest version's config.
    pub fn latest() -> Self {
        Self::get_for_version(ProtocolVersion::MAX)
    }

    /// Default config with all fields None.
    fn default_for(version: ProtocolVersion) -> Self {
        Self {
            version,
            feature_flags: FeatureFlags::default(),
            num_validators: None,
            min_validators: None,
            quorum_threshold_bps: None,
            max_block_mass: None,
            max_tx_mass: None,
            max_txs_per_block: None,
            max_block_parents: None,
            max_block_sig_ops: None,
            max_tx_size: None,
            max_mergeset_size: None,
            target_block_interval_ms: None,
            epoch_length_blocks: None,
            finality_depth: None,
            coinbase_maturity: None,
            pruning_depth: None,
            ghostdag_k: None,
            blocks_per_second: None,
            leader_round_wave: None,
            ml_dsa_pk_len: None,
            ml_dsa_sk_len: None,
            ml_dsa_sig_len: None,
            ml_kem_pk_len: None,
            ml_kem_ct_len: None,
            nist_security_level: None,
            max_supply: None,
            decimals: None,
            initial_block_reward: None,
            min_stake: None,
            dust_threshold: None,
            broadcaster_batch_size: None,
            broadcaster_window_size: None,
            broadcaster_max_pending_bytes: None,
            broadcaster_max_batch_delay_ms: None,
            block_subscriber_buffer_capacity: None,
            max_p2p_message_size: None,
            max_inbound_peers: None,
            max_outbound_peers: None,
            default_p2p_port: None,
            default_rpc_port: None,
            max_script_size: None,
            max_stack_size: None,
            max_ops_per_script: None,
            mainnet_chain_id: None,
            testnet_chain_id: None,
        }
    }

    /// V1: Initial mainnet parameters.
    ///
    /// - 21 SR DPoS + Narwhal/Bullshark DAG consensus
    /// - ML-DSA-65 (FIPS 204) + ML-KEM-768 (FIPS 203)
    /// - Transparent-only (privacy layer removed in v1.0)
    fn apply_v1(cfg: &mut Self) {
        // Feature flags
        cfg.feature_flags = FeatureFlags {
            transparent_only: true,
            bridge_enabled: false,
            faucet_enabled: false,
            dag_consensus: true,
            enforce_domain_separation_at_edge: true,
            equivocation_quorum_exclusion: true,
        };

        // BFT / Consensus
        cfg.num_validators = Some(21);
        cfg.min_validators = Some(4);
        cfg.quorum_threshold_bps = Some(6667); // 2/3 = 15 of 21

        // Block structure
        cfg.max_block_mass = Some(2_000_000);
        cfg.max_tx_mass = Some(200_000);
        cfg.max_txs_per_block = Some(256);
        cfg.max_block_parents = Some(10);
        cfg.max_block_sig_ops = Some(80_000);
        cfg.max_tx_size = Some(256 * 1024);
        cfg.max_mergeset_size = Some(512);

        // Block timing
        cfg.target_block_interval_ms = Some(2_000);
        cfg.epoch_length_blocks = Some(43_200);   // 24h at 2s blocks
        cfg.finality_depth = Some(30);            // ~1 min at 2s blocks
        cfg.coinbase_maturity = Some(300);        // ~10 min at 2s blocks
        cfg.pruning_depth = Some(1_000);

        // GhostDAG / DAG
        cfg.ghostdag_k = Some(18);
        cfg.blocks_per_second = Some(1);
        cfg.leader_round_wave = Some(2);

        // Cryptography — ML-DSA-65 (FIPS 204) / ML-KEM-768 (FIPS 203)
        cfg.ml_dsa_pk_len = Some(1_952);
        cfg.ml_dsa_sk_len = Some(4_032);
        cfg.ml_dsa_sig_len = Some(3_309);
        cfg.ml_kem_pk_len = Some(1_184);
        cfg.ml_kem_ct_len = Some(1_088);
        cfg.nist_security_level = Some(3);

        // Tokenomics
        cfg.max_supply = Some(10_000_000_000 * 1_000_000_000); // 10B MISAKA
        cfg.decimals = Some(9);
        cfg.initial_block_reward = Some(50 * 1_000_000_000);   // 50 MISAKA
        cfg.min_stake = Some(10_000_000 * 1_000_000_000);      // 10M MISAKA
        cfg.dust_threshold = Some(1_000);

        // Broadcaster / Subscriber — PQ-aware tuning
        // Sui block payloads are ~64B sig; ML-DSA-65 is 3,309B (50× larger).
        // Strategy: fewer, larger batches to amortise TLS/framing overhead,
        // with a hard 50ms latency ceiling.
        cfg.broadcaster_batch_size = Some(5);           // Sui ~20 → 1/4
        cfg.broadcaster_window_size = Some(3);          // Sui ~10 → 1/3
        cfg.broadcaster_max_pending_bytes = Some(64 * 1024 * 1024); // 64 MiB
        cfg.broadcaster_max_batch_delay_ms = Some(50);  // latency ceiling
        cfg.block_subscriber_buffer_capacity = Some(2000); // ~6.3 MiB at 3.3 KB/sig

        // Network
        cfg.max_p2p_message_size = Some(32 * 1024 * 1024);     // 32 MiB
        cfg.max_inbound_peers = Some(117);
        cfg.max_outbound_peers = Some(8);
        cfg.default_p2p_port = Some(16111);
        cfg.default_rpc_port = Some(16110);

        // Script engine
        cfg.max_script_size = Some(10_000);
        cfg.max_stack_size = Some(1_000);
        cfg.max_ops_per_script = Some(201);

        // Chain identity
        cfg.mainnet_chain_id = Some(0x4D534B01);
        cfg.testnet_chain_id = Some(0x4D534B02);
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_is_deterministic() {
        let a = ProtocolConfig::get_for_version(ProtocolVersion::V1);
        let b = ProtocolConfig::get_for_version(ProtocolVersion::V1);
        assert_eq!(a.num_validators(), b.num_validators());
        assert_eq!(a.quorum_threshold_bps(), b.quorum_threshold_bps());
        assert_eq!(a.max_block_mass(), b.max_block_mass());
        assert_eq!(a.ml_dsa_sig_len(), b.ml_dsa_sig_len());
        assert_eq!(a.target_block_interval_ms(), b.target_block_interval_ms());
        assert_eq!(a.max_supply(), b.max_supply());
        assert_eq!(a.leader_round_wave(), b.leader_round_wave());
    }

    #[test]
    fn v1_bft_threshold_is_two_thirds() {
        let c = ProtocolConfig::get_for_version(ProtocolVersion::V1);
        assert_eq!(c.quorum_threshold_bps(), 6667);
        let n = c.num_validators();
        let quorum = n - (n - 1) / 3; // Sui formula
        assert_eq!(quorum, 15);
        assert!(quorum as f64 / n as f64 > 0.6667);
    }

    #[test]
    fn v1_crypto_sizes_are_fips_compliant() {
        let c = ProtocolConfig::get_for_version(ProtocolVersion::V1);
        assert_eq!(c.ml_dsa_pk_len(), 1952);
        assert_eq!(c.ml_dsa_sk_len(), 4032);
        assert_eq!(c.ml_dsa_sig_len(), 3309);
        assert_eq!(c.ml_kem_pk_len(), 1184);
        assert_eq!(c.ml_kem_ct_len(), 1088);
        assert_eq!(c.nist_security_level(), 3);
    }

    #[test]
    fn v1_invariants_hold() {
        let c = ProtocolConfig::get_for_version(ProtocolVersion::V1);
        assert!(c.finality_depth() > 0);
        assert!(c.pruning_depth() > c.finality_depth());
        assert!(c.coinbase_maturity() > c.finality_depth());
        assert!(c.max_tx_mass() < c.max_block_mass());
        assert!(c.max_tx_size() < c.max_p2p_message_size());
        assert_eq!(c.num_validators(), 21);
    }

    #[test]
    fn v1_tokenomics_consistent() {
        let c = ProtocolConfig::get_for_version(ProtocolVersion::V1);
        assert_eq!(c.decimals(), 9);
        assert_eq!(c.max_supply(), 10_000_000_000_000_000_000);
        assert!((c.initial_block_reward() as u128) < c.max_supply());
    }

    #[test]
    fn v1_feature_flags() {
        let c = ProtocolConfig::get_for_version(ProtocolVersion::V1);
        assert!(c.feature_flags.transparent_only());
        assert!(!c.feature_flags.bridge_enabled());
        assert!(!c.feature_flags.faucet_enabled());
        assert!(c.feature_flags.dag_consensus());
        assert!(c.feature_flags.enforce_domain_separation_at_edge());
        assert!(c.feature_flags.equivocation_quorum_exclusion());
    }

    #[test]
    fn version_display() {
        assert_eq!(ProtocolVersion::V1.to_string(), "v1");
    }

    #[test]
    fn feature_flag_lookup() {
        let c = ProtocolConfig::get_for_version(ProtocolVersion::V1);
        assert_eq!(c.lookup_feature("transparent_only"), Some(true));
        assert_eq!(c.lookup_feature("bridge_enabled"), Some(false));
        assert_eq!(c.lookup_feature("nonexistent"), None);
    }

    #[test]
    fn feature_flag_map() {
        let c = ProtocolConfig::get_for_version(ProtocolVersion::V1);
        let map = c.feature_flags.as_map();
        assert_eq!(map.len(), 6);
        assert_eq!(map["transparent_only"], true);
        assert_eq!(map["bridge_enabled"], false);
    }

    #[test]
    fn attr_lookup() {
        let c = ProtocolConfig::get_for_version(ProtocolVersion::V1);
        assert_eq!(c.lookup_attr("num_validators"), Some("21".into()));
        assert_eq!(c.lookup_attr("quorum_threshold_bps"), Some("6667".into()));
        assert_eq!(c.lookup_attr("nonexistent"), None);
    }

    #[test]
    #[should_panic(expected = "protocol config value not present")]
    fn accessing_none_panics() {
        let cfg = ProtocolConfig::default_for(ProtocolVersion::V1);
        // default_for leaves all values as None
        let _ = cfg.num_validators(); // should panic
    }

    #[test]
    fn latest_is_v1() {
        let c = ProtocolConfig::latest();
        assert_eq!(c.version, ProtocolVersion::V1);
    }

    #[test]
    #[should_panic(expected = "unsupported protocol version")]
    fn unsupported_version_panics() {
        let _ = ProtocolConfig::get_for_version(ProtocolVersion::new(999));
    }

    #[test]
    fn leader_round_wave_present() {
        let c = ProtocolConfig::get_for_version(ProtocolVersion::V1);
        assert_eq!(c.leader_round_wave(), 2);
    }
}
