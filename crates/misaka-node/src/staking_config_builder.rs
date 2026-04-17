// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Group 1: `StakingConfig` construction glue.
//!
//! Before this module, `start_narwhal_node` / `start_dag_node` both picked
//! between `StakingConfig::default()` (mainnet defaults) and
//! `StakingConfig::testnet()` via an inline `if chain_id == 1 { ... } else { ... }`
//! block, and did not thread through any override from the loaded `NodeConfig`.
//!
//! This single helper unifies those two sites and (when a `NodeConfig` is
//! available) honors `NodeConfig.staking_unbonding_period` as an override for
//! `StakingConfig.unbonding_epochs`. Other `NodeConfig` staking fields
//! (`staking_min_stake`, `staking_max_validators`) are intentionally left as
//! follow-ups so this PR's semantics stay narrow: Group 1 only unifies
//! construction and one override, it does not change the chain-level defaults
//! for mainnet / testnet.
//!
//! `misaka-consensus` does not depend on `misaka-config`, so this helper lives
//! in `misaka-node` — the single binary crate that consumes both.

use misaka_config::NodeConfig;
use misaka_consensus::staking::StakingConfig;

/// Build a `StakingConfig` for the given `chain_id`, optionally overriding
/// fields from a loaded `NodeConfig`.
///
/// - `chain_id == 1` → mainnet defaults (`StakingConfig::default()`).
/// - any other chain_id (testnet, devnet) → `StakingConfig::testnet()`.
///
/// When `node_config` is `Some(..)` and its `staking_unbonding_period > 0`,
/// the corresponding `StakingConfig.unbonding_epochs` is overridden. A value
/// of `0` is treated as "no override" (keep the chain default); the
/// `NodeConfig` validator should already reject a genuinely-zero setting on
/// mainnet/testnet, so accepting `0` here as "unset" is safe.
///
/// Callers without a loaded `NodeConfig` in scope should pass `None`. This is
/// the expected shape for the two in-tree call sites in `main.rs`, where
/// `loaded_config` is consumed in an earlier lexical block and is not in
/// scope at the `StakingRegistry` bootstrap point.
pub fn build_staking_config_for_chain(
    chain_id: u32,
    node_config: Option<&NodeConfig>,
) -> StakingConfig {
    let mut base = if chain_id == 1 {
        StakingConfig::default()
    } else {
        StakingConfig::testnet()
    };

    if let Some(nc) = node_config {
        if nc.staking_unbonding_period > 0 {
            base.unbonding_epochs = nc.staking_unbonding_period;
        }
    }

    base
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_defaults_when_chain_id_is_one() {
        let sc = build_staking_config_for_chain(1, None);
        // Defaults from StakingConfig::default() — mainnet values.
        assert_eq!(sc.unbonding_epochs, 10_080);
        assert_eq!(sc.min_validator_stake, 10_000_000_000_000_000);
        assert_eq!(sc.max_active_validators, 150);
    }

    #[test]
    fn testnet_defaults_when_chain_id_is_not_one() {
        let sc = build_staking_config_for_chain(2, None);
        // StakingConfig::testnet() values.
        assert_eq!(sc.unbonding_epochs, 100);
        assert_eq!(sc.min_validator_stake, 1_000_000_000_000_000);
        assert_eq!(sc.max_active_validators, 50);
    }

    #[test]
    fn node_config_overrides_unbonding_on_testnet() {
        let mut nc = NodeConfig::default();
        nc.staking_unbonding_period = 14;
        let sc = build_staking_config_for_chain(2, Some(&nc));
        assert_eq!(sc.unbonding_epochs, 14);
        // Other fields untouched.
        assert_eq!(sc.min_validator_stake, 1_000_000_000_000_000);
    }

    #[test]
    fn node_config_overrides_unbonding_on_mainnet() {
        let mut nc = NodeConfig::default();
        nc.chain_id = 1;
        nc.staking_unbonding_period = 20_160;
        let sc = build_staking_config_for_chain(1, Some(&nc));
        assert_eq!(sc.unbonding_epochs, 20_160);
        assert_eq!(sc.min_validator_stake, 10_000_000_000_000_000);
    }

    #[test]
    fn zero_unbonding_period_means_no_override() {
        let mut nc = NodeConfig::default();
        nc.staking_unbonding_period = 0;
        let sc = build_staking_config_for_chain(2, Some(&nc));
        // Falls back to StakingConfig::testnet() default, not zero.
        assert_eq!(sc.unbonding_epochs, 100);
    }

    #[test]
    fn node_config_none_keeps_chain_defaults() {
        let sc_mainnet = build_staking_config_for_chain(1, None);
        let sc_testnet = build_staking_config_for_chain(2, None);
        assert_eq!(sc_mainnet.unbonding_epochs, 10_080);
        assert_eq!(sc_testnet.unbonding_epochs, 100);
    }
}
