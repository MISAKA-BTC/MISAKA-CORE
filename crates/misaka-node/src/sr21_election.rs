//! SR21 Auto-Election — Epoch-Based Validator Set Rotation
//!
//! At each epoch boundary (every 43,200 fast blocks = ~24 hours),
//! the validator set is recalculated:
//!
//! 1. Sort all registered validators by stake_weight (descending)
//! 2. Top 21 (or fewer if not enough) become the active SR set
//! 3. Update `DagNodeState.num_active_srs`
//! 4. Validators below minimum stake are excluded
//!
//! # Round-Robin Assignment
//!
//! Active SRs are assigned indices 0..N-1 sorted by stake weight.
//! SR_0 = highest stake, SR_20 = lowest stake among active set.
//! If a local validator is in the active set, its `sr_index` is updated.

use misaka_consensus::staking::{StakingRegistry, ValidatorState};
use misaka_types::validator::{ValidatorIdentity, ValidatorPublicKey};
use tracing::info;

/// Minimum stake to be eligible for SR21 (in base units).
pub const MIN_SR_STAKE: u128 = 10_000_000 * 1_000_000_000; // 10M MISAKA

/// Maximum SRs in the active set.
pub const MAX_SR_COUNT: usize = 21;

/// Effective minimum stake for the current chain.
///
/// On non-mainnet chains, Phase C uses the validator lifecycle testnet
/// threshold so SR21 bootstrap/rehearsal can operate before Solana-backed
/// stake reconciliation lands. Mainnet keeps the production 10M floor.
pub fn effective_min_sr_stake(chain_id: u32) -> u128 {
    let config = if chain_id == 1 {
        misaka_consensus::staking::StakingConfig::mainnet()
    } else {
        misaka_consensus::staking::StakingConfig::testnet()
    };
    u128::from(config.min_validator_stake)
}

/// Result of an SR21 election.
#[derive(Debug, Clone)]
pub struct ElectionResult {
    /// Active SR set, sorted by stake_weight descending.
    pub active_srs: Vec<ElectedSR>,
    /// Total active SRs (1..=21).
    pub num_active: usize,
    /// Total stake weight of all active SRs.
    pub total_active_stake: u128,
    /// Validators that were dropped (below min stake or rank > 21).
    pub dropped_count: usize,
    /// Epoch number this election applies to.
    pub epoch: u64,
}

#[derive(Debug, Clone)]
pub struct ElectedSR {
    pub validator_id: [u8; 32],
    pub stake_weight: u128,
    pub sr_index: usize,
}

/// Run SR21 election on a set of known validators.
///
/// Returns the active set sorted by stake_weight (descending).
/// Only validators with `stake_weight >= MIN_SR_STAKE` and `is_active == true` are eligible.
pub fn run_election(validators: &[ValidatorIdentity], epoch: u64) -> ElectionResult {
    run_election_with_min_stake(validators, MIN_SR_STAKE, epoch)
}

/// Run SR21 election using a caller-provided minimum stake floor.
pub fn run_election_with_min_stake(
    validators: &[ValidatorIdentity],
    min_sr_stake: u128,
    epoch: u64,
) -> ElectionResult {
    // Filter eligible validators
    let mut eligible: Vec<&ValidatorIdentity> = validators
        .iter()
        .filter(|v| v.is_active && v.stake_weight >= min_sr_stake)
        .collect();

    // Sort by stake_weight descending (tie-break by validator_id for determinism)
    eligible.sort_by(|a, b| {
        b.stake_weight
            .cmp(&a.stake_weight)
            .then_with(|| a.validator_id.cmp(&b.validator_id))
    });

    // Take top MAX_SR_COUNT
    let active_count = eligible.len().min(MAX_SR_COUNT);
    let active_srs: Vec<ElectedSR> = eligible[..active_count]
        .iter()
        .enumerate()
        .map(|(idx, v)| ElectedSR {
            validator_id: v.validator_id,
            stake_weight: v.stake_weight,
            sr_index: idx,
        })
        .collect();

    let total_stake: u128 = active_srs.iter().map(|sr| sr.stake_weight).sum();
    let dropped = validators.len() - active_count;

    info!(
        "SR21 Election (epoch={}): {} eligible, {} active, {} dropped | total_stake={}",
        epoch,
        eligible.len(),
        active_count,
        dropped,
        total_stake
    );

    for sr in &active_srs {
        info!(
            "  SR_{}: validator={}... stake={}",
            sr.sr_index,
            hex::encode(&sr.validator_id[..8]),
            sr.stake_weight
        );
    }

    ElectionResult {
        active_srs,
        num_active: active_count,
        total_active_stake: total_stake,
        dropped_count: dropped,
        epoch,
    }
}

/// Run SR21 election using the effective minimum stake floor for the chain.
pub fn run_election_for_chain(
    validators: &[ValidatorIdentity],
    chain_id: u32,
    epoch: u64,
) -> ElectionResult {
    run_election_with_min_stake(validators, effective_min_sr_stake(chain_id), epoch)
}

/// Find the SR index for a given validator_id in the election result.
/// Returns None if the validator is not in the active set.
pub fn find_sr_index(result: &ElectionResult, validator_id: &[u8; 32]) -> Option<usize> {
    result
        .active_srs
        .iter()
        .find(|sr| &sr.validator_id == validator_id)
        .map(|sr| sr.sr_index)
}

/// Check if a validator is in the active SR set.
pub fn is_active_sr(result: &ElectionResult, validator_id: &[u8; 32]) -> bool {
    find_sr_index(result, validator_id).is_some()
}

/// Group 2: Project a `StakingRegistry` snapshot into the
/// `ValidatorIdentity` vector that the election functions expect.
///
/// Only `ValidatorState::Active` validators are included — LOCKED / EXITING
/// / UNLOCKED validators have not met the stake-verification gate (or have
/// stepped out) and must not influence committee selection. Caller should
/// run `StakingRegistry::auto_activate_locked` BEFORE this if they want
/// newly-verified validators to appear in this epoch's election.
///
/// `stake_weight` comes from `ValidatorAccount::stake_amount` widened to
/// `u128`. `ValidatorPublicKey` is cloned from the registry's stored
/// ML-DSA-65 public key bytes (1952 bytes). `is_active` is always `true`
/// here by construction (we already filter on `state == Active`).
pub fn registry_to_validator_identities(
    registry: &StakingRegistry,
) -> Vec<ValidatorIdentity> {
    registry
        .all_validators()
        .filter(|v| v.state == ValidatorState::Active)
        .map(|v| ValidatorIdentity {
            validator_id: v.validator_id,
            stake_weight: v.stake_amount as u128,
            public_key: ValidatorPublicKey {
                bytes: v.pubkey.clone(),
            },
            is_active: true,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_types::validator::{ValidatorIdentity, ValidatorPublicKey};

    fn make_validator(id_byte: u8, stake: u128, active: bool) -> ValidatorIdentity {
        ValidatorIdentity {
            validator_id: [id_byte; 32],
            stake_weight: stake,
            public_key: ValidatorPublicKey {
                bytes: vec![id_byte; 32],
            },
            is_active: active,
        }
    }

    #[test]
    fn test_basic_election() {
        let validators = vec![
            make_validator(1, 50_000_000_000_000_000, true), // 50M
            make_validator(2, 20_000_000_000_000_000, true), // 20M
            make_validator(3, 10_000_000_000_000_000, true), // 10M
            make_validator(4, 5_000_000_000_000_000, true),  // 5M — below MIN_SR_STAKE
        ];
        let result = run_election(&validators, 1);
        assert_eq!(result.num_active, 3); // 4th excluded (below 10M)
        assert_eq!(result.active_srs[0].validator_id, [1u8; 32]); // highest stake first
        assert_eq!(result.active_srs[0].sr_index, 0);
        assert_eq!(result.active_srs[2].sr_index, 2);
    }

    #[test]
    fn test_max_21() {
        let validators: Vec<ValidatorIdentity> = (0..30u8)
            .map(|i| make_validator(i, (30 - i as u128) * 10_000_000_000_000_000, true))
            .collect();
        let result = run_election(&validators, 1);
        assert_eq!(result.num_active, 21);
        assert_eq!(result.dropped_count, 9);
    }

    #[test]
    fn test_inactive_excluded() {
        let validators = vec![
            make_validator(1, 50_000_000_000_000_000, true),
            make_validator(2, 100_000_000_000_000_000, false), // inactive
        ];
        let result = run_election(&validators, 1);
        assert_eq!(result.num_active, 1);
        assert_eq!(result.active_srs[0].validator_id, [1u8; 32]);
    }

    #[test]
    fn test_find_sr_index() {
        let validators = vec![
            make_validator(1, 50_000_000_000_000_000, true),
            make_validator(2, 20_000_000_000_000_000, true),
        ];
        let result = run_election(&validators, 1);
        assert_eq!(find_sr_index(&result, &[1u8; 32]), Some(0));
        assert_eq!(find_sr_index(&result, &[2u8; 32]), Some(1));
        assert_eq!(find_sr_index(&result, &[99u8; 32]), None);
    }

    #[test]
    fn test_effective_min_sr_stake_uses_testnet_floor_on_non_mainnet() {
        assert_eq!(effective_min_sr_stake(2), 1_000_000_000_000_000u128);
        assert_eq!(effective_min_sr_stake(1), MIN_SR_STAKE);
    }

    #[test]
    fn test_run_election_for_chain_uses_testnet_threshold() {
        let validators = vec![
            make_validator(1, 1_500_000_000_000_000, true), // 1.5M
            make_validator(2, 900_000_000_000_000, true),   // 0.9M
        ];
        let result = run_election_for_chain(&validators, 2, 1);
        assert_eq!(result.num_active, 1);
        assert_eq!(result.active_srs[0].validator_id, [1u8; 32]);
    }

    // ─── Group 2: registry_to_validator_identities test ───────────
    #[test]
    #[allow(deprecated)]
    fn registry_to_identities_includes_only_active() {
        use misaka_consensus::staking::{StakingConfig, StakingRegistry, ValidatorState};

        // Force min stake to 10_000_000 so the existing register() gate is
        // easy to satisfy with fixture stake = 50M.
        let config = StakingConfig {
            min_validator_stake: 10_000_000,
            max_active_validators: 10,
            ..StakingConfig::testnet()
        };
        let mut reg = StakingRegistry::new(config);

        // Seed via the public API so we don't depend on crate-private
        // struct fields:
        //   v1, v2 → register + activate  (ACTIVE)
        //   v3     → register only        (LOCKED)
        //   v4     → register + activate + exit (EXITING)
        let register_and_activate = |reg: &mut StakingRegistry, id: [u8; 32], stake: u64| {
            reg.register(
                id,
                vec![id[0]; 1952],
                stake,
                500,
                id,
                0,
                [id[0]; 32],
                0,
                true,
                Some(format!("sig_{}", id[0])),
                false,
            )
            .expect("register");
            reg.activate(&id, 1).expect("activate");
        };

        let v1 = [0x01u8; 32];
        let v2 = [0x02u8; 32];
        let v3 = [0x03u8; 32];
        let v4 = [0x04u8; 32];

        register_and_activate(&mut reg, v1, 50_000_000);
        register_and_activate(&mut reg, v2, 30_000_000);
        // v3 registered but NOT activated → stays LOCKED.
        reg.register(
            v3,
            vec![v3[0]; 1952],
            20_000_000,
            500,
            v3,
            0,
            [v3[0]; 32],
            0,
            true,
            Some("sig_3".into()),
            false,
        )
        .expect("register v3");
        // v4 registered + activated + exited → EXITING.
        register_and_activate(&mut reg, v4, 25_000_000);
        reg.exit(&v4, 5).expect("exit v4");

        // Sanity check on the seed before projecting.
        assert_eq!(reg.get(&v1).unwrap().state, ValidatorState::Active);
        assert_eq!(reg.get(&v2).unwrap().state, ValidatorState::Active);
        assert_eq!(reg.get(&v3).unwrap().state, ValidatorState::Locked);
        assert!(matches!(
            reg.get(&v4).unwrap().state,
            ValidatorState::Exiting { .. }
        ));

        let ids = registry_to_validator_identities(&reg);
        assert_eq!(ids.len(), 2, "only ACTIVE validators survive projection");

        let seen: std::collections::HashSet<[u8; 32]> =
            ids.iter().map(|v| v.validator_id).collect();
        assert!(seen.contains(&v1));
        assert!(seen.contains(&v2));
        assert!(!seen.contains(&v3), "LOCKED must not appear");
        assert!(!seen.contains(&v4), "EXITING must not appear");

        for v in &ids {
            assert!(v.is_active);
            assert!(v.stake_weight > 0);
            assert_eq!(v.public_key.bytes.len(), 1952);
        }

        // Feed projection straight into the election; the shape contract
        // must hold end-to-end.
        let election = run_election_with_min_stake(&ids, 0u128, 42);
        assert_eq!(election.num_active, 2);
    }
}
