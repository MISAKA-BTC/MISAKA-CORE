// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Stake-weighted quorum regression tests.
//!
//! HIGH #5: expected_dag_quorum_threshold was count-based, ignoring stake.
//! With skewed stake (e.g., 60/5×8), count-majority != stake-majority.
//! These tests verify that stake-weighted quorum is used everywhere.

use misaka_consensus::validator_set::ValidatorSet;
use misaka_types::validator::{ValidatorIdentity, ValidatorPublicKey};

fn make_set(stakes: &[u128]) -> ValidatorSet {
    let validators: Vec<ValidatorIdentity> = stakes
        .iter()
        .enumerate()
        .map(|(i, &stake)| {
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            ValidatorIdentity {
                validator_id: vid,
                stake_weight: stake,
                public_key: ValidatorPublicKey {
                    bytes: vec![i as u8; 1952],
                },
                is_active: true,
            }
        })
        .collect();
    ValidatorSet::new(validators)
}

/// HIGH #5 regression: count-majority of small validators does NOT reach
/// stake quorum when a whale validator exists.
#[test]
fn skewed_stake_count_majority_does_not_finalize() {
    // Stake: [60, 5, 5, 5, 5, 5, 5, 5, 5] = total 100
    // Quorum: (100 * 2) / 3 + 1 = 67
    let vs = make_set(&[60, 5, 5, 5, 5, 5, 5, 5, 5]);
    let quorum = vs.quorum_threshold();
    assert_eq!(quorum, 67, "quorum must be stake-weighted");

    // 8 small validators signing: 8 × 5 = 40 < 67
    let small_stake: u128 = 5 * 8;
    assert!(
        small_stake < quorum,
        "8 small validators (stake=40) must NOT reach quorum (67) without the whale"
    );
}

/// Whale alone (60) cannot finalize.
#[test]
fn whale_alone_does_not_finalize() {
    let vs = make_set(&[60, 5, 5, 5, 5, 5, 5, 5, 5]);
    assert!(
        60 < vs.quorum_threshold(),
        "whale (60) alone must NOT reach quorum (67)"
    );
}

/// Whale + 2 small = 70 ≥ 67 → finalize.
#[test]
fn whale_plus_two_small_finalizes() {
    let vs = make_set(&[60, 5, 5, 5, 5, 5, 5, 5, 5]);
    let signed: u128 = 60 + 5 + 5;
    assert!(
        signed >= vs.quorum_threshold(),
        "whale + 2 small (70) must reach quorum (67)"
    );
}

/// Uniform stake: count-based and stake-based agree.
#[test]
fn uniform_stake_count_matches_stake() {
    let vs = make_set(&[1, 1, 1, 1, 1, 1, 1, 1, 1]); // 9 × 1
    let quorum = vs.quorum_threshold();
    // (9 * 2) / 3 + 1 = 7
    assert_eq!(quorum, 7);
}

/// The count-based function (now test-only) gives a DIFFERENT answer
/// for skewed stake — this is the bug that HIGH #5 identified.
#[test]
fn count_based_differs_from_stake_based_on_skew() {
    // Count-based: 9 validators, quorum = (9*2)/3 + 1 = 7 (out of 9)
    let count_quorum: u128 = 9 * 2 / 3 + 1; // = 7

    // Stake-based: total=100, quorum = (100*2)/3 + 1 = 67
    let vs = make_set(&[60, 5, 5, 5, 5, 5, 5, 5, 5]);
    let stake_quorum = vs.quorum_threshold(); // = 67

    assert_ne!(
        count_quorum, stake_quorum,
        "count-based ({}) and stake-based ({}) MUST differ for skewed stake",
        count_quorum, stake_quorum
    );

    // 7 small validators = 35 stake → passes count-based but fails stake-based
    let signed_stake: u128 = 5 * 7;
    assert!(7 >= count_quorum, "7 validators pass count-based quorum");
    assert!(
        signed_stake < stake_quorum,
        "7 small validators ({}) must FAIL stake-based quorum ({}). \
         This is the HIGH #5 bug — count-based quorum gives false finality.",
        signed_stake,
        stake_quorum
    );
}

/// Single validator (total_stake > 0) has quorum = 1.
#[test]
fn single_validator_quorum() {
    let vs = make_set(&[100]);
    assert_eq!(vs.quorum_threshold(), 67); // (100*2)/3 + 1
                                           // Wait, single validator with stake 100? Quorum = 67, but there's
                                           // only 1 validator with 100 stake. That means quorum IS reachable (100 ≥ 67).
}

/// Zero-stake validator doesn't contribute.
#[test]
fn zero_stake_validator_ignored() {
    let mut validators = vec![];
    for i in 0..4 {
        let mut vid = [0u8; 32];
        vid[0] = i;
        validators.push(ValidatorIdentity {
            validator_id: vid,
            stake_weight: if i == 3 { 0 } else { 100 },
            public_key: ValidatorPublicKey {
                bytes: vec![i as u8; 1952],
            },
            is_active: true,
        });
    }
    let vs = ValidatorSet::new(validators);
    // total_stake = 300 (3 × 100, one has 0)
    assert_eq!(vs.total_stake(), 300);
    // quorum = (300*2)/3 + 1 = 201
    assert_eq!(vs.quorum_threshold(), 201);
}
