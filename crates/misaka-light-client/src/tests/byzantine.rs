// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation

use super::*;
use crate::error::LightClientError;

/// (b) Byzantine quorum: 2/4 votes (< quorum) → QuorumNotReached.
#[test]
fn byzantine_quorum_insufficient_votes() {
    let fix = TestFixture::new(4, 100); // total=400, quorum=267
    let mut client = fix.make_client();

    // Only 2 of 4 validators sign → 200 stake < 267 quorum
    let commit = fix.make_commit(1, 1, &[0, 1]);
    let result = client.verify_commit(commit);

    match result {
        Err(LightClientError::QuorumNotReached { got, need }) => {
            assert_eq!(got, 200);
            assert_eq!(need, 267);
        }
        other => panic!("expected QuorumNotReached, got: {other:?}"),
    }
}

/// Byzantine: 3/4 votes (>= quorum) → should succeed.
#[test]
fn quorum_reached_with_three_of_four() {
    let fix = TestFixture::new(4, 100);
    let mut client = fix.make_client();

    let commit = fix.make_commit(1, 1, &[0, 1, 2]); // 300 >= 267
    let verified = client.verify_commit(commit).expect("should pass quorum");
    assert_eq!(verified.verified_stake, 300);
}
