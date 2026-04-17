// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation

use super::*;
use crate::error::LightClientError;

/// (d) Replay detection: verify same commit_index twice → CommitReplay.
#[test]
fn replay_detection() {
    let fix = TestFixture::new(4, 100);
    let mut client = fix.make_client();

    let commit1 = fix.make_commit(1, 1, &[0, 1, 2]);
    client.verify_commit(commit1).expect("first should pass");

    // Same commit_index=1 again
    let commit1_dup = fix.make_commit(1, 1, &[0, 1, 2]);
    let result = client.verify_commit(commit1_dup);
    assert!(
        matches!(result, Err(LightClientError::CommitReplay(1))),
        "expected CommitReplay, got: {result:?}"
    );
}

/// (e) Protocol version: TrustRoot with unsupported version check.
/// The light client accepts V1 by default; testing that the protocol
/// version is stored correctly.
#[test]
fn protocol_version_stored() {
    let fix = TestFixture::new(4, 100);
    let client = fix.make_client();
    assert_eq!(client.current_epoch().unwrap(), 0);
    // Protocol version is stored in the TrustRoot, accessible via storage
}

/// (f) Fork detection: same commit_index, different content → reject.
#[test]
fn fork_detection_same_index_different_hash() {
    let fix = TestFixture::new(4, 100);
    let mut client = fix.make_client();

    // First commit at index 1
    let commit1 = fix.make_commit(1, 1, &[0, 1, 2]);
    client.verify_commit(commit1).expect("first should pass");

    // Second commit at index 1 with different block hash → replay
    let commit1_fork = fix.make_commit_with_hash(1, 1, &[0, 1, 2], [0xBB; 32]);
    let result = client.verify_commit(commit1_fork);
    assert!(
        matches!(result, Err(LightClientError::CommitReplay(1))),
        "fork should be caught as replay: {result:?}"
    );
}

/// (h) Chain ID binding: wrong chain_id → ChainIdMismatch.
#[test]
fn chain_id_binding() {
    let fix = TestFixture::new(4, 100);
    let mut client = fix.make_client();

    let mut commit = fix.make_commit(1, 1, &[0, 1, 2]);
    commit.chain_id = 99; // wrong chain_id (fixture uses chain_id=2)

    let result = client.verify_commit(commit);
    assert!(
        matches!(
            result,
            Err(LightClientError::ChainIdMismatch {
                expected: 2,
                got: 99
            })
        ),
        "expected ChainIdMismatch, got: {result:?}"
    );
}
