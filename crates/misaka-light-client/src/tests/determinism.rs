// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation

use super::*;

/// (g) Determinism: two clients with same inputs → identical state.
#[test]
fn determinism_two_clients_identical() {
    let fix = TestFixture::new(4, 100);

    let mut client_a = fix.make_client();
    let mut client_b = fix.make_client();

    // Feed same 5 commits to both
    for i in 1..=5u64 {
        let commit_a = fix.make_commit(i, i, &[0, 1, 2]);
        let commit_b = fix.make_commit(i, i, &[0, 1, 2]);
        let va = client_a.verify_commit(commit_a).unwrap();
        let vb = client_b.verify_commit(commit_b).unwrap();

        assert_eq!(va.commit_index, vb.commit_index);
        assert_eq!(va.verified_stake, vb.verified_stake);
        assert_eq!(va.block_hash, vb.block_hash);
        assert_eq!(va.epoch, vb.epoch);
    }

    let la = client_a.latest_verified_commit().unwrap().unwrap();
    let lb = client_b.latest_verified_commit().unwrap().unwrap();
    assert_eq!(la.commit_index, lb.commit_index);
    assert_eq!(la.commit_digest.0, lb.commit_digest.0);
}
