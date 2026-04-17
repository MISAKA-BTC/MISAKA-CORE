// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation

use super::*;

/// (a) Happy path: genesis → 3 commits with 3/4 quorum → all stored.
#[test]
fn happy_path_genesis_to_commits() {
    let fix = TestFixture::new(4, 100); // 4 validators, 100 stake each
    let mut client = fix.make_client();

    // Verify 3 commits signed by validators 0,1,2 (3/4 quorum)
    for i in 1..=3u64 {
        let commit = fix.make_commit(i, i, &[0, 1, 2]);
        let verified = client.verify_commit(commit).expect("commit should verify");
        assert_eq!(verified.commit_index, i);
        assert_eq!(verified.epoch, 0);
    }

    let latest = client.latest_verified_commit().unwrap().unwrap();
    assert_eq!(latest.commit_index, 3);
}
