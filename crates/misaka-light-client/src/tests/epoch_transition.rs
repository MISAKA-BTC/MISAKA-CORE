// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation

use super::*;
use crate::error::LightClientError;

/// (c) Fake epoch transition: wrong keys → reject.
#[test]
fn fake_epoch_transition_rejected() {
    let fix = TestFixture::new(4, 100);
    let mut client = fix.make_client();

    // Generate a DIFFERENT set of keys (attackers)
    let attacker_fix = TestFixture::new(4, 100);

    // Build a transition proof signed by the attacker's keys (not the genesis committee)
    let new_committee = attacker_fix.committee.clone();
    let proof = attacker_fix.make_epoch_transition(0, 1, &new_committee, &[0, 1, 2]);

    // Should fail: the signatures come from keys not in the current committee
    let result = client.verify_epoch_transition(proof);
    assert!(
        matches!(result, Err(LightClientError::UnknownVoter(_))),
        "expected UnknownVoter, got: {result:?}"
    );
}
