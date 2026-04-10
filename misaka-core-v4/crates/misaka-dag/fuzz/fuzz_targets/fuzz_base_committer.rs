//! Fuzz target for BaseCommitter — direct and indirect commit decisions.
//!
//! Generates random DAG topologies and verifies that the committer never
//! panics and always returns a valid Decision variant.
//!
//! Run: `cargo +nightly fuzz run fuzz_base_committer -- -max_total_time=3600`

#![no_main]
use libfuzzer_sys::fuzz_target;

use misaka_dag::narwhal_types::block::*;
use misaka_dag::narwhal_types::committee::*;
use misaka_dag::narwhal_dag::dag_state::*;
use misaka_dag::narwhal_ordering::base_committer::*;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 { return; }

    // Parse fuzz input as structured parameters
    let committee_size = ((data[0] % 20) + 4) as usize; // 4..23
    let num_rounds = ((data[1] % 10) + 2) as u32;       // 2..11
    let leader_round = ((data[2] % num_rounds.saturating_sub(1)) + 1) as Round;
    let missing_mask = data[3];  // bitmask: which authorities are offline
    let wave = ((data[4] % 3) + 1) as u32; // 1..3

    let committee = Committee::new_for_test(committee_size);
    let committer = BaseCommitter::new(committee.clone(), wave);
    let mut dag = DagState::new(committee, DagStateConfig::default());

    // Build DAG with some authorities missing (based on bitmask)
    let mut prev_refs = Vec::new();
    for round in 1..=num_rounds {
        let mut round_refs = Vec::new();
        for author in 0..committee_size as u32 {
            // Skip if bit is set (authority offline this round)
            if round > 1 && (missing_mask >> (author % 8)) & 1 == 1 {
                continue;
            }
            let block = Block {
                epoch: 0,
                round,
                author,
                timestamp_ms: round as u64 * 1000 + author as u64,
                ancestors: prev_refs.clone(),
                transactions: vec![vec![round as u8, author as u8]],
                commit_votes: vec![],
                tx_reject_votes: vec![],
                state_root: [0u8; 32],
                signature: vec![0xAA; 64],
            };
            let vb = VerifiedBlock::new_for_test(block);
            round_refs.push(vb.reference());
            dag.accept_block(vb);
        }
        prev_refs = round_refs;
    }

    // Try direct decide for the leader round
    let leader_author = (leader_round % committee_size as u32) as AuthorityIndex;
    let leader_block = dag.get_blocks_at_round(leader_round)
        .into_iter()
        .find(|b| b.author() == leader_author);

    if let Some(leader) = leader_block {
        let leader_ref = leader.reference();

        // Direct decide — must not panic
        let ledger = misaka_dag::narwhal_dag::slot_equivocation_ledger::SlotEquivocationLedger::new();
        let _decision = committer.try_direct_decide(&leader_ref, &dag, &ledger);

        // Indirect decide with anchor — must not panic
        if !prev_refs.is_empty() {
            let anchor_ref = prev_refs[0];
            let _indirect = committer.try_decide_with_anchor(&leader_ref, &anchor_ref, &dag);
        }

        // Bounded indirect — must not panic
        let _bounded = committer.try_decide_indirect_bounded(
            &leader_ref,
            &prev_refs.first().copied().unwrap_or(leader_ref),
            &dag,
            50,
        );
    }
});
