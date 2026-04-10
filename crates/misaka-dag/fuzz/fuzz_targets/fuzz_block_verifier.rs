//! Fuzz target for BlockVerifier — structural validation of blocks.
//!
//! Generates malformed blocks and verifies that the verifier never
//! panics and always returns a meaningful error.
//!
//! Run: `cargo +nightly fuzz run fuzz_block_verifier -- -max_total_time=3600`

#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

use misaka_dag::narwhal_types::block::*;
use misaka_dag::narwhal_types::committee::*;
use misaka_dag::narwhal_dag::block_verifier::*;

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 { return; }

    let committee = Committee::new_for_test(4);
    let chain_ctx = misaka_types::chain_context::ChainContext::new(99, [0u8; 32]);
    let verifier = BlockVerifier::new(
        committee, 0, Arc::new(MlDsa65Verifier), chain_ctx,
    );

    // Parse fuzz input into block fields
    let epoch = u64::from_le_bytes(data[0..8].try_into().unwrap_or([0; 8]));
    let round = u32::from_le_bytes(data[8..12].try_into().unwrap_or([0; 4]));
    let author = u32::from_le_bytes(data[12..16].try_into().unwrap_or([0; 4]));

    let timestamp = if data.len() > 24 {
        u64::from_le_bytes(data[16..24].try_into().unwrap_or([0; 8]))
    } else {
        1000
    };

    let tx_data = if data.len() > 24 { data[24..].to_vec() } else { vec![1] };

    // Construct ancestors from remaining data (if any)
    let mut ancestors = Vec::new();
    if data.len() > 60 {
        let ancestor_author = data[24] % 4;
        let ancestor_round = round.saturating_sub(1);
        let mut digest = [0u8; 32];
        if data.len() > 56 {
            digest[..32.min(data.len() - 24)].copy_from_slice(
                &data[24..24 + 32.min(data.len() - 24)]
            );
        }
        ancestors.push(BlockRef::new(ancestor_round, ancestor_author as u32, BlockDigest(digest)));
    }

    let sig = if data.len() > 80 {
        data[60..].to_vec()
    } else {
        vec![0xAA; 64] // structurally valid
    };

    let block = Block {
        epoch,
        round,
        author,
        timestamp_ms: timestamp,
        ancestors,
        transactions: vec![tx_data],
        commit_votes: vec![],
        tx_reject_votes: vec![],
        signature: sig,
    };

    // Verify — must never panic, only return Ok/Err
    let _ = verifier.verify(&block);
});
