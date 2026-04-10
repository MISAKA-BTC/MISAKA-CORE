// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Consensus benchmarks — Narwhal/Bullshark performance characterization.
//!
//! Measures:
//! 1. Commit throughput (blocks/sec, commits/sec)
//! 2. End-to-end TX latency (block accept → commit)
//! 3. Fast-path latency (certifier path)
//! 4. Recovery time (simulated crash → ready)
//!
//! Run: `cargo bench -p misaka-dag`
//! Results in: `target/criterion/`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::sync::Arc;
use std::time::Instant;

use misaka_dag::narwhal_dag::block_manager::*;
use misaka_dag::narwhal_dag::block_verifier::*;
use misaka_dag::narwhal_dag::commit_finalizer::*;
use misaka_dag::narwhal_dag::core_engine::*;
use misaka_dag::narwhal_dag::dag_state::*;
use misaka_dag::narwhal_dag::leader_schedule::*;
use misaka_dag::narwhal_dag::transaction_certifier::*;
use misaka_dag::narwhal_ordering::linearizer::*;
use misaka_dag::narwhal_ordering::universal_committer::*;
use misaka_dag::narwhal_types::block::*;
use misaka_dag::narwhal_types::commit::*;
use misaka_dag::narwhal_types::committee::*;

// ═══════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════

fn make_block(round: Round, author: AuthorityIndex, ancestors: Vec<BlockRef>) -> VerifiedBlock {
    let block = Block {
        epoch: 0,
        round,
        author,
        timestamp_ms: round as u64 * 1000 + author as u64,
        ancestors,
        transactions: vec![vec![round as u8, author as u8; 100]], // 100-byte tx
        commit_votes: vec![],
        tx_reject_votes: vec![],
        state_root: [0u8; 32],
        signature: vec![0xAA; 64],
    };
    VerifiedBlock::new_for_test(block)
}

/// Build a fully connected DAG and return all block refs per round.
fn build_dag(committee_size: usize, rounds: u32) -> (DagState, Vec<Vec<BlockRef>>) {
    let committee = Committee::new_for_test(committee_size);
    let mut dag = DagState::new(committee, DagStateConfig::default());
    let mut all_refs = Vec::new();

    for round in 1..=rounds {
        let prev = if round == 1 {
            vec![]
        } else {
            all_refs.last().unwrap().clone()
        };
        let mut round_refs = Vec::new();
        for author in 0..committee_size as u32 {
            let b = make_block(round, author, prev.clone());
            round_refs.push(b.reference());
            dag.accept_block(b);
        }
        all_refs.push(round_refs);
    }
    (dag, all_refs)
}

// ═══════════════════════════════════════════════════════════════
//  1. Commit Throughput
// ═══════════════════════════════════════════════════════════════

fn bench_commit_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit_throughput");

    for &n in &[4u32, 7, 21] {
        group.bench_with_input(
            BenchmarkId::new("full_commit", format!("n={}", n)),
            &n,
            |b, &n| {
                b.iter(|| {
                    let committee = Committee::new_for_test(n as usize);
                    let ls = LeaderSchedule::new(committee.clone(), 1);
                    let mut committer = UniversalCommitter::new(
                        committee.clone(), ls, 1, 2,
                    );
                    let (dag, _) = build_dag(n as usize, 20);
                    let ledger = misaka_dag::narwhal_dag::slot_equivocation_ledger::SlotEquivocationLedger::new();
                    black_box(committer.try_commit(&dag, &ledger));
                });
            },
        );
    }

    group.finish();
}

fn bench_dag_accept(c: &mut Criterion) {
    let mut group = c.benchmark_group("dag_accept");

    for &n in &[4u32, 21] {
        group.bench_with_input(
            BenchmarkId::new("accept_block", format!("n={}", n)),
            &n,
            |b, &n| {
                let committee = Committee::new_for_test(n as usize);
                let mut dag = DagState::new(committee, DagStateConfig::default());
                let mut round = 1u32;
                let mut author = 0u32;
                b.iter(|| {
                    let block = make_block(round, author % n, vec![]);
                    black_box(dag.accept_block(block));
                    author += 1;
                    if author % n == 0 {
                        round += 1;
                    }
                });
            },
        );
    }
    group.finish();
}

// ═══════════════════════════════════════════════════════════════
//  2. End-to-End TX Latency
// ═══════════════════════════════════════════════════════════════

fn bench_e2e_latency(c: &mut Criterion) {
    c.bench_function("e2e_tx_latency_4node", |b| {
        b.iter(|| {
            // TODO(CR-1): TestValidatorSet keygen inside iter() adds overhead to benchmarks
            let vs = TestValidatorSet::new(4);
            let committee = vs.committee();
            let signer = vs.signer(0);
            let verifier = vs.verifier(0);
            let chain_ctx = TestValidatorSet::chain_ctx();
            let mut engine = CoreEngine::new(0, 0, committee.clone(), signer, verifier, chain_ctx);
            let mut bm = BlockManager::new(committee.clone());
            let mut dag = DagState::new(committee, DagStateConfig::default());

            let mut prev = Vec::new();
            for round in 1..=5u32 {
                let mut refs = Vec::new();
                for author in 0..4u32 {
                    let block = Block {
                        epoch: 0,
                        round,
                        author,
                        timestamp_ms: round as u64 * 1000,
                        ancestors: prev.clone(),
                        transactions: vec![vec![round as u8, author as u8]],
                        commit_votes: vec![],
                        tx_reject_votes: vec![],
                        state_root: [0u8; 32],
                        signature: vec![0xAA; 64],
                    };
                    let vb = VerifiedBlock::new_for_test(block);
                    refs.push(vb.reference());
                    black_box(engine.process_block(vb, &mut bm, &mut dag));
                }
                prev = refs;
            }
        });
    });
}

// ═══════════════════════════════════════════════════════════════
//  3. Fast-Path Latency (Transaction Certifier)
// ═══════════════════════════════════════════════════════════════

fn bench_fast_path_latency(c: &mut Criterion) {
    c.bench_function("fast_path_certification_4node", |b| {
        b.iter(|| {
            let committee = Committee::new_for_test(4);
            let mut certifier = TxCertifier::new(committee);

            // Propose a block with 10 TXs
            let vb = {
                let block = Block {
                    epoch: 0,
                    round: 1,
                    author: 0,
                    timestamp_ms: 1000,
                    ancestors: vec![],
                    transactions: (0..10).map(|i| vec![i as u8; 100]).collect(),
                    commit_votes: vec![],
                    tx_reject_votes: vec![],
                    state_root: [0u8; 32],
                    signature: vec![0xAA; 64],
                };
                VerifiedBlock::new_for_test(block)
            };
            let br = vb.reference();
            certifier.track_block(&vb);

            // 3 authorities vote (quorum for n=4)
            for voter in 1..=3 {
                certifier.add_vote(&br, voter, false);
            }

            black_box(certifier.take_certified());
        });
    });
}

// ═══════════════════════════════════════════════════════════════
//  4. Recovery Time
// ═══════════════════════════════════════════════════════════════

fn bench_recovery(c: &mut Criterion) {
    c.bench_function("recovery_from_dag_state", |b| {
        // Pre-build a DAG with 100 rounds
        let (dag, _) = build_dag(21, 100);

        b.iter(|| {
            // TODO(CR-1): TestValidatorSet keygen inside iter() adds overhead to benchmarks
            let vs = TestValidatorSet::new(21);
            let committee = vs.committee();
            let signer = vs.signer(0);
            let verifier = vs.verifier(0);
            let chain_ctx = TestValidatorSet::chain_ctx();
            let mut engine = CoreEngine::new(0, 0, committee, signer, verifier, chain_ctx);
            engine.recover_from_state(&dag);
            black_box(engine.last_proposed_round());
        });
    });
}

// ═══════════════════════════════════════════════════════════════
//  5. Threshold Clock
// ═══════════════════════════════════════════════════════════════

fn bench_threshold_clock(c: &mut Criterion) {
    c.bench_function("threshold_clock_observe", |b| {
        let committee = Committee::new_for_test(21);
        let mut clock = ThresholdClock::new(committee);
        let mut round = 0u32;
        let mut author = 0u32;
        b.iter(|| {
            black_box(clock.observe(round, author % 21));
            author += 1;
            if author % 21 == 0 {
                round += 1;
            }
        });
    });
}

// ═══════════════════════════════════════════════════════════════
//  6. Commit Finalizer V2
// ═══════════════════════════════════════════════════════════════

fn bench_commit_finalizer(c: &mut Criterion) {
    c.bench_function("commit_finalizer_v2_direct", |b| {
        b.iter(|| {
            let committee = Committee::new_for_test(4);
            let mut finalizer = CommitFinalizerV2::new(committee);

            for i in 0..100u64 {
                let block = Block {
                    epoch: 0,
                    round: i as u32 + 1,
                    author: 0,
                    timestamp_ms: i * 1000,
                    ancestors: vec![],
                    transactions: vec![vec![i as u8; 50]],
                    commit_votes: vec![],
                    tx_reject_votes: vec![],
                    state_root: [0u8; 32],
                    signature: vec![0xAA; 64],
                };
                let commit = CommittedSubDag {
                    index: i,
                    leader: block.reference(),
                    blocks: vec![block.reference()],
                    timestamp_ms: i * 1000,
                    previous_digest: CommitDigest([0; 32]),
                    is_direct: true,
                };
                let bc = block.clone();
                finalizer.process_commit(&commit, |r| {
                    if *r == bc.reference() {
                        Some(bc.clone())
                    } else {
                        None
                    }
                });
            }
            black_box(finalizer.take_finalized());
        });
    });
}

criterion_group!(
    benches,
    bench_commit_throughput,
    bench_dag_accept,
    bench_e2e_latency,
    bench_fast_path_latency,
    bench_recovery,
    bench_threshold_clock,
    bench_commit_finalizer,
);
criterion_main!(benches);
