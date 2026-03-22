//! ZKP Performance Benchmark — measures core cryptographic operation latencies.
//!
//! # Usage
//!
//! ```bash
//! cargo test -p misaka-pqc --test zkp_benchmark --release -- --nocapture
//! ```
//!
//! # Measured Operations
//!
//! 1. Ring signature (LRS): sign + verify for ring sizes 4, 8, 16
//! 2. Key image proof: prove + verify
//! 3. BDLOP commitment: commit + balance proof + range proof
//! 4. SIS Merkle membership: prove + verify for tree sizes 16, 64, 256
//! 5. UnifiedMembershipProof: full prove + verify
//! 6. CompositeProof: prove + verify (1 input, 2 outputs)
//!
//! # Notes
//!
//! - Run with `--release` for meaningful numbers (debug is 10-50× slower)
//! - Results are printed to stdout, not asserted (hardware-dependent)
//! - Each operation is run N times and averaged

use std::time::Instant;

use misaka_pqc::pq_ring::*;
use misaka_pqc::pq_sign::MlDsaKeypair;
use misaka_pqc::ki_proof::{canonical_strong_ki, prove_key_image, verify_key_image};
use misaka_pqc::bdlop::{BdlopCrs, BdlopCommitment, BlindingFactor, BalanceExcessProof};
use misaka_pqc::range_proof::{prove_range, verify_range};
use misaka_pqc::membership::{
    SisMerkleCrs, sis_leaf, compute_sis_root, sis_root_hash,
    prove_membership_v2, verify_membership_v2,
};
use misaka_pqc::composite_proof::{prove_composite, verify_composite, OutputWitness};

const WARMUP: usize = 2;
const ITERATIONS: usize = 10;

fn bench<F: FnMut()>(name: &str, mut f: F) {
    // Warmup
    for _ in 0..WARMUP {
        f();
    }

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        f();
    }
    let elapsed = start.elapsed();
    let avg_us = elapsed.as_micros() / ITERATIONS as u128;
    let avg_ms = avg_us as f64 / 1000.0;

    println!("  {:<45} {:>8.2} ms  ({} iters)", name, avg_ms, ITERATIONS);
}

#[test]
fn zkp_benchmark_suite() {
    println!();
    println!("═══════════════════════════════════════════════════════════");
    println!("  MISAKA ZKP Performance Benchmark");
    println!("═══════════════════════════════════════════════════════════");
    println!();

    let a = derive_public_param(&DEFAULT_A_SEED);

    // ── 1. Ring Signatures ──
    println!("── Ring Signatures (LRS) ──");
    for ring_size in [4, 8, 16] {
        let wallets: Vec<SpendingKeypair> = (0..ring_size)
            .map(|_| SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key).unwrap())
            .collect();
        let ring: Vec<Poly> = wallets.iter().map(|w| w.public_poly.clone()).collect();
        let msg = [0x42u8; 32];

        let mut sig_out = None;
        bench(&format!("ring_sign (n={})", ring_size), || {
            let s = ring_sign(&a, &ring, 0, &wallets[0].secret_poly, &msg).unwrap();
            sig_out = Some(s);
        });

        let sig = sig_out.unwrap();
        bench(&format!("ring_verify (n={})", ring_size), || {
            ring_verify(&a, &ring, &msg, &sig).unwrap();
        });
    }
    println!();

    // ── 2. Key Image Proof ──
    println!("── Key Image Proof ──");
    {
        let kp = MlDsaKeypair::generate();
        let s = derive_secret_poly(&kp.secret_key).unwrap();
        let pk = compute_pubkey(&a, &s);
        let (_, ki) = canonical_strong_ki(&pk, &s);

        let mut proof_out = None;
        bench("ki_proof_prove", || {
            let p = prove_key_image(&a, &s, &pk, &ki).unwrap();
            proof_out = Some(p);
        });

        let proof = proof_out.unwrap();
        bench("ki_proof_verify", || {
            verify_key_image(&a, &pk, &ki, &proof).unwrap();
        });
    }
    println!();

    // ── 3. BDLOP Commitment + Proofs ──
    println!("── BDLOP Commitment ──");
    {
        let crs = BdlopCrs::default_crs();
        let blind = BlindingFactor::random();
        let amount = 10_000u64;

        bench("bdlop_commit", || {
            let _ = BdlopCommitment::commit(&crs, &blind, amount).unwrap();
        });

        let c = BdlopCommitment::commit(&crs, &blind, amount).unwrap();

        let mut rp_out = None;
        bench("range_proof_prove", || {
            let (rp, _) = prove_range(&crs, amount, &blind).unwrap();
            rp_out = Some(rp);
        });

        let rp = rp_out.unwrap();
        bench("range_proof_verify", || {
            verify_range(&crs, &c, &rp).unwrap();
        });
    }
    println!();

    // ── 4. SIS Merkle Membership ──
    println!("── SIS Merkle Membership (v2) ──");
    {
        let bdlop_crs = BdlopCrs::default_crs();
        let sis_crs = SisMerkleCrs::default_crs();

        for tree_size in [16, 64, 256] {
            let leaves: Vec<Poly> = (0..tree_size)
                .map(|_| {
                    let kp = MlDsaKeypair::generate();
                    let s = derive_secret_poly(&kp.secret_key).unwrap();
                    sis_leaf(&compute_pubkey(&a, &s))
                })
                .collect();

            let root = compute_sis_root(&sis_crs, &leaves).unwrap();
            let root_hash = sis_root_hash(&root);

            let mut proof_out = None;
            bench(&format!("membership_prove_v2 (n={})", tree_size), || {
                let p = prove_membership_v2(&bdlop_crs, &sis_crs, &leaves, 0).unwrap();
                proof_out = Some(p);
            });

            let proof = proof_out.unwrap();
            bench(&format!("membership_verify_v2 (n={})", tree_size), || {
                verify_membership_v2(&bdlop_crs, &sis_crs, &root_hash, &proof).unwrap();
            });
        }
    }
    println!();

    // ── 5. CompositeProof ──
    println!("── CompositeProof (1 input, 2 outputs) ──");
    {
        let crs = BdlopCrs::default_crs();
        let in_blind = BlindingFactor::random();
        let in_amount = 10_000u64;
        let in_commitment = BdlopCommitment::commit(&crs, &in_blind, in_amount).unwrap();

        let out1 = OutputWitness { amount: 9_000, blinding: BlindingFactor::random() };
        let out2 = OutputWitness { amount: 900, blinding: BlindingFactor::random() };
        let fee_amount = 100u64;
        let fee_blind = BlindingFactor::random();
        let fee_commitment = BdlopCommitment::commit(&crs, &fee_blind, fee_amount).unwrap();
        let tx_digest = [0xAA; 32];
        let nullifiers = vec![[0xBB; 32]];

        let mut proof_out = None;
        bench("composite_prove (1in 2out)", || {
            let p = prove_composite(
                &crs, &tx_digest, &[in_commitment.clone()], &[in_blind.clone()],
                &[OutputWitness { amount: 9_000, blinding: BlindingFactor::random() },
                  OutputWitness { amount: 900, blinding: BlindingFactor::random() }],
                fee_amount, &fee_blind, &nullifiers,
            ).unwrap();
            proof_out = Some(p);
        });

        let proof = proof_out.unwrap();
        bench("composite_verify (1in 2out)", || {
            verify_composite(
                &crs, &proof, &tx_digest, &[in_commitment.clone()],
                &fee_commitment, &nullifiers,
            ).unwrap();
        });
    }
    println!();

    // ── Summary ──
    println!("═══════════════════════════════════════════════════════════");
    println!("  Benchmark complete. Run with --release for production numbers.");
    println!("═══════════════════════════════════════════════════════════");
    println!();
}
