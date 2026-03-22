//! MISAKA Network — Full Cryptographic Benchmark Suite
//!
//! Measures every PQ cryptographic operation end-to-end.
//!
//! ```bash
//! cargo test -p misaka-pqc --test full_benchmark --release -- --nocapture
//! ```

use std::time::Instant;

use misaka_pqc::pq_sign::{MlDsaKeypair, ml_dsa_sign, ml_dsa_verify};
use misaka_pqc::pq_kem::{ml_kem_keygen, ml_kem_encapsulate, ml_kem_decapsulate};
use misaka_pqc::pq_ring::*;
use misaka_pqc::ki_proof::{canonical_strong_ki, prove_key_image, verify_key_image};
use misaka_pqc::bdlop::{BdlopCrs, BdlopCommitment, BlindingFactor, BalanceExcessProof,
    compute_balance_diff, verify_balance_with_excess};
use misaka_pqc::range_proof::{prove_range, verify_range};
use misaka_pqc::nullifier::{compute_nullifier, NullifierProof};
use misaka_pqc::membership::{
    SisMerkleCrs, sis_leaf, compute_sis_root, sis_root_hash,
    prove_membership_v2, verify_membership_v2,
};
use misaka_pqc::composite_proof::{prove_composite, verify_composite, OutputWitness};
use misaka_pqc::pq_stealth::{create_stealth_output, StealthScanner};
use misaka_pqc::packing::{pack_ring_sig, unpack_ring_sig, pack_ring_sig_v2, unpack_ring_sig_v2};

const WARMUP: usize = 3;
const ITERS: usize = 20;

struct BenchResult {
    name: String,
    avg_us: u128,
    iters: usize,
}

fn bench<F: FnMut()>(name: &str, iters: usize, mut f: F) -> BenchResult {
    for _ in 0..WARMUP { f(); }
    let start = Instant::now();
    for _ in 0..iters { f(); }
    let elapsed = start.elapsed();
    let avg_us = elapsed.as_micros() / iters as u128;
    let avg_ms = avg_us as f64 / 1000.0;
    println!("  {:<50} {:>8.2} ms  {:>8} µs  ({} iters)",
        name, avg_ms, avg_us, iters);
    BenchResult { name: name.to_string(), avg_us, iters }
}

#[test]
fn full_benchmark() {
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║       MISAKA Network — Full Cryptographic Benchmark v5.1        ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();

    let mut results: Vec<BenchResult> = Vec::new();

    // ═══════════════════════════════════════════════
    //  1. ML-DSA-65 (FIPS 204) — Digital Signatures
    // ═══════════════════════════════════════════════
    println!("┌─ ML-DSA-65 (FIPS 204) — Post-Quantum Signatures ─────────────────┐");

    results.push(bench("ML-DSA-65 keygen", ITERS, || {
        let _ = MlDsaKeypair::generate();
    }));

    let kp = MlDsaKeypair::generate();
    let msg = b"MISAKA benchmark message 2026";
    let sig = ml_dsa_sign(&kp.secret_key, msg).unwrap();

    results.push(bench("ML-DSA-65 sign", ITERS, || {
        let _ = ml_dsa_sign(&kp.secret_key, msg).unwrap();
    }));

    results.push(bench("ML-DSA-65 verify", ITERS, || {
        ml_dsa_verify(&kp.public_key, msg, &sig).unwrap();
    }));

    println!("  PK size: {} bytes | SK size: {} bytes | Sig size: {} bytes",
        kp.public_key.as_bytes().len(),
        kp.secret_key.as_bytes().len(),
        sig.as_bytes().len());
    println!("└─────────────────────────────────────────────────────────────────┘");
    println!();

    // ═══════════════════════════════════════════════
    //  2. ML-KEM-768 (FIPS 203) — Key Encapsulation
    // ═══════════════════════════════════════════════
    println!("┌─ ML-KEM-768 (FIPS 203) — Post-Quantum Key Exchange ──────────────┐");

    results.push(bench("ML-KEM-768 keygen", ITERS, || {
        let _ = ml_kem_keygen().unwrap();
    }));

    let kem_kp = ml_kem_keygen().unwrap();

    results.push(bench("ML-KEM-768 encapsulate", ITERS, || {
        let _ = ml_kem_encapsulate(&kem_kp.public_key).unwrap();
    }));

    let (ct, _ss) = ml_kem_encapsulate(&kem_kp.public_key).unwrap();

    results.push(bench("ML-KEM-768 decapsulate", ITERS, || {
        let _ = ml_kem_decapsulate(&kem_kp.secret_key, &ct).unwrap();
    }));

    println!("  PK: {} B | SK: {} B | CT: {} B | SS: 32 B",
        kem_kp.public_key.as_bytes().len(),
        kem_kp.secret_key.as_bytes().len(),
        ct.as_bytes().len());
    println!("└─────────────────────────────────────────────────────────────────┘");
    println!();

    // ═══════════════════════════════════════════════
    //  3. Lattice Ring Signatures (LRS)
    // ═══════════════════════════════════════════════
    println!("┌─ Lattice Ring Signatures — R_q = Z_12289[X]/(X^256+1) ───────────┐");

    let a = derive_public_param(&DEFAULT_A_SEED);

    for ring_size in [4, 8, 16, 32] {
        let wallets: Vec<SpendingKeypair> = (0..ring_size)
            .map(|_| SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key).unwrap())
            .collect();
        let ring: Vec<Poly> = wallets.iter().map(|w| w.public_poly.clone()).collect();
        let msg = [0x42u8; 32];

        let mut sig_out = None;
        results.push(bench(&format!("ring_sign (n={})", ring_size), ITERS, || {
            let s = ring_sign(&a, &ring, 0, &wallets[0].secret_poly, &msg).unwrap();
            sig_out = Some(s);
        }));

        let sig = sig_out.unwrap();
        results.push(bench(&format!("ring_verify (n={})", ring_size), ITERS, || {
            ring_verify(&a, &ring, &msg, &sig).unwrap();
        }));

        let raw = sig.to_bytes();
        let packed_v1 = pack_ring_sig(&sig);
        let packed_v2 = pack_ring_sig_v2(&sig);
        println!("  n={}: raw={} B | v1={} B (-{:.0}%) | v2={} B (-{:.0}%)",
            ring_size, raw.len(), packed_v1.len(),
            (1.0 - packed_v1.len() as f64 / raw.len() as f64) * 100.0,
            packed_v2.len(),
            (1.0 - packed_v2.len() as f64 / raw.len() as f64) * 100.0);
    }
    println!("└─────────────────────────────────────────────────────────────────┘");
    println!();

    // ═══════════════════════════════════════════════
    //  4. Key Image Proof (Σ-protocol)
    // ═══════════════════════════════════════════════
    println!("┌─ Key Image Proof — Dual-Relation Σ-Protocol ─────────────────────┐");
    {
        let kp = MlDsaKeypair::generate();
        let s = derive_secret_poly(&kp.secret_key).unwrap();
        let pk = compute_pubkey(&a, &s);
        let (_, ki) = canonical_strong_ki(&pk, &s);

        let mut proof_out = None;
        results.push(bench("ki_proof_prove", ITERS, || {
            proof_out = Some(prove_key_image(&a, &s, &pk, &ki).unwrap());
        }));

        let proof = proof_out.unwrap();
        results.push(bench("ki_proof_verify", ITERS, || {
            verify_key_image(&a, &pk, &ki, &proof).unwrap();
        }));
    }
    println!("└─────────────────────────────────────────────────────────────────┘");
    println!();

    // ═══════════════════════════════════════════════
    //  5. BDLOP Commitment + Range Proof + Balance
    // ═══════════════════════════════════════════════
    println!("┌─ BDLOP Commitment + Range Proof + Balance ───────────────────────┐");
    {
        let crs = BdlopCrs::default_crs();
        let blind = BlindingFactor::random();
        let amount = 10_000u64;

        results.push(bench("bdlop_commit", 50, || {
            let _ = BdlopCommitment::commit(&crs, &blind, amount).unwrap();
        }));

        let c = BdlopCommitment::commit(&crs, &blind, amount).unwrap();

        let mut rp_out = None;
        results.push(bench("range_proof_prove (64-bit)", ITERS, || {
            rp_out = Some(prove_range(&crs, amount, &blind).unwrap().0);
        }));

        let rp = rp_out.unwrap();
        results.push(bench("range_proof_verify (64-bit)", ITERS, || {
            verify_range(&crs, &c, &rp).unwrap();
        }));

        // Balance proof
        let r_in = BlindingFactor::random();
        let r_out = BlindingFactor::random();
        let c_in = BdlopCommitment::commit(&crs, &r_in, 1000).unwrap();
        let c_out = BdlopCommitment::commit(&crs, &r_out, 900).unwrap();
        let diff = compute_balance_diff(&crs, &[c_in.clone()], &[c_out.clone()], 100).unwrap();

        let mut r_excess = Poly::zero();
        for i in 0..256 {
            r_excess.coeffs[i] = ((r_in.as_poly().coeffs[i] as i64
                - r_out.as_poly().coeffs[i] as i64) % 12289 + 12289) as i32 % 12289;
        }

        let mut bp_out = None;
        results.push(bench("balance_excess_prove", ITERS, || {
            bp_out = Some(BalanceExcessProof::prove(&crs, &diff, &r_excess).unwrap());
        }));

        let bp = bp_out.unwrap();
        results.push(bench("balance_excess_verify", ITERS, || {
            verify_balance_with_excess(&crs, &diff, &bp).unwrap();
        }));
    }
    println!("└─────────────────────────────────────────────────────────────────┘");
    println!();

    // ═══════════════════════════════════════════════
    //  6. SIS Merkle Membership Proof
    // ═══════════════════════════════════════════════
    println!("┌─ SIS Merkle Membership Proof ────────────────────────────────────┐");
    {
        let bdlop_crs = BdlopCrs::default_crs();
        let sis_crs = SisMerkleCrs::default_crs();

        for tree_size in [16, 64, 256] {
            let leaves: Vec<Poly> = (0..tree_size)
                .map(|_| {
                    let s = derive_secret_poly(&MlDsaKeypair::generate().secret_key).unwrap();
                    sis_leaf(&compute_pubkey(&a, &s))
                })
                .collect();

            let root = compute_sis_root(&sis_crs, &leaves).unwrap();
            let rh = sis_root_hash(&root);

            let mut proof_out = None;
            results.push(bench(&format!("membership_prove (n={})", tree_size), ITERS, || {
                proof_out = Some(prove_membership_v2(&bdlop_crs, &sis_crs, &leaves, 0).unwrap());
            }));

            let proof = proof_out.unwrap();
            results.push(bench(&format!("membership_verify (n={})", tree_size), ITERS, || {
                verify_membership_v2(&bdlop_crs, &sis_crs, &rh, &proof).unwrap();
            }));
        }
    }
    println!("└─────────────────────────────────────────────────────────────────┘");
    println!();

    // ═══════════════════════════════════════════════
    //  7. Composite Proof (Full Confidential TX)
    // ═══════════════════════════════════════════════
    println!("┌─ CompositeProof — Full Confidential Transaction ─────────────────┐");
    {
        let crs = BdlopCrs::default_crs();
        let in_blind = BlindingFactor::random();
        let in_amount = 10_000u64;
        let in_commitment = BdlopCommitment::commit(&crs, &in_blind, in_amount).unwrap();

        let fee_amount = 100u64;
        let fee_blind = BlindingFactor::random();
        let fee_commitment = BdlopCommitment::commit(&crs, &fee_blind, fee_amount).unwrap();
        let tx_digest = [0xAA; 32];
        let nullifiers = vec![[0xBB; 32]];

        let mut proof_out = None;
        results.push(bench("composite_prove (1in→2out)", ITERS, || {
            let p = prove_composite(
                &crs, &tx_digest, &[in_commitment.clone()], &[in_blind.clone()],
                &[OutputWitness { amount: 9_000, blinding: BlindingFactor::random() },
                  OutputWitness { amount: 900, blinding: BlindingFactor::random() }],
                fee_amount, &fee_blind, &nullifiers,
            ).unwrap();
            proof_out = Some(p);
        }));

        let proof = proof_out.unwrap();
        results.push(bench("composite_verify (1in→2out)", ITERS, || {
            verify_composite(
                &crs, &proof, &tx_digest, &[in_commitment.clone()],
                &fee_commitment, &nullifiers,
            ).unwrap();
        }));
    }
    println!("└─────────────────────────────────────────────────────────────────┘");
    println!();

    // ═══════════════════════════════════════════════
    //  8. Stealth Address (ML-KEM-768)
    // ═══════════════════════════════════════════════
    println!("┌─ Stealth Address — ML-KEM-768 One-Time Address ──────────────────┐");
    {
        let kem_kp = ml_kem_keygen().unwrap();
        let tx_id = [0x77; 32];

        results.push(bench("stealth_create_output", ITERS, || {
            let _ = create_stealth_output(&kem_kp.public_key, 42000, b"m", &tx_id, 0).unwrap();
        }));

        let st = create_stealth_output(&kem_kp.public_key, 42000, b"m", &tx_id, 0).unwrap();
        let scanner = StealthScanner::new(kem_kp.secret_key.clone());

        results.push(bench("stealth_scan (match)", ITERS, || {
            let _ = scanner.try_recover(&st.stealth_data, &tx_id, 0).unwrap();
        }));
    }
    println!("└─────────────────────────────────────────────────────────────────┘");
    println!();

    // ═══════════════════════════════════════════════
    //  9. Nullifier Computation
    // ═══════════════════════════════════════════════
    println!("┌─ Nullifier — Algebraic Derivation ───────────────────────────────┐");
    {
        let s = derive_secret_poly(&MlDsaKeypair::generate().secret_key).unwrap();
        let output_id = [0x99u8; 32];

        results.push(bench("nullifier_compute", 50, || {
            let _ = compute_nullifier(&s, &output_id, 2);
        }));
    }
    println!("└─────────────────────────────────────────────────────────────────┘");
    println!();

    // ═══════════════════════════════════════════════
    //  Summary
    // ═══════════════════════════════════════════════
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║                        Summary                                  ║");
    println!("╠═══════════════════════════════════════════════════════════════════╣");

    let tx_prove = results.iter()
        .find(|r| r.name.contains("composite_prove"))
        .map(|r| r.avg_us).unwrap_or(0);
    let tx_verify = results.iter()
        .find(|r| r.name.contains("composite_verify"))
        .map(|r| r.avg_us).unwrap_or(0);
    let ring_sign_4 = results.iter()
        .find(|r| r.name == "ring_sign (n=4)")
        .map(|r| r.avg_us).unwrap_or(0);
    let ring_verify_4 = results.iter()
        .find(|r| r.name == "ring_verify (n=4)")
        .map(|r| r.avg_us).unwrap_or(0);
    let membership_prove_256 = results.iter()
        .find(|r| r.name == "membership_prove (n=256)")
        .map(|r| r.avg_us).unwrap_or(0);
    let membership_verify_256 = results.iter()
        .find(|r| r.name == "membership_verify (n=256)")
        .map(|r| r.avg_us).unwrap_or(0);

    let full_tx_prove = ring_sign_4 + membership_prove_256 + tx_prove;
    let full_tx_verify = ring_verify_4 + membership_verify_256 + tx_verify;
    let tps_verify = if full_tx_verify > 0 { 1_000_000 / full_tx_verify } else { 0 };

    println!("║  Full TX prove  (ring+membership+composite): {:>8} µs      ║", full_tx_prove);
    println!("║  Full TX verify (ring+membership+composite): {:>8} µs      ║", full_tx_verify);
    println!("║  Theoretical single-core TPS (verify):       {:>8} tx/s    ║", tps_verify);
    println!("║  ML-DSA-65 sign+verify:                      {:>8} µs      ║",
        results.iter().find(|r| r.name == "ML-DSA-65 sign").map(|r| r.avg_us).unwrap_or(0)
        + results.iter().find(|r| r.name == "ML-DSA-65 verify").map(|r| r.avg_us).unwrap_or(0));
    println!("║  ML-KEM-768 encap+decap:                     {:>8} µs      ║",
        results.iter().find(|r| r.name == "ML-KEM-768 encapsulate").map(|r| r.avg_us).unwrap_or(0)
        + results.iter().find(|r| r.name == "ML-KEM-768 decapsulate").map(|r| r.avg_us).unwrap_or(0));
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();
}
