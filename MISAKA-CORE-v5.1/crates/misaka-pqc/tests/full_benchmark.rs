//! MISAKA Network — Full Cryptographic Benchmark Suite v5.1
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
use misaka_pqc::nullifier::{OutputId, compute_nullifier};
use misaka_pqc::membership::{
    SisMerkleCrs, sis_leaf, compute_sis_root, sis_root_hash,
    prove_membership_v2, verify_membership_v2,
};
use misaka_pqc::composite_proof::{prove_composite, verify_composite, OutputWitness};
use misaka_pqc::pq_stealth::{create_stealth_output, StealthScanner};
use misaka_pqc::packing::{pack_ring_sig, pack_ring_sig_v2};

const WARMUP: usize = 3;
const ITERS: usize = 20;

struct BenchResult { name: String, avg_us: u128 }

fn bench<F: FnMut()>(name: &str, iters: usize, mut f: F) -> BenchResult {
    for _ in 0..WARMUP { f(); }
    let start = Instant::now();
    for _ in 0..iters { f(); }
    let elapsed = start.elapsed();
    let avg_us = elapsed.as_micros() / iters as u128;
    let avg_ms = avg_us as f64 / 1000.0;
    println!("  {:<50} {:>8.2} ms  {:>8} us  ({} iters)", name, avg_ms, avg_us, iters);
    BenchResult { name: name.to_string(), avg_us }
}

#[test]
fn full_benchmark() {
    println!();
    println!("=================================================================");
    println!("  MISAKA Network  Full Cryptographic Benchmark v5.1");
    println!("=================================================================");
    println!();

    let mut results: Vec<BenchResult> = Vec::new();

    // 1. ML-DSA-65
    println!("-- ML-DSA-65 (FIPS 204) --");
    results.push(bench("ML-DSA-65 keygen", ITERS, || { let _ = MlDsaKeypair::generate(); }));
    let kp = MlDsaKeypair::generate();
    let msg = b"MISAKA benchmark message 2026";
    let sig = ml_dsa_sign(&kp.secret_key, msg).unwrap();
    results.push(bench("ML-DSA-65 sign", ITERS, || { let _ = ml_dsa_sign(&kp.secret_key, msg).unwrap(); }));
    results.push(bench("ML-DSA-65 verify", ITERS, || { ml_dsa_verify(&kp.public_key, msg, &sig).unwrap(); }));
    println!("  PK: {} B | SK: {} B | Sig: {} B\n",
        kp.public_key.as_bytes().len(), kp.secret_key.as_bytes().len(), sig.as_bytes().len());

    // 2. ML-KEM-768
    println!("-- ML-KEM-768 (FIPS 203) --");
    results.push(bench("ML-KEM-768 keygen", ITERS, || { let _ = ml_kem_keygen().unwrap(); }));
    let kem_kp = ml_kem_keygen().unwrap();
    results.push(bench("ML-KEM-768 encapsulate", ITERS, || { let _ = ml_kem_encapsulate(&kem_kp.public_key).unwrap(); }));
    let (ct, _) = ml_kem_encapsulate(&kem_kp.public_key).unwrap();
    results.push(bench("ML-KEM-768 decapsulate", ITERS, || { let _ = ml_kem_decapsulate(&kem_kp.secret_key, &ct).unwrap(); }));
    println!("  PK: {} B | SK: {} B | CT: {} B\n",
        kem_kp.public_key.as_bytes().len(), kem_kp.secret_key.as_bytes().len(), ct.as_bytes().len());

    // 3. Ring Signatures
    println!("-- Lattice Ring Signatures --");
    let a = derive_public_param(&DEFAULT_A_SEED);
    for ring_size in [4, 8, 16, 32] {
        let wallets: Vec<SpendingKeypair> = (0..ring_size)
            .map(|_| SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key).unwrap())
            .collect();
        let ring: Vec<Poly> = wallets.iter().map(|w| w.public_poly.clone()).collect();
        let msg = [0x42u8; 32];
        let mut sig_out = None;
        results.push(bench(&format!("ring_sign (n={})", ring_size), ITERS, || {
            sig_out = Some(ring_sign(&a, &ring, 0, &wallets[0].secret_poly, &msg).unwrap());
        }));
        let sig = sig_out.unwrap();
        results.push(bench(&format!("ring_verify (n={})", ring_size), ITERS, || {
            ring_verify(&a, &ring, &msg, &sig).unwrap();
        }));
        let raw = sig.to_bytes();
        let v1 = pack_ring_sig(&sig);
        let v2 = pack_ring_sig_v2(&sig);
        println!("  n={}: raw={} B | v1={} B (-{:.0}%) | v2={} B (-{:.0}%)",
            ring_size, raw.len(), v1.len(),
            (1.0 - v1.len() as f64 / raw.len() as f64) * 100.0,
            v2.len(), (1.0 - v2.len() as f64 / raw.len() as f64) * 100.0);
    }
    println!();

    // 4. Key Image Proof
    println!("-- Key Image Proof --");
    {
        let s = derive_secret_poly(&MlDsaKeypair::generate().secret_key).unwrap();
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
    println!();

    // 5. BDLOP + Range + Balance
    println!("-- BDLOP Commitment + Range Proof + Balance --");
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
        let r_in = BlindingFactor::random();
        let r_out = BlindingFactor::random();
        let c_in = BdlopCommitment::commit(&crs, &r_in, 1000).unwrap();
        let c_out = BdlopCommitment::commit(&crs, &r_out, 900).unwrap();
        let diff = compute_balance_diff(&crs, &[c_in], &[c_out], 100).unwrap();
        let mut r_excess_coeffs = [0i32; 256];
        for i in 0..256 {
            r_excess_coeffs[i] = ((r_in.as_poly().coeffs[i] as i64
                - r_out.as_poly().coeffs[i] as i64) % 12289 + 12289) as i32 % 12289;
        }
        let r_excess = BlindingFactor(Poly { coeffs: r_excess_coeffs });
        let mut bp_out = None;
        results.push(bench("balance_excess_prove", ITERS, || {
            bp_out = Some(BalanceExcessProof::prove(&crs, &diff, &r_excess).unwrap());
        }));
        let bp = bp_out.unwrap();
        results.push(bench("balance_excess_verify", ITERS, || {
            verify_balance_with_excess(&crs, &diff, &bp).unwrap();
        }));
    }
    println!();

    // 6. SIS Merkle Membership
    println!("-- SIS Merkle Membership Proof --");
    {
        let bdlop_crs = BdlopCrs::default_crs();
        let sis_crs = SisMerkleCrs::default_crs();
        for tree_size in [16, 64, 256] {
            let wallets: Vec<SpendingKeypair> = (0..tree_size)
                .map(|_| SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key).unwrap())
                .collect();
            let leaves: Vec<Poly> = wallets.iter()
                .map(|w| sis_leaf(&sis_crs, &w.public_poly))
                .collect();
            let root = compute_sis_root(&sis_crs, &leaves).unwrap();
            let rh = sis_root_hash(&root);
            let mut proof_out = None;
            results.push(bench(&format!("membership_prove (n={})", tree_size), ITERS, || {
                let (p, _) = prove_membership_v2(&bdlop_crs, &sis_crs, &leaves, 0, &wallets[0].public_poly).unwrap();
                proof_out = Some(p);
            }));
            let proof = proof_out.unwrap();
            results.push(bench(&format!("membership_verify (n={})", tree_size), ITERS, || {
                verify_membership_v2(&bdlop_crs, &sis_crs, &rh, &proof).unwrap();
            }));
        }
    }
    println!();

    // 7. CompositeProof
    println!("-- CompositeProof (1in 2out) --");
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
        results.push(bench("composite_prove (1in 2out)", ITERS, || {
            let p = prove_composite(
                &crs, &tx_digest, &[in_commitment.clone()], &[in_blind.clone()],
                &[OutputWitness { amount: 9_000, blinding: BlindingFactor::random() },
                  OutputWitness { amount: 900, blinding: BlindingFactor::random() }],
                fee_amount, &fee_blind, &nullifiers,
            ).unwrap();
            proof_out = Some(p);
        }));
        let proof = proof_out.unwrap();
        results.push(bench("composite_verify (1in 2out)", ITERS, || {
            verify_composite(&crs, &proof, &tx_digest, &[in_commitment.clone()], &fee_commitment, &nullifiers).unwrap();
        }));
    }
    println!();

    // 8. Stealth Address
    println!("-- Stealth Address (ML-KEM-768) --");
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
    println!();

    // 9. Nullifier
    println!("-- Nullifier --");
    {
        let s = derive_secret_poly(&MlDsaKeypair::generate().secret_key).unwrap();
        let oid = OutputId { tx_hash: [0x99u8; 32], output_index: 0 };
        results.push(bench("nullifier_compute", 50, || {
            let _ = compute_nullifier(&s, &oid, 2);
        }));
    }
    println!();

    // Summary
    let get = |name: &str| results.iter().find(|r| r.name == name).map(|r| r.avg_us).unwrap_or(0);
    let full_prove = get("ring_sign (n=4)") + get("membership_prove (n=256)") + get("composite_prove (1in 2out)");
    let full_verify = get("ring_verify (n=4)") + get("membership_verify (n=256)") + get("composite_verify (1in 2out)");
    let tps = if full_verify > 0 { 1_000_000 / full_verify } else { 0 };

    println!("=================================================================");
    println!("  Summary");
    println!("=================================================================");
    println!("  Full TX prove  (ring+membership+composite): {:>8} us", full_prove);
    println!("  Full TX verify (ring+membership+composite): {:>8} us", full_verify);
    println!("  Theoretical single-core TPS (verify):       {:>8} tx/s", tps);
    println!("  ML-DSA-65 sign+verify:  {} us", get("ML-DSA-65 sign") + get("ML-DSA-65 verify"));
    println!("  ML-KEM-768 encap+decap: {} us", get("ML-KEM-768 encapsulate") + get("ML-KEM-768 decapsulate"));
    println!("=================================================================");
    println!();
}
