//! Benchmark: LRS vs ChipmunkRing at ring sizes 4, 8, 16, 32.
//!
//! Run: cargo bench -p misaka-pqc --bench ring_bench

use std::time::Instant;
use misaka_pqc::pq_sign::MlDsaKeypair;
use misaka_pqc::pq_ring::{
    Poly, derive_secret_poly, derive_public_param, DEFAULT_A_SEED,
    ring_sign as lrs_sign, ring_verify as lrs_verify,
    compute_key_image as lrs_ki,
};
use misaka_pqc::ki_proof::{prove_key_image as lrs_prove_ki, verify_key_image_proof as lrs_verify_ki};

#[cfg(feature = "chipmunk")]
use misaka_pqc::chipmunk::{
    chipmunk_ring_sign, chipmunk_ring_verify,
    chipmunk_compute_key_image, chipmunk_prove_ki, chipmunk_verify_ki,
};

// LogRing always available (system default)
use misaka_pqc::logring::{logring_sign_v2, logring_verify};

fn make_ring(a: &Poly, size: usize) -> (Vec<Poly>, Vec<Poly>) {
    let mut sks = Vec::with_capacity(size);
    let mut pks = Vec::with_capacity(size);
    for _ in 0..size {
        let kp = MlDsaKeypair::generate();
        let sk = derive_secret_poly(&kp.secret_key).unwrap();
        let pk = a.mul(&sk);
        sks.push(sk);
        pks.push(pk);
    }
    (sks, pks)
}

fn bench_one(label: &str, iterations: usize, mut f: impl FnMut()) -> f64 {
    // Warmup
    for _ in 0..2 { f(); }

    let start = Instant::now();
    for _ in 0..iterations { f(); }
    let elapsed = start.elapsed();
    let avg_ms = elapsed.as_secs_f64() * 1000.0 / iterations as f64;
    println!("  {:<40} {:>8.2} ms  ({} iters, {:.1}s total)", label, avg_ms, iterations, elapsed.as_secs_f64());
    avg_ms
}

fn main() {
    let a = derive_public_param(&DEFAULT_A_SEED);
    let msg = [0x42u8; 32];

    println!("╔═══════════════════════════════════════════════════════════════════════╗");
    println!("║  MISAKA Ring Signature Benchmark — LRS vs ChipmunkRing              ║");
    println!("╚═══════════════════════════════════════════════════════════════════════╝");
    println!();

    for ring_size in [4, 8, 16] {
        println!("── Ring Size: {} ──────────────────────────────────────────", ring_size);
        let (sks, pks) = make_ring(&a, ring_size);
        let iters = if ring_size <= 8 { 10 } else { 5 };

        // LRS Sign
        let sig = {
            let mut s = None;
            bench_one(&format!("LRS sign (ring={})", ring_size), iters, || {
                s = Some(lrs_sign(&a, &pks, 0, &sks[0], &msg).unwrap());
            });
            s.unwrap()
        };

        // LRS Verify
        bench_one(&format!("LRS verify (ring={})", ring_size), iters, || {
            lrs_verify(&a, &pks, &msg, &sig).unwrap();
        });

        // LRS KI
        let ki = lrs_ki(&sks[0]);
        let ki_proof = {
            let mut p = None;
            bench_one(&format!("LRS KI prove (ring={})", ring_size), iters, || {
                p = Some(lrs_prove_ki(&a, &sks[0], &pks[0], &ki).unwrap());
            });
            p.unwrap()
        };
        bench_one(&format!("LRS KI verify (ring={})", ring_size), iters, || {
            lrs_verify_ki(&a, &pks[0], &ki, &ki_proof).unwrap();
        });

        #[cfg(feature = "chipmunk")]
        {
            // ChipmunkRing Sign
            let cr_sig = {
                let mut s = None;
                bench_one(&format!("Chipmunk sign (ring={})", ring_size), iters, || {
                    s = Some(chipmunk_ring_sign(&a, &pks, 0, &sks[0], &msg).unwrap());
                });
                s.unwrap()
            };

            // ChipmunkRing Verify
            bench_one(&format!("Chipmunk verify (ring={})", ring_size), iters, || {
                chipmunk_ring_verify(&a, &pks, &msg, &cr_sig).unwrap();
            });

            // Chipmunk KI
            let cr_ki = chipmunk_compute_key_image(&sks[0]);
            let cr_ki_proof = {
                let mut p = None;
                bench_one(&format!("Chipmunk KI prove (ring={})", ring_size), iters, || {
                    p = Some(chipmunk_prove_ki(&a, &sks[0], &pks[0], &cr_ki).unwrap());
                });
                p.unwrap()
            };
            bench_one(&format!("Chipmunk KI verify (ring={})", ring_size), iters, || {
                chipmunk_verify_ki(&a, &pks[0], &cr_ki, &cr_ki_proof).unwrap();
            });
        }

        // Signature sizes
        println!("  LRS sig size:      {} bytes", sig.to_bytes().len());
        #[cfg(feature = "chipmunk")]
        {
            let cr_sig = chipmunk_ring_sign(&a, &pks, 0, &sks[0], &msg).unwrap();
            println!("  Chipmunk sig size: {} bytes", cr_sig.to_bytes().len());
        }
        println!();
    }

    // Ring size 32 — Chipmunk only (LRS max is 16)
    #[cfg(feature = "chipmunk")]
    {
        let ring_size = 32;
        println!("── Ring Size: {} (ChipmunkRing only) ──────────────────────", ring_size);
        let (sks, pks) = make_ring(&a, ring_size);
        let iters = 3;

        let cr_sig = {
            let mut s = None;
            bench_one(&format!("Chipmunk sign (ring={})", ring_size), iters, || {
                s = Some(chipmunk_ring_sign(&a, &pks, 0, &sks[0], &msg).unwrap());
            });
            s.unwrap()
        };
        bench_one(&format!("Chipmunk verify (ring={})", ring_size), iters, || {
            chipmunk_ring_verify(&a, &pks, &msg, &cr_sig).unwrap();
        });
        println!("  Chipmunk sig size: {} bytes", cr_sig.to_bytes().len());
        println!();
    }

    // ═══════════════════════════════════════════════════════
    // LogRing — O(log n) benchmarks
    // ═══════════════════════════════════════════════════════
    // LogRing always available (system default)
    {
        println!("╔═══════════════════════════════════════════════════════════════════════╗");
        println!("║  LogRing O(log n) Benchmark                                         ║");
        println!("╚═══════════════════════════════════════════════════════════════════════╝");
        println!();

        for ring_size in [4, 8, 16, 32, 64, 128, 256, 512, 1024] {
            println!("── LogRing Size: {} ──────────────────────────────────────", ring_size);
            let (sks, pks) = make_ring(&a, ring_size);
            let iters = if ring_size <= 32 { 5 } else if ring_size <= 256 { 3 } else { 1 };

            // LogRing Sign
            let lr_sig = {
                let mut s = None;
                bench_one(&format!("LogRing sign (ring={})", ring_size), iters, || {
                    s = Some(logring_sign_v2(&a, &pks, 0, &sks[0], &msg, 2).unwrap());
                });
                s.unwrap()
            };

            // LogRing Verify
            bench_one(&format!("LogRing verify (ring={})", ring_size), iters, || {
                logring_verify(&a, &pks, &msg, &lr_sig).unwrap();
            });

            println!("  LogRing sig size:  {} bytes", lr_sig.wire_size());
            println!("  Merkle depth:      {}", lr_sig.merkle_path.len());

            // Compare with LRS for small rings
            if ring_size <= 16 {
                let lrs_sig_local = lrs_sign(&a, &pks, 0, &sks[0], &msg).unwrap();
                let lrs_size = lrs_sig_local.to_bytes().len();
                println!("  LRS sig size:      {} bytes", lrs_size);
                println!("  Compression ratio: {:.1}x", lrs_size as f64 / lr_sig.wire_size() as f64);
            }
            println!();
        }
    }

    println!("Done.");
}
