use std::time::Instant;
use misaka_pqc::pq_sign::MlDsaKeypair;
use misaka_pqc::pq_ring::*;

fn bench(label: &str, f: impl Fn()) {
    let start = Instant::now();
    let n = 10;
    for _ in 0..n { f(); }
    let elapsed = start.elapsed();
    println!("  {}: {:.2}ms avg ({} runs)", label, elapsed.as_millis() as f64 / n as f64, n);
}

#[test]
fn bench_before_optimization() {
    println!("\n╔═══════════════════════════════════════════════╗");
    println!("║  Pre-optimization Benchmark                   ║");
    println!("╚═══════════════════════════════════════════════╝");

    let a = derive_public_param(&DEFAULT_A_SEED);

    // Poly mul benchmark
    let kp1 = SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key);
    let kp2 = SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key);
    bench("Poly mul (schoolbook)", || {
        let _ = kp1.public_poly.mul(&kp2.public_poly);
    });

    // Ring sig (ring=4)
    let ring4: Vec<Poly> = (0..4).map(|_|
        SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key).public_poly
    ).collect();
    let signer = SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key);
    let mut ring4_with_signer = ring4.clone();
    ring4_with_signer[0] = signer.public_poly.clone();
    let msg = [0x42u8; 32];

    bench("Ring sign (ring=4)", || {
        let _ = ring_sign(&a, &ring4_with_signer, 0, &signer.secret_poly, &msg);
    });

    let sig4 = ring_sign(&a, &ring4_with_signer, 0, &signer.secret_poly, &msg).unwrap();
    bench("Ring verify (ring=4)", || {
        ring_verify(&a, &ring4_with_signer, &msg, &sig4).unwrap();
    });

    // Ring sig (ring=8)
    let ring8: Vec<Poly> = (0..8).map(|_|
        SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key).public_poly
    ).collect();
    let mut ring8_with_signer = ring8.clone();
    ring8_with_signer[0] = signer.public_poly.clone();

    bench("Ring sign (ring=8)", || {
        let _ = ring_sign(&a, &ring8_with_signer, 0, &signer.secret_poly, &msg);
    });

    let sig8 = ring_sign(&a, &ring8_with_signer, 0, &signer.secret_poly, &msg).unwrap();
    bench("Ring verify (ring=8)", || {
        ring_verify(&a, &ring8_with_signer, &msg, &sig8).unwrap();
    });

    // Sig sizes
    println!("\n  Sig size (ring=4): {} bytes", sig4.to_bytes().len());
    println!("  Sig size (ring=8): {} bytes", sig8.to_bytes().len());
}
