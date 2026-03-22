use std::time::Instant;
use misaka_pqc::pq_sign::{MlDsaKeypair, ml_dsa_sign, ml_dsa_verify};
use misaka_pqc::pq_kem::{ml_kem_keygen, ml_kem_encapsulate, ml_kem_decapsulate};
use misaka_pqc::pq_ring::*;
use misaka_pqc::ki_proof::{canonical_strong_ki, prove_key_image, verify_key_image};
use misaka_pqc::bdlop::{BdlopCrs, BdlopCommitment, BlindingFactor, BalanceExcessProof,
    compute_balance_diff, verify_balance_with_excess};
use misaka_pqc::nullifier::{OutputId, compute_nullifier};
use misaka_pqc::range_proof::{prove_range_v2, verify_range, RANGE_BITS};
use misaka_pqc::membership::{
    SisMerkleCrs, sis_leaf, compute_sis_root, sis_root_hash,
    prove_membership_v2, verify_membership_v2,
};
use misaka_pqc::pq_stealth::{create_stealth_output, StealthScanner};
use misaka_pqc::packing::{pack_ring_sig, pack_ring_sig_v2};

const W: usize = 1;
const IT: usize = 5;
struct BR { name: String, us: u128 }
fn b<F: FnMut()>(name: &str, n: usize, mut f: F) -> BR {
    for _ in 0..W { f(); }
    let s = Instant::now();
    for _ in 0..n { f(); }
    let us = s.elapsed().as_micros() / n as u128;
    println!("  {:<52} {:>8.2} ms  {:>8} us", name, us as f64/1000.0, us);
    BR { name: name.into(), us }
}

#[test]
fn full_benchmark() {
    println!("\n================================================================");
    println!("  MISAKA Network — Full PQ Benchmark v5.1 (Phase 2 ZKP Fix)");
    println!("================================================================\n");
    let mut r: Vec<BR> = Vec::new();
    let a = derive_public_param(&DEFAULT_A_SEED);

    // ── ML-DSA-65 ──
    println!("── ML-DSA-65 (FIPS 204) ──");
    r.push(b("ML-DSA-65 keygen", IT, || { let _ = MlDsaKeypair::generate(); }));
    let kp = MlDsaKeypair::generate();
    let msg = b"MISAKA benchmark 2026";
    let sig = ml_dsa_sign(&kp.secret_key, msg).unwrap();
    r.push(b("ML-DSA-65 sign", IT, || { let _ = ml_dsa_sign(&kp.secret_key, msg).unwrap(); }));
    r.push(b("ML-DSA-65 verify", IT, || { ml_dsa_verify(&kp.public_key, msg, &sig).unwrap(); }));
    println!("  PK={}B  SK={}B  Sig={}B\n", kp.public_key.as_bytes().len(), kp.secret_key.as_bytes().len(), sig.as_bytes().len());

    // ── ML-KEM-768 ──
    println!("── ML-KEM-768 (FIPS 203) ──");
    r.push(b("ML-KEM-768 keygen", IT, || { let _ = ml_kem_keygen().unwrap(); }));
    let km = ml_kem_keygen().unwrap();
    r.push(b("ML-KEM-768 encapsulate", IT, || { let _ = ml_kem_encapsulate(&km.public_key).unwrap(); }));
    let (ct, _) = ml_kem_encapsulate(&km.public_key).unwrap();
    r.push(b("ML-KEM-768 decapsulate", IT, || { let _ = ml_kem_decapsulate(&km.secret_key, &ct).unwrap(); }));
    println!();

    // ── Ring Sig ──
    println!("── Lattice Ring Signatures (legacy) ──");
    for rs in [4, 8, 16] {
        let ws: Vec<SpendingKeypair> = (0..rs).map(|_| SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key).unwrap()).collect();
        let ring: Vec<Poly> = ws.iter().map(|w| w.public_poly.clone()).collect();
        let m = [0x42u8; 32];
        let mut so = None;
        r.push(b(&format!("ring_sign (n={})", rs), IT, || { so = Some(ring_sign(&a, &ring, 0, &ws[0].secret_poly, &m).unwrap()); }));
        let s = so.unwrap();
        r.push(b(&format!("ring_verify (n={})", rs), IT, || { ring_verify(&a, &ring, &m, &s).unwrap(); }));
        let raw = s.to_bytes(); let v2 = pack_ring_sig_v2(&s);
        println!("  n={}: raw={}B  v2={}B(-{:.0}%)", rs, raw.len(), v2.len(), (1.0-v2.len() as f64/raw.len() as f64)*100.0);
    }
    println!();

    // ── Key Image ──
    println!("── Key Image Proof ──");
    { let s = derive_secret_poly(&MlDsaKeypair::generate().secret_key).unwrap();
      let pk = compute_pubkey(&a, &s); let (_, ki) = canonical_strong_ki(&pk, &s);
      let mut po = None;
      r.push(b("ki_proof_prove", IT, || { po = Some(prove_key_image(&a, &s, &pk, &ki).unwrap()); }));
      let p = po.unwrap();
      r.push(b("ki_proof_verify", IT, || { verify_key_image(&a, &pk, &ki, &p).unwrap(); }));
    }
    println!();

    // ── BDLOP + Balance ──
    println!("── BDLOP Commitment + Balance ──");
    let crs = BdlopCrs::default_crs();
    r.push(b("bdlop_commit", 20, || { let _ = BdlopCommitment::commit(&crs, &BlindingFactor::random(), 42).unwrap(); }));
    { let ri = BlindingFactor::random(); let ro = BlindingFactor::random();
      let ci = BdlopCommitment::commit(&crs, &ri, 42).unwrap();
      let co = BdlopCommitment::commit(&crs, &ro, 30).unwrap();
      let diff = compute_balance_diff(&crs, &[ci], &[co], 12).unwrap();
      let re = BlindingFactor(Poly { coeffs: {
          let mut c = [0i32; 256];
          for i in 0..256 { c[i] = ((ri.as_poly().coeffs[i] as i64 - ro.as_poly().coeffs[i] as i64) % 12289 + 12289) as i32 % 12289; }
          c }});
      let mut bpo = None;
      r.push(b("balance_excess_prove", IT, || { bpo = Some(BalanceExcessProof::prove(&crs, &diff, &re).unwrap()); }));
      let bp = bpo.unwrap();
      r.push(b("balance_excess_verify", IT, || { verify_balance_with_excess(&crs, &diff, &bp).unwrap(); }));
    }
    println!();

    // ── Range Proof V2 (PHASE 2 FIX) ──
    println!("── Range Proof V2 (bottom-up, all short blinds) ──");
    { let mut rpo = None;
      r.push(b("range_proof_v2_prove (64-bit)", 3, || {
          rpo = Some(prove_range_v2(&crs, 42).unwrap());
      }));
      let (rp, c_range, _r_agg) = rpo.unwrap();
      r.push(b("range_proof_v2_verify (64-bit)", IT, || {
          verify_range(&crs, &c_range, &rp).unwrap();
      }));
      println!("  Range proof size: {} bits × {} bytes = ~{} KB",
          RANGE_BITS, rp.wire_size(), rp.wire_size() / 1024);
    }
    println!();

    // ── Membership V2 (PHASE 2 FIX: epsilon construction) ──
    println!("── SIS Merkle Membership (epsilon fix) ──");
    { let bc = BdlopCrs::default_crs(); let sc = SisMerkleCrs::default_crs();
      for ts in [16, 64, 256] {
          let ws: Vec<SpendingKeypair> = (0..ts).map(|_| SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key).unwrap()).collect();
          let leaves: Vec<Poly> = ws.iter().map(|w| sis_leaf(&sc, &w.public_poly)).collect();
          let root = compute_sis_root(&sc, &leaves).unwrap(); let rh = sis_root_hash(&root);
          let mut po = None;
          r.push(b(&format!("membership_prove (n={})", ts), 3, || {
              let (p, _) = prove_membership_v2(&bc, &sc, &leaves, 0, &ws[0].public_poly).unwrap();
              po = Some(p);
          }));
          let p = po.unwrap();
          r.push(b(&format!("membership_verify (n={})", ts), IT, || {
              verify_membership_v2(&bc, &sc, &rh, &p).unwrap();
          }));
      }
    }
    println!();

    // ── Stealth ──
    println!("── Stealth Address ──");
    { let k = ml_kem_keygen().unwrap(); let tx = [0x77; 32];
      r.push(b("stealth_create", IT, || { let _ = create_stealth_output(&k.public_key, 42, b"m", &tx, 0).unwrap(); }));
      let st = create_stealth_output(&k.public_key, 42, b"m", &tx, 0).unwrap();
      let sc = StealthScanner::new(k.secret_key.clone());
      r.push(b("stealth_scan", IT, || { let _ = sc.try_recover(&st.stealth_data, &tx, 0).unwrap(); }));
    }
    println!();

    // ── Nullifier ──
    println!("── Nullifier ──");
    { let s = derive_secret_poly(&MlDsaKeypair::generate().secret_key).unwrap();
      let oid = OutputId { tx_hash: [0x99; 32], output_index: 0 };
      r.push(b("nullifier_compute", 20, || { let _ = compute_nullifier(&s, &oid, 2); }));
    }
    println!();

    // ── Summary ──
    let g = |n: &str| r.iter().find(|x| x.name == n).map(|x| x.us).unwrap_or(0);

    let zkp_prove = g("membership_prove (n=256)")
        + g("range_proof_v2_prove (64-bit)")
        + g("balance_excess_prove")
        + g("ki_proof_prove")
        + g("nullifier_compute");
    let zkp_verify = g("membership_verify (n=256)")
        + g("range_proof_v2_verify (64-bit)")
        + g("balance_excess_verify")
        + g("ki_proof_verify");
    let tps = if zkp_verify > 0 { 1_000_000 / zkp_verify } else { 0 };

    println!("================================================================");
    println!("  SUMMARY — Full Confidential TX (all ZKP components)");
    println!("================================================================");
    println!("  ZKP TX prove  (mem+range+balance+ki+null):  {:>8} us ({:.1} ms)", zkp_prove, zkp_prove as f64/1000.0);
    println!("  ZKP TX verify (mem+range+balance+ki):       {:>8} us ({:.1} ms)", zkp_verify, zkp_verify as f64/1000.0);
    println!("  Single-core TPS (verify):                   {:>8} tx/s", tps);
    println!("  ML-DSA-65  keygen/sign/verify:  {}/{}/{} us", g("ML-DSA-65 keygen"), g("ML-DSA-65 sign"), g("ML-DSA-65 verify"));
    println!("  ML-KEM-768 kg/encap/decap:      {}/{}/{} us", g("ML-KEM-768 keygen"), g("ML-KEM-768 encapsulate"), g("ML-KEM-768 decapsulate"));
    println!("================================================================\n");
}
