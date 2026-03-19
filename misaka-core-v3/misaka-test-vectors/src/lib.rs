//! Test vectors: ML-DSA, ML-KEM, lattice ring sig, stealth.

use misaka_crypto::sha3_256;
use misaka_pqc::pq_sign::{MlDsaKeypair, ml_dsa_sign, ml_dsa_verify, ML_DSA_PK_LEN, ML_DSA_SIG_LEN};
use misaka_pqc::pq_kem::{ml_kem_keygen, ml_kem_encapsulate, ml_kem_decapsulate, ML_KEM_PK_LEN, ML_KEM_CT_LEN};
use misaka_pqc::pq_stealth::{create_stealth_output, StealthScanner};
use misaka_pqc::pq_ring::{SpendingKeypair, ring_sign, ring_verify, derive_public_param, DEFAULT_A_SEED};

pub fn run_all_vectors() -> (usize, usize, usize) {
    let mut p = 0; let mut f = 0;

    // SHA3-256
    if sha3_256(b"MISAKA") != [0; 32] { p += 1; } else { f += 1; }

    // ML-DSA keygen/sign/verify
    let kp = MlDsaKeypair::generate();
    if kp.public_key.as_bytes().len() == ML_DSA_PK_LEN { p += 1; } else { f += 1; }
    let sig = match ml_dsa_sign(&kp.secret_key, b"test") {
        Ok(s) => s,
        Err(_) => { f += 3; return (p, f, 0); },
    };
    if sig.as_bytes().len() == ML_DSA_SIG_LEN { p += 1; } else { f += 1; }
    if ml_dsa_verify(&kp.public_key, b"test", &sig).is_ok() { p += 1; } else { f += 1; }
    if ml_dsa_verify(&kp.public_key, b"wrong", &sig).is_err() { p += 1; } else { f += 1; }

    // ML-KEM
    let kem_kp = ml_kem_keygen().unwrap();
    if kem_kp.public_key.as_bytes().len() == ML_KEM_PK_LEN { p += 1; } else { f += 1; }
    let (ct, ss1) = ml_kem_encapsulate(&kem_kp.public_key).unwrap();
    if ct.as_bytes().len() == ML_KEM_CT_LEN { p += 1; } else { f += 1; }
    if ml_kem_decapsulate(&kem_kp.secret_key, &ct).unwrap() == ss1 { p += 1; } else { f += 1; }

    // Stealth
    let tx_id = [0x77; 32];
    let st = create_stealth_output(&kem_kp.public_key, 42000, b"m", &tx_id, 0).unwrap();
    if st.one_time_address != [0; 32] { p += 1; } else { f += 1; }
    let scanner = StealthScanner::new(kem_kp.secret_key);
    match scanner.try_recover(&st.stealth_data, &tx_id, 0) {
        Ok(Some(r)) if r.amount == 42000 => p += 1, _ => f += 1,
    }

    // Lattice ring sig (NO ECC)
    let a = derive_public_param(&DEFAULT_A_SEED);
    let ring_kps: Vec<SpendingKeypair> = (0..4)
        .map(|_| SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key).unwrap())
        .collect();
    let ring_pks: Vec<_> = ring_kps.iter().map(|k| k.public_poly.clone()).collect();
    let msg = [0x99; 32];
    match ring_sign(&a, &ring_pks, 1, &ring_kps[1].secret_poly, &msg) {
        Ok(sig) => {
            p += 1;
            if ring_verify(&a, &ring_pks, &msg, &sig).is_ok() { p += 1; } else { f += 1; }
            if ring_verify(&a, &ring_pks, &[0xFF; 32], &sig).is_err() { p += 1; } else { f += 1; }
        }
        Err(_) => { f += 3; }
    }

    // Key image determinism
    let skp = SpendingKeypair::from_ml_dsa(ring_kps[0].ml_dsa_sk.clone().unwrap());
    if skp.key_image == ring_kps[0].key_image { p += 1; } else { f += 1; }

    (p, f, p + f)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_all_pass() {
        let (_p, f, t) = run_all_vectors();
        assert_eq!(f, 0, "{f}/{t} failed");
        assert!(t >= 14, "got {t}");
    }
}
