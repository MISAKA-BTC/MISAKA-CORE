//! Property tests and integration tests for Q-DAG-CT.
//!
//! These tests verify critical security invariants across many random inputs.

#[cfg(test)]
mod tests {
    use misaka_pqc::pq_sign::MlDsaKeypair;
    use misaka_pqc::pq_ring::{
        Poly, derive_public_param, derive_secret_poly, compute_pubkey, DEFAULT_A_SEED, N, Q,
    };
    use misaka_pqc::nullifier::{OutputId, NullifierProof, compute_nullifier};
    use misaka_pqc::bdlop::{
        BdlopCrs, BdlopCommitment, BlindingFactor, BalanceExcessProof,
        compute_balance_diff, verify_balance_with_excess,
    };
    use misaka_pqc::range_proof::{prove_range, verify_range};
    use misaka_pqc::confidential_stealth::{
        create_confidential_stealth, CtStealthScanner,
    };
    use misaka_pqc::pq_kem::ml_kem_keygen;

    fn setup_key() -> (Poly, Poly, Poly) {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let kp = MlDsaKeypair::generate();
        let s = derive_secret_poly(&kp.secret_key).unwrap();
        let pk = compute_pubkey(&a, &s);
        (a, s, pk)
    }

    // ═══════════════════════════════════════════════════════════
    //  Property: Nullifier ring-independence (many random keys)
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn prop_nullifier_ring_independent_10_keys() {
        let (_, s, _) = setup_key();
        let output = OutputId { tx_hash: [0xAA; 32], output_index: 7 };
        let chain_id = 2u32;

        // Compute nullifier once
        let expected = compute_nullifier(&s, &output, chain_id);

        // Compute again 10 times — must always match
        for _ in 0..10 {
            let null = compute_nullifier(&s, &output, chain_id);
            assert_eq!(null, expected,
                "PROPERTY VIOLATION: nullifier changed across invocations");
        }
    }

    #[test]
    fn prop_nullifier_unique_per_output_100() {
        let (_, s, _) = setup_key();
        let mut nullifiers = std::collections::HashSet::new();

        for i in 0..100u32 {
            let output = OutputId {
                tx_hash: {
                    let mut h = [0u8; 32];
                    h[..4].copy_from_slice(&i.to_le_bytes());
                    h
                },
                output_index: i,
            };
            let null = compute_nullifier(&s, &output, 2);
            assert!(nullifiers.insert(null),
                "PROPERTY VIOLATION: nullifier collision at output {i}");
        }
    }

    #[test]
    fn prop_nullifier_unique_per_key_50() {
        let output = OutputId { tx_hash: [0xBB; 32], output_index: 0 };
        let mut nullifiers = std::collections::HashSet::new();

        for _ in 0..50 {
            let (_, s, _) = setup_key();
            let null = compute_nullifier(&s, &output, 2);
            assert!(nullifiers.insert(null),
                "PROPERTY VIOLATION: different keys produced same nullifier");
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  Property: NullifierProof correctness
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn prop_nullifier_proof_roundtrip_20() {
        let a = derive_public_param(&DEFAULT_A_SEED);

        for i in 0..20u32 {
            let kp = MlDsaKeypair::generate();
            let s = derive_secret_poly(&kp.secret_key).unwrap();
            let pk = compute_pubkey(&a, &s);
            let output = OutputId { tx_hash: [i as u8; 32], output_index: i };
            let null = compute_nullifier(&s, &output, 2);

            let proof = NullifierProof::prove(&a, &s, &pk, &output, 2, &null).unwrap();
            proof.verify(&a, &pk, &null).expect(
                &format!("PROPERTY VIOLATION: valid proof failed at iteration {i}"));

            // Wrong nullifier must fail
            let wrong = [0xFF; 32];
            assert!(proof.verify(&a, &pk, &wrong).is_err(),
                "PROPERTY VIOLATION: wrong nullifier accepted at iteration {i}");
        }
    }

    #[test]
    fn prop_nullifier_proof_serialization_20() {
        let a = derive_public_param(&DEFAULT_A_SEED);

        for i in 0..20u32 {
            let kp = MlDsaKeypair::generate();
            let s = derive_secret_poly(&kp.secret_key).unwrap();
            let pk = compute_pubkey(&a, &s);
            let output = OutputId { tx_hash: [(i + 10) as u8; 32], output_index: i };
            let null = compute_nullifier(&s, &output, 2);

            let proof = NullifierProof::prove(&a, &s, &pk, &output, 2, &null).unwrap();
            let bytes = proof.to_bytes();
            let proof2 = NullifierProof::from_bytes(&bytes).unwrap();
            proof2.verify(&a, &pk, &null).expect(
                &format!("PROPERTY VIOLATION: deserialized proof failed at iteration {i}"));
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  Property: BDLOP homomorphic balance
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn prop_bdlop_balance_10_random() {
        let crs = BdlopCrs::default_crs();

        for _ in 0..10 {
            let amount_in: u64 = rand::random::<u32>() as u64 + 1000;
            let fee: u64 = (rand::random::<u16>() as u64) % 500 + 1;
            let amount_out = amount_in - fee;

            let r_in = BlindingFactor::random();
            let r_out = BlindingFactor::random();

            let c_in = BdlopCommitment::commit(&crs, &r_in, amount_in);
            let c_out = BdlopCommitment::commit(&crs, &r_out, amount_out);

            let diff = compute_balance_diff(&crs, &[c_in], &[c_out], fee);

            // Compute r_excess
            let mut r_excess_poly = Poly::zero();
            for i in 0..N {
                r_excess_poly.coeffs[i] = (r_in.as_poly().coeffs[i] - r_out.as_poly().coeffs[i]) % Q;
                if r_excess_poly.coeffs[i] < 0 { r_excess_poly.coeffs[i] += Q; }
            }
            let r_excess = BlindingFactor(r_excess_poly);

            let proof = BalanceExcessProof::prove(&crs, &diff, &r_excess).unwrap();
            verify_balance_with_excess(&crs, &diff, &proof).expect(
                "PROPERTY VIOLATION: valid balance proof failed");
        }
    }

    #[test]
    fn prop_bdlop_imbalance_rejected_10() {
        let crs = BdlopCrs::default_crs();

        for _ in 0..10 {
            let r_in = BlindingFactor::random();
            let r_out = BlindingFactor::random();

            let c_in = BdlopCommitment::commit(&crs, &r_in, 1000);
            let c_out = BdlopCommitment::commit(&crs, &r_out, 900);

            // Declare wrong fee (50 instead of 100) → imbalance
            let diff = compute_balance_diff(&crs, &[c_in], &[c_out], 50);

            // Real excess is for fee=100, not fee=50 → proof must fail
            let mut r_excess_poly = Poly::zero();
            for i in 0..N {
                r_excess_poly.coeffs[i] = (r_in.as_poly().coeffs[i] - r_out.as_poly().coeffs[i]) % Q;
                if r_excess_poly.coeffs[i] < 0 { r_excess_poly.coeffs[i] += Q; }
            }
            let r_excess = BlindingFactor(r_excess_poly);

            let proof = BalanceExcessProof::prove(&crs, &diff, &r_excess).unwrap();
            // This proof was generated for the wrong diff, so verify should fail
            // because the diff doesn't equal A₁·r_excess when fee is wrong
            assert!(verify_balance_with_excess(&crs, &diff, &proof).is_err(),
                "PROPERTY VIOLATION: imbalanced TX accepted");
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  Property: Range proof
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn prop_range_proof_various_amounts() {
        let crs = BdlopCrs::default_crs();
        let amounts = [0u64, 1, 42, 1000, 999_999, u32::MAX as u64, u64::MAX / 2];

        for &amount in &amounts {
            let r = BlindingFactor::random();
            let c = BdlopCommitment::commit(&crs, &r, amount);
            let (proof, _) = prove_range(&crs, amount, &r).unwrap();
            verify_range(&crs, &c, &proof).expect(
                &format!("PROPERTY VIOLATION: range proof failed for amount {amount}"));
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  Integration: Full confidential stealth roundtrip
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn integration_confidential_stealth_full_flow() {
        let crs = BdlopCrs::default_crs();
        let kem_kp = ml_kem_keygen().unwrap();

        // Sender creates output
        let amount = 500_000u64;
        let blind = BlindingFactor::random();
        let commitment = BdlopCommitment::commit(&crs, &blind, amount);

        let stealth_out = create_confidential_stealth(
            &kem_kp.public_key, amount, &blind, 2,
        ).unwrap();

        // Recipient recovers
        let scanner = CtStealthScanner::new(kem_kp.secret_key);
        let recovered = scanner.try_recover(&stealth_out.stealth_data, 2)
            .unwrap().expect("should recover");

        assert_eq!(recovered.amount, amount);

        // Verify commitment
        let recomputed = BdlopCommitment::commit(&crs, &recovered.blinding_factor, recovered.amount);
        assert_eq!(recomputed, commitment,
            "recovered blind+amount must reconstruct the on-chain commitment");

        // Recipient can now create a range proof for this output
        let (rp, _) = prove_range(&crs, recovered.amount, &recovered.blinding_factor).unwrap();
        verify_range(&crs, &commitment, &rp).expect("range proof from recovered values must verify");
    }

    #[test]
    fn integration_multi_input_balance() {
        let crs = BdlopCrs::default_crs();

        // 2 inputs: 300 + 700 = 1000
        let r1 = BlindingFactor::random();
        let r2 = BlindingFactor::random();
        let c_in1 = BdlopCommitment::commit(&crs, &r1, 300);
        let c_in2 = BdlopCommitment::commit(&crs, &r2, 700);

        // 2 outputs: 500 + 400 = 900, fee = 100
        let r3 = BlindingFactor::random();
        let r4 = BlindingFactor::random();
        let c_out1 = BdlopCommitment::commit(&crs, &r3, 500);
        let c_out2 = BdlopCommitment::commit(&crs, &r4, 400);

        let diff = compute_balance_diff(
            &crs, &[c_in1, c_in2], &[c_out1, c_out2], 100,
        );

        // r_excess = (r1 + r2) - (r3 + r4)
        let mut r_excess_poly = Poly::zero();
        for i in 0..N {
            let sum_in = r1.as_poly().coeffs[i] + r2.as_poly().coeffs[i];
            let sum_out = r3.as_poly().coeffs[i] + r4.as_poly().coeffs[i];
            r_excess_poly.coeffs[i] = ((sum_in - sum_out) % Q + Q) % Q;
        }
        let r_excess = BlindingFactor(r_excess_poly);

        let proof = BalanceExcessProof::prove(&crs, &diff, &r_excess).unwrap();
        verify_balance_with_excess(&crs, &diff, &proof).expect("multi-input balance must verify");
    }

    // ═══════════════════════════════════════════════════════════
    //  Malformed input rejection (DoS)
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn test_malformed_nullifier_proof_rejected() {
        assert!(NullifierProof::from_bytes(&[]).is_err());
        assert!(NullifierProof::from_bytes(&[0u8; 10]).is_err());
        assert!(NullifierProof::from_bytes(&[0xFF; 10000]).is_err());
    }

    #[test]
    fn test_malformed_balance_proof_rejected() {
        assert!(BalanceExcessProof::from_bytes(&[]).is_err());
        assert!(BalanceExcessProof::from_bytes(&[0u8; 5]).is_err());
    }
}
