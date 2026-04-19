//! 21-validator convergence test: all validators must produce identical state_root.

#[cfg(test)]
mod tests {
    use crate::fixtures::*;
    use misaka_types::utxo::OutputRef;

    #[test]
    fn all_21_validators_agree_on_state_root() {
        const N: usize = 21;

        fn build_state() -> [u8; 32] {
            let mut us = fresh_utxo_set();
            for i in 0u8..10 {
                let outref = OutputRef { tx_hash: [i + 1; 32], output_index: 0 };
                prefund_utxo(&mut us, outref, 1_000_000 * (i as u64 + 1), [(i + 20); 32]);
            }
            us.compute_state_root()
        }

        let mut roots = Vec::with_capacity(N);
        for _ in 0..N {
            roots.push(build_state());
        }

        let first = roots[0];
        for (i, r) in roots.iter().enumerate().skip(1) {
            assert_eq!(r, &first, "validator {} diverges", i);
        }
    }

    #[test]
    fn utxo_set_order_independent_state_root() {
        // Adding UTXOs in different orders produces same state_root.
        let pairs: Vec<(OutputRef, u64)> = (0u8..10)
            .map(|i| {
                (
                    OutputRef { tx_hash: [i + 1; 32], output_index: 0 },
                    1_000_000 * (i as u64 + 1),
                )
            })
            .collect();

        let addr = [99u8; 32];

        let mut us1 = fresh_utxo_set();
        for (outref, amt) in &pairs {
            prefund_utxo(&mut us1, outref.clone(), *amt, addr);
        }
        let r1 = us1.compute_state_root();

        let mut us2 = fresh_utxo_set();
        for (outref, amt) in pairs.iter().rev() {
            prefund_utxo(&mut us2, outref.clone(), *amt, addr);
        }
        let r2 = us2.compute_state_root();

        assert_eq!(r1, r2, "MuHash must be order-independent");
    }

    /// v1.0 hard-fork parallel SMT: 21-validator convergence on
    /// the v4 state root (SMT-folded). Same contract as the v3
    /// test above — identical inputs, identical output across
    /// every validator. This is the audit-level pin for the
    /// Step 2 parallel SMT's cross-validator determinism.
    #[test]
    fn all_21_validators_agree_on_state_root_v4() {
        const N: usize = 21;

        fn build_state_v4() -> [u8; 32] {
            let mut us = fresh_utxo_set();
            for i in 0u8..10 {
                let outref = OutputRef { tx_hash: [i + 1; 32], output_index: 0 };
                prefund_utxo(&mut us, outref, 1_000_000 * (i as u64 + 1), [(i + 20); 32]);
            }
            us.compute_state_root_v4()
        }

        let mut roots = Vec::with_capacity(N);
        for _ in 0..N {
            roots.push(build_state_v4());
        }

        let first = roots[0];
        for (i, r) in roots.iter().enumerate().skip(1) {
            assert_eq!(r, &first, "validator {} diverges on v4 root", i);
        }
    }

    /// v1.0 hard-fork parallel SMT: order-independence holds for
    /// v4 too. Although SMT insertions run in tree traversal
    /// order internally, the final root is determined solely by
    /// the leaf set (sparse-Merkle key→value map).
    #[test]
    fn utxo_set_order_independent_state_root_v4() {
        let pairs: Vec<(OutputRef, u64)> = (0u8..10)
            .map(|i| {
                (
                    OutputRef { tx_hash: [i + 1; 32], output_index: 0 },
                    1_000_000 * (i as u64 + 1),
                )
            })
            .collect();

        let addr = [99u8; 32];

        let mut us1 = fresh_utxo_set();
        for (outref, amt) in &pairs {
            prefund_utxo(&mut us1, outref.clone(), *amt, addr);
        }
        let r1 = us1.compute_state_root_v4();

        let mut us2 = fresh_utxo_set();
        for (outref, amt) in pairs.iter().rev() {
            prefund_utxo(&mut us2, outref.clone(), *amt, addr);
        }
        let r2 = us2.compute_state_root_v4();

        assert_eq!(r1, r2, "SMT (v4 root) must be order-independent");
    }
}
