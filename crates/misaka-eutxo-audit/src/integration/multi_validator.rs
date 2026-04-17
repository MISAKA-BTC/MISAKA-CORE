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
}
