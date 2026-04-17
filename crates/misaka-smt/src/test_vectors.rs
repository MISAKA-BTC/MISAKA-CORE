//! Frozen SMT test vectors. These values are part of the public
//! v1.0 specification. Any change to these constants is a CONSENSUS
//! BREAK and requires a hard fork.
//!
//! Implementers of independent SMT clients (light clients, bridges,
//! audit tools) MUST verify their implementation produces these exact values.

/// SHA3-256(DST_EMPTY || 0x0000) — the empty leaf slot hash.
pub const EMPTY_LEAF_HASH_HEX: &str =
    "b6e66f334e91d2a435b187ba43d7ca05ad1de4249808b89bb55fe0566f6cea3e";

/// Empty SMT root hash (depth 256).
pub const EMPTY_ROOT_HEX: &str = "00a8dc116dd567fbe7e1786f8cb81ca22d3b5c78f6735fdb763c2f6c61b0a82a";

/// SMT key derivation test vector: tx_hash = [0u8; 32], output_index = 0.
pub const SMT_KEY_ZERO_ZERO_HEX: &str =
    "ed7dba5198beca5599bd10d9a3a79e4f26d39c3b47de2f5e0cbb68d9747c1ac7";

#[cfg(test)]
mod lock_in {
    use super::*;
    use crate::empty::{empty_hash, empty_root};
    use crate::key::smt_key;

    /// First-run helper: prints actual hex values so they can be pasted
    /// into the constants above. After locking, this test verifies they
    /// stay constant forever.
    #[test]
    fn lock_in_test_vectors() {
        let empty_leaf = empty_hash(0);
        let empty_r = empty_root();
        let key00 = smt_key(&[0u8; 32], 0);

        eprintln!("EMPTY_LEAF_HASH_HEX   = {}", hex::encode(empty_leaf));
        eprintln!("EMPTY_ROOT_HEX        = {}", hex::encode(empty_r));
        eprintln!("SMT_KEY_ZERO_ZERO_HEX = {}", hex::encode(key00));

        // After first run, replace constants and assert:
        if EMPTY_LEAF_HASH_HEX != "REPLACE_AFTER_FIRST_RUN" {
            assert_eq!(
                hex::encode(empty_leaf),
                EMPTY_LEAF_HASH_HEX,
                "EMPTY_LEAF_HASH changed — consensus break"
            );
            assert_eq!(
                hex::encode(empty_r),
                EMPTY_ROOT_HEX,
                "EMPTY_ROOT changed — consensus break"
            );
            assert_eq!(
                hex::encode(key00),
                SMT_KEY_ZERO_ZERO_HEX,
                "SMT_KEY derivation changed — consensus break"
            );
        }
    }
}
