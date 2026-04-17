//! SMT domain separation tags. FROZEN at v0.7.x.
//!
//! These bytes are part of the consensus rules and CANNOT be changed
//! without a hard fork. The "v1" suffix allows future hash upgrades
//! (e.g., SHA3-384) by bumping to "v2".

/// Domain tag for leaf nodes: H(DST_LEAF || key || value).
pub const DST_LEAF: &[u8] = b"MISAKA:smt:leaf:v1:";

/// Domain tag for internal nodes: H(DST_INTERNAL || left || right).
pub const DST_INTERNAL: &[u8] = b"MISAKA:smt:internal:v1:";

/// Domain tag for empty subtree base: H(DST_EMPTY || depth_be16).
pub const DST_EMPTY: &[u8] = b"MISAKA:smt:empty:v1:";

/// Domain tag for root finalization: H(DST_ROOT || smt_root || height_be16).
pub const DST_ROOT: &[u8] = b"MISAKA:smt:root:v1:";

/// Domain tag for proof binding.
pub const DST_PROOF: &[u8] = b"MISAKA:smt:proof:v1:";

/// Domain tag for key derivation: H(DST_KEY || tx_hash || output_index_be32).
pub const DST_KEY: &[u8] = b"MISAKA:smt:key:v1:";

/// Domain tag for value hashing: H(DST_VALUE || serialized_output).
pub const DST_VALUE: &[u8] = b"MISAKA:smt:value:v1:";

/// SMT tree height in bits. SHA3-256 output = 256 bits -> 256 levels.
pub const SMT_DEPTH: usize = 256;
