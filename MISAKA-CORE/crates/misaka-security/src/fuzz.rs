//! Fuzz testing infrastructure — structured inputs for property testing.

use sha3::{Sha3_256, Digest};

/// Generate a deterministic pseudo-random byte sequence for fuzzing.
pub fn fuzz_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(len);
    let mut state = seed;
    while result.len() < len {
        let mut h = Sha3_256::new();
        h.update(&state.to_le_bytes());
        let hash: [u8; 32] = h.finalize().into();
        result.extend_from_slice(&hash[..len.saturating_sub(result.len()).min(32)]);
        state = state.wrapping_add(1);
    }
    result.truncate(len);
    result
}

/// Generate a fuzz transaction with random but structurally valid data.
pub fn fuzz_transaction(seed: u64) -> FuzzTransaction {
    let data = fuzz_bytes(seed, 256);
    let input_count = (data[0] % 5) as usize + 1;
    let output_count = (data[1] % 5) as usize + 1;

    FuzzTransaction {
        version: 1,
        input_count,
        output_count,
        total_input: u64::from_le_bytes(data[2..10].try_into().unwrap_or([0; 8])),
        total_output: u64::from_le_bytes(data[10..18].try_into().unwrap_or([0; 8])),
        mass: (data[18] as u64 + 1) * 100,
        raw: data,
    }
}

pub struct FuzzTransaction {
    pub version: u32,
    pub input_count: usize,
    pub output_count: usize,
    pub total_input: u64,
    pub total_output: u64,
    pub mass: u64,
    pub raw: Vec<u8>,
}

/// Fuzz target categories.
pub enum FuzzTarget {
    ScriptEngine,
    TransactionValidation,
    BlockValidation,
    P2PMessageParsing,
    RpcInputParsing,
    AddressDecoding,
    MerkleProofVerification,
}
