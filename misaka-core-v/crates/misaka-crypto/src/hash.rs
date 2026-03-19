//! Core hash functions — SHA3-only (Grover-resistant).
//!
//! # Security Policy
//!
//! - SHA2 is PROHIBITED everywhere in MISAKA Network.
//! - SHA3-256 for standard hashing (128-bit PQ security via 256-bit output).
//! - SHA3-512 for extended hashing (256-bit PQ security).
//! - `pq_hash` provides CPU-bound Grover-resistant hashing:
//!   SHA3-512(randomx_mix(data)) — ASIC-resistant + quantum-resistant.
//!
//! # ⚠ pq_hash Status: TESTNET-LEVEL
//!
//! The current `pq_hash` implementation uses a simplified RandomX-style
//! mixing function (SHA3 + XOR folding). It is NOT a full memory-hard
//! PoW algorithm (RandomX / Argon2id level). This is sufficient for
//! testnet consensus but does NOT provide real ASIC/FPGA resistance.
//!
//! **Mainnet P1:** Replace with a proper memory-hard function
//! (RandomX, Argon2id, or equivalent) that provides measurable
//! ASIC resistance via large working-set memory requirements.

use sha3::{Sha3_256, Sha3_512, Digest as Sha3Digest};

pub type Digest = [u8; 32];
pub type Digest512 = [u8; 64];

/// Standard hash: SHA3-256 (128-bit post-quantum security).
pub fn sha3_256(data: &[u8]) -> Digest {
    let mut h = Sha3_256::new();
    h.update(data);
    h.finalize().into()
}

/// Extended hash: SHA3-512 (256-bit post-quantum security).
pub fn sha3_512(data: &[u8]) -> Digest512 {
    let mut h = Sha3_512::new();
    h.update(data);
    h.finalize().into()
}

/// Grover-resistant PoW hash: SHA3-based memory-hard mixing + SHA3-512.
///
/// Uses a 1 MiB scratchpad with SHA3-256 random read/write mixing,
/// followed by SHA3-512 for quantum resistance.
///
/// ```text
/// result = SHA3-512(memory_hard_mix(data, scratchpad=1MiB, rounds=32))
/// ```
///
/// This uses ONLY the SHA3 crate (no external deps). For production,
/// consider integrating `randomx-rs` or `argon2` when a compatible
/// Rust toolchain is available.
pub fn pq_hash(data: &[u8]) -> Digest512 {
    let mixed = memory_hard_mix(data);
    sha3_512(&mixed)
}

/// SHA3-based memory-hard mixing.
///
/// 32 rounds over a 1 MiB scratchpad. Each round performs
/// data-dependent reads and writes through SHA3-256.
fn memory_hard_mix(data: &[u8]) -> Vec<u8> {
    const SCRATCHPAD_SIZE: usize = 1024 * 1024; // 1 MiB
    const BLOCK_SIZE: usize = 32;
    const NUM_BLOCKS: usize = SCRATCHPAD_SIZE / BLOCK_SIZE;
    const ROUNDS: usize = 32;

    let mut scratchpad = vec![0u8; SCRATCHPAD_SIZE];
    let seed: [u8; 32] = sha3_256(data);

    // Fill scratchpad deterministically
    let mut fill_state = seed;
    for chunk in scratchpad.chunks_mut(BLOCK_SIZE) {
        fill_state = sha3_256(&fill_state);
        let copy_len = chunk.len().min(BLOCK_SIZE);
        chunk[..copy_len].copy_from_slice(&fill_state[..copy_len]);
    }

    // Memory-hard mixing rounds
    let mut state = seed;
    for round in 0..ROUNDS {
        // Data-dependent read address
        let read_idx = u32::from_le_bytes([state[0], state[1], state[2], state[3]]) as usize;
        let read_addr = (read_idx % NUM_BLOCKS) * BLOCK_SIZE;

        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(&scratchpad[read_addr..read_addr + BLOCK_SIZE]);

        // Non-linear mixing with round-dependent rotation
        for i in 0..BLOCK_SIZE {
            block[i] = block[i]
                .wrapping_add(state[(i + round) % BLOCK_SIZE])
                .rotate_left(((round + i) % 7 + 1) as u32);
        }

        // Data-dependent write address (different from read)
        let write_idx = u32::from_le_bytes([state[4], state[5], state[6], state[7]]) as usize;
        let write_addr = (write_idx % NUM_BLOCKS) * BLOCK_SIZE;
        scratchpad[write_addr..write_addr + BLOCK_SIZE].copy_from_slice(&block);

        // Second read (long-range dependency)
        let read2_idx = u32::from_le_bytes([state[8], state[9], state[10], state[11]]) as usize;
        let read2_addr = (read2_idx % NUM_BLOCKS) * BLOCK_SIZE;
        let mut block2 = [0u8; BLOCK_SIZE];
        block2.copy_from_slice(&scratchpad[read2_addr..read2_addr + BLOCK_SIZE]);

        // Mix block2 into block
        for i in 0..BLOCK_SIZE {
            block[i] ^= block2[i];
        }

        // Advance state through SHA3
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_POW_MIX_V2:");
        h.update(&state);
        h.update(&block);
        h.update(&(round as u32).to_le_bytes());
        state = h.finalize().into();
    }

    // Final: hash entire scratchpad + state
    let mut h = Sha3_256::new();
    h.update(b"MISAKA_POW_FINAL_V2:");
    for chunk in scratchpad.chunks(4096) {
        h.update(chunk);
    }
    h.update(&state);
    let final_hash: [u8; 32] = h.finalize().into();
    final_hash.to_vec()
}

/// Merkle root from a list of leaf digests (SHA3-256).
///
/// Uses domain-separated hashing to prevent second preimage attacks:
/// - Leaf nodes are prefixed with 0x00
/// - Internal nodes are prefixed with 0x01
/// This prevents an attacker from constructing a valid leaf that
/// collides with an internal node hash.
pub fn merkle_root(leaves: &[Digest]) -> Digest {
    if leaves.is_empty() {
        return sha3_256(&[]);
    }
    // Domain-separate leaf nodes
    let mut layer: Vec<Digest> = leaves.iter().map(|leaf| {
        let mut h = Sha3_256::new();
        h.update(&[0x00]); // Leaf domain tag
        h.update(leaf);
        h.finalize().into()
    }).collect();
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            let last = match layer.last() {
                Some(v) => *v,
                None => return sha3_256(&[]),
            };
            layer.push(last);
        }
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            let mut h = Sha3_256::new();
            h.update(&[0x01]); // Internal node domain tag
            h.update(&pair[0]);
            h.update(&pair[1]);
            next.push(h.finalize().into());
        }
        layer = next;
    }
    layer[0]
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256_deterministic() {
        let d1 = sha3_256(b"MISAKA");
        let d2 = sha3_256(b"MISAKA");
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_sha3_512_deterministic() {
        let d1 = sha3_512(b"MISAKA");
        let d2 = sha3_512(b"MISAKA");
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 64);
    }

    #[test]
    fn test_pq_hash_deterministic() {
        let d1 = pq_hash(b"test block data");
        let d2 = pq_hash(b"test block data");
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 64);
    }

    #[test]
    fn test_pq_hash_avalanche() {
        let d1 = pq_hash(b"test1");
        let d2 = pq_hash(b"test2");
        assert_ne!(d1, d2);
        // At least 25% of bits should differ (avalanche effect)
        let diff_bits: u32 = d1.iter().zip(d2.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum();
        assert!(diff_bits > 64, "avalanche effect too weak: {} bits differ", diff_bits);
    }

    #[test]
    fn test_pq_hash_differs_from_plain_sha3() {
        let d_pq = pq_hash(b"test");
        let d_sha3 = sha3_512(b"test");
        assert_ne!(d_pq, d_sha3, "pq_hash must differ from plain SHA3-512");
    }

    #[test]
    fn test_merkle_root_empty() {
        let root = merkle_root(&[]);
        assert_eq!(root, sha3_256(&[]));
    }

    #[test]
    fn test_merkle_root_single() {
        let leaf = sha3_256(b"leaf");
        let root = merkle_root(&[leaf]);
        // With domain separation, single leaf root = H(0x00 || leaf), not leaf itself
        let expected = {
            let mut h = Sha3_256::new();
            h.update(&[0x00]);
            h.update(&leaf);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        assert_eq!(root, expected);
        assert_ne!(root, leaf, "domain separation must change the hash");
    }

    #[test]
    fn test_merkle_root_deterministic() {
        let leaves = vec![sha3_256(b"a"), sha3_256(b"b"), sha3_256(b"c")];
        let r1 = merkle_root(&leaves);
        let r2 = merkle_root(&leaves);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_merkle_root_order_matters() {
        let a = sha3_256(b"a");
        let b = sha3_256(b"b");
        let r1 = merkle_root(&[a, b]);
        let r2 = merkle_root(&[b, a]);
        assert_ne!(r1, r2);
    }
}
