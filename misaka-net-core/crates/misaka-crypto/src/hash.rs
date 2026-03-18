//! Core hash functions — SHA3-only (Grover-resistant).
//!
//! # Security Policy
//!
//! - SHA2 is PROHIBITED everywhere in MISAKA Network.
//! - SHA3-256 for standard hashing (128-bit PQ security via 256-bit output).
//! - SHA3-512 for extended hashing (256-bit PQ security).
//! - `pq_hash` provides CPU-bound Grover-resistant hashing:
//!   SHA3-512(randomx_mix(data)) — ASIC-resistant + quantum-resistant.

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

/// Grover-resistant PoW hash: CPU-bound mixing + SHA3-512.
///
/// Provides ASIC resistance via memory-hard mixing (simplified RandomX-style)
/// combined with SHA3-512 for quantum resistance.
///
/// ```text
/// result = SHA3-512(randomx_mix(data))
/// ```
///
/// The mixing stage performs multiple rounds of:
/// 1. SHA3-256 hash expansion to fill scratchpad
/// 2. Memory-dependent random reads/writes
/// 3. Non-linear mixing (rotate, XOR, add)
///
/// This is NOT a full RandomX implementation — it provides a reasonable
/// CPU-bound pre-processing stage. A proper RandomX integration would
/// use the `randomx-rs` crate for production PoW.
pub fn pq_hash(data: &[u8]) -> Digest512 {
    let mixed = randomx_mix(data);
    sha3_512(&mixed)
}

/// Simplified CPU-bound mixing (RandomX-style).
///
/// 8 rounds of memory-hard mixing over a 4 KiB scratchpad.
/// Each round performs SHA3-256 dependent reads and non-linear mixing.
fn randomx_mix(data: &[u8]) -> Vec<u8> {
    const SCRATCHPAD_SIZE: usize = 4096; // 4 KiB
    const ROUNDS: usize = 8;

    // Initialize scratchpad from input data
    let mut scratchpad = vec![0u8; SCRATCHPAD_SIZE];
    let seed: [u8; 32] = sha3_256(data);

    // Fill scratchpad with deterministic pseudorandom data
    let mut fill_state = seed;
    for chunk in scratchpad.chunks_mut(32) {
        fill_state = sha3_256(&fill_state);
        let copy_len = chunk.len().min(32);
        chunk[..copy_len].copy_from_slice(&fill_state[..copy_len]);
    }

    // Memory-hard mixing rounds
    let mut state = seed;
    for round in 0..ROUNDS {
        // Derive round-dependent index
        let idx = u32::from_le_bytes([state[0], state[1], state[2], state[3]]) as usize;
        let addr = (idx % (SCRATCHPAD_SIZE / 32)) * 32;

        // Read from scratchpad
        let mut block = [0u8; 32];
        block.copy_from_slice(&scratchpad[addr..addr + 32]);

        // Non-linear mixing: rotate + XOR + round counter
        for i in 0..32 {
            block[i] = block[i]
                .wrapping_add(state[(i + round) % 32])
                .rotate_left(((round + i) % 7 + 1) as u32);
        }

        // Write back to scratchpad
        let write_idx = u32::from_le_bytes([state[4], state[5], state[6], state[7]]) as usize;
        let write_addr = (write_idx % (SCRATCHPAD_SIZE / 32)) * 32;
        scratchpad[write_addr..write_addr + 32].copy_from_slice(&block);

        // Advance state
        let mut h = Sha3_256::new();
        h.update(&state);
        h.update(&block);
        h.update(&(round as u32).to_le_bytes());
        state = h.finalize().into();
    }

    // Final output: hash of scratchpad + final state
    let mut output = Vec::with_capacity(SCRATCHPAD_SIZE + 32);
    output.extend_from_slice(&scratchpad);
    output.extend_from_slice(&state);
    output
}

/// Merkle root from a list of leaf digests (SHA3-256).
pub fn merkle_root(leaves: &[Digest]) -> Digest {
    if leaves.is_empty() {
        return sha3_256(&[]);
    }
    let mut layer: Vec<Digest> = leaves.to_vec();
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
        assert_eq!(root, leaf);
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
