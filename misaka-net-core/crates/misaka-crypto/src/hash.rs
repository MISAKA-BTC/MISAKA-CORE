//! Core hash functions.

use sha3::{Digest as Sha3Digest, Sha3_256};

pub type Digest = [u8; 32];

pub fn sha3_256(data: &[u8]) -> Digest {
    let mut h = Sha3_256::new();
    h.update(data);
    h.finalize().into()
}

pub fn merkle_root(leaves: &[Digest]) -> Digest {
    if leaves.is_empty() { return sha3_256(&[]); }
    let mut layer: Vec<Digest> = leaves.to_vec();
    while layer.len() > 1 {
        if layer.len() % 2 == 1 { let last = match layer.last() { Some(v) => *v, None => return sha3_256(&[]) }; layer.push(last); }
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            let mut h = Sha3_256::new(); h.update(&pair[0]); h.update(&pair[1]);
            next.push(h.finalize().into());
        }
        layer = next;
    }
    layer[0]
}
