//! Checkpoint types per Spec 01 §6.

use crate::{CheckpointSeq, Digest, Epoch};
use sha3::{Digest as Sha3Digest, Sha3_256};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CheckpointSummary {
    pub epoch: Epoch,
    pub sequence_number: CheckpointSeq,
    pub content_digest: Digest,
    pub previous_digest: Digest,
    pub timestamp_ms: u64,
    pub tx_count: u32,
    pub state_root: Digest,
}

impl CheckpointSummary {
    pub fn digest(&self) -> Digest {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        buf.extend_from_slice(&self.sequence_number.to_le_bytes());
        buf.extend_from_slice(&self.content_digest);
        buf.extend_from_slice(&self.previous_digest);
        buf.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        buf.extend_from_slice(&self.tx_count.to_le_bytes());
        buf.extend_from_slice(&self.state_root);
        let mut h = Sha3_256::new();
        h.update(&buf);
        h.finalize().into()
    }
}

pub fn compute_tx_digest_merkle_root(tx_digests: &[Digest]) -> Digest {
    if tx_digests.is_empty() {
        let mut h = Sha3_256::new();
        h.update(b"");
        return h.finalize().into();
    }
    let mut layer: Vec<Digest> = tx_digests
        .iter()
        .map(|d| {
            let mut h = Sha3_256::new();
            h.update(d);
            h.finalize().into()
        })
        .collect();
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            // SAFETY: layer.len() >= 2 (while condition) and odd, so last() always Some
            let last = match layer.last() {
                Some(v) => *v,
                None => break,
            };
            layer.push(last);
        }
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            let mut h = Sha3_256::new();
            h.update(pair[0]);
            h.update(pair[1]);
            next.push(h.finalize().into());
        }
        layer = next;
    }
    layer[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_digest_deterministic() {
        let cp = CheckpointSummary {
            epoch: 1,
            sequence_number: 42,
            content_digest: [0xAA; 32],
            previous_digest: [0xBB; 32],
            timestamp_ms: 1700000000000,
            tx_count: 10,
            state_root: [0xCC; 32],
        };
        assert_eq!(cp.digest(), cp.digest());
    }

    #[test]
    fn test_merkle_root_single() {
        let d = [0xAA; 32];
        let root = compute_tx_digest_merkle_root(&[d]);
        // Single leaf: layer = [SHA3(d)], len==1 → loop doesn't execute → returns SHA3(d)
        let expected: Digest = {
            let mut h = Sha3_256::new();
            h.update(&d);
            h.finalize().into()
        };
        assert_eq!(root, expected);
    }
}
