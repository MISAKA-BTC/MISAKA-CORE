//! Block Synchronization — DAG + Unified ZKP native.
//!
//! # Architecture
//!
//! DAG sync differs from linear chain sync:
//! - No sequential height-based sync
//! - Request missing blocks by hash (from GhostDAG parent references)
//! - Parallel block download from multiple peers
//! - Total order recomputation after each new block
//!
//! # Sync Flow
//!
//! 1. Exchange tips with peer
//! 2. Identify missing blocks (BFS from peer tips)
//! 3. Request missing blocks by hash
//! 4. Validate header (fast) → insert into DAG → compute GhostDAG
//! 5. Recompute total order + apply state (after all blocks received)

use misaka_dag::dag_block::{Hash, DagBlockHeader, ZERO_HASH};
use misaka_dag::wire_protocol::{WireMessage, WireMessageType, encode_hash_list, decode_hash_list};

/// Sync state for a peer connection.
#[derive(Debug)]
pub struct PeerSyncState {
    /// Peer's reported tips.
    pub peer_tips: Vec<Hash>,
    /// Blocks we've requested but not yet received.
    pub pending_requests: std::collections::HashSet<Hash>,
    /// Number of blocks received from this peer.
    pub blocks_received: u64,
}

impl PeerSyncState {
    pub fn new() -> Self {
        Self {
            peer_tips: vec![],
            pending_requests: std::collections::HashSet::new(),
            blocks_received: 0,
        }
    }
}

/// Create a GetTips request message.
pub fn make_get_tips() -> WireMessage {
    WireMessage {
        msg_type: WireMessageType::GetTips,
        payload: vec![],
    }
}

/// Create a Tips response message.
pub fn make_tips_response(tips: &[Hash]) -> WireMessage {
    WireMessage {
        msg_type: WireMessageType::Tips,
        payload: encode_hash_list(tips),
    }
}

/// Create a GetBlocks request for specific hashes.
pub fn make_get_blocks(hashes: &[Hash]) -> WireMessage {
    WireMessage {
        msg_type: WireMessageType::GetBlocks,
        payload: encode_hash_list(hashes),
    }
}

/// Determine which blocks we're missing from a peer's tips.
///
/// BFS backwards from peer tips, stopping at blocks we already have.
pub fn find_missing_blocks(
    peer_tips: &[Hash],
    have_block: impl Fn(&Hash) -> bool,
    get_parents: impl Fn(&Hash) -> Vec<Hash>,
) -> Vec<Hash> {
    let mut missing = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let mut queue: std::collections::VecDeque<Hash> = peer_tips.iter().copied().collect();

    while let Some(hash) = queue.pop_front() {
        if !visited.insert(hash) { continue; }
        if have_block(&hash) { continue; }

        missing.push(hash);

        // BFS into parents (which we might also be missing)
        for parent in get_parents(&hash) {
            if parent != ZERO_HASH && !visited.contains(&parent) {
                queue.push_back(parent);
            }
        }
    }

    missing
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_message_roundtrip() {
        let tips = vec![[0x11u8; 32], [0x22; 32]];
        let msg = make_tips_response(&tips);
        let encoded = msg.encode();
        let decoded = WireMessage::decode(&encoded).unwrap();
        let decoded_tips = decode_hash_list(&decoded.payload).unwrap();
        assert_eq!(decoded_tips, tips);
    }

    #[test]
    fn test_find_missing_simple() {
        // Peer has blocks A → B → C (we have A and B, missing C)
        let a = [0xAA; 32];
        let b = [0xBB; 32];
        let c = [0xCC; 32];

        let have = |h: &[u8; 32]| *h == a || *h == b;
        let parents = |h: &[u8; 32]| -> Vec<[u8; 32]> {
            if *h == c { vec![b] }
            else if *h == b { vec![a] }
            else { vec![] }
        };

        let missing = find_missing_blocks(&[c], have, parents);
        assert_eq!(missing, vec![c]);
    }

    #[test]
    fn test_find_missing_dag_fork() {
        // DAG: A ← B, A ← C (peer has B and C, we have only A)
        let a = [0xAA; 32];
        let b = [0xBB; 32];
        let c = [0xCC; 32];

        let have = |h: &[u8; 32]| *h == a;
        let parents = |h: &[u8; 32]| -> Vec<[u8; 32]> {
            if *h == b || *h == c { vec![a] }
            else { vec![] }
        };

        let missing = find_missing_blocks(&[b, c], have, parents);
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(&b));
        assert!(missing.contains(&c));
    }
}
