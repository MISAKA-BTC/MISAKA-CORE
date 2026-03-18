//! Replay protection — nullifier set for bridge requests.

use std::collections::HashSet;

pub struct ReplayProtection {
    used_ids: HashSet<[u8; 32]>,
}

impl ReplayProtection {
    pub fn new() -> Self { Self { used_ids: HashSet::new() } }

    pub fn is_used(&self, request_id: &[u8; 32]) -> bool {
        self.used_ids.contains(request_id)
    }

    pub fn mark_used(&mut self, request_id: [u8; 32]) {
        self.used_ids.insert(request_id);
    }

    pub fn len(&self) -> usize { self.used_ids.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_protection() {
        let mut rp = ReplayProtection::new();
        let id = [0xAA; 32];
        assert!(!rp.is_used(&id));
        rp.mark_used(id);
        assert!(rp.is_used(&id));
        assert_eq!(rp.len(), 1);
    }
}
