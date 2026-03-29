//! Mock consensus API for mining tests.

/// Mock consensus for testing block template construction.
pub struct MockConsensus {
    pub virtual_state_id: u64,
    pub daa_score: u64,
    pub timestamp: u64,
    pub bits: u32,
    pub tip_hashes: Vec<[u8; 32]>,
}

impl MockConsensus {
    pub fn new() -> Self {
        Self {
            virtual_state_id: 1,
            daa_score: 1000,
            timestamp: 1700000000,
            bits: 0x1d00ffff,
            tip_hashes: vec![[1u8; 32]],
        }
    }

    pub fn get_virtual_state_approx_id(&self) -> u64 { self.virtual_state_id }
}

impl Default for MockConsensus {
    fn default() -> Self { Self::new() }
}
