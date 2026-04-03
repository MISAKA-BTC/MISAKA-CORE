//! Committee management with reputation-based leader election.

use crate::block::AuthorityIndex;
use crate::block::Round;

pub type Stake = u64;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Authority {
    pub index: AuthorityIndex,
    pub stake: Stake,
    pub address: String,
    /// ML-DSA-65 public key (1952 bytes). Used for block/vote signature verification.
    /// Empty only for genesis / test authorities.
    pub public_key: Vec<u8>,
    /// Reputation score (0-10000). Higher = better propagation quality.
    pub reputation_score: u64,
    /// Whether this authority is an active SR (finality committee member).
    pub is_sr: bool,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Committee {
    pub epoch: u64,
    pub authorities: Vec<Authority>,
    pub total_stake: Stake,
    /// Number of leaders per round (Mysticeti: configurable).
    pub leaders_per_round: u32,
    /// Wave length for commit rule (minimum 3).
    pub wave_length: u32,
}

impl Committee {
    pub fn size(&self) -> usize { self.authorities.len() }

    /// Quorum threshold: 2f+1 where f = (n-1)/3.
    pub fn quorum_threshold(&self) -> Stake {
        self.total_stake * 2 / 3 + 1
    }

    /// Validity threshold: f+1.
    pub fn validity_threshold(&self) -> Stake {
        let quorum = self.quorum_threshold();
        (self.total_stake - quorum) + 1
    }

    /// Elect leaders for a given round.
    /// Returns `leaders_per_round` leaders, weighted by stake + reputation.
    pub fn elect_leaders(&self, round: Round) -> Vec<AuthorityIndex> {
        if self.authorities.is_empty() { return vec![]; }
        let mut leaders = Vec::with_capacity(self.leaders_per_round as usize);
        for offset in 0..self.leaders_per_round {
            let seed = round.wrapping_mul(97).wrapping_add(offset as u64);
            // Weighted selection: higher stake+reputation = more likely
            let mut weighted: Vec<(AuthorityIndex, u64)> = self.authorities.iter()
                .map(|a| (a.index, a.stake.saturating_add(a.reputation_score)))
                .collect();
            weighted.sort_by(|a, b| b.1.cmp(&a.1)); // highest weight first
            let idx = (seed as usize) % weighted.len();
            leaders.push(weighted[idx].0);
        }
        leaders
    }

    /// Check if an authority is an SR (finality committee member).
    pub fn is_sr(&self, index: AuthorityIndex) -> bool {
        self.authorities.get(index as usize).map(|a| a.is_sr).unwrap_or(false)
    }

    /// Get stake for an authority.
    pub fn stake(&self, index: AuthorityIndex) -> Stake {
        self.authorities.get(index as usize).map(|a| a.stake).unwrap_or(0)
    }

    /// Count of SR members.
    pub fn sr_count(&self) -> usize {
        self.authorities.iter().filter(|a| a.is_sr).count()
    }

    /// SR quorum threshold: ceil(2N/3) — standard BFT 2/3 supermajority.
    /// SR15: 10.  SR18: 12.  SR21: 14.
    pub fn sr_quorum(&self) -> usize {
        let n = self.sr_count();
        if n < 3 { return n; }
        (2 * n + 2) / 3
    }

    /// Update reputation scores based on block propagation quality.
    /// Called periodically (e.g., every N commits).
    pub fn update_reputation(&mut self, block_counts: &std::collections::HashMap<AuthorityIndex, u64>, window_commits: u64) {
        if window_commits == 0 { return; }
        let expected_per_auth = window_commits;

        for auth in &mut self.authorities {
            let actual = block_counts.get(&auth.index).copied().unwrap_or(0);
            // Score = (actual / expected) * 10000, capped at 10000
            let ratio = if expected_per_auth > 0 {
                (actual * 10000) / expected_per_auth
            } else {
                5000
            };
            auth.reputation_score = std::cmp::min(ratio, 10000);
        }
    }

    /// Demote an equivocating authority (reputation = 0).
    pub fn penalize_equivocator(&mut self, authority: AuthorityIndex) {
        if let Some(auth) = self.authorities.get_mut(authority as usize) {
            auth.reputation_score = 0;
            auth.is_sr = false; // Remove SR status
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_21sr_committee() {
        let auths: Vec<Authority> = (0..21).map(|i| Authority {
            index: i, stake: 1_000_000, address: format!("node-{}", i),
            public_key: vec![0xAA; 1952], // test key
            reputation_score: 5000, is_sr: true,
        }).collect();
        let c = Committee {
            epoch: 0, authorities: auths, total_stake: 21_000_000,
            leaders_per_round: 2, wave_length: 3,
        };
        assert_eq!(c.size(), 21);
        assert_eq!(c.sr_count(), 21);
        assert_eq!(c.sr_quorum(), 14); // ceil(2*21/3) = 14
        let leaders = c.elect_leaders(1);
        assert_eq!(leaders.len(), 2); // multi-leader
    }
}
