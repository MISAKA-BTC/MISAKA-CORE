// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Sui equivalent: consensus/core/src/round_prober.rs (436 lines)
//
//! Round Prober — periodic network health monitoring.
//!
//! Queries peers for their highest received/accepted rounds, then
//! computes per-authority quorum rounds and propagation delay.
//! Results feed into AncestorSelector and CoreEngine for adaptive
//! proposal timing.
//!
//! See Sui's `round_prober.rs` for the reference implementation.

use crate::narwhal_types::block::*;
use crate::narwhal_types::committee::{Committee, Stake};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Quorum round: (low_quorum_round, high_quorum_round) per authority.
pub type QuorumRound = (Round, Round);

/// Peer round information returned by a probe.
#[derive(Clone, Debug)]
pub struct PeerRoundInfo {
    /// Highest round received from each authority (post-verify, pre-dependency).
    pub highest_received: Vec<Round>,
    /// Highest round accepted from each authority (post-dependency).
    pub highest_accepted: Vec<Round>,
}

/// Probe error.
#[derive(Debug)]
pub enum ProbeError {
    Timeout,
    NetworkError(String),
    InvalidResponse,
}

/// Trait for network communication — implemented by the P2P layer.
pub trait PeerProber: Send + Sync {
    /// Query a peer for their latest round information.
    fn probe_peer(
        &self,
        peer: AuthorityIndex,
        timeout: Duration,
    ) -> Result<PeerRoundInfo, ProbeError>;
}

/// Configuration.
#[derive(Clone, Debug)]
pub struct RoundProberConfig {
    /// Probe interval in milliseconds.
    pub interval_ms: u64,
    /// Per-peer request timeout.
    pub timeout: Duration,
    /// Our authority index.
    pub own_index: AuthorityIndex,
}

impl Default for RoundProberConfig {
    fn default() -> Self {
        Self {
            interval_ms: 5_000,
            timeout: Duration::from_millis(2_000),
            own_index: 0,
        }
    }
}

/// Result of a single probe cycle.
#[derive(Clone, Debug)]
pub struct ProbeResult {
    pub propagation_delay: Round,
    pub quorum_rounds: Vec<QuorumRound>,
    pub success_count: u32,
    pub fail_count: u32,
    pub duration: Duration,
}

/// Round prober — tracks network health.
///
/// Sui equivalent: `RoundProber` in `round_prober.rs`.
pub struct RoundProber {
    config: RoundProberConfig,
    committee: Committee,
    quorum: Stake,
    /// Per-authority quorum rounds.
    quorum_rounds: Vec<QuorumRound>,
    /// Propagation delay (rounds behind quorum).
    propagation_delay: Round,
    /// Last probe time.
    last_probe: Option<Instant>,
    /// Total probes executed.
    total_probes: u64,
}

impl RoundProber {
    /// Create a new prober.
    #[must_use]
    pub fn new(committee: Committee, config: RoundProberConfig) -> Self {
        let n = committee.size();
        let quorum = committee.quorum_threshold();
        Self {
            config,
            committee,
            quorum,
            quorum_rounds: vec![(0, 0); n],
            propagation_delay: 0,
            last_probe: None,
            total_probes: 0,
        }
    }

    /// Execute a single probe cycle.
    ///
    /// Queries all peers, updates quorum rounds and propagation delay.
    ///
    /// Sui equivalent: `RoundProber::probe()`.
    pub fn probe(&mut self, network: &dyn PeerProber, own_last_proposed: Round) -> ProbeResult {
        let start = Instant::now();
        let n = self.committee.size();
        let own = self.config.own_index;

        let mut accepted_matrix: Vec<Vec<Round>> = vec![vec![0; n]; n];
        let mut success = 0u32;
        let mut fail = 0u32;

        // Own data
        if (own as usize) < n {
            for i in 0..n {
                accepted_matrix[own as usize][i] = own_last_proposed;
            }
            success += 1;
        }

        // Query peers
        for peer in 0..n as AuthorityIndex {
            if peer == own {
                continue;
            }
            match network.probe_peer(peer, self.config.timeout) {
                Ok(info) if info.highest_accepted.len() == n => {
                    accepted_matrix[peer as usize] = info.highest_accepted;
                    success += 1;
                }
                _ => {
                    fail += 1;
                } // timeout/error → zeros (conservative)
            }
        }

        // Compute per-authority quorum rounds
        for author in 0..n {
            let mut rounds_stake: Vec<(Round, Stake)> = (0..n)
                .map(|peer| {
                    (
                        accepted_matrix[peer][author],
                        self.committee.stake(peer as AuthorityIndex),
                    )
                })
                .collect();
            rounds_stake.sort_by(|a, b| b.0.cmp(&a.0)); // descending by round

            let mut cum: Stake = 0;
            let mut high_qr: Round = 0;
            let mut low_qr: Round = 0;
            let validity = self.committee.validity_threshold();

            for (round, stake) in &rounds_stake {
                cum += stake;
                if low_qr == 0 && cum >= validity {
                    low_qr = *round;
                }
                if cum >= self.quorum {
                    high_qr = *round;
                    break;
                }
            }
            self.quorum_rounds[author] = (low_qr, high_qr);
        }

        // Propagation delay for our own blocks
        let own_qr = self
            .quorum_rounds
            .get(own as usize)
            .map(|qr| qr.1)
            .unwrap_or(0);
        self.propagation_delay = own_last_proposed.saturating_sub(own_qr);

        self.last_probe = Some(start);
        self.total_probes += 1;

        ProbeResult {
            propagation_delay: self.propagation_delay,
            quorum_rounds: self.quorum_rounds.clone(),
            success_count: success,
            fail_count: fail,
            duration: start.elapsed(),
        }
    }

    /// Check if it's time to probe.
    #[must_use]
    pub fn should_probe(&self) -> bool {
        self.last_probe.map_or(true, |t| {
            t.elapsed() >= Duration::from_millis(self.config.interval_ms)
        })
    }

    /// Current propagation delay.
    #[must_use]
    pub fn propagation_delay(&self) -> Round {
        self.propagation_delay
    }

    /// Per-authority quorum rounds.
    #[must_use]
    pub fn quorum_rounds(&self) -> &[QuorumRound] {
        &self.quorum_rounds
    }

    /// Total probes executed.
    #[must_use]
    pub fn total_probes(&self) -> u64 {
        self.total_probes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProber {
        responses: HashMap<AuthorityIndex, PeerRoundInfo>,
    }
    impl PeerProber for MockProber {
        fn probe_peer(
            &self,
            peer: AuthorityIndex,
            _: Duration,
        ) -> Result<PeerRoundInfo, ProbeError> {
            self.responses
                .get(&peer)
                .cloned()
                .ok_or(ProbeError::Timeout)
        }
    }

    fn uniform_response(n: usize, round: Round) -> HashMap<AuthorityIndex, PeerRoundInfo> {
        let mut m = HashMap::new();
        for i in 0..n as AuthorityIndex {
            m.insert(
                i,
                PeerRoundInfo {
                    highest_received: vec![round; n],
                    highest_accepted: vec![round; n],
                },
            );
        }
        m
    }

    #[test]
    fn test_all_healthy() {
        let committee = Committee::new_for_test(4);
        let config = RoundProberConfig {
            own_index: 0,
            ..Default::default()
        };
        let mut prober = RoundProber::new(committee, config);
        let network = MockProber {
            responses: uniform_response(4, 10),
        };

        let result = prober.probe(&network, 10);
        assert_eq!(result.success_count, 4);
        assert_eq!(result.propagation_delay, 0);
    }

    #[test]
    fn test_lagging_peer() {
        let committee = Committee::new_for_test(4);
        let config = RoundProberConfig {
            own_index: 0,
            ..Default::default()
        };
        let mut prober = RoundProber::new(committee, config);
        let mut responses = uniform_response(4, 10);
        responses.get_mut(&3).unwrap().highest_accepted = vec![5, 5, 5, 5];
        let network = MockProber { responses };

        let result = prober.probe(&network, 10);
        assert!(result.propagation_delay <= 10);
    }

    #[test]
    fn test_peer_timeout() {
        let committee = Committee::new_for_test(4);
        let config = RoundProberConfig {
            own_index: 0,
            ..Default::default()
        };
        let mut prober = RoundProber::new(committee, config);
        let mut responses = HashMap::new();
        responses.insert(
            1,
            PeerRoundInfo {
                highest_received: vec![10; 4],
                highest_accepted: vec![10; 4],
            },
        );
        let network = MockProber { responses };

        let result = prober.probe(&network, 10);
        assert_eq!(result.success_count, 2); // own + peer 1
        assert_eq!(result.fail_count, 2);
    }

    #[test]
    fn test_should_probe() {
        let committee = Committee::new_for_test(4);
        let config = RoundProberConfig {
            interval_ms: 100,
            own_index: 0,
            ..Default::default()
        };
        let prober = RoundProber::new(committee, config);
        assert!(prober.should_probe()); // never probed
    }

    #[test]
    fn test_quorum_round_calculation() {
        let committee = Committee::new_for_test(4);
        let config = RoundProberConfig {
            own_index: 0,
            ..Default::default()
        };
        let mut prober = RoundProber::new(committee, config);
        let mut responses = HashMap::new();
        // All peers see authority 0 at round 10
        for peer in 0..4 {
            responses.insert(
                peer,
                PeerRoundInfo {
                    highest_received: vec![10, 8, 6, 4],
                    highest_accepted: vec![10, 8, 6, 4],
                },
            );
        }
        let network = MockProber { responses };
        let result = prober.probe(&network, 10);
        // Authority 0: all 4 see round 10 → high_qr = 10
        assert_eq!(prober.quorum_rounds()[0].1, 10);
    }
}
