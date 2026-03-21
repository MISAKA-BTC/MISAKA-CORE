//! # Validator Network Policy — Sentry Isolation + Admission Control
//!
//! # Solana-Inspired Design
//!
//! Like Solana's validator architecture, MISAKA validators do NOT directly
//! participate in the public P2P mesh. Instead:
//!
//! ```text
//!                    Public Internet
//!                         │
//!        ┌────────────────┼────────────────┐
//!        │                │                │
//!   ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
//!   │ Sentry A│     │ Sentry B│     │ Sentry C│
//!   └────┬────┘     └────┬────┘     └────┬────┘
//!        │                │                │
//!        └────────────────┼────────────────┘
//!                         │
//!                   Private Link
//!                         │
//!                  ┌──────┴──────┐
//!                  │  VALIDATOR  │
//!                  │ (hidden IP) │
//!                  └─────────────┘
//! ```
//!
//! # Security Properties
//!
//! - Validator IP is never advertised in peer records
//! - Validator rejects inbound from non-allowlisted peers
//! - Multiple sentries prevent single point of failure
//! - If all sentries are lost, validator enters degraded mode (no block production)

use serde::{Deserialize, Serialize};
use crate::peer_id::PeerId;

// ═══════════════════════════════════════════════════════════════
//  Extended Node Role
// ═══════════════════════════════════════════════════════════════

/// Network role — extends the basic Validator/FullNode with Sentry and Bootstrap.
///
/// This replaces the simple `NodeRole` for network-level decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkRole {
    /// Standard full node — syncs chain, serves RPC, relays P2P.
    Full,
    /// Sentry node — public-facing shield for a validator.
    /// Accepts public inbound, relays to upstream validator(s).
    Sentry,
    /// Validator node — produces blocks, hidden behind sentries.
    /// Rejects public inbound, only accepts allowlisted sentries.
    Validator,
    /// Bootstrap/seed node — serves peer discovery only.
    Bootstrap,
}

impl NetworkRole {
    /// Whether this role accepts inbound from the public mesh.
    pub fn accepts_public_inbound(&self) -> bool {
        matches!(self, Self::Full | Self::Sentry | Self::Bootstrap)
    }

    /// Whether this role advertises its address in peer records.
    pub fn advertises_address(&self) -> bool {
        matches!(self, Self::Full | Self::Sentry | Self::Bootstrap)
    }

    /// Whether this role participates in public gossip.
    pub fn participates_in_gossip(&self) -> bool {
        matches!(self, Self::Full | Self::Sentry | Self::Bootstrap)
    }

    /// Whether this role produces blocks.
    pub fn produces_blocks(&self) -> bool {
        matches!(self, Self::Validator)
    }

    /// Whether this role requires PQ auth for ALL inbound.
    pub fn requires_pq_auth_always(&self) -> bool {
        matches!(self, Self::Validator)
    }
}

impl std::fmt::Display for NetworkRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => write!(f, "full"),
            Self::Sentry => write!(f, "sentry"),
            Self::Validator => write!(f, "validator"),
            Self::Bootstrap => write!(f, "bootstrap"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Validator Network Config
// ═══════════════════════════════════════════════════════════════

/// Network policy for validator nodes.
///
/// # Fail-Closed Defaults
///
/// - `allow_public_inbound: false` — no public connections accepted
/// - `require_pq_auth: true` — all connections must PQ-authenticate
/// - `sentry_allowlist` — only these PeerIds can connect inbound
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorNetworkConfig {
    /// PeerIds of allowed sentry nodes.
    /// Only these peers can initiate inbound connections to this validator.
    pub sentry_allowlist: Vec<PeerId>,
    /// Minimum number of live sentry connections before entering safe mode.
    pub min_live_sentries: usize,
    /// Whether to accept inbound from public (non-allowlisted) peers.
    /// **MUST be false for mainnet validators.**
    pub allow_public_inbound: bool,
    /// Whether outbound-only mode is forced (no listening at all).
    pub outbound_only_mode: bool,
    /// Whether PQ mutual auth is required for ALL connections.
    /// **MUST be true for mainnet validators.**
    pub require_pq_auth: bool,
    /// Optional separate identity key for network (vs consensus key).
    /// If None, the consensus key is used for network identity.
    pub network_identity_key_path: Option<String>,
    /// PeerIds of other validators for direct validator-to-validator links.
    pub validator_peers: Vec<PeerId>,
}

impl Default for ValidatorNetworkConfig {
    fn default() -> Self {
        Self {
            sentry_allowlist: Vec::new(),
            min_live_sentries: 1,
            allow_public_inbound: false, // Fail-closed: no public inbound by default
            outbound_only_mode: false,
            require_pq_auth: true,       // Fail-closed: PQ auth required by default
            network_identity_key_path: None,
            validator_peers: Vec::new(),
        }
    }
}

impl ValidatorNetworkConfig {
    /// Check if a peer is allowed to connect inbound.
    pub fn is_allowed_inbound(&self, peer_id: &PeerId) -> bool {
        if self.allow_public_inbound {
            return true;
        }
        self.sentry_allowlist.contains(peer_id)
            || self.validator_peers.contains(peer_id)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Sentry Config
// ═══════════════════════════════════════════════════════════════

/// Network policy for sentry nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentryConfig {
    /// PeerIds of upstream validators this sentry serves.
    pub validator_upstream: Vec<PeerId>,
    /// Maximum public inbound peers.
    pub max_public_inbound: usize,
    /// Maximum outbound peers.
    pub max_public_outbound: usize,
    /// Whether to relay consensus traffic (blocks/votes) to validators.
    pub relay_consensus: bool,
    /// Whether to relay general gossip (transactions) to validators.
    pub relay_gossip: bool,
}

impl Default for SentryConfig {
    fn default() -> Self {
        Self {
            validator_upstream: Vec::new(),
            max_public_inbound: 64,
            max_public_outbound: 16,
            relay_consensus: true,
            relay_gossip: true,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Admission Control
// ═══════════════════════════════════════════════════════════════

/// Inbound connection admission decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// Connection is accepted.
    Accept,
    /// Connection is rejected with reason.
    Reject(String),
}

/// Evaluate whether to admit an inbound connection.
///
/// # Fail-Closed Logic
///
/// For validators:
///   1. PQ auth MUST succeed (enforced at transport level)
///   2. PeerId MUST be in sentry_allowlist or validator_peers
///   3. Everything else → REJECT
///
/// For sentries:
///   1. PQ auth preferred but not required for public peers
///   2. Rate limits apply
///   3. Peer scoring applies
///
/// For full nodes / bootstrap:
///   1. Standard limits apply
pub fn evaluate_inbound(
    our_role: NetworkRole,
    remote_peer_id: &PeerId,
    validator_config: Option<&ValidatorNetworkConfig>,
    current_inbound_count: usize,
    max_inbound: usize,
) -> AdmissionDecision {
    // ── Capacity check ──
    if current_inbound_count >= max_inbound {
        return AdmissionDecision::Reject("inbound peer limit reached".into());
    }

    // ── Validator admission: allowlist-only ──
    if our_role == NetworkRole::Validator {
        let config = match validator_config {
            Some(c) => c,
            None => return AdmissionDecision::Reject(
                "validator mode requires ValidatorNetworkConfig".into()
            ),
        };
        if !config.is_allowed_inbound(remote_peer_id) {
            return AdmissionDecision::Reject(format!(
                "peer {} not in validator allowlist",
                remote_peer_id.short_hex()
            ));
        }
    }

    AdmissionDecision::Accept
}

// ═══════════════════════════════════════════════════════════════
//  Validator Degraded Mode
// ═══════════════════════════════════════════════════════════════

/// Operational state of a validator.
///
/// # v5 change: Extended from 3 states to 8 states.
///
/// v4 only had Normal/Degraded/Isolated.
/// v5 adds states that affect block production policy differently,
/// enabling fine-grained safety decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatorOperationalState {
    /// All sentries connected, state verified. Full block production.
    Normal,
    /// Below min_live_sentries. Voting allowed, proposing disabled.
    Degraded { live_sentries: usize, required: usize },
    /// No sentries connected. All consensus participation halted.
    Isolated,
    /// Peer scoring detected suspicious clustering. Outbound restricted.
    Quarantined { reason: String },
    /// Local clock is skewed beyond tolerance. Voting disabled.
    ClockSkewed { drift_ms: i64 },
    /// Snapshot integrity check failed. Must re-sync before producing.
    SnapshotUnsafe { reason: String },
    /// Behind the latest finalized checkpoint by too many epochs. Finality vote disabled.
    CheckpointLagging { local_epoch: u64, network_epoch: u64 },
    /// Detected conflicting checkpoints from different peers. Halt everything.
    SplitBrainSuspected { evidence: String },
}

/// Block production policy derived from operational state.
///
/// This is the ONLY place where the decision "can this validator propose/vote"
/// is made. All consensus code MUST check this before acting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockProductionPolicy {
    /// Whether the validator may propose new blocks.
    pub may_propose: bool,
    /// Whether the validator may vote on proposals.
    pub may_vote: bool,
    /// Whether the validator may participate in gossip.
    pub may_gossip: bool,
}

impl ValidatorOperationalState {
    /// Derive the block production policy from the current state.
    pub fn production_policy(&self) -> BlockProductionPolicy {
        match self {
            Self::Normal => BlockProductionPolicy {
                may_propose: true,
                may_vote: true,
                may_gossip: true,
            },
            Self::Degraded { .. } => BlockProductionPolicy {
                may_propose: false, // Too risky without full sentry shield
                may_vote: true,     // Voting is safe (doesn't reveal IP)
                may_gossip: true,
            },
            Self::Isolated => BlockProductionPolicy {
                may_propose: false,
                may_vote: false,
                may_gossip: false, // No peers to gossip to anyway
            },
            Self::Quarantined { .. } => BlockProductionPolicy {
                may_propose: false,
                may_vote: true,
                may_gossip: false, // Restricted to prevent eclipse exploitation
            },
            Self::ClockSkewed { .. } => BlockProductionPolicy {
                may_propose: false, // Timestamps would be wrong
                may_vote: false,    // Vote timestamps matter for finality
                may_gossip: true,   // Can still relay
            },
            Self::SnapshotUnsafe { .. } => BlockProductionPolicy {
                may_propose: false,
                may_vote: false,
                may_gossip: false, // State is untrustworthy
            },
            Self::CheckpointLagging { .. } => BlockProductionPolicy {
                may_propose: false, // Would propose on stale state
                may_vote: false,    // Finality vote on wrong epoch
                may_gossip: true,   // Can still relay to catch up
            },
            Self::SplitBrainSuspected { .. } => BlockProductionPolicy {
                may_propose: false,
                may_vote: false,
                may_gossip: false, // Full halt until operator resolves
            },
        }
    }
}

/// Check validator's operational state based on live sentry count.
pub fn check_validator_state(
    live_sentry_count: usize,
    config: &ValidatorNetworkConfig,
) -> ValidatorOperationalState {
    if live_sentry_count == 0 {
        ValidatorOperationalState::Isolated
    } else if live_sentry_count < config.min_live_sentries {
        ValidatorOperationalState::Degraded {
            live_sentries: live_sentry_count,
            required: config.min_live_sentries,
        }
    } else {
        ValidatorOperationalState::Normal
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(b: u8) -> PeerId { PeerId([b; 32]) }

    #[test]
    fn test_validator_rejects_non_allowlisted_peer() {
        let config = ValidatorNetworkConfig {
            sentry_allowlist: vec![pid(1), pid(2)],
            ..Default::default()
        };
        let decision = evaluate_inbound(
            NetworkRole::Validator,
            &pid(3), // not in allowlist
            Some(&config),
            0,
            10,
        );
        assert_eq!(decision, AdmissionDecision::Reject(
            format!("peer {} not in validator allowlist", pid(3).short_hex())
        ));
    }

    #[test]
    fn test_validator_accepts_allowlisted_sentry() {
        let config = ValidatorNetworkConfig {
            sentry_allowlist: vec![pid(1)],
            ..Default::default()
        };
        let decision = evaluate_inbound(
            NetworkRole::Validator,
            &pid(1),
            Some(&config),
            0,
            10,
        );
        assert_eq!(decision, AdmissionDecision::Accept);
    }

    #[test]
    fn test_full_node_accepts_any_peer() {
        let decision = evaluate_inbound(
            NetworkRole::Full,
            &pid(99),
            None,
            0,
            48,
        );
        assert_eq!(decision, AdmissionDecision::Accept);
    }

    #[test]
    fn test_capacity_rejection() {
        let decision = evaluate_inbound(
            NetworkRole::Full,
            &pid(1),
            None,
            48, // at limit
            48,
        );
        assert!(matches!(decision, AdmissionDecision::Reject(_)));
    }

    #[test]
    fn test_validator_isolated_when_no_sentries() {
        let config = ValidatorNetworkConfig {
            min_live_sentries: 2,
            ..Default::default()
        };
        assert_eq!(
            check_validator_state(0, &config),
            ValidatorOperationalState::Isolated
        );
    }

    #[test]
    fn test_validator_degraded_below_minimum() {
        let config = ValidatorNetworkConfig {
            min_live_sentries: 3,
            ..Default::default()
        };
        assert!(matches!(
            check_validator_state(1, &config),
            ValidatorOperationalState::Degraded { .. }
        ));
    }

    #[test]
    fn test_validator_normal_above_minimum() {
        let config = ValidatorNetworkConfig {
            min_live_sentries: 2,
            ..Default::default()
        };
        assert_eq!(
            check_validator_state(3, &config),
            ValidatorOperationalState::Normal
        );
    }

    #[test]
    fn test_network_role_properties() {
        assert!(!NetworkRole::Validator.accepts_public_inbound());
        assert!(!NetworkRole::Validator.advertises_address());
        assert!(!NetworkRole::Validator.participates_in_gossip());
        assert!(NetworkRole::Validator.produces_blocks());

        assert!(NetworkRole::Sentry.accepts_public_inbound());
        assert!(NetworkRole::Sentry.advertises_address());
        assert!(!NetworkRole::Sentry.produces_blocks());

        assert!(NetworkRole::Bootstrap.accepts_public_inbound());
        assert!(!NetworkRole::Bootstrap.produces_blocks());
    }

    #[test]
    fn test_production_policy_normal() {
        let state = ValidatorOperationalState::Normal;
        let policy = state.production_policy();
        assert!(policy.may_propose);
        assert!(policy.may_vote);
        assert!(policy.may_gossip);
    }

    #[test]
    fn test_production_policy_degraded_no_propose() {
        let state = ValidatorOperationalState::Degraded { live_sentries: 1, required: 3 };
        let policy = state.production_policy();
        assert!(!policy.may_propose, "degraded validator must not propose");
        assert!(policy.may_vote, "degraded validator may still vote");
    }

    #[test]
    fn test_production_policy_isolated_full_halt() {
        let state = ValidatorOperationalState::Isolated;
        let policy = state.production_policy();
        assert!(!policy.may_propose);
        assert!(!policy.may_vote);
        assert!(!policy.may_gossip);
    }

    #[test]
    fn test_production_policy_split_brain_full_halt() {
        let state = ValidatorOperationalState::SplitBrainSuspected {
            evidence: "conflicting checkpoints".into(),
        };
        let policy = state.production_policy();
        assert!(!policy.may_propose);
        assert!(!policy.may_vote);
        assert!(!policy.may_gossip);
    }
}
