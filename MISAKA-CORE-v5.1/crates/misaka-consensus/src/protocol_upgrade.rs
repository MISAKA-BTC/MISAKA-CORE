//! Protocol Upgrade — Feature Activation Heights & Version Negotiation.
//!
//! # Design
//!
//! MISAKA uses a **height-based feature activation** model (similar to Bitcoin BIPs):
//!
//! 1. Features are defined with an activation height
//! 2. At that height, the feature becomes mandatory for block validation
//! 3. Nodes running older versions that don't support the feature will
//!    reject blocks at/after the activation height → natural fork-off
//!
//! # Hard Fork vs Soft Fork
//!
//! All protocol upgrades in MISAKA are **hard forks** (tightening OR loosening rules).
//! Soft forks (tightening-only) are not used because:
//! - PQ crypto parameter changes (e.g., ring size, ZKP scheme) require both
//! - The validator set is small enough for coordinated upgrades
//!
//! # Upgrade Procedure
//!
//! 1. Feature is added to `FEATURE_ACTIVATIONS` with a future height
//! 2. New node version is released with support for the feature
//! 3. Operators upgrade before activation height
//! 4. At activation height, feature becomes mandatory
//! 5. Nodes that haven't upgraded will stall (cannot validate new blocks)

use serde::{Deserialize, Serialize};

/// Current node protocol version.
///
/// Bumped on each consensus-breaking change.
/// Used in P2P handshake to detect incompatible peers.
pub const NODE_PROTOCOL_VERSION: u32 = 4;

/// Minimum protocol version that this node will accept from peers.
///
/// Peers below this version are disconnected immediately after handshake.
pub const MIN_COMPATIBLE_VERSION: u32 = 4;

/// Human-readable version string for logging/RPC.
pub const NODE_VERSION_STRING: &str = "MISAKA/v0.5.0";

// ═══════════════════════════════════════════════════════════════
//  Feature Activation
// ═══════════════════════════════════════════════════════════════

/// A consensus feature that activates at a specific block height.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureActivation {
    /// Unique feature identifier (e.g., "dag-consensus", "composite-proof").
    pub name: &'static str,
    /// Block height at which this feature becomes mandatory.
    /// `0` = active from genesis.
    /// `u64::MAX` = not yet scheduled (development only).
    pub activation_height: u64,
    /// Protocol version that introduced this feature.
    pub introduced_in: u32,
    /// Short description for RPC/logging.
    pub description: &'static str,
}

/// Master list of all protocol features and their activation heights.
///
/// # Adding a New Feature
///
/// 1. Add a new entry here with `activation_height: u64::MAX` (dev-only)
/// 2. Implement the feature, gated by `is_feature_active("feature-name", height)`
/// 3. Test on testnet
/// 4. Set `activation_height` to the agreed-upon mainnet height
/// 5. Release new node version
pub const FEATURE_ACTIVATIONS: &[FeatureActivation] = &[
    FeatureActivation {
        name: "pq-ring-signatures",
        activation_height: 0, // Active from genesis
        introduced_in: 1,
        description: "Post-quantum ring signatures (LRS/LogRing) for transaction privacy",
    },
    FeatureActivation {
        name: "ki-proof-required",
        activation_height: 0,
        introduced_in: 1,
        description: "Key image proofs mandatory for all ring signature inputs",
    },
    FeatureActivation {
        name: "dag-consensus",
        activation_height: 0, // Active from genesis in DAG builds
        introduced_in: 2,
        description: "GhostDAG BlockDAG consensus with multi-parent blocks",
    },
    FeatureActivation {
        name: "economic-finality",
        activation_height: 0,
        introduced_in: 3,
        description: "BFT 2/3 checkpoint finality with ML-DSA-65 validator attestations",
    },
    FeatureActivation {
        name: "composite-proof",
        activation_height: 0,
        introduced_in: 4,
        description: "Lattice-based CompositeProof (BDLOP balance + range) replaces STARK stub",
    },
    FeatureActivation {
        name: "encrypted-keystore",
        activation_height: 0,
        introduced_in: 4,
        description: "ChaCha20-Poly1305 encrypted validator key storage",
    },
    FeatureActivation {
        name: "on-chain-staking",
        activation_height: u64::MAX, // Not yet scheduled
        introduced_in: 5,
        description: "Permissionless validator staking via StakeDeposit/StakeWithdraw TxTypes",
    },
    FeatureActivation {
        name: "slashing",
        activation_height: u64::MAX,
        introduced_in: 5,
        description: "Equivocation/downtime slashing with on-chain evidence submission",
    },
    FeatureActivation {
        name: "qdag-ct",
        activation_height: u64::MAX,
        introduced_in: 5,
        description: "Q-DAG-CT confidential transactions with UnifiedMembershipProof",
    },
];

/// Check whether a feature is active at a given block height.
pub fn is_feature_active(name: &str, height: u64) -> bool {
    FEATURE_ACTIVATIONS
        .iter()
        .any(|f| f.name == name && height >= f.activation_height)
}

/// Get all features active at a given height.
pub fn active_features_at(height: u64) -> Vec<&'static FeatureActivation> {
    FEATURE_ACTIVATIONS
        .iter()
        .filter(|f| height >= f.activation_height)
        .collect()
}

/// Get all features scheduled for future activation.
pub fn pending_features() -> Vec<&'static FeatureActivation> {
    FEATURE_ACTIVATIONS
        .iter()
        .filter(|f| f.activation_height == u64::MAX)
        .collect()
}

// ═══════════════════════════════════════════════════════════════
//  P2P Version Negotiation
// ═══════════════════════════════════════════════════════════════

/// Result of version negotiation during P2P handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionCompatibility {
    /// Fully compatible — proceed with connection.
    Compatible,
    /// Peer is too old — disconnect.
    PeerTooOld {
        our_version: u32,
        peer_version: u32,
        min_required: u32,
    },
    /// We are too old — disconnect and warn operator to upgrade.
    WeTooOld {
        our_version: u32,
        peer_version: u32,
        peer_min_required: u32,
    },
}

/// Check version compatibility with a remote peer.
///
/// Called during P2P handshake after receiving the peer's version info.
pub fn check_version_compatibility(
    peer_version: u32,
    peer_min_compatible: u32,
) -> VersionCompatibility {
    if peer_version < MIN_COMPATIBLE_VERSION {
        return VersionCompatibility::PeerTooOld {
            our_version: NODE_PROTOCOL_VERSION,
            peer_version,
            min_required: MIN_COMPATIBLE_VERSION,
        };
    }
    if NODE_PROTOCOL_VERSION < peer_min_compatible {
        return VersionCompatibility::WeTooOld {
            our_version: NODE_PROTOCOL_VERSION,
            peer_version,
            peer_min_required: peer_min_compatible,
        };
    }
    VersionCompatibility::Compatible
}

/// Format feature activation schedule for RPC response.
pub fn feature_schedule_json() -> Vec<serde_json::Value> {
    FEATURE_ACTIVATIONS
        .iter()
        .map(|f| {
            serde_json::json!({
                "name": f.name,
                "activationHeight": if f.activation_height == u64::MAX {
                    "not_scheduled".to_string()
                } else {
                    f.activation_height.to_string()
                },
                "introducedIn": f.introduced_in,
                "description": f.description,
                "active": f.activation_height != u64::MAX,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_features_active() {
        assert!(is_feature_active("pq-ring-signatures", 0));
        assert!(is_feature_active("ki-proof-required", 0));
        assert!(is_feature_active("dag-consensus", 0));
        assert!(is_feature_active("composite-proof", 0));
    }

    #[test]
    fn test_pending_features() {
        assert!(!is_feature_active("on-chain-staking", 0));
        assert!(!is_feature_active("on-chain-staking", 1_000_000));
        assert!(!is_feature_active("slashing", 0));
        assert!(!is_feature_active("qdag-ct", 0));
    }

    #[test]
    fn test_unknown_feature() {
        assert!(!is_feature_active("nonexistent-feature", 0));
    }

    #[test]
    fn test_active_features_at_genesis() {
        let active = active_features_at(0);
        assert!(active.len() >= 4); // pq-ring, ki-proof, dag, economic-finality
    }

    #[test]
    fn test_pending_list() {
        let pending = pending_features();
        assert!(pending.iter().any(|f| f.name == "on-chain-staking"));
        assert!(pending.iter().any(|f| f.name == "slashing"));
    }

    #[test]
    fn test_version_compatible() {
        assert_eq!(
            check_version_compatibility(4, 4),
            VersionCompatibility::Compatible
        );
        assert_eq!(
            check_version_compatibility(5, 3),
            VersionCompatibility::Compatible
        );
    }

    #[test]
    fn test_peer_too_old() {
        match check_version_compatibility(2, 1) {
            VersionCompatibility::PeerTooOld { peer_version, .. } => {
                assert_eq!(peer_version, 2);
            }
            _ => panic!("expected PeerTooOld"),
        }
    }

    #[test]
    fn test_we_too_old() {
        match check_version_compatibility(10, 8) {
            VersionCompatibility::WeTooOld { peer_min_required, .. } => {
                assert_eq!(peer_min_required, 8);
            }
            _ => panic!("expected WeTooOld"),
        }
    }

    #[test]
    fn test_feature_schedule_json() {
        let schedule = feature_schedule_json();
        assert!(!schedule.is_empty());
        let first = &schedule[0];
        assert!(first.get("name").is_some());
        assert!(first.get("activationHeight").is_some());
    }
}
