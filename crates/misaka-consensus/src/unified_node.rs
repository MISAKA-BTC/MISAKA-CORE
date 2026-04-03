//! Unified Node System — single node type, automatic role assignment.
//!
//! # Design Philosophy
//!
//! ```text
//! ┌──────────────────────────────────────────────────┐
//! │  User sees:                                       │
//! │    • Mode: VPS / LOCAL                            │
//! │    • Stake amount                                 │
//! │    • Status: Active / Contributing / Producer     │
//! │    • Estimated reward                             │
//! │                                                   │
//! │  Internally:                                      │
//! │    • RoleScore computed from runtime metrics      │
//! │    • vote_weight, relay_weight, verify_weight,    │
//! │      producer_weight assigned dynamically         │
//! │    • Roles are NOT exclusive — each node has      │
//! │      weighted participation in ALL roles          │
//! │    • Hysteresis prevents oscillation              │
//! └──────────────────────────────────────────────────┘
//! ```
//!
//! # vs BTC / Kaspa / XMR
//!
//! | Feature | BTC | Kaspa | XMR | MISAKA Unified |
//! |---------|-----|-------|-----|----------------|
//! | Node types | Full/SPV/Mining | Full/Mining | Full/Mining | ONE type |
//! | Home participation | Mining pool only | Mining pool only | Solo mining | Direct staking |
//! | Role assignment | Manual | Manual | Manual | Automatic |
//! | NAT traversal | N/A | N/A | N/A | Relay system |

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
//  User-Facing Types (the ONLY choices a user makes)
// ═══════════════════════════════════════════════════════════════

/// Connection mode — the ONLY infrastructure choice the user makes.
///
/// Everything else (role, weight, eligibility) is computed automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionMode {
    /// VPS or server with public IP, can accept inbound connections.
    /// Higher relay_weight and producer_weight potential.
    Vps,
    /// Home PC behind NAT, outbound-only connections via relay.
    /// Can still produce blocks if eligibility criteria are met.
    Local,
}

impl ConnectionMode {
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "vps" | "server" | "public" => Self::Vps,
            "local" | "home" | "nat" | "hidden" => Self::Local,
            _ => Self::Local, // Safe default
        }
    }

    /// Whether this mode can accept inbound P2P connections.
    pub fn accepts_inbound(&self) -> bool {
        matches!(self, Self::Vps)
    }

    /// Whether this mode should participate in peer discovery gossip.
    pub fn advertises_address(&self) -> bool {
        matches!(self, Self::Vps)
    }
}

impl std::fmt::Display for ConnectionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vps => write!(f, "VPS"),
            Self::Local => write!(f, "LOCAL"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  User-Facing Status (what the user sees)
// ═══════════════════════════════════════════════════════════════

/// User-facing node status — simplified view of internal state.
///
/// The user NEVER sees internal scores, weights, or role assignments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeStatus {
    /// Node is starting up, syncing, or connecting to relays.
    Syncing,
    /// Node is online and participating in the network.
    Active,
    /// Node is actively contributing (voting, relaying, verifying).
    Contributing,
    /// Node meets eligibility criteria for block production.
    ProducerEligible,
}

impl NodeStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Syncing => "Syncing",
            Self::Active => "Active",
            Self::Contributing => "Contributing",
            Self::ProducerEligible => "Producer Eligible",
        }
    }
}

impl std::fmt::Display for NodeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// User-facing node summary — everything the user dashboard shows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeDashboard {
    /// Connection mode (user's choice).
    pub mode: ConnectionMode,
    /// Current stake amount (base units).
    pub stake: u64,
    /// Simplified status.
    pub status: NodeStatus,
    /// Estimated reward per epoch (base units).
    pub estimated_reward_per_epoch: u64,
    /// Uptime percentage (0-100).
    pub uptime_percent: f64,
    /// Connected relay count (LOCAL mode only).
    pub relay_count: u32,
    /// Whether block production is currently active.
    pub producing_blocks: bool,
}

// ═══════════════════════════════════════════════════════════════
//  Internal Role Weights (NEVER exposed to user)
// ═══════════════════════════════════════════════════════════════

/// Dynamic role weights — computed per epoch from RoleScore.
///
/// A node participates in ALL roles simultaneously with these weights.
/// Weights are in BPS (0-10000 = 0%-100%).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RoleWeights {
    /// Weight for BFT voting participation.
    pub vote_weight: u32,
    /// Weight for message relay (TX, blocks, votes).
    pub relay_weight: u32,
    /// Weight for block/TX verification.
    pub verify_weight: u32,
    /// Weight for block production eligibility.
    pub producer_weight: u32,
}

impl Default for RoleWeights {
    fn default() -> Self {
        Self {
            vote_weight: 5000,    // 50% baseline
            relay_weight: 3000,   // 30% baseline
            verify_weight: 5000,  // 50% baseline
            producer_weight: 0,   // 0% until eligible
        }
    }
}

impl RoleWeights {
    /// Whether this node has any producer weight.
    pub fn is_producer_eligible(&self) -> bool {
        self.producer_weight > 0
    }

    /// Compute the user-facing status from weights.
    pub fn to_status(&self) -> NodeStatus {
        if self.is_producer_eligible() {
            NodeStatus::ProducerEligible
        } else if self.vote_weight > 0 || self.relay_weight > 0 || self.verify_weight > 0 {
            NodeStatus::Contributing
        } else {
            NodeStatus::Active
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Node Capability Metrics (measured at runtime)
// ═══════════════════════════════════════════════════════════════

/// Runtime-measured capabilities of this node.
///
/// These metrics are updated periodically and used to compute RoleScore.
/// They are NEVER self-reported to the network — only used locally
/// and verified through protocol behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapabilities {
    /// Whether the node is reachable from the internet (auto-detected).
    pub is_reachable: bool,
    /// Average round-trip latency to connected peers (ms).
    pub avg_latency_ms: u32,
    /// Uptime in the current epoch (BPS, 0-10000).
    pub uptime_bps: u32,
    /// Estimated CPU capacity (relative score, 0-10000).
    pub cpu_score: u32,
    /// Available RAM in MB.
    pub ram_mb: u32,
    /// Measured bandwidth (bytes/sec, inbound+outbound average).
    pub bandwidth_bps: u64,
    /// Historical success rate (BPS) — votes + proposals accepted / total.
    pub history_bps: u32,
    /// Number of connected relays (LOCAL mode).
    pub connected_relays: u32,
    /// Connection mode.
    pub mode: ConnectionMode,
}

impl Default for NodeCapabilities {
    fn default() -> Self {
        Self {
            is_reachable: false,
            avg_latency_ms: 1000,
            uptime_bps: 0,
            cpu_score: 5000,
            ram_mb: 4096,
            bandwidth_bps: 1_000_000,
            history_bps: 0,
            connected_relays: 0,
            mode: ConnectionMode::Local,
        }
    }
}

impl NodeCapabilities {
    /// Create capabilities for a VPS node with good defaults.
    pub fn vps_default() -> Self {
        Self {
            is_reachable: true,
            avg_latency_ms: 50,
            uptime_bps: 9500,
            cpu_score: 7000,
            ram_mb: 8192,
            bandwidth_bps: 100_000_000,
            history_bps: 5000,
            connected_relays: 0,
            mode: ConnectionMode::Vps,
        }
    }

    /// Create capabilities for a LOCAL node with typical home values.
    pub fn local_default() -> Self {
        Self {
            is_reachable: false,
            avg_latency_ms: 150,
            uptime_bps: 7000,
            cpu_score: 5000,
            ram_mb: 8192,
            bandwidth_bps: 10_000_000,
            history_bps: 0,
            connected_relays: 2,
            mode: ConnectionMode::Local,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Unified Node Config (replaces NodeMode + NodeRole)
// ═══════════════════════════════════════════════════════════════

/// Configuration for the unified node system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedNodeConfig {
    /// Connection mode (user's only infrastructure choice).
    pub mode: ConnectionMode,
    /// Stake amount (base units).
    pub stake: u64,
    /// Minimum relays for LOCAL mode.
    pub min_relays_local: u32,
    /// Epoch interval for role recalculation (seconds).
    pub role_recalc_interval_secs: u64,
    /// Hysteresis threshold — role weights must change by this much
    /// (BPS) before an update is applied.
    pub hysteresis_threshold_bps: u32,
}

impl Default for UnifiedNodeConfig {
    fn default() -> Self {
        Self {
            mode: ConnectionMode::Local,
            stake: 0,
            min_relays_local: 2,
            role_recalc_interval_secs: 1800, // 30 minutes
            hysteresis_threshold_bps: 500,    // 5% change threshold
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_mode_parse() {
        assert_eq!(ConnectionMode::from_str_loose("vps"), ConnectionMode::Vps);
        assert_eq!(ConnectionMode::from_str_loose("VPS"), ConnectionMode::Vps);
        assert_eq!(ConnectionMode::from_str_loose("local"), ConnectionMode::Local);
        assert_eq!(ConnectionMode::from_str_loose("home"), ConnectionMode::Local);
        assert_eq!(ConnectionMode::from_str_loose("unknown"), ConnectionMode::Local);
    }

    #[test]
    fn test_vps_accepts_inbound() {
        assert!(ConnectionMode::Vps.accepts_inbound());
        assert!(!ConnectionMode::Local.accepts_inbound());
    }

    #[test]
    fn test_role_weights_status() {
        let mut w = RoleWeights::default();
        assert_eq!(w.to_status(), NodeStatus::Contributing);
        w.producer_weight = 1000;
        assert_eq!(w.to_status(), NodeStatus::ProducerEligible);
    }

    #[test]
    fn test_default_producer_weight_zero() {
        let w = RoleWeights::default();
        assert!(!w.is_producer_eligible());
    }
}
