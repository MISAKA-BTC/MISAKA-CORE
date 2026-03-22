//! Peer management (Spec 14 §4).
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;

pub const MAX_INBOUND: usize = 48;
pub const MAX_OUTBOUND: usize = 16;
pub const MAX_DISCOVERY_RESPONSE_PEERS: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAdvertisementCandidate {
    pub advertise_addr: Option<String>,
    pub node_name: String,
    pub mode: PeerModeLabel,
    pub advertisable: bool,
}

impl PeerAdvertisementCandidate {
    pub fn new(
        advertise_addr: Option<String>,
        node_name: String,
        mode: PeerModeLabel,
        advertisable: bool,
    ) -> Self {
        Self {
            advertise_addr,
            node_name,
            mode,
            advertisable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerModeLabel {
    Public,
    Hidden,
    Seed,
    Validator,
    Unknown,
}

impl PeerModeLabel {
    pub fn parse(mode: &str) -> Self {
        match mode.to_ascii_lowercase().as_str() {
            "public" => Self::Public,
            "hidden" => Self::Hidden,
            "seed" => Self::Seed,
            "validator" => Self::Validator,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Hidden => "hidden",
            Self::Seed => "seed",
            Self::Validator => "validator",
            Self::Unknown => "unknown",
        }
    }

    pub fn is_advertisable(&self) -> bool {
        matches!(self, Self::Public | Self::Seed | Self::Validator)
    }

    pub fn serves_peer_discovery(&self) -> bool {
        matches!(self, Self::Public | Self::Seed | Self::Validator)
    }

    pub fn counts_as_active_validator_surface(&self) -> bool {
        matches!(self, Self::Public | Self::Validator)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerDiscoveryEntry {
    pub address: String,
    pub node_name: String,
    pub mode: PeerModeLabel,
    pub advertisable: bool,
    #[serde(rename = "servesPeerDiscovery")]
    pub serves_peer_discovery: bool,
}

impl PeerDiscoveryEntry {
    pub fn from_legacy_tuple(address: String, node_name: String) -> Self {
        Self {
            address,
            node_name,
            mode: PeerModeLabel::Unknown,
            advertisable: true,
            serves_peer_discovery: false,
        }
    }

    pub fn from_parts(address: String, node_name: String, mode: PeerModeLabel) -> Self {
        Self {
            address,
            node_name,
            mode,
            advertisable: mode.is_advertisable(),
            serves_peer_discovery: mode.serves_peer_discovery(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDiscoveryValidationSummary {
    pub accepted: Vec<PeerDiscoveryEntry>,
    pub rejected: usize,
    pub truncated: usize,
}

pub fn sanitize_peer_discovery_entries<F>(
    entries: &[PeerDiscoveryEntry],
    mut address_ok: F,
) -> PeerDiscoveryValidationSummary
where
    F: FnMut(&str) -> bool,
{
    let truncated = entries.len().saturating_sub(MAX_DISCOVERY_RESPONSE_PEERS);
    let bounded = &entries[..entries.len().min(MAX_DISCOVERY_RESPONSE_PEERS)];

    let mut accepted = Vec::with_capacity(bounded.len());
    let mut rejected = 0usize;

    for entry in bounded {
        if address_ok(&entry.address) {
            accepted.push(entry.clone());
        } else {
            rejected += 1;
        }
    }

    PeerDiscoveryValidationSummary {
        accepted,
        rejected,
        truncated,
    }
}

pub fn build_peer_discovery_response(
    candidates: &[PeerAdvertisementCandidate],
) -> Vec<PeerDiscoveryEntry> {
    candidates
        .iter()
        .filter(|candidate| candidate.advertisable)
        .filter_map(|candidate| {
            candidate.advertise_addr.as_ref().map(|address| {
                PeerDiscoveryEntry::from_parts(
                    address.clone(),
                    candidate.node_name.clone(),
                    candidate.mode,
                )
            })
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub inbound: bool,
    pub connected_at_ms: u64,
}

pub struct PeerManager {
    peers: HashMap<SocketAddr, PeerInfo>,
}

impl PeerManager {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    pub fn add_peer(&mut self, info: PeerInfo) -> Result<(), &'static str> {
        let (inbound_count, outbound_count) = self.counts();
        if info.inbound && inbound_count >= MAX_INBOUND {
            return Err("inbound peer limit reached");
        }
        if !info.inbound && outbound_count >= MAX_OUTBOUND {
            return Err("outbound peer limit reached");
        }
        self.peers.insert(info.addr, info);
        Ok(())
    }

    pub fn remove_peer(&mut self, addr: &SocketAddr) {
        self.peers.remove(addr);
    }

    pub fn counts(&self) -> (usize, usize) {
        let inb = self.peers.values().filter(|p| p.inbound).count();
        (inb, self.peers.len() - inb)
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_peer_limits() {
        let mut pm = PeerManager::new();
        for i in 0..MAX_INBOUND {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8)), 6690);
            pm.add_peer(PeerInfo {
                addr,
                inbound: true,
                connected_at_ms: 0,
            })
            .unwrap();
        }
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 0)), 6690);
        assert!(pm
            .add_peer(PeerInfo {
                addr,
                inbound: true,
                connected_at_ms: 0
            })
            .is_err());
    }

    #[test]
    fn test_peer_mode_label_parse_and_flags() {
        let hidden = PeerModeLabel::parse("hidden");
        assert_eq!(hidden, PeerModeLabel::Hidden);
        assert!(!hidden.is_advertisable());
        assert!(!hidden.serves_peer_discovery());

        let public = PeerModeLabel::parse("public");
        assert!(public.is_advertisable());
        assert!(public.serves_peer_discovery());
        assert!(public.counts_as_active_validator_surface());

        let validator = PeerModeLabel::parse("validator");
        assert_eq!(validator.as_str(), "validator");
        assert!(validator.counts_as_active_validator_surface());
    }

    #[test]
    fn test_peer_discovery_entry_from_parts() {
        let entry = PeerDiscoveryEntry::from_parts(
            "203.0.113.10:6690".into(),
            "seed-1".into(),
            PeerModeLabel::Seed,
        );
        assert_eq!(entry.address, "203.0.113.10:6690");
        assert_eq!(entry.node_name, "seed-1");
        assert_eq!(entry.mode, PeerModeLabel::Seed);
        assert!(entry.advertisable);
        assert!(entry.serves_peer_discovery);
    }

    #[test]
    fn test_peer_discovery_entry_from_legacy_tuple() {
        let entry = PeerDiscoveryEntry::from_legacy_tuple(
            "203.0.113.11:6690".into(),
            "legacy".into(),
        );
        assert_eq!(entry.mode, PeerModeLabel::Unknown);
        assert!(entry.advertisable);
        assert!(!entry.serves_peer_discovery);
    }

    #[test]
    fn test_sanitize_peer_discovery_entries() {
        let entries = vec![
            PeerDiscoveryEntry::from_parts(
                "203.0.113.10:6690".into(),
                "seed-1".into(),
                PeerModeLabel::Seed,
            ),
            PeerDiscoveryEntry::from_parts(
                "not-an-addr".into(),
                "bad".into(),
                PeerModeLabel::Public,
            ),
        ];

        let summary = sanitize_peer_discovery_entries(&entries, |addr| addr.contains(':'));
        assert_eq!(summary.accepted.len(), 1);
        assert_eq!(summary.rejected, 1);
        assert_eq!(summary.truncated, 0);
        assert_eq!(summary.accepted[0].node_name, "seed-1");
    }

    #[test]
    fn test_build_peer_discovery_response_filters_non_advertisable_entries() {
        let candidates = vec![
            PeerAdvertisementCandidate::new(
                Some("203.0.113.10:6690".into()),
                "seed-1".into(),
                PeerModeLabel::Seed,
                true,
            ),
            PeerAdvertisementCandidate::new(
                None,
                "hidden-1".into(),
                PeerModeLabel::Hidden,
                false,
            ),
        ];

        let peers = build_peer_discovery_response(&candidates);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].node_name, "seed-1");
        assert_eq!(peers[0].address, "203.0.113.10:6690");
    }

    #[test]
    fn test_build_peer_discovery_response_drops_missing_addresses() {
        let candidates = vec![PeerAdvertisementCandidate::new(
            None,
            "public-1".into(),
            PeerModeLabel::Public,
            true,
        )];

        let peers = build_peer_discovery_response(&candidates);
        assert!(peers.is_empty());
    }
}
