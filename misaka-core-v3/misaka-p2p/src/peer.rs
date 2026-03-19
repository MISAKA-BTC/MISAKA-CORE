//! Peer management (Spec 14 §4).
use std::collections::HashMap;
use std::net::SocketAddr;

pub const MAX_INBOUND: usize = 48;
pub const MAX_OUTBOUND: usize = 16;

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
    pub fn new() -> Self { Self { peers: HashMap::new() } }

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

    pub fn remove_peer(&mut self, addr: &SocketAddr) { self.peers.remove(addr); }

    pub fn counts(&self) -> (usize, usize) {
        let inb = self.peers.values().filter(|p| p.inbound).count();
        (inb, self.peers.len() - inb)
    }

    pub fn len(&self) -> usize { self.peers.len() }
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
            pm.add_peer(PeerInfo { addr, inbound: true, connected_at_ms: 0 }).unwrap();
        }
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 0)), 6690);
        assert!(pm.add_peer(PeerInfo { addr, inbound: true, connected_at_ms: 0 }).is_err());
    }
}
