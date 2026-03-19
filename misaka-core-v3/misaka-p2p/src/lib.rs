pub mod handshake;
pub mod peer;
pub mod session;  // Improvement D+F: Hardened session + DoS protection

pub use handshake::{InitiatorHandshake, HandshakeResult};
pub use peer::PeerManager;
pub use session::{HandshakeTranscript, PeerBudget, OrphanPool};
