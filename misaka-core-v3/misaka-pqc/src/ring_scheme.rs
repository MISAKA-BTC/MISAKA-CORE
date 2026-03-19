//! Membership Proof Scheme Version.
//!
//! Only `UnifiedZkpV1` (0x10) is supported.
//! All legacy schemes (LRS, ChipmunkRing, LogRing) have been removed.

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum MembershipSchemeVersion {
    /// Unified ZKP — position-hiding membership + nullifier + key ownership.
    UnifiedZkpV1 = 0x10,
}

impl MembershipSchemeVersion {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x10 => Some(Self::UnifiedZkpV1),
            _ => None,
        }
    }
}

impl std::fmt::Display for MembershipSchemeVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::UnifiedZkpV1 => write!(f, "UnifiedZkp-v1") }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_zkp_recognized() {
        assert_eq!(MembershipSchemeVersion::from_u8(0x10), Some(MembershipSchemeVersion::UnifiedZkpV1));
    }

    #[test]
    fn test_legacy_schemes_rejected() {
        assert_eq!(MembershipSchemeVersion::from_u8(0x01), None); // LRS — removed
        assert_eq!(MembershipSchemeVersion::from_u8(0x02), None); // Chipmunk — removed
        assert_eq!(MembershipSchemeVersion::from_u8(0x03), None); // LogRing — removed
        assert_eq!(MembershipSchemeVersion::from_u8(0xFF), None);
    }
}
