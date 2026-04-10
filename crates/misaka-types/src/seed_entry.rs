//! Seed node entry with PK pinning (Phase 2a).
//!
//! Replaces the legacy `Vec<String>` seed list with a type that
//! requires a transport public key for every seed node. This makes
//! TOFU on seed connections structurally impossible — the PK must
//! be known at config-load time.
//!
//! See `docs/architecture.md` §7.3 for seed independence requirements.

use serde::{Deserialize, Serialize};

/// A seed node entry with mandatory ML-DSA-65 transport public key.
///
/// # Example (TOML)
///
/// ```toml
/// [[seeds]]
/// address = "163.43.225.27:6690"
/// transport_pubkey = "0x<3904 hex chars>"
/// ```
///
/// # Security
///
/// Without a pinned PK, the first connection to a seed is vulnerable
/// to MITM attacks. By requiring the PK at config time, we eliminate
/// TOFU from the bootstrap path entirely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedEntry {
    /// Network address of the seed node (host:port).
    pub address: String,
    /// ML-DSA-65 transport public key (hex-encoded, 0x-prefixed, 3904 hex chars = 1952 bytes).
    pub transport_pubkey: String,
}

impl SeedEntry {
    /// Validate the seed entry.
    ///
    /// Returns an error message if the entry is malformed.
    pub fn validate(&self) -> Result<(), String> {
        if self.address.is_empty() {
            return Err("seed address is empty".into());
        }

        // Must contain host:port
        if !self.address.contains(':') {
            return Err(format!(
                "seed address '{}' must be in host:port format",
                self.address,
            ));
        }

        // PK must be present and correct length
        let pk_hex = self.transport_pubkey.strip_prefix("0x")
            .unwrap_or(&self.transport_pubkey);

        if pk_hex.len() != 3904 {
            return Err(format!(
                "transport_pubkey must be 3904 hex chars (1952 bytes ML-DSA-65 PK), got {}",
                pk_hex.len(),
            ));
        }

        // Must be valid hex
        if hex::decode(pk_hex).is_err() {
            return Err("transport_pubkey contains invalid hex characters".into());
        }

        Ok(())
    }

    /// Decode the transport public key bytes (1952 bytes).
    ///
    /// Returns `None` if the hex is malformed.
    pub fn transport_pubkey_bytes(&self) -> Option<Vec<u8>> {
        let pk_hex = self.transport_pubkey.strip_prefix("0x")
            .unwrap_or(&self.transport_pubkey);
        hex::decode(pk_hex).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_seed_entry() {
        let pk_hex = format!("0x{}", "AA".repeat(1952));
        let entry = SeedEntry {
            address: "163.43.225.27:6690".into(),
            transport_pubkey: pk_hex,
        };
        assert!(entry.validate().is_ok());
        assert_eq!(entry.transport_pubkey_bytes().unwrap().len(), 1952);
    }

    #[test]
    fn reject_empty_address() {
        let entry = SeedEntry {
            address: "".into(),
            transport_pubkey: format!("0x{}", "BB".repeat(1952)),
        };
        assert!(entry.validate().is_err());
    }

    #[test]
    fn reject_missing_port() {
        let entry = SeedEntry {
            address: "163.43.225.27".into(),
            transport_pubkey: format!("0x{}", "CC".repeat(1952)),
        };
        assert!(entry.validate().unwrap_err().contains("host:port"));
    }

    #[test]
    fn reject_wrong_pk_length() {
        let entry = SeedEntry {
            address: "1.2.3.4:6690".into(),
            transport_pubkey: "0xAABBCC".into(),
        };
        assert!(entry.validate().unwrap_err().contains("3904 hex chars"));
    }
}
