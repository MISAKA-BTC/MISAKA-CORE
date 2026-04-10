//! Weak subjectivity checkpoint verification (Phase 2b M9).
//!
//! Audit finding #2: new nodes joining the network must start from
//! a trusted checkpoint, not an attacker-controlled fork.
//!
//! The checkpoint is configured statically in mainnet.toml as:
//!   ws_checkpoint = "epoch:block_hash_hex"
//!
//! During sync, the node verifies that the block at the checkpoint
//! height has exactly the configured hash. If not, sync is aborted.
//!
//! See `docs/architecture.md` §10 Phase 2 deliverables.

use tracing::{error, info, warn};

/// Errors during weak subjectivity checkpoint verification.
#[derive(Debug, thiserror::Error)]
pub enum WsCheckpointError {
    #[error("checkpoint mismatch at height {height}: expected {expected}, got {actual}")]
    Mismatch {
        height: u64,
        expected: String,
        actual: String,
    },
    #[error("checkpoint height {height} not yet synced")]
    NotSynced { height: u64 },
    #[error("checkpoint hash is all-zero — refusing to verify")]
    AllZeroHash,
    #[error("invalid checkpoint format: {0}")]
    InvalidFormat(String),
}

/// Parsed weak subjectivity checkpoint.
pub struct WsCheckpoint {
    pub height: u64,
    pub hash: [u8; 32],
}

impl WsCheckpoint {
    /// Parse from "height:hex_hash" string format.
    ///
    /// Example: "0:abcdef0123456789..."
    pub fn parse(s: &str) -> Result<Self, WsCheckpointError> {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(WsCheckpointError::InvalidFormat(
                "expected format 'height:hex_hash'".into(),
            ));
        }
        let height: u64 = parts[0]
            .parse()
            .map_err(|e| WsCheckpointError::InvalidFormat(format!("invalid height: {}", e)))?;
        let hash_hex = parts[1];
        if hash_hex.len() != 64 {
            return Err(WsCheckpointError::InvalidFormat(format!(
                "hash must be 64 hex chars, got {}",
                hash_hex.len()
            )));
        }
        let hash_vec = hex::decode(hash_hex)
            .map_err(|e| WsCheckpointError::InvalidFormat(format!("invalid hex: {}", e)))?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_vec);
        Ok(Self { height, hash })
    }

    /// Verify a locally-synced block matches the configured checkpoint.
    ///
    /// Called during sync / restart, before the node begins producing
    /// or validating new blocks.
    pub fn verify(&self, local_hash_at_height: Option<[u8; 32]>) -> Result<(), WsCheckpointError> {
        // Defense in depth: all-zero checkpoint is never valid
        if self.hash == [0u8; 32] {
            return Err(WsCheckpointError::AllZeroHash);
        }

        match local_hash_at_height {
            None => Err(WsCheckpointError::NotSynced {
                height: self.height,
            }),
            Some(actual) if actual == self.hash => {
                info!(
                    "Weak subjectivity checkpoint verified: height={} hash={}",
                    self.height,
                    hex::encode(&self.hash[..8]),
                );
                Ok(())
            }
            Some(actual) => Err(WsCheckpointError::Mismatch {
                height: self.height,
                expected: hex::encode(&self.hash),
                actual: hex::encode(&actual),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_checkpoint() {
        let cp = WsCheckpoint::parse(&format!("100:{}", "ab".repeat(32))).unwrap();
        assert_eq!(cp.height, 100);
        assert_eq!(cp.hash, [0xAB; 32]);
    }

    #[test]
    fn parse_invalid_format() {
        assert!(WsCheckpoint::parse("no_colon").is_err());
        assert!(WsCheckpoint::parse("abc:0011").is_err()); // non-numeric height
        assert!(WsCheckpoint::parse("0:tooshort").is_err()); // short hash
    }

    #[test]
    fn all_zero_hash_rejected() {
        let cp = WsCheckpoint {
            height: 100,
            hash: [0u8; 32],
        };
        let result = cp.verify(Some([0u8; 32]));
        assert!(matches!(result, Err(WsCheckpointError::AllZeroHash)));
    }

    #[test]
    fn matching_hash_accepted() {
        let cp = WsCheckpoint {
            height: 100,
            hash: [0xAB; 32],
        };
        assert!(cp.verify(Some([0xAB; 32])).is_ok());
    }

    #[test]
    fn mismatch_rejected() {
        let cp = WsCheckpoint {
            height: 100,
            hash: [0xAB; 32],
        };
        let result = cp.verify(Some([0xCD; 32]));
        assert!(matches!(result, Err(WsCheckpointError::Mismatch { .. })));
    }

    #[test]
    fn not_synced_rejected() {
        let cp = WsCheckpoint {
            height: 100,
            hash: [0xAB; 32],
        };
        let result = cp.verify(None);
        assert!(matches!(result, Err(WsCheckpointError::NotSynced { .. })));
    }
}
