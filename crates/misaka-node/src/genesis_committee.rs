// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Genesis committee manifest — loads real validator PK from TOML.
//!
//! Replaces the placeholder `vec![i as u8; 1952]` pattern that was
//! used during development. Production nodes MUST use a genesis manifest
//! with real ML-DSA-65 public keys.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

use misaka_dag::narwhal_types::block::AuthorityIndex;
use misaka_dag::narwhal_types::committee::{Authority, Committee};

/// ML-DSA-65 public key length.
const PK_LEN: usize = 1952;

/// Genesis manifest error.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parse error: {0}")]
    Parse(String),
    #[error("duplicate authority_index: {0}")]
    DuplicateIndex(u32),
    #[error("duplicate public_key for authority {0}")]
    DuplicateKey(u32),
    #[error("authority {0} public_key wrong length: {1} bytes, expected {2}")]
    WrongKeyLength(u32, usize, usize),
    #[error("authority {0} has zero stake")]
    ZeroStake(u32),
    #[error("authority_index gap: expected {expected}, got {got}")]
    IndexGap { expected: u32, got: u32 },
    #[error("empty committee")]
    EmptyCommittee,
    #[error("validator not in genesis: authority_index={0}")]
    ValidatorNotInGenesis(u32),
}

/// A single validator entry in the genesis manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisValidator {
    pub authority_index: u32,
    pub public_key: String, // hex-encoded, 0x-prefixed
    pub stake: u64,
    pub network_address: String,
    #[serde(default)]
    pub solana_stake_account: Option<String>,
}

/// Top-level manifest structure.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisManifestToml {
    pub committee: GenesisCommitteeSection,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisCommitteeSection {
    pub epoch: u64,
    pub validators: Vec<GenesisValidator>,
}

/// Loaded and validated genesis committee manifest.
pub struct GenesisCommitteeManifest {
    pub epoch: u64,
    pub validators: Vec<GenesisValidator>,
}

impl GenesisCommitteeManifest {
    /// Load from a TOML file.
    pub fn load(path: &Path) -> Result<Self, ManifestError> {
        let contents = std::fs::read_to_string(path)?;
        let parsed: GenesisManifestToml = toml::from_str(&contents)
            .map_err(|e: toml::de::Error| ManifestError::Parse(e.to_string()))?;
        Ok(Self {
            epoch: parsed.committee.epoch,
            validators: parsed.committee.validators,
        })
    }

    /// Validate the manifest.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.validators.is_empty() {
            return Err(ManifestError::EmptyCommittee);
        }

        let mut seen_indices = HashSet::new();
        let mut seen_pks = HashSet::new();

        for (i, v) in self.validators.iter().enumerate() {
            // Contiguous indices
            if v.authority_index != i as u32 {
                return Err(ManifestError::IndexGap {
                    expected: i as u32,
                    got: v.authority_index,
                });
            }
            // No duplicate index
            if !seen_indices.insert(v.authority_index) {
                return Err(ManifestError::DuplicateIndex(v.authority_index));
            }
            // PK length
            let pk_bytes = Self::decode_pk(&v.public_key).map_err(|_| {
                ManifestError::WrongKeyLength(v.authority_index, v.public_key.len() / 2, PK_LEN)
            })?;
            if pk_bytes.len() != PK_LEN {
                return Err(ManifestError::WrongKeyLength(
                    v.authority_index,
                    pk_bytes.len(),
                    PK_LEN,
                ));
            }
            // No duplicate PK
            if !seen_pks.insert(v.public_key.clone()) {
                return Err(ManifestError::DuplicateKey(v.authority_index));
            }
            // Non-zero stake
            if v.stake == 0 {
                return Err(ManifestError::ZeroStake(v.authority_index));
            }
        }
        Ok(())
    }

    /// Convert to a `Committee` for the DAG consensus layer.
    pub fn to_committee(&self) -> Result<Committee, ManifestError> {
        let authorities: Vec<Authority> = self
            .validators
            .iter()
            .map(|v| {
                let pk = Self::decode_pk(&v.public_key)
                    .map_err(|_| ManifestError::WrongKeyLength(v.authority_index, 0, PK_LEN))?;
                Ok(Authority {
                    hostname: v.network_address.clone(),
                    stake: v.stake,
                    public_key: pk,
                })
            })
            .collect::<Result<Vec<_>, ManifestError>>()?;
        Ok(Committee::new(self.epoch, authorities))
    }

    /// Check if a validator with the given index and PK is in the manifest.
    #[must_use]
    pub fn contains(&self, authority_index: AuthorityIndex, pk: &[u8]) -> bool {
        self.validators.iter().any(|v| {
            v.authority_index == authority_index
                && Self::decode_pk(&v.public_key)
                    .map(|decoded| decoded == pk)
                    .unwrap_or(false)
        })
    }

    fn decode_pk(hex_str: &str) -> Result<Vec<u8>, ()> {
        let trimmed = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        hex::decode(trimmed).map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest(n: usize) -> GenesisCommitteeManifest {
        let validators: Vec<GenesisValidator> = (0..n)
            .map(|i| {
                let pk = vec![0xAA; PK_LEN];
                let mut pk_varied = pk.clone();
                pk_varied[0] = i as u8; // make each PK unique
                GenesisValidator {
                    authority_index: i as u32,
                    public_key: format!("0x{}", hex::encode(&pk_varied)),
                    stake: 1000,
                    network_address: format!("validator-{}.test:16111", i),
                    solana_stake_account: None,
                }
            })
            .collect();
        GenesisCommitteeManifest {
            epoch: 0,
            validators,
        }
    }

    #[test]
    fn test_valid_manifest() {
        let m = sample_manifest(4);
        assert!(m.validate().is_ok());
    }

    #[test]
    fn test_empty_committee_rejected() {
        let m = GenesisCommitteeManifest {
            epoch: 0,
            validators: vec![],
        };
        assert!(matches!(m.validate(), Err(ManifestError::EmptyCommittee)));
    }

    #[test]
    fn test_zero_stake_rejected() {
        let mut m = sample_manifest(4);
        m.validators[2].stake = 0;
        assert!(matches!(m.validate(), Err(ManifestError::ZeroStake(2))));
    }

    #[test]
    fn test_duplicate_index_rejected() {
        let mut m = sample_manifest(4);
        m.validators[2].authority_index = 1; // duplicate
        assert!(m.validate().is_err());
    }

    #[test]
    fn test_wrong_pk_length_rejected() {
        let mut m = sample_manifest(4);
        m.validators[1].public_key = "0xAABBCC".to_string(); // too short
        assert!(m.validate().is_err());
    }

    #[test]
    fn test_to_committee() {
        let m = sample_manifest(4);
        let committee = m.to_committee().unwrap();
        assert_eq!(committee.size(), 4);
    }

    #[test]
    fn test_contains() {
        let m = sample_manifest(4);
        let mut pk = vec![0xAA; PK_LEN];
        pk[0] = 0; // authority 0's PK
        assert!(m.contains(0, &pk));
        pk[0] = 99; // not in manifest
        assert!(!m.contains(0, &pk));
    }

    #[test]
    fn test_load_from_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("genesis_committee.toml");

        let pk0 = hex::encode(vec![0x00u8; PK_LEN]);
        let pk1 = hex::encode(vec![0x01u8; PK_LEN]);

        let toml_content = format!(
            r#"
[committee]
epoch = 0

[[committee.validators]]
authority_index = 0
public_key = "0x{pk0}"
stake = 1000
network_address = "v0.test:16111"

[[committee.validators]]
authority_index = 1
public_key = "0x{pk1}"
stake = 1000
network_address = "v1.test:16111"
"#
        );
        std::fs::write(&path, toml_content).unwrap();

        let m = GenesisCommitteeManifest::load(&path).unwrap();
        assert!(m.validate().is_ok());
        assert_eq!(m.validators.len(), 2);
    }
}
