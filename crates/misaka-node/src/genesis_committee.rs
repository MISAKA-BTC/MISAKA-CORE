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
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use misaka_consensus::staking::StakingRegistry;
use misaka_crypto::validator_sig::ValidatorPqPublicKey;
use misaka_dag::narwhal_types::block::AuthorityIndex;
use misaka_dag::narwhal_types::committee::{Authority, Committee};
use misaka_types::validator::{ValidatorIdentity, ValidatorPublicKey};

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
    #[error("authority {0} network_address is invalid: {1}")]
    InvalidNetworkAddress(u32, String),
    #[error("authority {0} public_key is not a valid ML-DSA-65 key: {1}")]
    InvalidPublicKey(u32, String),
    #[error("duplicate network_address: {0}")]
    DuplicateNetworkAddress(String),
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
    /// Option C (v0.9.0-dev): optional pointer to an `initial_utxos.json`
    /// file. When present, and when the node boots with no existing
    /// `chain.db`, the UTXO set is pre-seeded from this file. Written
    /// by `misaka-cli migrate-utxo-snapshot` when migrating from v0.8.8.
    #[serde(default)]
    pub initial_utxos: Option<InitialUtxosSection>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisCommitteeSection {
    pub epoch: u64,
    pub validators: Vec<GenesisValidator>,
}

/// `[initial_utxos]` section of `genesis_committee.toml`.
///
/// Only `source` is required — it is the path (absolute, or relative
/// to the genesis TOML's directory) to a JSON file with the shape
/// produced by `misaka-cli migrate-utxo-snapshot`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitialUtxosSection {
    pub source: String,
}

/// A single seed UTXO as parsed from `initial_utxos.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitialUtxoEntry {
    pub address: String,
    pub amount: u64,
    #[serde(default)]
    pub spending_pubkey: Option<String>,
    #[serde(default)]
    pub label: String,
}

/// Wrapper for `initial_utxos.json` — mirrors
/// `misaka-cli::migrate_snapshot::InitialUtxoFile`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitialUtxoFile {
    pub schema_version: u32,
    #[serde(default)]
    pub source_height: u64,
    #[serde(default)]
    pub source_snapshot: String,
    #[serde(default)]
    pub total_amount: u64,
    pub utxos: Vec<InitialUtxoEntry>,
}

/// Current schema version that the node accepts. Bumped when the
/// on-disk shape changes incompatibly.
pub const INITIAL_UTXO_SCHEMA_VERSION: u32 = 1;

/// Validated seed UTXO passed to the bootstrap seeder.
///
/// Unlike the wire struct (`InitialUtxoEntry`), this carries pre-decoded
/// byte arrays so the seed function does not re-run hex parsing.
#[derive(Clone, Debug)]
pub struct SeedUtxo {
    pub address: [u8; 32],
    pub amount: u64,
    pub spending_pubkey: Option<Vec<u8>>,
    pub label: String,
}

/// Synthetic `tx_hash` for a seeded UTXO.
///
/// The seeded UTXO has no backing transaction — we make up a canonical
/// `OutputRef` from the genesis epoch + label + address so downstream
/// storage invariants (uniqueness of OutputRef) hold. All nodes that
/// load the same `initial_utxos.json` derive the same `tx_hash` bit-for-bit.
pub fn synthetic_seed_tx_hash(epoch: u64, label: &str, address: &[u8; 32]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:genesis_seed_utxo:v1:");
    h.update(epoch.to_le_bytes());
    h.update((label.len() as u32).to_le_bytes());
    h.update(label.as_bytes());
    h.update(address);
    h.finalize().into()
}

/// A dynamically registered validator (from `/api/register_validator`).
///
/// 0.9.0: retained for the on-disk migration format only — reading
/// `registered_validators.json` from pre-0.9.0 nodes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisteredValidator {
    pub public_key: String,
    pub network_address: String,
}

/// 0.9.0 β-2 wire format for `POST /api/register_validator`.
///
/// Backwards compatible with the 0.8.8 body shape (`public_key` +
/// `network_address`). All new fields are `#[serde(default)]` so existing
/// clients (Python scripts, bash curl snippets, 0.8.8 CLI) continue to work
/// without modification.
///
/// - `solana_stake_signature` / `solana_staking_program`: used by β-3 to spawn
///   the Solana RPC verification task. When present, the node calls
///   `getTransaction` asynchronously and flips `solana_stake_verified` on
///   success.
/// - `intent_signature`: ML-DSA-65 signature over
///   `sha3_256("MISAKA:rest_register:v1:" || pubkey || network_address)`.
///   Proves the pubkey owner approved THIS registration for THIS endpoint.
///   Optional for backwards compat; when provided the node verifies it and
///   echoes `intent_verified: true` in the response.
#[derive(Clone, Debug, Deserialize)]
pub struct RegisterValidatorRequest {
    pub public_key: String,
    pub network_address: String,
    #[serde(default)]
    pub solana_stake_signature: Option<String>,
    #[serde(default)]
    pub solana_staking_program: Option<String>,
    #[serde(default)]
    pub intent_signature: Option<String>,
}

impl RegisterValidatorRequest {
    /// Canonical signing payload for the `intent_signature` field.
    ///
    /// The domain tag `"MISAKA:rest_register:v1:"` is 24 bytes of ASCII and
    /// binds the signature to *this* REST endpoint (so a sig valid on
    /// `/api/register_validator` cannot be replayed against any other route).
    /// The pubkey and network_address commit to the specific validator
    /// identity and endpoint being registered.
    pub fn signing_payload(pubkey_bytes: &[u8], network_address: &str) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:rest_register:v1:");
        h.update(pubkey_bytes);
        h.update(network_address.as_bytes());
        h.finalize().into()
    }
}

/// Loaded and validated genesis committee manifest.
pub struct GenesisCommitteeManifest {
    pub epoch: u64,
    pub validators: Vec<GenesisValidator>,
    /// Option C: path (as written in the TOML) to the initial_utxos JSON
    /// file, resolved relative to the manifest's parent directory. `None`
    /// means "no initial UTXO allocation from genesis", which is the
    /// backwards-compatible default.
    pub initial_utxos_source: Option<PathBuf>,
}

impl GenesisCommitteeManifest {
    /// Load from a TOML file.
    pub fn load(path: &Path) -> Result<Self, ManifestError> {
        let contents = std::fs::read_to_string(path)?;
        let parsed: GenesisManifestToml = toml::from_str(&contents)
            .map_err(|e: toml::de::Error| ManifestError::Parse(e.to_string()))?;
        let initial_utxos_source = parsed.initial_utxos.as_ref().map(|s| {
            let src = Path::new(&s.source);
            if src.is_absolute() {
                src.to_path_buf()
            } else {
                path.parent().unwrap_or(Path::new(".")).join(src)
            }
        });
        Ok(Self {
            epoch: parsed.committee.epoch,
            validators: parsed.committee.validators,
            initial_utxos_source,
        })
    }

    /// Option C: load and validate the `initial_utxos.json` referenced
    /// by this manifest, if any. Returns `None` when the manifest does
    /// not have an `[initial_utxos]` section.
    ///
    /// Validation:
    /// - `schema_version == INITIAL_UTXO_SCHEMA_VERSION`
    /// - every `address` decodes to exactly 32 bytes
    /// - every `spending_pubkey` (when present) decodes to 1952 bytes
    /// - sum of `amount` equals the declared `total_amount` (catches
    ///   truncation)
    pub fn load_initial_utxos(&self) -> Result<Option<Vec<SeedUtxo>>, ManifestError> {
        let Some(source) = &self.initial_utxos_source else {
            return Ok(None);
        };
        let contents = std::fs::read_to_string(source).map_err(|e| {
            ManifestError::Parse(format!(
                "failed to read initial_utxos source {}: {}",
                source.display(),
                e
            ))
        })?;
        let parsed: InitialUtxoFile = serde_json::from_str(&contents).map_err(|e| {
            ManifestError::Parse(format!(
                "failed to parse initial_utxos JSON {}: {}",
                source.display(),
                e
            ))
        })?;
        if parsed.schema_version != INITIAL_UTXO_SCHEMA_VERSION {
            return Err(ManifestError::Parse(format!(
                "initial_utxos schema_version {} not supported (expected {})",
                parsed.schema_version, INITIAL_UTXO_SCHEMA_VERSION
            )));
        }

        let mut out = Vec::with_capacity(parsed.utxos.len());
        let mut sum: u64 = 0;
        for (i, u) in parsed.utxos.iter().enumerate() {
            let addr_bytes = hex::decode(&u.address).map_err(|e| {
                ManifestError::Parse(format!("utxo[{i}] address decode: {e}"))
            })?;
            if addr_bytes.len() != 32 {
                return Err(ManifestError::Parse(format!(
                    "utxo[{i}] address length {} (expected 32)",
                    addr_bytes.len()
                )));
            }
            let mut address = [0u8; 32];
            address.copy_from_slice(&addr_bytes);

            let spending_pubkey = match &u.spending_pubkey {
                Some(hex_str) => {
                    let pk = hex::decode(hex_str).map_err(|e| {
                        ManifestError::Parse(format!("utxo[{i}] pubkey decode: {e}"))
                    })?;
                    if pk.len() != 1952 {
                        return Err(ManifestError::Parse(format!(
                            "utxo[{i}] spending_pubkey length {} (expected 1952)",
                            pk.len()
                        )));
                    }
                    Some(pk)
                }
                None => None,
            };
            sum = sum.checked_add(u.amount).ok_or_else(|| {
                ManifestError::Parse(format!("utxo[{i}] amount overflow at sum"))
            })?;
            out.push(SeedUtxo {
                address,
                amount: u.amount,
                spending_pubkey,
                label: u.label.clone(),
            });
        }
        if parsed.total_amount != 0 && parsed.total_amount != sum {
            return Err(ManifestError::Parse(format!(
                "initial_utxos total_amount {} != sum {} (file may be truncated)",
                parsed.total_amount, sum
            )));
        }
        Ok(Some(out))
    }

    /// Load genesis + merge any dynamically registered validators from
    /// `registered_validators.json` in the same directory.
    pub fn load_with_registered(path: &Path) -> Result<Self, ManifestError> {
        let mut manifest = Self::load(path)?;
        let reg_path = path
            .parent()
            .unwrap_or(Path::new("."))
            .join("registered_validators.json");
        if reg_path.exists() {
            if let Ok(data) = std::fs::read_to_string(&reg_path) {
                if let Ok(registered) =
                    serde_json::from_str::<Vec<RegisteredValidator>>(&data)
                {
                    let existing_pks: HashSet<String> = manifest
                        .validators
                        .iter()
                        .map(|v| v.public_key.clone())
                        .collect();
                    let existing_addrs: HashSet<String> = manifest
                        .validators
                        .iter()
                        .map(|v| v.network_address.clone())
                        .collect();
                    let genesis_count = manifest.validators.len();
                    let mut next_index = genesis_count as u32;
                    let mut seen_addrs = existing_addrs;
                    for rv in registered {
                        if existing_pks.contains(&rv.public_key) {
                            continue;
                        }
                        if !seen_addrs.insert(rv.network_address.clone()) {
                            tracing::warn!(
                                "Skipping registered validator with duplicate \
                                 network_address: {}",
                                rv.network_address,
                            );
                            continue;
                        }
                        manifest.validators.push(GenesisValidator {
                            authority_index: next_index,
                            public_key: rv.public_key,
                            stake: 1000,
                            network_address: rv.network_address,
                            solana_stake_account: None,
                        });
                        next_index += 1;
                    }
                    let added = manifest.validators.len() - genesis_count;
                    if added > 0 {
                        tracing::info!(
                            "Merged {} registered validators (total committee size: {})",
                            added,
                            manifest.validators.len(),
                        );
                    }
                }
            }
        }
        Ok(manifest)
    }

    /// Validate the manifest.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.validators.is_empty() {
            return Err(ManifestError::EmptyCommittee);
        }

        let mut seen_indices = HashSet::new();
        let mut seen_pks = HashSet::new();
        let mut seen_addresses = HashSet::new();

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
            let addr = v.network_address.parse::<SocketAddr>().map_err(|_| {
                ManifestError::InvalidNetworkAddress(v.authority_index, v.network_address.clone())
            })?;
            if !seen_addresses.insert(addr) {
                return Err(ManifestError::DuplicateNetworkAddress(
                    v.network_address.clone(),
                ));
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

    /// Find a validator's authority_index by matching their public key.
    /// Returns `None` if the pubkey is not in the genesis committee.
    #[must_use]
    pub fn find_by_pubkey(&self, pk: &[u8]) -> Option<u32> {
        self.validators.iter().find_map(|v| {
            Self::decode_pk(&v.public_key)
                .ok()
                .filter(|decoded| decoded == pk)
                .map(|_| v.authority_index)
        })
    }

    /// Build bootstrap validator identities from the genesis committee.
    ///
    /// On non-mainnet chains, Phase C uses the genesis committee as the first
    /// committee source of truth before stake reconciliation and epoch-based
    /// SR21 rotation take over. We therefore normalize the bootstrap weights to
    /// at least the chain's SR floor while preserving manifest ordering.
    pub fn bootstrap_validator_identities(
        &self,
        chain_id: u32,
    ) -> Result<Vec<ValidatorIdentity>, ManifestError> {
        let effective_floor = crate::sr21_election::effective_min_sr_stake(chain_id);
        let validator_count = self.validators.len() as u128;

        self.validators
            .iter()
            .map(|validator| {
                let pk_bytes = Self::decode_pk(&validator.public_key).map_err(|_| {
                    ManifestError::WrongKeyLength(validator.authority_index, 0, PK_LEN)
                })?;
                let pq_pk = ValidatorPqPublicKey::from_bytes(&pk_bytes).map_err(|err| {
                    ManifestError::InvalidPublicKey(validator.authority_index, err.to_string())
                })?;
                let public_key = ValidatorPublicKey::from_bytes(&pk_bytes).map_err(|err| {
                    ManifestError::InvalidPublicKey(validator.authority_index, err.to_string())
                })?;
                let authority_bonus =
                    validator_count.saturating_sub(u128::from(validator.authority_index));
                let bootstrap_stake_weight = if chain_id == 1 {
                    u128::from(validator.stake).max(1)
                } else {
                    effective_floor
                        .saturating_add(u128::from(validator.stake))
                        .saturating_add(authority_bonus)
                };

                Ok(ValidatorIdentity {
                    validator_id: pq_pk.to_canonical_id(),
                    stake_weight: bootstrap_stake_weight,
                    public_key,
                    is_active: true,
                })
            })
            .collect()
    }

    fn decode_pk(hex_str: &str) -> Result<Vec<u8>, ()> {
        let trimmed = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        hex::decode(trimmed).map_err(|_| ())
    }
}

/// v0.9.0: Build the DAG `Committee` from two sources of truth.
///
/// 1. The genesis manifest TOML — the bootstrap validator set that is fixed at
///    chain launch.
/// 2. Any additional validators that have become `ACTIVE` in the
///    [`StakingRegistry`] since launch (registered via REST in β or via L1
///    `ValidatorStakeTx` in γ).
///
/// Genesis validators keep their manifest-assigned `authority_index` values.
/// Dynamic registry validators are appended with fresh indices starting at
/// `genesis.validators.len()`, sorted by their 32-byte canonical `validator_id`
/// (the SHA3 of the ML-DSA-65 pubkey) so that every node builds the same
/// ordering without depending on `HashMap` iteration.
///
/// `public_key` and `network_address` must be unique across both sources —
/// this mirrors [`GenesisCommitteeManifest::validate`]. Duplicates from the
/// registry side are logged and skipped rather than returned as errors, so
/// that a mis-registered validator cannot brick the committee build.
pub fn build_committee_from_sources(
    genesis: &GenesisCommitteeManifest,
    registry: &StakingRegistry,
) -> Result<Committee, ManifestError> {
    let mut authorities: Vec<Authority> = Vec::with_capacity(genesis.validators.len());
    let mut seen_pks: HashSet<Vec<u8>> = HashSet::new();
    let mut seen_addrs: HashSet<String> = HashSet::new();

    // Pass 1: genesis TOML
    for v in &genesis.validators {
        let pk = GenesisCommitteeManifest::decode_pk(&v.public_key)
            .map_err(|_| ManifestError::WrongKeyLength(v.authority_index, 0, PK_LEN))?;
        if pk.len() != PK_LEN {
            return Err(ManifestError::WrongKeyLength(
                v.authority_index,
                pk.len(),
                PK_LEN,
            ));
        }
        if !seen_pks.insert(pk.clone()) {
            return Err(ManifestError::DuplicateKey(v.authority_index));
        }
        if !seen_addrs.insert(v.network_address.clone()) {
            return Err(ManifestError::DuplicateNetworkAddress(
                v.network_address.clone(),
            ));
        }
        authorities.push(Authority {
            hostname: v.network_address.clone(),
            stake: v.stake,
            public_key: pk,
        });
    }

    // Pass 2: registry ACTIVE validators (with L1 or Solana verification + address)
    let dynamic: Vec<&misaka_consensus::staking::ValidatorAccount> = registry.active_authorities();
    for v in dynamic {
        let addr = match v.network_address.as_ref() {
            Some(a) => a.clone(),
            None => {
                tracing::warn!(
                    "committee build: skip validator {} (no network_address)",
                    hex::encode(v.validator_id)
                );
                continue;
            }
        };
        if seen_pks.contains(&v.pubkey) {
            tracing::warn!(
                "committee build: skip validator {} (pubkey already in genesis)",
                hex::encode(v.validator_id)
            );
            continue;
        }
        if !seen_addrs.insert(addr.clone()) {
            tracing::warn!(
                "committee build: skip validator {} (duplicate network_address {})",
                hex::encode(v.validator_id),
                addr
            );
            continue;
        }
        seen_pks.insert(v.pubkey.clone());
        authorities.push(Authority {
            hostname: addr,
            stake: v.stake_amount,
            public_key: v.pubkey.clone(),
        });
    }

    Ok(Committee::new(genesis.epoch, authorities))
}

/// PR-A (SR21 reform): like [`build_committee_from_sources`] but applies the
/// SR21 top-21 stake-ranked cap.
///
/// Pipeline:
/// 1. Gather ALL candidates from genesis TOML + registry `active_authorities()`,
///    deduplicating by public key and network address (same rules as
///    `build_committee_from_sources`).
/// 2. Project each candidate to `ValidatorIdentity`
///    (`validator_id = SHA3-256(pk)`, `stake_weight = stake as u128`),
///    keeping a side-table `validator_id → Authority` so we can rebuild the
///    committee after the election.
/// 3. Run `sr21_election::run_election_for_chain(identities, chain_id, epoch)`
///    — this enforces `effective_min_sr_stake(chain_id)` and takes the top
///    `MAX_SR_COUNT` (=21) by stake, with `validator_id` ascending as the
///    tie-break.
/// 4. Rebuild the committee in election order (highest stake first, stable
///    by validator_id). The resulting BFT invariants are checked inside
///    `Committee::new()`.
///
/// # Fallback behavior
///
/// If the election drops every candidate (e.g., 0 validators meet the chain
/// min stake floor), fall back to the unfiltered `build_committee_from_sources`
/// result. `Committee::new()` panics on an empty authority list, and collapsing
/// the committee at an epoch boundary would halt block production; preserving
/// the pre-filter set is the safer liveness-preserving choice. Logs a
/// `tracing::warn!` so operators notice.
///
/// # Wire-format note
///
/// The on-chain committee set can shrink at an epoch boundary (e.g., 30
/// ACTIVE → 21 elected). This is wire-visible to anyone tracking
/// `committee_shared` via `/api/status`. REST clients have no stable
/// ordering guarantee — clients that cared about order were informed before
/// this PR (per Q3 in the design review).
pub fn build_sr21_committee(
    genesis: &GenesisCommitteeManifest,
    registry: &StakingRegistry,
    chain_id: u32,
    epoch: u64,
) -> Result<Committee, ManifestError> {
    use std::collections::HashMap;

    // Step 1: gather + deduplicate all candidate authorities. This mirrors
    // `build_committee_from_sources` so we can swap call sites safely.
    let mut authorities: Vec<Authority> = Vec::with_capacity(genesis.validators.len());
    let mut seen_pks: HashSet<Vec<u8>> = HashSet::new();
    let mut seen_addrs: HashSet<String> = HashSet::new();

    // 1a: genesis TOML entries — same validation as build_committee_from_sources.
    for v in &genesis.validators {
        let pk = GenesisCommitteeManifest::decode_pk(&v.public_key)
            .map_err(|_| ManifestError::WrongKeyLength(v.authority_index, 0, PK_LEN))?;
        if pk.len() != PK_LEN {
            return Err(ManifestError::WrongKeyLength(
                v.authority_index,
                pk.len(),
                PK_LEN,
            ));
        }
        if !seen_pks.insert(pk.clone()) {
            return Err(ManifestError::DuplicateKey(v.authority_index));
        }
        if !seen_addrs.insert(v.network_address.clone()) {
            return Err(ManifestError::DuplicateNetworkAddress(
                v.network_address.clone(),
            ));
        }
        authorities.push(Authority {
            hostname: v.network_address.clone(),
            stake: v.stake,
            public_key: pk,
        });
    }

    // 1b: registry dynamic entries — same skip rules as
    // build_committee_from_sources (log + continue on conflict).
    let dynamic: Vec<&misaka_consensus::staking::ValidatorAccount> = registry.active_authorities();
    for v in dynamic {
        let addr = match v.network_address.as_ref() {
            Some(a) => a.clone(),
            None => {
                tracing::warn!(
                    "SR21 committee build: skip validator {} (no network_address)",
                    hex::encode(v.validator_id)
                );
                continue;
            }
        };
        if seen_pks.contains(&v.pubkey) {
            tracing::warn!(
                "SR21 committee build: skip validator {} (pubkey already in genesis)",
                hex::encode(v.validator_id)
            );
            continue;
        }
        if !seen_addrs.insert(addr.clone()) {
            tracing::warn!(
                "SR21 committee build: skip validator {} (duplicate network_address {})",
                hex::encode(v.validator_id),
                addr
            );
            continue;
        }
        seen_pks.insert(v.pubkey.clone());
        authorities.push(Authority {
            hostname: addr,
            stake: v.stake_amount,
            public_key: v.pubkey.clone(),
        });
    }

    // Step 2: project into ValidatorIdentity for the election, keeping a
    // lookup from `validator_id` back to the full Authority tuple.
    //
    // `validator_id = SHA3-256(pk)` is the canonical id used everywhere
    // else in the system (ValidatorPqPublicKey::to_canonical_id).
    let mut identities: Vec<ValidatorIdentity> = Vec::with_capacity(authorities.len());
    let mut by_id: HashMap<[u8; 32], Authority> = HashMap::with_capacity(authorities.len());
    for auth in &authorities {
        let pq = match ValidatorPqPublicKey::from_bytes(&auth.public_key) {
            Ok(pq) => pq,
            Err(e) => {
                tracing::warn!(
                    "SR21 committee build: skip invalid pubkey (hostname={}): {}",
                    auth.hostname, e
                );
                continue;
            }
        };
        let validator_id = pq.to_canonical_id();
        identities.push(ValidatorIdentity {
            validator_id,
            stake_weight: auth.stake as u128,
            public_key: ValidatorPublicKey {
                bytes: auth.public_key.clone(),
            },
            is_active: true,
        });
        by_id.insert(validator_id, auth.clone());
    }

    // Step 3: run SR21 election. `run_election_for_chain` uses the chain's
    // effective min stake floor (mainnet=10M, testnet=1M) and caps at
    // MAX_SR_COUNT (=21).
    let election =
        crate::sr21_election::run_election_for_chain(&identities, chain_id, epoch);

    // Fallback: if every candidate failed the min-stake floor, keep the
    // pre-filter committee. An empty Committee::new panics on BFT
    // invariants and halts block production. Genesis validators with
    // sub-floor stake trigger this on testnet bring-up; matches the
    // existing "fail open at epoch boundary" policy from Phase 8.
    if election.active_srs.is_empty() {
        tracing::warn!(
            "SR21 committee build: election returned 0 SRs at epoch {} \
             (all candidates below min stake floor {}?) — falling back to \
             unfiltered merged committee to preserve liveness.",
            epoch,
            crate::sr21_election::effective_min_sr_stake(chain_id),
        );
        return Ok(Committee::new(genesis.epoch, authorities));
    }

    // Step 4: rebuild the committee in election order.
    let mut elected_authorities: Vec<Authority> =
        Vec::with_capacity(election.active_srs.len());
    for sr in &election.active_srs {
        match by_id.get(&sr.validator_id) {
            Some(auth) => elected_authorities.push(auth.clone()),
            None => {
                // Should never happen — we populated by_id from the same
                // identities we fed to the election. Defensive log + skip.
                tracing::error!(
                    "SR21 committee build: elected validator_id {} not in \
                     side-table; internal invariant violated",
                    hex::encode(sr.validator_id)
                );
            }
        }
    }

    Ok(Committee::new(genesis.epoch, elected_authorities))
}

/// v0.9.0: One-shot migration for `registered_validators.json`.
///
/// Prior versions persisted the dynamic validator set next to the genesis TOML
/// in a JSON file. 0.9.0 consolidates everything into the
/// [`StakingRegistry`] snapshot. This function reads the old JSON (if any),
/// registers each entry in the registry with the chain's current
/// `min_validator_stake` as the floor, and renames the JSON file so it is not
/// re-processed on the next boot.
///
/// Semantics:
/// - If the file does not exist: no-op, returns `Ok(())`.
/// - If the file exists but is malformed: log a `warn!`, leave the file in
///   place, return `Ok(())` — we never fail-closed on migration so that an
///   operator with a broken JSON can still start the node.
/// - If the file exists and can be parsed: register every entry that is not
///   already in the registry, then rename the file to
///   `<original>.migrated.bak`.
///
/// `stake_tx_hash` matches the derivation used by
/// `validator_api::handle_register` (`sha3("MISAKA:stake_lock:" || pk || epoch_le)`)
/// so migrated records look identical to records produced by the REST path.
///
/// Migrated validators enter `LOCKED` with neither verification flag set and
/// no `network_address` populated. They are therefore not emitted by
/// `StakingRegistry::active_authorities()` until an operator re-registers via
/// `/api/register_validator` (β-2) with a Solana signature OR submits an L1
/// `ValidatorStakeTx::Register` (γ-3).
pub fn migrate_registered_validators_if_present(
    genesis_path: &Path,
    registry: &mut StakingRegistry,
    current_epoch: u64,
) -> Result<(), ManifestError> {
    let reg_path: PathBuf = genesis_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("registered_validators.json");
    if !reg_path.exists() {
        return Ok(());
    }

    let data = match std::fs::read_to_string(&reg_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                "migration: could not read {}: {}; leaving file in place",
                reg_path.display(),
                e,
            );
            return Ok(());
        }
    };

    let registered: Vec<RegisteredValidator> = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "migration: could not parse {}: {}; leaving file in place",
                reg_path.display(),
                e,
            );
            return Ok(());
        }
    };

    if registered.is_empty() {
        // Nothing to move; still rename so we don't poll it each boot.
        let bak = reg_path.with_extension("json.migrated.bak");
        if let Err(e) = std::fs::rename(&reg_path, &bak) {
            tracing::warn!(
                "migration: empty file rename failed ({} -> {}): {}",
                reg_path.display(),
                bak.display(),
                e,
            );
        } else {
            tracing::info!(
                "migration: empty {} archived as {}",
                reg_path.display(),
                bak.display(),
            );
        }
        return Ok(());
    }

    let min_stake = registry.config().min_validator_stake;
    let mut migrated = 0usize;
    let mut skipped = 0usize;

    for rv in &registered {
        let pk_hex = rv.public_key.strip_prefix("0x").unwrap_or(&rv.public_key);
        let pk_bytes = match hex::decode(pk_hex) {
            Ok(b) if b.len() == PK_LEN => b,
            Ok(b) => {
                tracing::warn!(
                    "migration: skip {} — pubkey is {} bytes (want {})",
                    rv.network_address,
                    b.len(),
                    PK_LEN,
                );
                skipped += 1;
                continue;
            }
            Err(e) => {
                tracing::warn!(
                    "migration: skip {} — pubkey hex decode failed: {}",
                    rv.network_address,
                    e,
                );
                skipped += 1;
                continue;
            }
        };

        let pq_pk = match ValidatorPqPublicKey::from_bytes(&pk_bytes) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    "migration: skip {} — not a valid ML-DSA-65 key: {}",
                    rv.network_address,
                    e,
                );
                skipped += 1;
                continue;
            }
        };
        let validator_id = pq_pk.to_canonical_id();

        if registry.get(&validator_id).is_some() {
            skipped += 1;
            continue;
        }

        let stake_tx_hash = {
            use sha3::{Digest, Sha3_256};
            let mut h = Sha3_256::new();
            h.update(b"MISAKA:stake_lock:");
            h.update(&pk_bytes);
            h.update(current_epoch.to_le_bytes());
            let r: [u8; 32] = h.finalize().into();
            r
        };

        // Reward address is not known at migration time (the legacy JSON did
        // not carry one). Use zero; operator must re-register to set it.
        let reward_address = [0u8; 32];

        if let Err(e) = registry.register(
            validator_id,
            pk_bytes,
            min_stake,
            500, // 5% default commission (mirrors main.rs bootstrap)
            reward_address,
            current_epoch,
            stake_tx_hash,
            0,
            false, // solana_stake_verified — unverified at migration time
            None,
            false, // l1_stake_verified — migration does not touch the L1 path
        ) {
            tracing::warn!(
                "migration: register failed for {}: {}",
                rv.network_address,
                e,
            );
            skipped += 1;
            continue;
        }

        if let Err(e) =
            registry.set_network_address(&validator_id, Some(rv.network_address.clone()))
        {
            tracing::warn!(
                "migration: set_network_address failed for {}: {}",
                rv.network_address,
                e,
            );
            // not fatal — validator is already registered
        }

        migrated += 1;
    }

    let bak_path = reg_path.with_extension("json.migrated.bak");
    match std::fs::rename(&reg_path, &bak_path) {
        Ok(()) => {
            tracing::info!(
                "migration: {} → StakingRegistry complete (migrated={}, skipped={}); \
                 backup at {}. Operators must re-register via /api/register_validator \
                 with solana_stake_signature to activate these validators.",
                reg_path.display(),
                migrated,
                skipped,
                bak_path.display(),
            );
        }
        Err(e) => {
            tracing::warn!(
                "migration: migrated {} validators but rename {} -> {} failed: {}; \
                 file left in place (next boot will re-process, which is idempotent)",
                migrated,
                reg_path.display(),
                bak_path.display(),
                e,
            );
        }
    }
    Ok(())
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
                    network_address: format!("127.0.0.{}:16111", i + 1),
                    solana_stake_account: None,
                }
            })
            .collect();
        GenesisCommitteeManifest {
            epoch: 0,
            validators,
            initial_utxos_source: None,
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
            initial_utxos_source: None,
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
    fn test_invalid_network_address_rejected() {
        let mut m = sample_manifest(4);
        m.validators[1].network_address = "not-an-addr".to_string();
        assert!(matches!(
            m.validate(),
            Err(ManifestError::InvalidNetworkAddress(1, _))
        ));
    }

    #[test]
    fn test_duplicate_network_address_rejected() {
        let mut m = sample_manifest(4);
        m.validators[2].network_address = m.validators[1].network_address.clone();
        assert!(matches!(
            m.validate(),
            Err(ManifestError::DuplicateNetworkAddress(_))
        ));
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
network_address = "127.0.0.1:16111"

[[committee.validators]]
authority_index = 1
public_key = "0x{pk1}"
stake = 1000
network_address = "127.0.0.2:16111"
"#
        );
        std::fs::write(&path, toml_content).unwrap();

        let m = GenesisCommitteeManifest::load(&path).unwrap();
        assert!(m.validate().is_ok());
        assert_eq!(m.validators.len(), 2);
    }

    #[test]
    fn test_bootstrap_validator_identities_preserve_manifest_order_and_floor() {
        let manifest = sample_manifest(3);
        let identities = manifest.bootstrap_validator_identities(2).unwrap();
        let floor = crate::sr21_election::effective_min_sr_stake(2);

        assert_eq!(identities.len(), 3);
        assert_eq!(identities[0].stake_weight, floor + 1000 + 3);
        assert_eq!(identities[1].stake_weight, floor + 1000 + 2);
        assert_eq!(identities[2].stake_weight, floor + 1000 + 1);
        assert_ne!(identities[0].validator_id, identities[1].validator_id);
    }

    // ── Validator registration tests ──

    #[test]
    fn test_registered_validator_serialization() {
        let rv = RegisteredValidator {
            public_key: format!("0x{}", hex::encode(vec![0xBB; PK_LEN])),
            network_address: "10.0.0.1:16110".to_string(),
        };
        let json = serde_json::to_string(&rv).unwrap();
        let parsed: RegisteredValidator = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.public_key, rv.public_key);
        assert_eq!(parsed.network_address, rv.network_address);
    }

    #[test]
    fn test_load_with_registered_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("genesis_committee.toml");

        let pk0 = hex::encode(vec![0x00u8; PK_LEN]);
        let toml_content = format!(
            r#"
[committee]
epoch = 0

[[committee.validators]]
authority_index = 0
public_key = "0x{pk0}"
stake = 1000
network_address = "127.0.0.1:16111"
"#
        );
        std::fs::write(&path, toml_content).unwrap();

        let m = GenesisCommitteeManifest::load_with_registered(&path).unwrap();
        assert_eq!(m.validators.len(), 1);
    }

    #[test]
    fn test_load_with_registered_merges_new_validators() {
        let dir = tempfile::tempdir().unwrap();
        let genesis_path = dir.path().join("genesis_committee.toml");
        let reg_path = dir.path().join("registered_validators.json");

        let pk0 = hex::encode(vec![0x00u8; PK_LEN]);
        let toml_content = format!(
            r#"
[committee]
epoch = 0

[[committee.validators]]
authority_index = 0
public_key = "0x{pk0}"
stake = 1000
network_address = "127.0.0.1:16111"
"#
        );
        std::fs::write(&genesis_path, toml_content).unwrap();

        let mut pk1 = vec![0xAA; PK_LEN];
        pk1[0] = 0x11;
        let mut pk2 = vec![0xAA; PK_LEN];
        pk2[0] = 0x22;
        let registered = vec![
            RegisteredValidator {
                public_key: format!("0x{}", hex::encode(&pk1)),
                network_address: "10.0.0.1:16110".to_string(),
            },
            RegisteredValidator {
                public_key: format!("0x{}", hex::encode(&pk2)),
                network_address: "10.0.0.2:16110".to_string(),
            },
        ];
        std::fs::write(&reg_path, serde_json::to_string(&registered).unwrap()).unwrap();

        let m = GenesisCommitteeManifest::load_with_registered(&genesis_path).unwrap();
        assert_eq!(m.validators.len(), 3);
        assert_eq!(m.validators[0].authority_index, 0);
        assert_eq!(m.validators[1].authority_index, 1);
        assert_eq!(m.validators[2].authority_index, 2);
        assert_eq!(m.validators[1].network_address, "10.0.0.1:16110");
        assert_eq!(m.validators[2].network_address, "10.0.0.2:16110");
        assert_eq!(m.validators[1].stake, 1000);
    }

    #[test]
    fn test_load_with_registered_skips_duplicate_pk() {
        let dir = tempfile::tempdir().unwrap();
        let genesis_path = dir.path().join("genesis_committee.toml");
        let reg_path = dir.path().join("registered_validators.json");

        let pk0 = hex::encode(vec![0x00u8; PK_LEN]);
        let toml_content = format!(
            r#"
[committee]
epoch = 0

[[committee.validators]]
authority_index = 0
public_key = "0x{pk0}"
stake = 1000
network_address = "127.0.0.1:16111"
"#
        );
        std::fs::write(&genesis_path, toml_content).unwrap();

        let registered = vec![RegisteredValidator {
            public_key: format!("0x{pk0}"),
            network_address: "10.0.0.99:16110".to_string(),
        }];
        std::fs::write(&reg_path, serde_json::to_string(&registered).unwrap()).unwrap();

        let m = GenesisCommitteeManifest::load_with_registered(&genesis_path).unwrap();
        assert_eq!(m.validators.len(), 1, "duplicate PK should not be added");
    }

    #[test]
    fn test_load_with_registered_validates_successfully() {
        let dir = tempfile::tempdir().unwrap();
        let genesis_path = dir.path().join("genesis_committee.toml");
        let reg_path = dir.path().join("registered_validators.json");

        let pk0 = hex::encode(vec![0x00u8; PK_LEN]);
        let toml_content = format!(
            r#"
[committee]
epoch = 0

[[committee.validators]]
authority_index = 0
public_key = "0x{pk0}"
stake = 1000
network_address = "127.0.0.1:16111"
"#
        );
        std::fs::write(&genesis_path, toml_content).unwrap();

        let mut pk1 = vec![0xAA; PK_LEN];
        pk1[0] = 0x33;
        let registered = vec![RegisteredValidator {
            public_key: format!("0x{}", hex::encode(&pk1)),
            network_address: "10.0.0.5:16110".to_string(),
        }];
        std::fs::write(&reg_path, serde_json::to_string(&registered).unwrap()).unwrap();

        let m = GenesisCommitteeManifest::load_with_registered(&genesis_path).unwrap();
        assert_eq!(m.validators.len(), 2);
        assert!(m.validate().is_ok(), "merged manifest should pass validation");
        let committee = m.to_committee().unwrap();
        assert_eq!(committee.size(), 2);
    }

    #[test]
    fn test_load_with_registered_ignores_corrupt_json() {
        let dir = tempfile::tempdir().unwrap();
        let genesis_path = dir.path().join("genesis_committee.toml");
        let reg_path = dir.path().join("registered_validators.json");

        let pk0 = hex::encode(vec![0x00u8; PK_LEN]);
        let toml_content = format!(
            r#"
[committee]
epoch = 0

[[committee.validators]]
authority_index = 0
public_key = "0x{pk0}"
stake = 1000
network_address = "127.0.0.1:16111"
"#
        );
        std::fs::write(&genesis_path, toml_content).unwrap();
        std::fs::write(&reg_path, "not valid json!!!").unwrap();

        let m = GenesisCommitteeManifest::load_with_registered(&genesis_path).unwrap();
        assert_eq!(m.validators.len(), 1, "corrupt JSON should be ignored");
    }

    #[test]
    fn test_load_with_registered_skips_duplicate_network_address() {
        let dir = tempfile::tempdir().unwrap();
        let genesis_path = dir.path().join("genesis_committee.toml");
        let reg_path = dir.path().join("registered_validators.json");

        let pk0 = hex::encode(vec![0x00u8; PK_LEN]);
        let toml_content = format!(
            r#"
[committee]
epoch = 0

[[committee.validators]]
authority_index = 0
public_key = "0x{pk0}"
stake = 1000
network_address = "127.0.0.1:16111"
"#
        );
        std::fs::write(&genesis_path, toml_content).unwrap();

        let mut pk1 = vec![0xAA; PK_LEN];
        pk1[0] = 0x11;
        let mut pk2 = vec![0xAA; PK_LEN];
        pk2[0] = 0x22;
        let mut pk3 = vec![0xAA; PK_LEN];
        pk3[0] = 0x33;
        let registered = vec![
            RegisteredValidator {
                public_key: format!("0x{}", hex::encode(&pk1)),
                network_address: "10.0.0.1:16110".to_string(),
            },
            RegisteredValidator {
                public_key: format!("0x{}", hex::encode(&pk2)),
                network_address: "10.0.0.1:16110".to_string(), // duplicate of pk1
            },
            RegisteredValidator {
                public_key: format!("0x{}", hex::encode(&pk3)),
                network_address: "127.0.0.1:16111".to_string(), // duplicate of genesis
            },
        ];
        std::fs::write(&reg_path, serde_json::to_string(&registered).unwrap()).unwrap();

        let m = GenesisCommitteeManifest::load_with_registered(&genesis_path).unwrap();
        assert_eq!(
            m.validators.len(),
            2,
            "only pk1 should be added; pk2 (dup addr of pk1) and pk3 (dup addr of genesis) skipped"
        );
        assert!(m.validate().is_ok(), "no duplicate addresses after dedup");
    }

    // ─── Phase 8 (Gap A): epoch-boundary committee rebuild behavior ───
    //
    // These tests exercise `build_committee_from_sources` against registry
    // states that mirror what the narwhal commit loop's epoch hook sees
    // right after `settle_unlocks` (γ-5) / `auto_activate_locked` (Group 2)
    // have run. They verify the contract the hot-reload relies on:
    //   - newly-ACTIVE validators appear in the rebuilt committee
    //   - validators that transitioned out of ACTIVE (Unlocked, Exiting)
    //     disappear from the rebuilt committee

    /// Helper: build a StakingRegistry with a specific validator injected
    /// directly in ACTIVE state with l1_stake_verified=true and a
    /// network_address — mirrors the post-auto_activate_locked snapshot.
    #[cfg(test)]
    #[allow(deprecated)]
    fn registry_with_active(id_byte: u8, stake: u64, addr: &str) -> misaka_consensus::staking::StakingRegistry {
        use misaka_consensus::staking::{StakingConfig, StakingRegistry};
        let config = StakingConfig {
            min_validator_stake: 10_000_000,
            max_active_validators: 10,
            ..StakingConfig::testnet()
        };
        let mut reg = StakingRegistry::new(config);
        let id = [id_byte; 32];
        reg.register(
            id,
            vec![id_byte; PK_LEN],
            stake,
            500,
            id,
            0,
            [id_byte; 32],
            0,
            true, // solana_stake_verified — satisfies the activate() OR-gate
            Some(format!("sig_{}", id_byte)),
            false,
        )
        .expect("register");
        reg.update_score(&id, 5000);
        reg.activate(&id, 1).expect("activate");
        // network_address must be set — active_authorities() filters on this.
        reg.set_network_address(&id, Some(addr.to_string()))
            .expect("set_network_address");
        reg
    }

    #[test]
    fn phase8_committee_includes_newly_activated_registry_validator() {
        // Scenario: start with N genesis validators, then
        // auto_activate_locked promotes a new one. The rebuild must
        // include the new validator.
        let manifest = sample_manifest(3);
        // Pick an id_byte and address that do NOT collide with genesis
        // (sample_manifest uses pk[0]=0..2 and 127.0.0.{1..3}:16111).
        let new_byte = 0xAA;
        let new_addr = "10.0.0.50:16111";
        let reg = registry_with_active(new_byte, 20_000_000, new_addr);

        let committee = build_committee_from_sources(&manifest, &reg)
            .expect("build committee after auto-activate");

        // Size = 3 genesis + 1 new ACTIVE.
        assert_eq!(committee.size(), 4, "new ACTIVE validator must be appended");

        // The new authority's public_key and hostname must appear.
        let found = committee
            .authorities
            .iter()
            .any(|a| a.hostname == new_addr && a.public_key == vec![new_byte; PK_LEN]);
        assert!(found, "new ACTIVE validator must appear in committee");
    }

    #[test]
    fn phase8_committee_drops_no_longer_active_validator() {
        // Scenario: a validator was ACTIVE in the registry (would have
        // appeared in the previous committee), but has since exited. The
        // rebuild must NOT include it.
        use misaka_consensus::staking::ValidatorState;

        let manifest = sample_manifest(3);
        let exiting_byte = 0xBB;
        let exiting_addr = "10.0.0.60:16111";
        let mut reg = registry_with_active(exiting_byte, 20_000_000, exiting_addr);

        // Pre-condition: new validator IS in the committee while ACTIVE.
        let before = build_committee_from_sources(&manifest, &reg).unwrap();
        assert_eq!(before.size(), 4, "precondition: new ACTIVE included");

        // Now exit it — drops out of `active_authorities()`.
        let vid = [exiting_byte; 32];
        reg.exit(&vid, 10).expect("exit");
        assert!(matches!(
            reg.get(&vid).unwrap().state,
            ValidatorState::Exiting { .. }
        ));

        let after = build_committee_from_sources(&manifest, &reg)
            .expect("build committee after exit");

        // Back to 3 genesis authorities only.
        assert_eq!(after.size(), 3, "EXITING validator must be dropped");
        let dropped = after
            .authorities
            .iter()
            .all(|a| a.hostname != exiting_addr);
        assert!(dropped, "EXITING validator's hostname must not appear");
    }

    // ─── PR-A: SR21 top-21 cap applied to narwhal committee ───────────
    //
    // These tests exercise `build_sr21_committee`. Genesis and registry
    // validators must all exceed `effective_min_sr_stake(chain_id)`
    // (testnet = 1M MISAKA base units = 1_000_000_000_000_000). We use a
    // helper variant of `sample_manifest` that produces above-threshold
    // stake, and a helper variant of `registry_with_active` that seeds a
    // varying amount.

    /// Sample manifest whose genesis stake is well above the testnet SR21
    /// floor (1M MISAKA = 10^15 base units). `base_stake` scales per index.
    #[cfg(test)]
    fn sample_manifest_with_stake(n: usize, base_stake: u64) -> GenesisCommitteeManifest {
        let validators: Vec<GenesisValidator> = (0..n)
            .map(|i| {
                let mut pk_varied = vec![0xAAu8; PK_LEN];
                pk_varied[0] = i as u8;
                pk_varied[1] = (i >> 8) as u8; // support n up to 2^16
                GenesisValidator {
                    authority_index: i as u32,
                    public_key: format!("0x{}", hex::encode(&pk_varied)),
                    stake: base_stake + i as u64, // unique-ish, above floor
                    network_address: format!("10.1.{}.{}:16111", (i / 256) + 1, (i % 256) + 1),
                    solana_stake_account: None,
                }
            })
            .collect();
        GenesisCommitteeManifest {
            epoch: 0,
            validators,
            initial_utxos_source: None,
        }
    }

    /// Registry helper mirroring `registry_with_active` but with configurable
    /// stake (so tests can arrange the stake ordering for SR21 assertions).
    #[cfg(test)]
    #[allow(deprecated)]
    fn registry_with_active_stake(
        id_byte: u8,
        stake: u64,
        addr: &str,
    ) -> misaka_consensus::staking::StakingRegistry {
        use misaka_consensus::staking::{StakingConfig, StakingRegistry};
        // Loosen the per-registry min_validator_stake for these tests so
        // the registry admits our test amounts; the SR21 floor is
        // enforced by `run_election_for_chain` against the chain_id's
        // StakingConfig (not this per-registry one).
        let config = StakingConfig {
            min_validator_stake: 1_000,
            max_active_validators: 100,
            ..StakingConfig::testnet()
        };
        let mut reg = StakingRegistry::new(config);
        let id = [id_byte; 32];
        reg.register(
            id,
            vec![id_byte; PK_LEN],
            stake,
            500,
            id,
            0,
            [id_byte; 32],
            0,
            true,
            Some(format!("sig_{}", id_byte)),
            false,
        )
        .expect("register");
        reg.update_score(&id, 5000);
        reg.activate(&id, 1).expect("activate");
        reg.set_network_address(&id, Some(addr.to_string()))
            .expect("set_network_address");
        reg
    }

    /// Test 1: 30 ACTIVE validators → SR21 cap → committee has exactly 21.
    #[test]
    fn pra_sr21_caps_at_21() {
        // 30 genesis validators, all above the testnet SR21 floor.
        // We use testnet chain_id=2, floor = 1_000_000_000_000_000.
        let floor: u64 = 1_000_000_000_000_000;
        let manifest = sample_manifest_with_stake(30, floor + 1);
        let empty_reg = {
            use misaka_consensus::staking::{StakingConfig, StakingRegistry};
            StakingRegistry::new(StakingConfig::testnet())
        };

        let committee = build_sr21_committee(&manifest, &empty_reg, /* chain_id */ 2, 1)
            .expect("build sr21 committee");
        assert_eq!(
            committee.size(),
            21,
            "30 ACTIVE candidates must cap at MAX_SR_COUNT=21"
        );
    }

    /// Test 2: build_sr21_committee reflects the election result — the
    /// committee's authorities are exactly the election's elected set,
    /// in election order, all above the stake floor.
    #[test]
    fn pra_committee_reflects_sr21_result() {
        // 5 genesis validators with strictly-increasing stake so the
        // election order is deterministic (highest stake first).
        let floor: u64 = 1_000_000_000_000_000;
        let manifest = sample_manifest_with_stake(5, floor + 100);
        let empty_reg = {
            use misaka_consensus::staking::{StakingConfig, StakingRegistry};
            StakingRegistry::new(StakingConfig::testnet())
        };

        let committee = build_sr21_committee(&manifest, &empty_reg, 2, 1)
            .expect("build sr21 committee");
        assert_eq!(committee.size(), 5);

        // Every authority's stake is above the chain floor.
        for (i, auth) in committee.authorities.iter().enumerate() {
            assert!(
                (auth.stake as u128) >= (floor as u128),
                "authority {} stake {} is below SR21 floor {}",
                i, auth.stake, floor,
            );
        }

        // Election orders by stake descending. sample_manifest_with_stake
        // assigns stake = base + i so validator i=4 has the highest stake.
        // The elected committee's first authority must therefore have the
        // highest stake in the candidate set.
        let max_candidate_stake = manifest
            .validators
            .iter()
            .map(|v| v.stake)
            .max()
            .unwrap();
        assert_eq!(
            committee.authorities[0].stake, max_candidate_stake,
            "SR_0 must be the highest-staked candidate"
        );
    }

    /// Test 3: dynamic (registry) validator with higher stake than a
    /// genesis validator REPLACES the lower-staked genesis in the cap.
    #[test]
    fn pra_higher_stake_replaces_lower() {
        // 21 genesis validators, each with the minimum stake above the
        // floor. Then one registry validator with much higher stake.
        // After the election, the cap fills at 21; the new registry
        // validator enters, and the lowest-staked genesis drops.
        let floor: u64 = 1_000_000_000_000_000;
        let genesis_stake = floor + 1; // bare minimum above floor
        let manifest = sample_manifest_with_stake(21, genesis_stake);

        // Registry validator: stake = 10x genesis, different pubkey & addr
        // so it does not collide with genesis dedup.
        let big_byte: u8 = 0xFE; // different from any sample_manifest pk[0]
        let big_addr = "10.200.0.1:16111";
        let big_stake = genesis_stake * 10;
        let reg = registry_with_active_stake(big_byte, big_stake, big_addr);

        // 22 candidates total, cap is 21 → the lowest genesis drops.
        let committee = build_sr21_committee(&manifest, &reg, 2, 1)
            .expect("build sr21 committee");
        assert_eq!(committee.size(), 21);

        // The high-stake registry validator is in.
        let contains_registry = committee
            .authorities
            .iter()
            .any(|a| a.hostname == big_addr);
        assert!(
            contains_registry,
            "high-stake registry validator must displace the lowest genesis"
        );
        // Its stake is the max.
        let max_stake = committee.authorities.iter().map(|a| a.stake).max().unwrap();
        assert_eq!(max_stake, big_stake);

        // Exactly one genesis validator was dropped (21 genesis - 1 dropped
        // + 1 registry = 21).
        let genesis_addrs_in_committee = committee
            .authorities
            .iter()
            .filter(|a| a.hostname.starts_with("10.1."))
            .count();
        assert_eq!(
            genesis_addrs_in_committee, 20,
            "exactly one genesis validator must have been displaced"
        );
    }

    // ─── Option C: initial_utxos loader tests ─────────────────────────
    //
    // Exercises `GenesisCommitteeManifest::load_initial_utxos` against
    // on-disk JSON files produced in the `migrate-utxo-snapshot` shape.

    fn write_initial_utxos_json(dir: &std::path::Path, body: &serde_json::Value) -> std::path::PathBuf {
        let path = dir.join("initial_utxos.json");
        std::fs::write(&path, serde_json::to_string_pretty(body).unwrap()).unwrap();
        path
    }

    fn make_manifest_with_utxo_source(
        source: std::path::PathBuf,
    ) -> GenesisCommitteeManifest {
        GenesisCommitteeManifest {
            epoch: 0,
            validators: sample_manifest(3).validators,
            initial_utxos_source: Some(source),
        }
    }

    #[test]
    fn option_c_loader_happy_path() {
        let dir = tempfile::tempdir().unwrap();
        let body = serde_json::json!({
            "schema_version": INITIAL_UTXO_SCHEMA_VERSION,
            "source_height": 42,
            "source_snapshot": "narwhal_utxo_snapshot.json",
            "total_amount": 3000u64,
            "utxos": [
                {
                    "address": hex::encode([0x11u8; 32]),
                    "amount": 1000u64,
                    "spending_pubkey": hex::encode(vec![0xAAu8; 1952]),
                    "label": "migrated_0"
                },
                {
                    "address": hex::encode([0x22u8; 32]),
                    "amount": 2000u64,
                    "spending_pubkey": hex::encode(vec![0xBBu8; 1952]),
                    "label": "migrated_1"
                }
            ]
        });
        let source = write_initial_utxos_json(dir.path(), &body);
        let manifest = make_manifest_with_utxo_source(source);
        let seeds = manifest
            .load_initial_utxos()
            .expect("load")
            .expect("Some(vec)");
        assert_eq!(seeds.len(), 2);
        assert_eq!(seeds[0].address, [0x11u8; 32]);
        assert_eq!(seeds[0].amount, 1000);
        assert_eq!(seeds[0].spending_pubkey.as_ref().unwrap().len(), 1952);
        assert_eq!(seeds[1].amount, 2000);
    }

    #[test]
    fn option_c_loader_none_when_no_section() {
        let manifest = sample_manifest(3); // helper sets initial_utxos_source: None
        assert!(manifest.load_initial_utxos().unwrap().is_none());
    }

    #[test]
    fn option_c_loader_rejects_total_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let body = serde_json::json!({
            "schema_version": INITIAL_UTXO_SCHEMA_VERSION,
            "source_height": 1,
            "source_snapshot": "x",
            "total_amount": 999u64,       // lies — real sum is 1000
            "utxos": [
                {
                    "address": hex::encode([0x11u8; 32]),
                    "amount": 1000u64,
                    "spending_pubkey": hex::encode(vec![0xAAu8; 1952]),
                    "label": ""
                }
            ]
        });
        let source = write_initial_utxos_json(dir.path(), &body);
        let manifest = make_manifest_with_utxo_source(source);
        let err = manifest.load_initial_utxos().unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("total_amount") || msg.contains("total"),
            "error must mention total mismatch, got: {}", msg);
    }

    #[test]
    fn option_c_loader_rejects_bad_schema_version() {
        let dir = tempfile::tempdir().unwrap();
        let body = serde_json::json!({
            "schema_version": 99u32,
            "source_height": 0,
            "source_snapshot": "x",
            "total_amount": 0u64,
            "utxos": []
        });
        let source = write_initial_utxos_json(dir.path(), &body);
        let manifest = make_manifest_with_utxo_source(source);
        assert!(manifest.load_initial_utxos().is_err());
    }

    #[test]
    fn option_c_loader_rejects_bad_pubkey_length() {
        let dir = tempfile::tempdir().unwrap();
        let body = serde_json::json!({
            "schema_version": INITIAL_UTXO_SCHEMA_VERSION,
            "source_height": 0,
            "source_snapshot": "x",
            "total_amount": 10u64,
            "utxos": [
                {
                    "address": hex::encode([0x11u8; 32]),
                    "amount": 10u64,
                    "spending_pubkey": hex::encode(vec![0xAAu8; 100]), // wrong length
                    "label": ""
                }
            ]
        });
        let source = write_initial_utxos_json(dir.path(), &body);
        let manifest = make_manifest_with_utxo_source(source);
        assert!(manifest.load_initial_utxos().is_err());
    }

    #[test]
    fn synthetic_seed_tx_hash_is_deterministic() {
        let addr = [0x42u8; 32];
        let h1 = synthetic_seed_tx_hash(0, "migrated_0", &addr);
        let h2 = synthetic_seed_tx_hash(0, "migrated_0", &addr);
        assert_eq!(h1, h2, "same inputs must produce same hash");
        // Different label → different hash.
        let h3 = synthetic_seed_tx_hash(0, "migrated_1", &addr);
        assert_ne!(h1, h3);
        // Different epoch → different hash.
        let h4 = synthetic_seed_tx_hash(1, "migrated_0", &addr);
        assert_ne!(h1, h4);
        // Different address → different hash.
        let h5 = synthetic_seed_tx_hash(0, "migrated_0", &[0x43u8; 32]);
        assert_ne!(h1, h5);
    }

    #[test]
    fn toml_parse_accepts_initial_utxos_section() {
        let dir = tempfile::tempdir().unwrap();
        // Write a real initial_utxos.json so the test load can finish
        // (load() alone doesn't touch the JSON file, but this makes the
        // round-trip path-correct relative resolution explicit).
        let json_path = dir.path().join("initial_utxos.json");
        std::fs::write(
            &json_path,
            serde_json::to_string(&serde_json::json!({
                "schema_version": INITIAL_UTXO_SCHEMA_VERSION,
                "source_height": 1,
                "source_snapshot": "x",
                "total_amount": 100u64,
                "utxos": [{
                    "address": hex::encode([0x11u8; 32]),
                    "amount": 100u64,
                    "spending_pubkey": hex::encode(vec![0xAAu8; 1952]),
                    "label": ""
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        let toml_path = dir.path().join("genesis_committee.toml");
        let pk_hex = format!("0x{}", hex::encode(vec![0xCCu8; PK_LEN]));
        let toml_body = format!(
            r#"
[committee]
epoch = 0
[[committee.validators]]
authority_index = 0
public_key = "{pk_hex}"
stake = 1000
network_address = "127.0.0.1:16111"

[initial_utxos]
source = "initial_utxos.json"
"#
        );
        std::fs::write(&toml_path, toml_body).unwrap();

        let manifest = GenesisCommitteeManifest::load(&toml_path).expect("load");
        assert!(manifest.initial_utxos_source.is_some());
        // Relative path must resolve to dir/initial_utxos.json.
        assert_eq!(
            manifest.initial_utxos_source.as_ref().unwrap(),
            &json_path,
        );
        // Loader can read it.
        let seeds = manifest
            .load_initial_utxos()
            .expect("loader")
            .expect("Some");
        assert_eq!(seeds.len(), 1);
    }

    #[test]
    fn toml_without_initial_utxos_section_leaves_source_none() {
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("genesis_committee.toml");
        let pk_hex = format!("0x{}", hex::encode(vec![0xCCu8; PK_LEN]));
        let toml_body = format!(
            r#"
[committee]
epoch = 0
[[committee.validators]]
authority_index = 0
public_key = "{pk_hex}"
stake = 1000
network_address = "127.0.0.1:16111"
"#
        );
        std::fs::write(&toml_path, toml_body).unwrap();
        let manifest = GenesisCommitteeManifest::load(&toml_path).expect("load");
        assert!(manifest.initial_utxos_source.is_none());
    }
}
