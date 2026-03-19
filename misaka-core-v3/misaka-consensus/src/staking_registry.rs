//! Staking Registry — validator lifecycle state machine.
//!
//! The staking registry manages the validator set across epochs.
//! It is the SINGLE authority for validator eligibility.
//!
//! # Persistence
//!
//! The registry is persisted to `{data_dir}/staking-registry.json`.
//! On startup, the registry is loaded from disk if the file exists.
//! On every state mutation, the registry is saved to disk.
//! This ensures validator state survives node restarts.
//!
//! # Trust Model
//!
//! - misakastake.com is the registration UI (off-chain)
//! - Registrations are submitted as signed transactions (on-chain)
//! - The registry verifies proof-of-possession signatures
//! - Epoch boundaries trigger Active/Unbonding transitions
//! - All state is locally verifiable (no external API dependency)

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use misaka_types::validator::*;
use misaka_types::error::MisakaError;
use misaka_crypto::validator_sig::{ValidatorPqPublicKey, ValidatorPqSignature, validator_verify};
use misaka_crypto::sha3_256;

/// Serializable snapshot of the staking registry for disk persistence.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RegistrySnapshot {
    version: u32,
    current_epoch: u64,
    /// Validators serialized as a list (HashMap<[u8;20], _> doesn't JSON well).
    validators: Vec<ValidatorIdentity>,
    /// Epoch hashes serialized as (epoch, hex_hash) pairs.
    epoch_hashes: Vec<(u64, String)>,
}

/// The staking registry: manages all validators and their lifecycle.
#[derive(Debug, Clone)]
pub struct StakingRegistry {
    /// All validators by ID.
    validators: HashMap<ValidatorId, ValidatorIdentity>,
    /// Current epoch.
    current_epoch: u64,
    /// Historical epoch snapshots (epoch → set_hash).
    epoch_hashes: HashMap<u64, [u8; 32]>,
    /// Path to persistence file. None = in-memory only (tests).
    persist_path: Option<PathBuf>,
}

/// Result of processing a registration.
#[derive(Debug)]
pub enum RegistrationResult {
    Accepted { validator_id: ValidatorId },
    Rejected(String),
}

impl StakingRegistry {
    pub fn new() -> Self {
        Self {
            validators: HashMap::new(),
            current_epoch: 0,
            epoch_hashes: HashMap::new(),
            persist_path: None,
        }
    }

    /// Create a registry with an initial validator set (for genesis).
    pub fn with_genesis_validators(validators: Vec<ValidatorIdentity>) -> Self {
        let mut reg = Self::new();
        for v in validators {
            reg.validators.insert(v.validator_id, v);
        }
        // Snapshot epoch 0
        let hash = reg.compute_set_hash();
        reg.epoch_hashes.insert(0, hash);
        reg
    }

    /// Set persistence path and immediately save current state.
    pub fn with_persistence(mut self, path: PathBuf) -> Self {
        self.persist_path = Some(path);
        self.persist_to_disk();
        self
    }

    /// Load registry from disk, or return a fresh empty registry.
    /// If the file exists and is valid, the loaded registry is returned.
    /// If the file is missing or corrupt, a fresh registry is returned with a warning.
    pub fn load_or_new(path: &Path) -> Self {
        if path.exists() {
            match std::fs::read_to_string(path) {
                Ok(json) => {
                    match serde_json::from_str::<RegistrySnapshot>(&json) {
                        Ok(snap) => {
                            if snap.version != 1 {
                                tracing::warn!("StakingRegistry: unsupported version {}, starting fresh", snap.version);
                                return Self::new().with_persistence(path.to_path_buf());
                            }
                            let mut reg = Self {
                                validators: HashMap::new(),
                                current_epoch: snap.current_epoch,
                                epoch_hashes: HashMap::new(),
                                persist_path: Some(path.to_path_buf()),
                            };
                            for v in snap.validators {
                                reg.validators.insert(v.validator_id, v);
                            }
                            for (epoch, hex_hash) in snap.epoch_hashes {
                                if let Ok(bytes) = hex::decode(&hex_hash) {
                                    if bytes.len() == 32 {
                                        let mut h = [0u8; 32];
                                        h.copy_from_slice(&bytes);
                                        reg.epoch_hashes.insert(epoch, h);
                                    }
                                }
                            }
                            tracing::info!(
                                "StakingRegistry loaded: epoch={}, validators={}, active={}",
                                reg.current_epoch, reg.validators.len(), reg.active_set().len()
                            );
                            return reg;
                        }
                        Err(e) => {
                            tracing::warn!("StakingRegistry: corrupt file {}: {}, starting fresh", path.display(), e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("StakingRegistry: cannot read {}: {}, starting fresh", path.display(), e);
                }
            }
        }
        Self::new().with_persistence(path.to_path_buf())
    }

    /// Persist current state to disk (if persist_path is set).
    fn persist_to_disk(&self) {
        let path = match &self.persist_path {
            Some(p) => p,
            None => return,
        };
        let snap = RegistrySnapshot {
            version: 1,
            current_epoch: self.current_epoch,
            validators: self.validators.values().cloned().collect(),
            epoch_hashes: self.epoch_hashes.iter()
                .map(|(e, h)| (*e, hex::encode(h)))
                .collect(),
        };
        match serde_json::to_string_pretty(&snap) {
            Ok(json) => {
                if let Err(e) = std::fs::write(path, &json) {
                    tracing::error!("StakingRegistry: failed to persist to {}: {}", path.display(), e);
                }
            }
            Err(e) => {
                tracing::error!("StakingRegistry: failed to serialize: {}", e);
            }
        }
    }

    pub fn current_epoch(&self) -> u64 { self.current_epoch }

    /// Get validator by ID.
    pub fn get(&self, id: &ValidatorId) -> Option<&ValidatorIdentity> {
        self.validators.get(id)
    }

    /// Get mutable validator by ID.
    pub fn get_mut(&mut self, id: &ValidatorId) -> Option<&mut ValidatorIdentity> {
        self.validators.get_mut(id)
    }

    /// Return the current Active validator set.
    pub fn active_set(&self) -> Vec<ValidatorIdentity> {
        self.validators.values()
            .filter(|v| v.is_active())
            .cloned()
            .collect()
    }

    /// Build a ValidatorSet from current Active validators.
    pub fn to_validator_set(&self) -> super::validator_set::ValidatorSet {
        super::validator_set::ValidatorSet::new(self.active_set())
    }

    // ─── Registration ──────────────────────────────────────

    /// Process a validator registration.
    ///
    /// Verifies:
    /// 1. Proof-of-possession (signature by consensus key)
    /// 2. Minimum stake requirement
    /// 3. Commission rate within bounds
    /// 4. Not already registered
    pub fn register(&mut self, reg: &ValidatorRegistration) -> RegistrationResult {
        // Derive validator ID from consensus pubkey
        let vid_hash = sha3_256(&reg.consensus_pubkey.bytes);
        let mut validator_id = [0u8; 20];
        validator_id.copy_from_slice(&vid_hash[..20]);

        // Check not already registered
        if self.validators.contains_key(&validator_id) {
            return RegistrationResult::Rejected("already registered".into());
        }

        // Check minimum stake
        if reg.initial_stake < MINIMUM_SELF_STAKE {
            return RegistrationResult::Rejected(
                format!("stake {} below minimum {}", reg.initial_stake, MINIMUM_SELF_STAKE));
        }

        // Check commission bounds
        if reg.commission_bps > MAX_COMMISSION_BPS {
            return RegistrationResult::Rejected(
                format!("commission {} exceeds max {}", reg.commission_bps, MAX_COMMISSION_BPS));
        }

        // Verify proof-of-possession
        let signing_bytes = reg.signing_bytes();
        let pk = match ValidatorPqPublicKey::from_bytes(&reg.consensus_pubkey.bytes) {
            Ok(pk) => pk,
            Err(e) => return RegistrationResult::Rejected(format!("invalid pubkey: {}", e)),
        };
        let sig = match ValidatorPqSignature::from_bytes(&reg.proof_of_possession.bytes) {
            Ok(sig) => sig,
            Err(e) => return RegistrationResult::Rejected(format!("invalid signature: {}", e)),
        };
        if validator_verify(&signing_bytes, &sig, &pk).is_err() {
            return RegistrationResult::Rejected("proof-of-possession verification failed".into());
        }

        // Register as Pending
        let vi = ValidatorIdentity {
            validator_id,
            stake_weight: reg.initial_stake,
            public_key: reg.consensus_pubkey.clone(),
            status: ValidatorStatus::Pending,
            commission_bps: reg.commission_bps,
            moniker: reg.moniker.clone(),
            bonded_at_epoch: self.current_epoch,
            activated_at_epoch: 0,
            unbonding_ends_epoch: 0,
            jailed_at_epoch: 0,
            slashes: Vec::new(),
            payout_address: reg.payout_address.clone(),
            _compat: (),
        };

        self.validators.insert(validator_id, vi);
        self.persist_to_disk();
        RegistrationResult::Accepted { validator_id }
    }

    // ─── Lifecycle Transitions ─────────────────────────────

    /// Process epoch boundary: activate pending, complete unbonding, auto-tombstone.
    ///
    /// Returns the new Active validator set hash.
    pub fn on_epoch_boundary(&mut self) -> [u8; 32] {
        self.current_epoch += 1;
        let epoch = self.current_epoch;

        let ids: Vec<ValidatorId> = self.validators.keys().cloned().collect();
        for id in ids {
            if let Some(v) = self.validators.get_mut(&id) {
                match v.status {
                    ValidatorStatus::Pending => {
                        if v.meets_minimum_stake() {
                            v.status = ValidatorStatus::Active;
                            v.activated_at_epoch = epoch;
                        }
                    }
                    ValidatorStatus::Unbonding => {
                        if epoch >= v.unbonding_ends_epoch {
                            // Unbonding complete — remove from set
                            // (we'll clean up after the loop)
                        }
                    }
                    ValidatorStatus::Jailed => {
                        if epoch - v.jailed_at_epoch > MAX_JAIL_EPOCHS {
                            v.status = ValidatorStatus::Tombstoned;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Remove fully unbonded validators
        self.validators.retain(|_, v| {
            !(v.status == ValidatorStatus::Unbonding && epoch >= v.unbonding_ends_epoch)
        });

        // Remove tombstoned validators (after grace period for evidence)
        // Keep for now — tombstoned validators stay in registry for audit trail

        let hash = self.compute_set_hash();
        self.epoch_hashes.insert(epoch, hash);
        self.persist_to_disk();
        hash
    }

    /// Begin voluntary unbonding.
    pub fn begin_unbonding(&mut self, id: &ValidatorId) -> Result<(), MisakaError> {
        let v = self.validators.get_mut(id)
            .ok_or_else(|| MisakaError::SignatureVerificationFailed("unknown validator".into()))?;
        if v.status != ValidatorStatus::Active {
            return Err(MisakaError::SignatureVerificationFailed(
                format!("cannot unbond: status is {:?}", v.status)));
        }
        v.status = ValidatorStatus::Unbonding;
        v.unbonding_ends_epoch = self.current_epoch + UNBONDING_EPOCHS;
        self.persist_to_disk();
        Ok(())
    }

    /// Jail a validator for misbehavior.
    pub fn jail(&mut self, id: &ValidatorId, reason: SlashReason, slash_amount: u128) -> Result<(), MisakaError> {
        let v = self.validators.get_mut(id)
            .ok_or_else(|| MisakaError::SignatureVerificationFailed("unknown validator".into()))?;
        if v.status == ValidatorStatus::Tombstoned {
            return Ok(()); // Already tombstoned, no-op
        }
        v.status = ValidatorStatus::Jailed;
        v.jailed_at_epoch = self.current_epoch;
        v.slashes.push(SlashRecord {
            epoch: self.current_epoch,
            reason,
            amount: slash_amount,
        });
        v.stake_weight = v.stake_weight.saturating_sub(slash_amount);
        self.persist_to_disk();
        Ok(())
    }

    /// Tombstone a validator (permanent removal from consensus).
    pub fn tombstone(&mut self, id: &ValidatorId, reason: SlashReason, slash_amount: u128) -> Result<(), MisakaError> {
        let v = self.validators.get_mut(id)
            .ok_or_else(|| MisakaError::SignatureVerificationFailed("unknown validator".into()))?;
        v.status = ValidatorStatus::Tombstoned;
        v.slashes.push(SlashRecord {
            epoch: self.current_epoch,
            reason,
            amount: slash_amount,
        });
        v.stake_weight = v.stake_weight.saturating_sub(slash_amount);
        self.persist_to_disk();
        Ok(())
    }

    /// Unjail a validator (after penalty served).
    pub fn unjail(&mut self, id: &ValidatorId) -> Result<(), MisakaError> {
        let v = self.validators.get_mut(id)
            .ok_or_else(|| MisakaError::SignatureVerificationFailed("unknown validator".into()))?;
        if v.status != ValidatorStatus::Jailed {
            return Err(MisakaError::SignatureVerificationFailed(
                format!("cannot unjail: status is {:?}", v.status)));
        }
        if v.meets_minimum_stake() {
            v.status = ValidatorStatus::Active;
        } else {
            v.status = ValidatorStatus::Pending;
        }
        self.persist_to_disk();
        Ok(())
    }

    // ─── Historical Queries ────────────────────────────────

    /// Get the validator set hash for a given epoch.
    pub fn epoch_hash(&self, epoch: u64) -> Option<&[u8; 32]> {
        self.epoch_hashes.get(&epoch)
    }

    /// Compute the current set hash.
    pub fn compute_set_hash(&self) -> [u8; 32] {
        self.to_validator_set().set_hash()
    }

    /// Total number of registered validators (all statuses).
    pub fn total_registered(&self) -> usize {
        self.validators.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_crypto::validator_sig::{generate_validator_keypair, validator_sign};

    fn make_registration(chain_id: u32, epoch: u64, stake: u128) -> ValidatorRegistration {
        let kp = generate_validator_keypair();
        let reg = ValidatorRegistration {
            consensus_pubkey: ValidatorPublicKey { bytes: kp.public_key.to_bytes() },
            initial_stake: stake,
            commission_bps: 500,
            moniker: "test-validator".into(),
            payout_address: vec![0xAA; 20],
            proof_of_possession: ValidatorSignature { bytes: vec![] }, // placeholder
            chain_id,
            registration_epoch: epoch,
        };
        let signing_bytes = reg.signing_bytes();
        let sig = validator_sign(&signing_bytes, &kp.secret_key).unwrap();
        ValidatorRegistration {
            proof_of_possession: ValidatorSignature { bytes: sig.to_bytes() },
            ..reg
        }
    }

    #[test]
    fn test_register_and_activate() {
        let mut registry = StakingRegistry::new();
        let reg = make_registration(2, 0, MINIMUM_SELF_STAKE);
        match registry.register(&reg) {
            RegistrationResult::Accepted { validator_id } => {
                let v = registry.get(&validator_id).unwrap();
                assert_eq!(v.status, ValidatorStatus::Pending);

                // Epoch boundary activates
                registry.on_epoch_boundary();
                let v = registry.get(&validator_id).unwrap();
                assert_eq!(v.status, ValidatorStatus::Active);
            }
            RegistrationResult::Rejected(reason) => panic!("rejected: {}", reason),
        }
    }

    #[test]
    fn test_below_minimum_stake_rejected() {
        let mut registry = StakingRegistry::new();
        let reg = make_registration(2, 0, MINIMUM_SELF_STAKE - 1);
        match registry.register(&reg) {
            RegistrationResult::Rejected(_) => {} // expected
            RegistrationResult::Accepted { .. } => panic!("should reject below minimum stake"),
        }
    }

    #[test]
    fn test_jail_and_unjail() {
        let mut registry = StakingRegistry::new();
        let reg = make_registration(2, 0, MINIMUM_SELF_STAKE * 2);
        let vid = match registry.register(&reg) {
            RegistrationResult::Accepted { validator_id } => validator_id,
            _ => panic!("register failed"),
        };
        registry.on_epoch_boundary(); // activate

        // Jail
        registry.jail(&vid, SlashReason::Downtime, 1000).unwrap();
        assert_eq!(registry.get(&vid).unwrap().status, ValidatorStatus::Jailed);
        assert_eq!(registry.active_set().len(), 0);

        // Unjail
        registry.unjail(&vid).unwrap();
        assert_eq!(registry.get(&vid).unwrap().status, ValidatorStatus::Active);
    }

    #[test]
    fn test_tombstone_permanent() {
        let mut registry = StakingRegistry::new();
        let reg = make_registration(2, 0, MINIMUM_SELF_STAKE);
        let vid = match registry.register(&reg) {
            RegistrationResult::Accepted { validator_id } => validator_id,
            _ => panic!("register failed"),
        };
        registry.on_epoch_boundary();

        registry.tombstone(&vid, SlashReason::DoubleSign, MINIMUM_SELF_STAKE / 2).unwrap();
        assert_eq!(registry.get(&vid).unwrap().status, ValidatorStatus::Tombstoned);
        assert!(registry.unjail(&vid).is_err(), "tombstoned validator cannot be unjailed");
    }

    #[test]
    fn test_unbonding() {
        let mut registry = StakingRegistry::new();
        let reg = make_registration(2, 0, MINIMUM_SELF_STAKE);
        let vid = match registry.register(&reg) {
            RegistrationResult::Accepted { validator_id } => validator_id,
            _ => panic!("register failed"),
        };
        registry.on_epoch_boundary(); // activate

        registry.begin_unbonding(&vid).unwrap();
        assert_eq!(registry.get(&vid).unwrap().status, ValidatorStatus::Unbonding);

        // Advance past unbonding period
        for _ in 0..UNBONDING_EPOCHS {
            registry.on_epoch_boundary();
        }
        assert!(registry.get(&vid).is_none(), "unbonded validator should be removed");
    }

    #[test]
    fn test_epoch_hash_snapshots() {
        let mut registry = StakingRegistry::new();
        let reg = make_registration(2, 0, MINIMUM_SELF_STAKE);
        registry.register(&reg);
        let h1 = registry.on_epoch_boundary();
        let h2 = registry.on_epoch_boundary();
        // Same set → same hash
        assert_eq!(h1, h2);
        assert!(registry.epoch_hash(1).is_some());
    }

    #[test]
    fn test_duplicate_registration_rejected() {
        let mut registry = StakingRegistry::new();
        let reg = make_registration(2, 0, MINIMUM_SELF_STAKE);
        registry.register(&reg);
        match registry.register(&reg) {
            RegistrationResult::Rejected(reason) => assert!(reason.contains("already registered")),
            _ => panic!("duplicate should be rejected"),
        }
    }

    #[test]
    fn test_persist_and_reload() {
        let dir = std::env::temp_dir().join(format!("misaka_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("staking-registry.json");

        // Create registry, register validator, activate
        let vid = {
            let mut registry = StakingRegistry::new().with_persistence(path.clone());
            let reg = make_registration(2, 0, MINIMUM_SELF_STAKE);
            let vid = match registry.register(&reg) {
                RegistrationResult::Accepted { validator_id } => validator_id,
                _ => panic!("register failed"),
            };
            registry.on_epoch_boundary(); // Pending → Active
            assert_eq!(registry.get(&vid).unwrap().status, ValidatorStatus::Active);
            assert_eq!(registry.current_epoch(), 1);
            vid
            // registry dropped here → file was written
        };

        // Reload from disk
        let loaded = StakingRegistry::load_or_new(&path);
        assert_eq!(loaded.current_epoch(), 1, "epoch must survive restart");
        assert_eq!(loaded.active_set().len(), 1, "active set must survive restart");
        let v = loaded.get(&vid).expect("validator must survive restart");
        assert_eq!(v.status, ValidatorStatus::Active, "status must survive restart");
        assert!(v.stake_weight >= MINIMUM_SELF_STAKE, "stake must survive restart");

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_missing_file_returns_fresh() {
        let path = std::env::temp_dir().join("nonexistent_misaka_registry.json");
        let _ = std::fs::remove_file(&path); // ensure it doesn't exist
        let registry = StakingRegistry::load_or_new(&path);
        assert_eq!(registry.current_epoch(), 0);
        assert_eq!(registry.active_set().len(), 0);
    }

    #[test]
    fn test_validator_identity_survives_restart() {
        let dir = std::env::temp_dir().join(format!("misaka_test_id_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("staking-registry.json");

        let reg = make_registration(2, 0, MINIMUM_SELF_STAKE);
        let vid_hash = misaka_crypto::sha3_256(&reg.consensus_pubkey.bytes);
        let mut expected_vid = [0u8; 20];
        expected_vid.copy_from_slice(&vid_hash[..20]);

        {
            let mut registry = StakingRegistry::new().with_persistence(path.clone());
            registry.register(&reg);
            registry.on_epoch_boundary();
        }

        let loaded = StakingRegistry::load_or_new(&path);
        let v = loaded.get(&expected_vid).expect("validator must be found after restart");
        assert_eq!(v.validator_id, expected_vid, "validator_id must be identical after restart");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
