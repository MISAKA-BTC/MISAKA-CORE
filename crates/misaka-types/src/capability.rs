// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Capability Delegation — QRL slave key pattern, redesigned for MISAKA.
//!
//! ## QRL → MISAKA mapping
//!
//! | QRL concept           | MISAKA equivalent              |
//! |-----------------------|--------------------------------|
//! | SlaveTransaction      | CapabilityDelegationTx         |
//! | slave_pks + access    | DelegatedKey + CapabilityFlags |
//! | OptimizedAddressState | CryptoStateMetadata            |
//! | ChainManager (slaves) | DelegatedKeyRegistry           |
//!
//! ## Design
//!
//! A master key can delegate specific capabilities to subkeys:
//! - `SPEND_LIMITED`: can sign transfers up to a daily limit
//! - `VALIDATOR_SIGN_ONLY`: can sign consensus blocks (hot key)
//! - `BRIDGE_APPROVE_ONLY`: can approve bridge withdrawals
//! - `RESERVED_0x0010`: reserved (removed in v1.0)
//! - `RELAYER_SUBMIT_ONLY`: can submit relay transactions
//! - `AUDIT_EXPORT_ONLY`: can export audit trails
//! - `VIEW_ONLY`: can read state but not sign anything
//!
//! Each delegation is recorded on-chain as a `CapabilityDelegation`.
//! Validation checks the signer's delegation status before allowing
//! capability-gated operations.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Capability flags — what a delegated key can do.
///
/// Uses bitflags for efficient combination and checking.
/// QRL equivalent: access_type ∈ {0, 1}, but MISAKA needs more granularity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum Capability {
    /// Read-only access. Cannot sign any transactions.
    ViewOnly = 0x0001,
    /// Can sign transfers up to the configured daily limit.
    SpendLimited = 0x0002,
    /// Can sign consensus blocks (validator hot key).
    ValidatorSignOnly = 0x0004,
    /// Can approve bridge withdrawals (bridge committee).
    BridgeApproveOnly = 0x0008,
    /// Reserved: removed in v1.0.
    /// Discriminant 0x0010 preserved for on-chain compatibility -- do not reuse.
    #[deprecated(note = "Removed in v1.0; discriminant reserved")]
    Reserved0x0010 = 0x0010,
    /// Can submit relay transactions.
    RelayerSubmitOnly = 0x0020,
    /// Can export audit trails.
    AuditExportOnly = 0x0040,
    /// Full access — equivalent to the master key.
    /// Should be used sparingly (e.g., recovery key).
    FullAccess = 0xFFFF,
}

impl Capability {
    /// Check if this capability is included in a set of flags.
    pub fn is_in(&self, flags: u32) -> bool {
        let v = *self as u32;
        (flags & v) == v
    }
}

/// Combined capability flags (bitwise OR of Capability values).
pub type CapabilityFlags = u32;

/// Build a flags value from a set of capabilities.
pub fn capabilities_to_flags(caps: &[Capability]) -> CapabilityFlags {
    caps.iter().fold(0u32, |acc, c| acc | (*c as u32))
}

/// Extract individual capabilities from a flags value.
#[allow(deprecated)]
pub fn flags_to_capabilities(flags: CapabilityFlags) -> Vec<Capability> {
    let all = [
        Capability::ViewOnly,
        Capability::SpendLimited,
        Capability::ValidatorSignOnly,
        Capability::BridgeApproveOnly,
        Capability::Reserved0x0010,
        Capability::RelayerSubmitOnly,
        Capability::AuditExportOnly,
    ];
    let mut result = Vec::new();
    if flags == Capability::FullAccess as u32 {
        return vec![Capability::FullAccess];
    }
    for cap in all {
        if cap.is_in(flags) {
            result.push(cap);
        }
    }
    result
}

// ═══════════════════════════════════════════════════════════
//  Delegated key
// ═══════════════════════════════════════════════════════════

/// A delegated key registration — on-chain record.
///
/// QRL equivalent: (master_addr, slave_pk, access_type).
/// MISAKA adds: expiry, daily spend limit, label, revocation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DelegatedKey {
    /// Master address that owns this delegation.
    pub master_address: [u8; 32],
    /// Delegated public key (ML-DSA-65, 1952 bytes).
    pub delegated_pk: Vec<u8>,
    /// Granted capability flags.
    pub capabilities: CapabilityFlags,
    /// Optional daily spend limit (in base units). 0 = no limit.
    pub daily_spend_limit: u64,
    /// Optional expiry epoch. 0 = never expires.
    pub expiry_epoch: u64,
    /// Human-readable label (max 64 bytes).
    pub label: String,
    /// Whether this delegation has been revoked.
    pub revoked: bool,
    /// Transaction hash that created this delegation.
    pub creation_tx: [u8; 32],
    /// Block height at creation.
    pub created_at_height: u64,
}

impl DelegatedKey {
    /// Check if this delegation is active (not revoked, not expired).
    pub fn is_active(&self, current_epoch: u64) -> bool {
        !self.revoked && (self.expiry_epoch == 0 || current_epoch < self.expiry_epoch)
    }

    /// Check if a specific capability is granted.
    pub fn has_capability(&self, cap: Capability) -> bool {
        self.capabilities == Capability::FullAccess as u32 || cap.is_in(self.capabilities)
    }
}

// ═══════════════════════════════════════════════════════════
//  Capability delegation transaction
// ═══════════════════════════════════════════════════════════

/// Transaction to register or revoke delegated keys.
///
/// QRL equivalent: SlaveTransaction.
/// Must be signed by the master key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityDelegationTx {
    /// Master address signing this transaction.
    pub master_address: [u8; 32],
    /// Action: register, revoke, or update.
    pub action: DelegationAction,
    /// Keys being delegated (for Register action).
    pub delegated_keys: Vec<DelegatedKeySpec>,
    /// Keys being revoked (for Revoke action).
    pub revoke_pks: Vec<Vec<u8>>,
    /// Transaction fee.
    pub fee: u64,
    /// Nonce for replay protection.
    pub nonce: u64,
    /// ML-DSA-65 signature by the master key.
    pub signature: Vec<u8>,
}

/// Delegation action type.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum DelegationAction {
    /// Register new delegated keys.
    Register,
    /// Revoke existing delegated keys.
    Revoke,
    /// Update capabilities of existing delegated keys.
    Update,
}

/// Specification for a key to delegate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DelegatedKeySpec {
    /// Public key to delegate to.
    pub public_key: Vec<u8>,
    /// Capabilities to grant.
    pub capabilities: CapabilityFlags,
    /// Daily spend limit (0 = no limit).
    pub daily_spend_limit: u64,
    /// Expiry epoch (0 = never).
    pub expiry_epoch: u64,
    /// Label.
    pub label: String,
}

/// Maximum delegated keys per transaction.
pub const MAX_DELEGATED_KEYS_PER_TX: usize = 16;

/// Maximum label length.
pub const MAX_LABEL_LENGTH: usize = 64;

/// Validation errors for capability delegation.
#[derive(Debug, thiserror::Error)]
pub enum DelegationValidationError {
    #[error("too many delegated keys: {count} > {}", MAX_DELEGATED_KEYS_PER_TX)]
    TooManyKeys { count: usize },
    #[error("duplicate delegated key")]
    DuplicateKey,
    #[error("empty public key")]
    EmptyPublicKey,
    #[error("invalid capabilities: 0")]
    ZeroCapabilities,
    #[error("label too long: {len} > {}", MAX_LABEL_LENGTH)]
    LabelTooLong { len: usize },
    #[error("key already delegated")]
    AlreadyDelegated,
    #[error("key not found for revocation")]
    KeyNotFound,
    #[error("insufficient balance for fee")]
    InsufficientBalance,
    #[error("self-delegation not allowed")]
    SelfDelegation,
    #[error("cannot delegate FullAccess capability")]
    FullAccessDelegation,
}

impl CapabilityDelegationTx {
    /// Validate the transaction structure (no state access needed).
    pub fn validate_structure(&self) -> Result<(), DelegationValidationError> {
        match self.action {
            DelegationAction::Register | DelegationAction::Update => {
                if self.delegated_keys.len() > MAX_DELEGATED_KEYS_PER_TX {
                    return Err(DelegationValidationError::TooManyKeys {
                        count: self.delegated_keys.len(),
                    });
                }
                if self.delegated_keys.is_empty() {
                    return Err(DelegationValidationError::TooManyKeys { count: 0 });
                }

                let mut seen = HashSet::new();
                for spec in &self.delegated_keys {
                    if spec.public_key.is_empty() {
                        return Err(DelegationValidationError::EmptyPublicKey);
                    }
                    if spec.capabilities == 0 {
                        return Err(DelegationValidationError::ZeroCapabilities);
                    }
                    // Disallow delegating FullAccess (security)
                    if spec.capabilities == Capability::FullAccess as u32 {
                        return Err(DelegationValidationError::FullAccessDelegation);
                    }
                    if spec.label.len() > MAX_LABEL_LENGTH {
                        return Err(DelegationValidationError::LabelTooLong {
                            len: spec.label.len(),
                        });
                    }
                    if !seen.insert(&spec.public_key) {
                        return Err(DelegationValidationError::DuplicateKey);
                    }
                }
            }
            DelegationAction::Revoke => {
                if self.revoke_pks.is_empty() {
                    return Err(DelegationValidationError::TooManyKeys { count: 0 });
                }
                for pk in &self.revoke_pks {
                    if pk.is_empty() {
                        return Err(DelegationValidationError::EmptyPublicKey);
                    }
                }
            }
        }
        Ok(())
    }

    /// Compute transaction digest for signing.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = sha3::Sha3_256::new();
        use sha3::Digest;
        h.update(b"MISAKA:cap_delegation:v1:");
        h.update(&self.master_address);
        h.update(&[self.action.clone() as u8]);
        for spec in &self.delegated_keys {
            h.update(&(spec.public_key.len() as u32).to_le_bytes());
            h.update(&spec.public_key);
            h.update(&spec.capabilities.to_le_bytes());
            h.update(&spec.daily_spend_limit.to_le_bytes());
            h.update(&spec.expiry_epoch.to_le_bytes());
        }
        for pk in &self.revoke_pks {
            h.update(&(pk.len() as u32).to_le_bytes());
            h.update(pk);
        }
        h.update(&self.fee.to_le_bytes());
        h.update(&self.nonce.to_le_bytes());
        let result = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

// Implement From for DelegationAction to u8
impl DelegationAction {
    #[allow(dead_code)]
    fn as_u8(&self) -> u8 {
        match self {
            Self::Register => 0,
            Self::Revoke => 1,
            Self::Update => 2,
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Delegated key registry
// ═══════════════════════════════════════════════════════════

/// In-memory registry of all active delegations.
///
/// QRL equivalent: state_container.slaves.data keyed by (addr, pk).
/// Production: backed by RocksDB (KeyDelegations prefix).
#[derive(Default, Debug)]
pub struct DelegatedKeyRegistry {
    /// All delegations indexed by master address.
    by_master: std::collections::HashMap<[u8; 32], Vec<DelegatedKey>>,
    /// Reverse index: delegated_pk hash → (master_address, index).
    by_delegated_pk: std::collections::HashMap<Vec<u8>, ([u8; 32], usize)>,
    /// Total active delegations.
    total_active: usize,
}

impl DelegatedKeyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new delegated key.
    ///
    /// QRL equivalent: SlaveTransaction.apply()
    pub fn register(&mut self, delegation: DelegatedKey) -> Result<(), DelegationValidationError> {
        // Check for duplicate
        if self.by_delegated_pk.contains_key(&delegation.delegated_pk) {
            return Err(DelegationValidationError::AlreadyDelegated);
        }

        let master = delegation.master_address;
        let pk = delegation.delegated_pk.clone();

        let entries = self.by_master.entry(master).or_default();
        let idx = entries.len();
        entries.push(delegation);
        self.by_delegated_pk.insert(pk, (master, idx));
        self.total_active += 1;

        Ok(())
    }

    /// Revoke a delegated key.
    pub fn revoke(
        &mut self,
        master: &[u8; 32],
        delegated_pk: &[u8],
    ) -> Result<(), DelegationValidationError> {
        if let Some((stored_master, idx)) = self.by_delegated_pk.get(delegated_pk) {
            if stored_master != master {
                return Err(DelegationValidationError::KeyNotFound);
            }
            let idx = *idx;
            if let Some(entries) = self.by_master.get_mut(master) {
                if let Some(entry) = entries.get_mut(idx) {
                    if entry.revoked {
                        return Err(DelegationValidationError::KeyNotFound);
                    }
                    entry.revoked = true;
                    self.total_active -= 1;
                    return Ok(());
                }
            }
        }
        Err(DelegationValidationError::KeyNotFound)
    }

    /// Look up a delegation by delegated public key.
    ///
    /// QRL equivalent: state_container.slaves.data[(addr, pk)]
    pub fn lookup(&self, delegated_pk: &[u8]) -> Option<&DelegatedKey> {
        let (master, idx) = self.by_delegated_pk.get(delegated_pk)?;
        let entries = self.by_master.get(master)?;
        entries.get(*idx)
    }

    /// Check if a delegated key has a specific capability.
    ///
    /// QRL equivalent: validate_slave() + allowed_access_types check.
    pub fn check_capability(
        &self,
        delegated_pk: &[u8],
        required_cap: Capability,
        current_epoch: u64,
    ) -> Result<&DelegatedKey, String> {
        let delegation = self
            .lookup(delegated_pk)
            .ok_or_else(|| "delegated key not registered".to_string())?;

        if !delegation.is_active(current_epoch) {
            return Err("delegation expired or revoked".to_string());
        }

        if !delegation.has_capability(required_cap) {
            return Err(format!(
                "capability {:?} not granted (flags=0x{:04X})",
                required_cap, delegation.capabilities
            ));
        }

        Ok(delegation)
    }

    /// Get all delegations for a master address.
    pub fn delegations_for(&self, master: &[u8; 32]) -> &[DelegatedKey] {
        self.by_master
            .get(master)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Total active delegations.
    pub fn total_active(&self) -> usize {
        self.total_active
    }

    /// Total delegations (including revoked).
    pub fn total_all(&self) -> usize {
        self.by_master.values().map(|v| v.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_master() -> [u8; 32] {
        [0xAA; 32]
    }
    fn test_pk(id: u8) -> Vec<u8> {
        vec![id; 1952]
    }

    #[test]
    #[allow(deprecated)] // `Reserved0x0010` is deprecated but exercised here
                        // to pin the bit-flag semantics of reserved variants
                        // until they get replaced (v1.0 tracking). Drop the
                        // allow once the variant is deleted.
    fn test_capability_flags() {
        let flags = capabilities_to_flags(&[Capability::SpendLimited, Capability::Reserved0x0010]);
        assert!(Capability::SpendLimited.is_in(flags));
        assert!(Capability::Reserved0x0010.is_in(flags));
        assert!(!Capability::ValidatorSignOnly.is_in(flags));
        assert!(!Capability::FullAccess.is_in(flags));
    }

    #[test]
    fn test_register_and_lookup() {
        let mut reg = DelegatedKeyRegistry::new();
        let delegation = DelegatedKey {
            master_address: test_master(),
            delegated_pk: test_pk(1),
            capabilities: Capability::ValidatorSignOnly as u32,
            daily_spend_limit: 0,
            expiry_epoch: 0,
            label: "hot key".to_string(),
            revoked: false,
            creation_tx: [0; 32],
            created_at_height: 100,
        };
        reg.register(delegation).unwrap();

        let found = reg.lookup(&test_pk(1)).unwrap();
        assert!(found.has_capability(Capability::ValidatorSignOnly));
        assert!(!found.has_capability(Capability::SpendLimited));
        assert_eq!(reg.total_active(), 1);
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut reg = DelegatedKeyRegistry::new();
        let d = DelegatedKey {
            master_address: test_master(),
            delegated_pk: test_pk(1),
            capabilities: Capability::ViewOnly as u32,
            daily_spend_limit: 0,
            expiry_epoch: 0,
            label: String::new(),
            revoked: false,
            creation_tx: [0; 32],
            created_at_height: 0,
        };
        assert!(reg.register(d.clone()).is_ok());
        assert!(matches!(
            reg.register(d),
            Err(DelegationValidationError::AlreadyDelegated)
        ));
    }

    #[test]
    fn test_revoke() {
        let mut reg = DelegatedKeyRegistry::new();
        let d = DelegatedKey {
            master_address: test_master(),
            delegated_pk: test_pk(1),
            capabilities: Capability::SpendLimited as u32,
            daily_spend_limit: 1_000_000,
            expiry_epoch: 0,
            label: "daily spend".to_string(),
            revoked: false,
            creation_tx: [0; 32],
            created_at_height: 0,
        };
        reg.register(d).unwrap();
        assert_eq!(reg.total_active(), 1);

        reg.revoke(&test_master(), &test_pk(1)).unwrap();
        assert_eq!(reg.total_active(), 0);

        // Revoked key should fail capability check
        let result = reg.check_capability(&test_pk(1), Capability::SpendLimited, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_expiry() {
        let mut reg = DelegatedKeyRegistry::new();
        let d = DelegatedKey {
            master_address: test_master(),
            delegated_pk: test_pk(1),
            capabilities: Capability::RelayerSubmitOnly as u32,
            daily_spend_limit: 0,
            expiry_epoch: 100,
            label: "temp relay".to_string(),
            revoked: false,
            creation_tx: [0; 32],
            created_at_height: 0,
        };
        reg.register(d).unwrap();

        // Before expiry
        assert!(reg
            .check_capability(&test_pk(1), Capability::RelayerSubmitOnly, 50)
            .is_ok());
        // After expiry
        assert!(reg
            .check_capability(&test_pk(1), Capability::RelayerSubmitOnly, 100)
            .is_err());
    }

    #[test]
    fn test_capability_check_wrong_cap() {
        let mut reg = DelegatedKeyRegistry::new();
        let d = DelegatedKey {
            master_address: test_master(),
            delegated_pk: test_pk(1),
            capabilities: Capability::ValidatorSignOnly as u32,
            daily_spend_limit: 0,
            expiry_epoch: 0,
            label: String::new(),
            revoked: false,
            creation_tx: [0; 32],
            created_at_height: 0,
        };
        reg.register(d).unwrap();

        // Correct capability
        assert!(reg
            .check_capability(&test_pk(1), Capability::ValidatorSignOnly, 0)
            .is_ok());
        // Wrong capability
        assert!(reg
            .check_capability(&test_pk(1), Capability::SpendLimited, 0)
            .is_err());
    }

    #[test]
    fn test_delegation_tx_validation() {
        let tx = CapabilityDelegationTx {
            master_address: test_master(),
            action: DelegationAction::Register,
            delegated_keys: vec![DelegatedKeySpec {
                public_key: test_pk(1),
                capabilities: Capability::SpendLimited as u32,
                daily_spend_limit: 1_000_000,
                expiry_epoch: 0,
                label: "daily wallet".to_string(),
            }],
            revoke_pks: vec![],
            fee: 1000,
            nonce: 0,
            signature: vec![0xAA; 64],
        };
        assert!(tx.validate_structure().is_ok());
    }

    #[test]
    fn test_full_access_delegation_rejected() {
        let tx = CapabilityDelegationTx {
            master_address: test_master(),
            action: DelegationAction::Register,
            delegated_keys: vec![DelegatedKeySpec {
                public_key: test_pk(1),
                capabilities: Capability::FullAccess as u32,
                daily_spend_limit: 0,
                expiry_epoch: 0,
                label: String::new(),
            }],
            revoke_pks: vec![],
            fee: 0,
            nonce: 0,
            signature: vec![],
        };
        assert!(matches!(
            tx.validate_structure(),
            Err(DelegationValidationError::FullAccessDelegation)
        ));
    }

    #[test]
    fn test_delegations_for_master() {
        let mut reg = DelegatedKeyRegistry::new();
        for i in 0..5 {
            reg.register(DelegatedKey {
                master_address: test_master(),
                delegated_pk: test_pk(i),
                capabilities: Capability::ViewOnly as u32,
                daily_spend_limit: 0,
                expiry_epoch: 0,
                label: format!("key-{}", i),
                revoked: false,
                creation_tx: [0; 32],
                created_at_height: 0,
            })
            .unwrap();
        }
        assert_eq!(reg.delegations_for(&test_master()).len(), 5);
        assert_eq!(reg.delegations_for(&[0xBB; 32]).len(), 0);
    }
}
