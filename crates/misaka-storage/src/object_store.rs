// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Object Store — versioned key-value store for smart contract state.
//!
//! Each Object is keyed by ObjectId (32 bytes).
//! Version is checked on write (optimistic concurrency control):
//! - write succeeds only if current_version == expected_version
//! - version is incremented atomically on each mutation
//!
//! Phase 1: InMemoryObjectStore (HashMap-backed)
//! Phase 2: RocksDB column family "objects"

use misaka_types::error::MisakaError;
use misaka_types::object::{Object, OwnerKind};
use misaka_types::Address;
use misaka_types::ObjectId;
use sha3::{Digest as Sha3Digest, Sha3_256};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════
//  Object mutation
// ═══════════════════════════════════════════════════════════

/// Object mutation produced by VM execution.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ObjectMutation {
    /// Create a new object (id must not exist).
    Create(Object),
    /// Mutate an existing object's data (version must match).
    Mutate {
        id: ObjectId,
        expected_version: u64,
        new_data: Vec<u8>,
    },
    /// Delete an object (version must match).
    Delete { id: ObjectId, expected_version: u64 },
    /// Transfer ownership (version must match).
    Transfer {
        id: ObjectId,
        expected_version: u64,
        new_owner: Address,
        new_owner_kind: OwnerKind,
    },
    /// Freeze: make immutable (irreversible).
    Freeze { id: ObjectId, expected_version: u64 },
}

// ═══════════════════════════════════════════════════════════
//  Object store trait
// ═══════════════════════════════════════════════════════════

/// Versioned object store trait.
///
/// Implementations: InMemoryObjectStore (test/dev), RocksDB (production).
pub trait ObjectStoreAccess: Send + Sync {
    /// Read an object by ID. Returns None if not found.
    fn get(&self, id: &ObjectId) -> Result<Option<Object>, MisakaError>;

    /// Apply a batch of mutations atomically.
    /// All version checks must pass, or the entire batch is rejected.
    fn apply_mutations(&mut self, mutations: &[ObjectMutation]) -> Result<(), MisakaError>;

    /// List objects owned by an address (for wallet scanning).
    fn objects_by_owner(&self, owner: &Address) -> Result<Vec<Object>, MisakaError>;

    /// Number of stored objects.
    fn len(&self) -> usize;

    /// Compute Merkle root of all objects (for state root commitment).
    fn compute_object_root(&self) -> [u8; 32];
}

// ═══════════════════════════════════════════════════════════
//  In-memory implementation
// ═══════════════════════════════════════════════════════════

/// In-memory object store backed by HashMap.
///
/// Suitable for testing and development.
/// Production uses RocksDB column family.
pub struct InMemoryObjectStore {
    objects: HashMap<ObjectId, Object>,
}

impl InMemoryObjectStore {
    pub fn new() -> Self {
        Self {
            objects: HashMap::new(),
        }
    }

    pub fn put(&mut self, obj: Object) {
        self.objects.insert(obj.id, obj);
    }

    pub fn get_ref(&self, id: &ObjectId) -> Option<&Object> {
        self.objects.get(id)
    }

    pub fn delete(&mut self, id: &ObjectId) -> bool {
        self.objects.remove(id).is_some()
    }

    /// Validate all version checks without applying.
    fn validate_versions(&self, mutations: &[ObjectMutation]) -> Result<(), MisakaError> {
        for m in mutations {
            match m {
                ObjectMutation::Create(obj) => {
                    if self.objects.contains_key(&obj.id) {
                        return Err(MisakaError::ObjectNotFound(format!(
                            "object already exists: {}",
                            hex::encode(obj.id)
                        )));
                    }
                }
                ObjectMutation::Mutate {
                    id,
                    expected_version,
                    ..
                }
                | ObjectMutation::Delete {
                    id,
                    expected_version,
                    ..
                }
                | ObjectMutation::Transfer {
                    id,
                    expected_version,
                    ..
                }
                | ObjectMutation::Freeze {
                    id,
                    expected_version,
                    ..
                } => {
                    let obj = self
                        .objects
                        .get(id)
                        .ok_or_else(|| MisakaError::ObjectNotFound(hex::encode(id)))?;
                    if obj.version != *expected_version {
                        return Err(MisakaError::VersionMismatch {
                            expected: *expected_version,
                            got: obj.version,
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

impl Default for InMemoryObjectStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectStoreAccess for InMemoryObjectStore {
    fn get(&self, id: &ObjectId) -> Result<Option<Object>, MisakaError> {
        Ok(self.objects.get(id).cloned())
    }

    fn apply_mutations(&mut self, mutations: &[ObjectMutation]) -> Result<(), MisakaError> {
        // Phase 1: validate all versions first
        self.validate_versions(mutations)?;

        // Phase 2: apply all mutations (validation passed)
        for m in mutations {
            match m {
                ObjectMutation::Create(obj) => {
                    self.objects.insert(obj.id, obj.clone());
                }
                ObjectMutation::Mutate { id, new_data, .. } => {
                    if let Some(obj) = self.objects.get_mut(id) {
                        obj.data = new_data.clone();
                        obj.version += 1;
                    }
                }
                ObjectMutation::Delete { id, .. } => {
                    self.objects.remove(id);
                }
                ObjectMutation::Transfer {
                    id,
                    new_owner,
                    new_owner_kind,
                    ..
                } => {
                    if let Some(obj) = self.objects.get_mut(id) {
                        obj.owner = *new_owner;
                        obj.owner_kind = *new_owner_kind;
                        obj.version += 1;
                    }
                }
                ObjectMutation::Freeze { id, .. } => {
                    if let Some(obj) = self.objects.get_mut(id) {
                        obj.owner_kind = OwnerKind::Immutable;
                        obj.version += 1;
                    }
                }
            }
        }
        Ok(())
    }

    fn objects_by_owner(&self, owner: &Address) -> Result<Vec<Object>, MisakaError> {
        Ok(self
            .objects
            .values()
            .filter(|obj| obj.owner == *owner)
            .cloned()
            .collect())
    }

    fn len(&self) -> usize {
        self.objects.len()
    }

    fn compute_object_root(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:object_root:v1:");

        // Sort by ObjectId for deterministic root
        let mut sorted: Vec<_> = self.objects.values().collect();
        sorted.sort_by_key(|o| o.id);

        for obj in sorted {
            let d: [u8; 32] = obj.digest();
            h.update(&d);
        }

        h.finalize().into()
    }
}

// ═══════════════════════════════════════════════════════════
//  Contract event
// ═══════════════════════════════════════════════════════════

/// Event emitted by a smart contract during execution.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContractEvent {
    /// Event tag (e.g., "transfer", "mint", "burn").
    pub tag: String,
    /// Serialized event data.
    pub data: Vec<u8>,
    /// Contract module that emitted this event.
    pub module: String,
    /// Transaction hash.
    pub tx_hash: [u8; 32],
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_obj(id: u8, version: u64) -> Object {
        Object {
            id: [id; 32],
            version,
            owner_kind: OwnerKind::AddressOwner,
            owner: [0xBB; 32],
            type_tag: "coin".into(),
            data: vec![1, 2, 3],
        }
    }

    #[test]
    fn test_create_and_read() {
        let mut store = InMemoryObjectStore::new();
        let obj = test_obj(1, 0);
        store
            .apply_mutations(&[ObjectMutation::Create(obj.clone())])
            .unwrap();
        let got = store.get(&[1; 32]).unwrap().unwrap();
        assert_eq!(got.version, 0);
        assert_eq!(got.data, vec![1, 2, 3]);
    }

    #[test]
    fn test_mutate_increments_version() {
        let mut store = InMemoryObjectStore::new();
        store
            .apply_mutations(&[ObjectMutation::Create(test_obj(1, 0))])
            .unwrap();

        store
            .apply_mutations(&[ObjectMutation::Mutate {
                id: [1; 32],
                expected_version: 0,
                new_data: vec![4, 5, 6],
            }])
            .unwrap();

        let obj = store.get(&[1; 32]).unwrap().unwrap();
        assert_eq!(obj.version, 1);
        assert_eq!(obj.data, vec![4, 5, 6]);
    }

    #[test]
    fn test_version_mismatch_rejected() {
        let mut store = InMemoryObjectStore::new();
        store
            .apply_mutations(&[ObjectMutation::Create(test_obj(1, 0))])
            .unwrap();

        let result = store.apply_mutations(&[ObjectMutation::Mutate {
            id: [1; 32],
            expected_version: 99, // wrong!
            new_data: vec![],
        }]);
        assert!(result.is_err());
    }

    #[test]
    fn test_delete() {
        let mut store = InMemoryObjectStore::new();
        store
            .apply_mutations(&[ObjectMutation::Create(test_obj(1, 0))])
            .unwrap();
        store
            .apply_mutations(&[ObjectMutation::Delete {
                id: [1; 32],
                expected_version: 0,
            }])
            .unwrap();
        assert!(store.get(&[1; 32]).unwrap().is_none());
    }

    #[test]
    fn test_transfer() {
        let mut store = InMemoryObjectStore::new();
        store
            .apply_mutations(&[ObjectMutation::Create(test_obj(1, 0))])
            .unwrap();

        let new_owner = [0xCC; 32];
        store
            .apply_mutations(&[ObjectMutation::Transfer {
                id: [1; 32],
                expected_version: 0,
                new_owner,
                new_owner_kind: OwnerKind::SharedOwner,
            }])
            .unwrap();

        let obj = store.get(&[1; 32]).unwrap().unwrap();
        assert_eq!(obj.owner, new_owner);
        assert_eq!(obj.owner_kind, OwnerKind::SharedOwner);
        assert_eq!(obj.version, 1);
    }

    #[test]
    fn test_freeze() {
        let mut store = InMemoryObjectStore::new();
        store
            .apply_mutations(&[ObjectMutation::Create(test_obj(1, 0))])
            .unwrap();
        store
            .apply_mutations(&[ObjectMutation::Freeze {
                id: [1; 32],
                expected_version: 0,
            }])
            .unwrap();

        let obj = store.get(&[1; 32]).unwrap().unwrap();
        assert_eq!(obj.owner_kind, OwnerKind::Immutable);
    }

    #[test]
    fn test_duplicate_create_rejected() {
        let mut store = InMemoryObjectStore::new();
        store
            .apply_mutations(&[ObjectMutation::Create(test_obj(1, 0))])
            .unwrap();
        let result = store.apply_mutations(&[ObjectMutation::Create(test_obj(1, 0))]);
        assert!(result.is_err());
    }

    #[test]
    fn test_objects_by_owner() {
        let mut store = InMemoryObjectStore::new();
        let owner = [0xBB; 32];
        store
            .apply_mutations(&[
                ObjectMutation::Create(test_obj(1, 0)),
                ObjectMutation::Create(test_obj(2, 0)),
            ])
            .unwrap();
        let owned = store.objects_by_owner(&owner).unwrap();
        assert_eq!(owned.len(), 2);
    }

    #[test]
    fn test_object_root_deterministic() {
        let mut store = InMemoryObjectStore::new();
        store
            .apply_mutations(&[
                ObjectMutation::Create(test_obj(2, 0)),
                ObjectMutation::Create(test_obj(1, 0)),
            ])
            .unwrap();
        let r1 = store.compute_object_root();
        let r2 = store.compute_object_root();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_atomic_batch_rollback() {
        let mut store = InMemoryObjectStore::new();
        store
            .apply_mutations(&[ObjectMutation::Create(test_obj(1, 0))])
            .unwrap();

        // Batch: valid mutate + invalid mutate (wrong version)
        let result = store.apply_mutations(&[
            ObjectMutation::Mutate {
                id: [1; 32],
                expected_version: 0,
                new_data: vec![9],
            },
            ObjectMutation::Mutate {
                id: [1; 32],
                expected_version: 99,
                new_data: vec![10],
            },
        ]);
        // Should fail because second mutation has wrong version
        assert!(result.is_err());
        // Original data should be unchanged (atomic rollback)
        let obj = store.get(&[1; 32]).unwrap().unwrap();
        assert_eq!(obj.data, vec![1, 2, 3]); // unchanged
    }
}
