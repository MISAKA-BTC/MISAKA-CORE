//! Transaction types — PQC-native (Spec 01 §4).
//!
//! Transactions carry scheme-tagged signatures. The same transaction
//! structure works with ML-DSA-65 signers.

use sha3::{Digest as Sha3Digest, Sha3_256};

use crate::error::MisakaError;
use crate::mcs1;
use crate::scheme::{MisakaPublicKey, MisakaSignature};
use crate::{Digest, ObjectId};

/// Transaction classification for ordering (Spec 03 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxClass {
    OwnedOnly,
    Shared,
}

/// Input reference kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum InputKind {
    Owned = 0,
    Shared = 1,
    Immutable = 2,
}

/// Access mode for inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum AccessMode {
    ReadOnly = 0,
    Mutable = 1,
}

/// Reference to an input object.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InputRef {
    pub object_id: ObjectId,
    pub kind: InputKind,
    pub access: AccessMode,
    pub expected_version: Option<u64>,
    pub expected_digest: Option<Digest>,
}

/// Transaction action (command within a TX).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Action {
    pub module: String,
    pub function: String,
    pub args: Vec<Vec<u8>>,
}

/// Complete transaction with PQC-aware signature.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    pub sender: MisakaPublicKey,
    pub inputs: Vec<InputRef>,
    pub actions: Vec<Action>,
    pub gas_budget: u64,
    pub gas_price: u64,
    pub expiration_epoch: Option<u64>,
    pub signature: MisakaSignature,
}

impl Transaction {
    /// Compute tx_hash = SHA3-256(MCS-1(tx without signature)).
    pub fn tx_hash(&self) -> Digest {
        let payload = self.signing_payload();
        let mut hasher = Sha3_256::new();
        hasher.update(&payload);
        hasher.finalize().into()
    }

    /// Build the signing payload (everything except signature).
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);

        // sender pk
        self.sender.mcs1_encode(&mut buf);

        // inputs
        mcs1::write_u32(&mut buf, self.inputs.len() as u32);
        for inp in &self.inputs {
            mcs1::write_fixed(&mut buf, &inp.object_id);
            mcs1::write_u8(&mut buf, inp.kind as u8);
            mcs1::write_u8(&mut buf, inp.access as u8);
            match inp.expected_version {
                Some(v) => { mcs1::write_u8(&mut buf, 1); mcs1::write_u64(&mut buf, v); }
                None => { mcs1::write_u8(&mut buf, 0); }
            }
            match inp.expected_digest {
                Some(d) => { mcs1::write_u8(&mut buf, 1); mcs1::write_fixed(&mut buf, &d); }
                None => { mcs1::write_u8(&mut buf, 0); }
            }
        }

        // actions
        mcs1::write_u32(&mut buf, self.actions.len() as u32);
        for act in &self.actions {
            mcs1::write_bytes(&mut buf, act.module.as_bytes());
            mcs1::write_bytes(&mut buf, act.function.as_bytes());
            mcs1::write_u32(&mut buf, act.args.len() as u32);
            for arg in &act.args {
                mcs1::write_bytes(&mut buf, arg);
            }
        }

        // gas
        mcs1::write_u64(&mut buf, self.gas_budget);
        mcs1::write_u64(&mut buf, self.gas_price);

        // expiration
        match self.expiration_epoch {
            Some(e) => { mcs1::write_u8(&mut buf, 1); mcs1::write_u64(&mut buf, e); }
            None => { mcs1::write_u8(&mut buf, 0); }
        }

        buf
    }

    /// Classify this TX for DET_ORDER_V1.
    pub fn tx_class(&self) -> TxClass {
        if self.inputs.iter().any(|i| matches!(i.kind, InputKind::Shared)) {
            TxClass::Shared
        } else {
            TxClass::OwnedOnly
        }
    }

    /// Validate structural invariants (no crypto verification).
    pub fn validate_structure(&self) -> Result<(), MisakaError> {
        if self.actions.is_empty() {
            return Err(MisakaError::EmptyActions);
        }
        if self.inputs.is_empty() {
            return Err(MisakaError::EmptyInputs);
        }
        // Check no duplicate inputs
        let mut seen = std::collections::HashSet::new();
        for inp in &self.inputs {
            if !seen.insert(inp.object_id) {
                return Err(MisakaError::DuplicateInput(hex::encode(inp.object_id)));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::SignatureScheme;

    fn make_test_tx() -> Transaction {
        Transaction {
            sender: MisakaPublicKey { scheme: SignatureScheme::MlDsa65, bytes: vec![0xAA; 1952] },
            inputs: vec![InputRef {
                object_id: [0xBB; 32],
                kind: InputKind::Owned,
                access: AccessMode::Mutable,
                expected_version: Some(1),
                expected_digest: None,
            }],
            actions: vec![Action {
                module: "transfer".into(),
                function: "send".into(),
                args: vec![vec![1, 2, 3]],
            }],
            gas_budget: 1000,
            gas_price: 1,
            expiration_epoch: None,
            signature: MisakaSignature::ml_dsa(vec![0xCC; 3309]),
        }
    }

    #[test]
    fn test_tx_hash_deterministic() {
        let tx = make_test_tx();
        let h1 = tx.tx_hash();
        let h2 = tx.tx_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_tx_classification() {
        let mut tx = make_test_tx();
        assert_eq!(tx.tx_class(), TxClass::OwnedOnly);

        tx.inputs.push(InputRef {
            object_id: [0xEE; 32],
            kind: InputKind::Shared,
            access: AccessMode::Mutable,
            expected_version: None,
            expected_digest: None,
        });
        assert_eq!(tx.tx_class(), TxClass::Shared);
    }

    #[test]
    fn test_falcon_tx_hash_differs() {
        let ed_tx = make_test_tx();
        let falcon_tx = Transaction {
            sender: MisakaPublicKey {
                scheme: SignatureScheme::LatticeRing,
                bytes: vec![0xAA; 897],
            },
            signature: MisakaSignature { scheme: SignatureScheme::LatticeRing, bytes: vec![0xCC; 655] },
            ..make_test_tx()
        };
        // Different sender scheme → different hash
        assert_ne!(ed_tx.tx_hash(), falcon_tx.tx_hash());
    }

    #[test]
    fn test_validate_structure() {
        let tx = make_test_tx();
        tx.validate_structure().unwrap();
    }

    #[test]
    fn test_empty_actions_rejected() {
        let mut tx = make_test_tx();
        tx.actions.clear();
        assert!(matches!(tx.validate_structure(), Err(MisakaError::EmptyActions)));
    }
}
