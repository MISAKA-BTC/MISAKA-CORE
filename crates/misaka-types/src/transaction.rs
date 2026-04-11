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

// ═══════════════════════════════════════════════════════════
//  Hard bounds — Mochimo-inspired wire-level safety
// ═══════════════════════════════════════════════════════════

/// Maximum inputs per transaction.
pub const MAX_INPUTS: usize = 256;

/// Maximum actions per transaction.
pub const MAX_ACTIONS: usize = 64;

/// Maximum args per action.
pub const MAX_ARGS_PER_ACTION: usize = 32;

/// Maximum total args size per action (bytes).
pub const MAX_ARGS_TOTAL_BYTES: usize = 65_536;

/// Maximum module name length.
pub const MAX_MODULE_NAME_LEN: usize = 128;

/// Maximum function name length.
pub const MAX_FUNCTION_NAME_LEN: usize = 128;

/// Minimum gas price (prevent zero-fee spam).
pub const MIN_GAS_PRICE: u64 = 1;

/// Maximum gas budget.
pub const MAX_GAS_BUDGET: u64 = 100_000_000_000; // 100B

/// Expected ML-DSA-65 signature size.
pub const MLDSA65_SIG_SIZE: usize = 3309;

/// Block-to-live: max epochs ahead for expiration (Mochimo-inspired).
pub const MAX_EXPIRATION_EPOCHS_AHEAD: u64 = 256;

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
                Some(v) => {
                    mcs1::write_u8(&mut buf, 1);
                    mcs1::write_u64(&mut buf, v);
                }
                None => {
                    mcs1::write_u8(&mut buf, 0);
                }
            }
            match inp.expected_digest {
                Some(d) => {
                    mcs1::write_u8(&mut buf, 1);
                    mcs1::write_fixed(&mut buf, &d);
                }
                None => {
                    mcs1::write_u8(&mut buf, 0);
                }
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
            Some(e) => {
                mcs1::write_u8(&mut buf, 1);
                mcs1::write_u64(&mut buf, e);
            }
            None => {
                mcs1::write_u8(&mut buf, 0);
            }
        }

        buf
    }

    /// Classify this TX for DET_ORDER_V1.
    pub fn tx_class(&self) -> TxClass {
        if self
            .inputs
            .iter()
            .any(|i| matches!(i.kind, InputKind::Shared))
        {
            TxClass::Shared
        } else {
            TxClass::OwnedOnly
        }
    }

    /// Validate structural invariants (no crypto verification).
    ///
    /// Mochimo-inspired hard bounds:
    /// 1. Non-empty inputs and actions
    /// 2. Hard caps on input/action/args counts
    /// 3. Size bounds on module/function names and args
    /// 4. Gas sanity (min price, max budget)
    /// 5. Signature size matches scheme
    /// 6. No duplicate inputs
    pub fn validate_structure(&self) -> Result<(), MisakaError> {
        // ── Non-empty ──
        if self.actions.is_empty() {
            return Err(MisakaError::EmptyActions);
        }
        if self.inputs.is_empty() {
            return Err(MisakaError::EmptyInputs);
        }

        // ── Hard caps (Mochimo-inspired) ──
        if self.inputs.len() > MAX_INPUTS {
            return Err(MisakaError::TooManyInputs {
                count: self.inputs.len(),
                max: MAX_INPUTS,
            });
        }
        if self.actions.len() > MAX_ACTIONS {
            return Err(MisakaError::TooManyActions {
                count: self.actions.len(),
                max: MAX_ACTIONS,
            });
        }

        // ── Per-action bounds ──
        for act in &self.actions {
            if act.module.len() > MAX_MODULE_NAME_LEN {
                return Err(MisakaError::ModuleNameTooLong {
                    len: act.module.len(),
                    max: MAX_MODULE_NAME_LEN,
                });
            }
            if act.function.len() > MAX_FUNCTION_NAME_LEN {
                return Err(MisakaError::FunctionNameTooLong {
                    len: act.function.len(),
                    max: MAX_FUNCTION_NAME_LEN,
                });
            }
            // R7 M-2: Enforce per-action argument count limit
            if act.args.len() > MAX_ARGS_PER_ACTION {
                return Err(MisakaError::TooManyArgsPerAction {
                    count: act.args.len(),
                    max: MAX_ARGS_PER_ACTION,
                });
            }
            let total_args_size: usize = act.args.iter().map(|a| a.len()).sum();
            if total_args_size > MAX_ARGS_TOTAL_BYTES {
                return Err(MisakaError::ActionArgsTooLarge {
                    size: total_args_size,
                    max: MAX_ARGS_TOTAL_BYTES,
                });
            }
        }

        // ── Gas sanity ──
        if self.gas_price < MIN_GAS_PRICE {
            return Err(MisakaError::GasPriceTooLow {
                price: self.gas_price,
                min: MIN_GAS_PRICE,
            });
        }
        if self.gas_budget > MAX_GAS_BUDGET {
            return Err(MisakaError::GasBudgetTooHigh {
                budget: self.gas_budget,
                max: MAX_GAS_BUDGET,
            });
        }

        // ── Signature size check ──
        let expected_sig_size = match self.signature.scheme {
            crate::scheme::SignatureScheme::MlDsa65 => MLDSA65_SIG_SIZE,
            _ => 0, // other schemes validated elsewhere
        };
        if expected_sig_size > 0 && self.signature.bytes.len() != expected_sig_size {
            return Err(MisakaError::SignatureSizeMismatch {
                expected: expected_sig_size,
                got: self.signature.bytes.len(),
            });
        }

        // ── Duplicate input check ──
        let mut seen = std::collections::HashSet::new();
        for inp in &self.inputs {
            if !seen.insert(inp.object_id) {
                return Err(MisakaError::DuplicateInput(hex::encode(inp.object_id)));
            }
        }

        Ok(())
    }

    /// Validate expiration against current epoch.
    ///
    /// Mochimo's "block-to-live" concept: TXs expire after a bounded window.
    pub fn validate_expiration(&self, current_epoch: u64) -> Result<(), MisakaError> {
        if let Some(exp) = self.expiration_epoch {
            if exp < current_epoch {
                return Err(MisakaError::TransactionExpired {
                    tx_epoch: exp,
                    current_epoch,
                });
            }
            if exp > current_epoch + MAX_EXPIRATION_EPOCHS_AHEAD {
                return Err(MisakaError::TransactionExpired {
                    tx_epoch: exp,
                    current_epoch,
                });
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
            sender: MisakaPublicKey {
                scheme: SignatureScheme::MlDsa65,
                bytes: vec![0xAA; 1952],
            },
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
    fn test_different_sender_tx_hash_differs() {
        let ed_tx = make_test_tx();
        let other_tx = Transaction {
            sender: MisakaPublicKey {
                scheme: SignatureScheme::MlDsa65,
                bytes: vec![0xAA; 1952],
            },
            signature: MisakaSignature {
                scheme: SignatureScheme::MlDsa65,
                bytes: vec![0xCC; 3309],
            },
            ..make_test_tx()
        };
        // Different sender bytes → different hash
        assert_ne!(ed_tx.tx_hash(), other_tx.tx_hash());
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
        assert!(matches!(
            tx.validate_structure(),
            Err(MisakaError::EmptyActions)
        ));
    }
}
