//! Script classification: determine the type of a script public key.

use crate::opcodes::*;

/// The class of a script public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptClass {
    /// Pay to Public Key
    PubKey,
    /// Pay to Public Key Hash
    PubKeyHash,
    /// Pay to Script Hash
    ScriptHash,
    /// Multisig
    MultiSig,
    /// Post-Quantum Pay to Public Key
    PubKeyPQ,
    /// Post-Quantum Pay to Public Key Hash
    PubKeyHashPQ,
    /// Post-Quantum Multisig
    MultiSigPQ,
    /// Null data (OP_RETURN)
    NullData,
    /// Unrecognized script
    NonStandard,
}

impl ScriptClass {
    /// Classify a script public key.
    pub fn from_script(script: &[u8]) -> Self {
        if script.is_empty() {
            return ScriptClass::NonStandard;
        }

        // OP_RETURN ...
        if script[0] == OP_RETURN {
            return ScriptClass::NullData;
        }

        // P2PKH: OP_DUP OP_BLAKE3 PUSH32 <hash> OP_EQUALVERIFY OP_CHECKSIG
        if script.len() == 37
            && script[0] == OP_DUP
            && script[1] == OP_BLAKE3_256
            && script[2] == 32
            && script[35] == OP_EQUALVERIFY
            && script[36] == OP_CHECKSIG
        {
            return ScriptClass::PubKeyHash;
        }

        // P2PKH_PQ: same but with OP_CHECKSIG_PQ
        if script.len() == 37
            && script[0] == OP_DUP
            && script[1] == OP_BLAKE3_256
            && script[2] == 32
            && script[35] == OP_EQUALVERIFY
            && script[36] == OP_CHECKSIG_PQ
        {
            return ScriptClass::PubKeyHashPQ;
        }

        // P2SH: OP_BLAKE3 PUSH32 <hash> OP_EQUAL
        if script.len() == 35
            && script[0] == OP_BLAKE3_256
            && script[1] == 32
            && script[34] == OP_EQUAL
        {
            return ScriptClass::ScriptHash;
        }

        // P2PK: PUSH<pubkey> OP_CHECKSIG
        if script.len() > 2
            && script[0] as usize == script.len() - 2
            && script[script.len() - 1] == OP_CHECKSIG
        {
            return ScriptClass::PubKey;
        }

        // P2PK_PQ: PUSH<pubkey> OP_CHECKSIG_PQ
        if script.len() > 2
            && script[0] as usize == script.len() - 2
            && script[script.len() - 1] == OP_CHECKSIG_PQ
        {
            return ScriptClass::PubKeyPQ;
        }

        // Multisig: OP_M <pubkeys> OP_N OP_CHECKMULTISIG
        if script.len() > 3 && script.last() == Some(&OP_CHECKMULTISIG) {
            let m = script[0];
            let n = script[script.len() - 2];
            if m >= OP_1 && m <= OP_16 && n >= OP_1 && n <= OP_16 && m <= n {
                return ScriptClass::MultiSig;
            }
        }

        // PQ Multisig
        if script.len() > 3 && script.last() == Some(&OP_CHECKMULTISIG_PQ) {
            let m = script[0];
            let n = script[script.len() - 2];
            if m >= OP_1 && m <= OP_16 && n >= OP_1 && n <= OP_16 && m <= n {
                return ScriptClass::MultiSigPQ;
            }
        }

        ScriptClass::NonStandard
    }

    /// Returns true if this is a standard script class.
    pub fn is_standard(&self) -> bool {
        !matches!(self, ScriptClass::NonStandard)
    }

    /// Returns true if this is a PQ-enabled script.
    pub fn is_pq(&self) -> bool {
        matches!(
            self,
            ScriptClass::PubKeyPQ | ScriptClass::PubKeyHashPQ | ScriptClass::MultiSigPQ
        )
    }

    /// Returns the number of required signatures.
    pub fn required_sigs(&self) -> usize {
        match self {
            ScriptClass::PubKey
            | ScriptClass::PubKeyHash
            | ScriptClass::PubKeyPQ
            | ScriptClass::PubKeyHashPQ => 1,
            _ => 0, // Multisig is variable, determined by script
        }
    }
}

/// Extract the pubkey hash from a P2PKH script.
pub fn extract_pubkey_hash(script: &[u8]) -> Option<[u8; 32]> {
    let class = ScriptClass::from_script(script);
    if class == ScriptClass::PubKeyHash || class == ScriptClass::PubKeyHashPQ {
        if script.len() >= 35 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&script[3..35]);
            return Some(hash);
        }
    }
    None
}

/// Extract the script hash from a P2SH script.
pub fn extract_script_hash(script: &[u8]) -> Option<[u8; 32]> {
    if ScriptClass::from_script(script) == ScriptClass::ScriptHash {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&script[2..34]);
        return Some(hash);
    }
    None
}

/// Extract the OP_RETURN payload.
pub fn extract_null_data(script: &[u8]) -> Option<&[u8]> {
    if script.is_empty() || script[0] != OP_RETURN {
        return None;
    }
    if script.len() < 2 {
        return Some(&[]);
    }
    let data_len = script[1] as usize;
    if script.len() >= 2 + data_len {
        Some(&script[2..2 + data_len])
    } else {
        Some(&script[2..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script_builder::ScriptBuilder;

    #[test]
    fn test_classify_p2pkh() {
        let hash = [0x42u8; 32];
        let script = ScriptBuilder::p2pkh(&hash);
        assert_eq!(ScriptClass::from_script(&script), ScriptClass::PubKeyHash);
        assert_eq!(extract_pubkey_hash(&script), Some(hash));
    }

    #[test]
    fn test_classify_p2sh() {
        let hash = [0xABu8; 32];
        let script = ScriptBuilder::p2sh(&hash);
        assert_eq!(ScriptClass::from_script(&script), ScriptClass::ScriptHash);
        assert_eq!(extract_script_hash(&script), Some(hash));
    }

    #[test]
    fn test_classify_pq() {
        let hash = [0x01u8; 32];
        let script = ScriptBuilder::p2pkh_pq(&hash);
        assert_eq!(ScriptClass::from_script(&script), ScriptClass::PubKeyHashPQ);
        assert!(ScriptClass::from_script(&script).is_pq());
    }

    #[test]
    fn test_classify_op_return() {
        let script = ScriptBuilder::op_return(b"hello");
        assert_eq!(ScriptClass::from_script(&script), ScriptClass::NullData);
        assert_eq!(extract_null_data(&script), Some(&b"hello"[..]));
    }
}
