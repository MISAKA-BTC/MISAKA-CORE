//! Script builder for programmatic construction of scripts.

use crate::opcodes::*;
use crate::data_stack::encode_script_num;

/// Builder pattern for constructing transaction scripts.
#[derive(Debug, Clone)]
pub struct ScriptBuilder {
    script: Vec<u8>,
}

impl ScriptBuilder {
    pub fn new() -> Self { Self { script: Vec::with_capacity(128) } }

    /// Build and return the final script bytes.
    pub fn build(self) -> Vec<u8> { self.script }

    /// Get current script length.
    pub fn len(&self) -> usize { self.script.len() }
    pub fn is_empty(&self) -> bool { self.script.is_empty() }

    /// Add a raw opcode.
    pub fn opcode(mut self, op: u8) -> Self {
        self.script.push(op);
        self
    }

    /// Push arbitrary data onto the stack.
    pub fn push_data(mut self, data: &[u8]) -> Self {
        let len = data.len();
        if len == 0 {
            self.script.push(OP_0);
        } else if len <= 75 {
            self.script.push(len as u8);
            self.script.extend_from_slice(data);
        } else if len <= 255 {
            self.script.push(OP_PUSHDATA1);
            self.script.push(len as u8);
            self.script.extend_from_slice(data);
        } else if len <= 65535 {
            self.script.push(OP_PUSHDATA2);
            self.script.extend_from_slice(&(len as u16).to_le_bytes());
            self.script.extend_from_slice(data);
        } else {
            self.script.push(OP_PUSHDATA4);
            self.script.extend_from_slice(&(len as u32).to_le_bytes());
            self.script.extend_from_slice(data);
        }
        self
    }

    /// Push an integer as a script number.
    pub fn push_int(self, val: i64) -> Self {
        if val == 0 {
            return self.opcode(OP_0);
        }
        if val == -1 {
            return self.opcode(OP_1NEGATE);
        }
        if val >= 1 && val <= 16 {
            return self.opcode(OP_1 + (val as u8) - 1);
        }
        let bytes = encode_script_num(val);
        self.push_data(&bytes)
    }

    /// Push a boolean.
    pub fn push_bool(self, val: bool) -> Self {
        if val { self.opcode(OP_TRUE) } else { self.opcode(OP_FALSE) }
    }

    /// Push a 32-byte hash.
    pub fn push_hash(self, hash: &[u8; 32]) -> Self {
        self.push_data(hash)
    }

    // ─── Standard script templates ────────────────────

    /// Pay to Public Key Hash (P2PKH): OP_DUP OP_BLAKE3 OP_PUSH<hash> OP_EQUALVERIFY OP_CHECKSIG
    pub fn p2pkh(pubkey_hash: &[u8; 32]) -> Vec<u8> {
        ScriptBuilder::new()
            .opcode(OP_DUP)
            .opcode(OP_BLAKE3_256)
            .push_hash(pubkey_hash)
            .opcode(OP_EQUALVERIFY)
            .opcode(OP_CHECKSIG)
            .build()
    }

    /// Pay to Public Key (P2PK): OP_PUSH<pubkey> OP_CHECKSIG
    pub fn p2pk(pubkey: &[u8]) -> Vec<u8> {
        ScriptBuilder::new()
            .push_data(pubkey)
            .opcode(OP_CHECKSIG)
            .build()
    }

    /// Pay to Script Hash (P2SH): OP_BLAKE3 OP_PUSH<hash> OP_EQUAL
    pub fn p2sh(script_hash: &[u8; 32]) -> Vec<u8> {
        ScriptBuilder::new()
            .opcode(OP_BLAKE3_256)
            .push_hash(script_hash)
            .opcode(OP_EQUAL)
            .build()
    }

    /// P2PKH with PQ signature: OP_DUP OP_BLAKE3 OP_PUSH<hash> OP_EQUALVERIFY OP_CHECKSIG_PQ
    pub fn p2pkh_pq(pubkey_hash: &[u8; 32]) -> Vec<u8> {
        ScriptBuilder::new()
            .opcode(OP_DUP)
            .opcode(OP_BLAKE3_256)
            .push_hash(pubkey_hash)
            .opcode(OP_EQUALVERIFY)
            .opcode(OP_CHECKSIG_PQ)
            .build()
    }

    /// P2PK with PQ signature.
    pub fn p2pk_pq(pubkey: &[u8]) -> Vec<u8> {
        ScriptBuilder::new()
            .push_data(pubkey)
            .opcode(OP_CHECKSIG_PQ)
            .build()
    }

    /// Multisig: OP_M <pubkeys> OP_N OP_CHECKMULTISIG
    pub fn multisig(required: usize, pubkeys: &[Vec<u8>]) -> Vec<u8> {
        let mut b = ScriptBuilder::new().push_int(required as i64);
        for pk in pubkeys {
            b = b.push_data(pk);
        }
        b.push_int(pubkeys.len() as i64)
            .opcode(OP_CHECKMULTISIG)
            .build()
    }

    /// PQ Multisig.
    pub fn multisig_pq(required: usize, pubkeys: &[Vec<u8>]) -> Vec<u8> {
        let mut b = ScriptBuilder::new().push_int(required as i64);
        for pk in pubkeys {
            b = b.push_data(pk);
        }
        b.push_int(pubkeys.len() as i64)
            .opcode(OP_CHECKMULTISIG_PQ)
            .build()
    }

    /// OP_RETURN with arbitrary data payload.
    pub fn op_return(data: &[u8]) -> Vec<u8> {
        ScriptBuilder::new()
            .opcode(OP_RETURN)
            .push_data(data)
            .build()
    }

    /// Time-locked script: OP_PUSH<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <inner_script>
    pub fn time_locked(lock_time: u64, inner: &[u8]) -> Vec<u8> {
        let mut b = ScriptBuilder::new()
            .push_int(lock_time as i64)
            .opcode(OP_CHECKLOCKTIMEVERIFY)
            .opcode(OP_DROP);
        b.script.extend_from_slice(inner);
        b.build()
    }
}

impl Default for ScriptBuilder {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2pkh_script() {
        let hash = [0xABu8; 32];
        let script = ScriptBuilder::p2pkh(&hash);
        assert_eq!(script[0], OP_DUP);
        assert_eq!(script[1], OP_BLAKE3_256);
        assert_eq!(script[2], 32); // Push 32 bytes
        assert_eq!(&script[3..35], &hash);
        assert_eq!(script[35], OP_EQUALVERIFY);
        assert_eq!(script[36], OP_CHECKSIG);
    }

    #[test]
    fn test_push_int_small() {
        let script = ScriptBuilder::new().push_int(5).build();
        assert_eq!(script, vec![OP_5]);
    }

    #[test]
    fn test_push_int_large() {
        let script = ScriptBuilder::new().push_int(1000).build();
        assert!(script.len() > 1);
    }

    #[test]
    fn test_multisig() {
        let keys: Vec<Vec<u8>> = (0..3).map(|i| vec![i; 33]).collect();
        let script = ScriptBuilder::multisig(2, &keys);
        assert_eq!(script[0], OP_2); // M=2
        assert_eq!(*script.last().unwrap(), OP_CHECKMULTISIG);
    }
}
