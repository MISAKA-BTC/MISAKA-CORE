//! ScriptBuilder DSL — fluent API for building validator / mint policy scripts.

use misaka_protocol_config::eutxo_v2::opcodes;
use misaka_types::eutxo::script::{ScriptBytecode, ScriptVmVersion, VersionedScript};

#[derive(Clone, Debug, Default)]
pub struct ScriptBuilder {
    bytecode: Vec<u8>,
}

impl ScriptBuilder {
    pub fn new() -> Self {
        Self { bytecode: Vec::new() }
    }

    // ── Constants ──
    pub fn op_false(mut self) -> Self {
        self.bytecode.push(0x00);
        self
    }
    pub fn op_true(mut self) -> Self {
        self.bytecode.push(0x51);
        self
    }
    /// Push small int 1..=16.
    pub fn push_int(mut self, n: u8) -> Self {
        assert!(n >= 1 && n <= 16, "push_int range 1-16");
        self.bytecode.push(0x50 + n);
        self
    }

    // ── Stack ──
    pub fn dup(mut self) -> Self { self.bytecode.push(0x76); self }
    pub fn swap(mut self) -> Self { self.bytecode.push(0x7C); self }
    pub fn drop(mut self) -> Self { self.bytecode.push(0x75); self }

    // ── Arithmetic ──
    pub fn add(mut self) -> Self { self.bytecode.push(0x93); self }
    pub fn sub(mut self) -> Self { self.bytecode.push(0x94); self }
    pub fn bool_and(mut self) -> Self { self.bytecode.push(0x9A); self }
    pub fn bool_or(mut self) -> Self { self.bytecode.push(0x9B); self }

    // ── Comparison / flow ──
    pub fn equal(mut self) -> Self { self.bytecode.push(0x87); self }
    pub fn equal_verify(mut self) -> Self { self.bytecode.push(0x88); self }
    pub fn verify(mut self) -> Self { self.bytecode.push(0x69); self }
    pub fn op_return(mut self) -> Self { self.bytecode.push(0x6A); self }

    // ── eUTXO context (0xC0-0xC6) ──
    pub fn push_datum(mut self) -> Self {
        self.bytecode.push(opcodes::OPCODE_DATUM as u8);
        self
    }
    pub fn push_redeemer(mut self) -> Self {
        self.bytecode.push(opcodes::OPCODE_REDEEMER as u8);
        self
    }
    pub fn push_ref_input(mut self) -> Self {
        self.bytecode.push(opcodes::OPCODE_REF_INPUT as u8);
        self
    }
    pub fn check_valid_range(mut self) -> Self {
        self.bytecode.push(opcodes::OPCODE_CHECK_VALID_RANGE as u8);
        self
    }
    pub fn check_req_signer(mut self) -> Self {
        self.bytecode.push(opcodes::OPCODE_CHECK_REQ_SIGNER as u8);
        self
    }
    pub fn check_mint(mut self) -> Self {
        self.bytecode.push(opcodes::OPCODE_CHECK_MINT as u8);
        self
    }
    pub fn value_of(mut self) -> Self {
        self.bytecode.push(opcodes::OPCODE_VALUE_OF as u8);
        self
    }

    // ── Hash (0xA8-0xA9) ──
    pub fn sha3(mut self) -> Self {
        self.bytecode.push(opcodes::OPCODE_SHA3 as u8);
        self
    }
    pub fn keccak(mut self) -> Self {
        self.bytecode.push(opcodes::OPCODE_KECCAK as u8);
        self
    }

    // ── PQC (0xB0-0xB1) ──
    pub fn check_ml_dsa(mut self) -> Self {
        self.bytecode.push(opcodes::OPCODE_CHECK_ML_DSA as u8);
        self
    }
    pub fn check_ml_kem(mut self) -> Self {
        self.bytecode.push(opcodes::OPCODE_CHECK_ML_KEM as u8);
        self
    }

    // ── Build ──
    pub fn build(self) -> VersionedScript {
        VersionedScript {
            vm_version: ScriptVmVersion::V1,
            bytecode: ScriptBytecode(self.bytecode),
        }
    }

    pub fn bytecode(&self) -> &[u8] {
        &self.bytecode
    }

    pub fn bytecode_hex(&self) -> String {
        hex::encode(&self.bytecode)
    }
}
