//! Versioned script types (CIP-33 reference scripts).
//!
//! Scripts are the programs that validate eUTXO spending conditions.
//! V1 uses a Bitcoin Script extension; V2/V3 are reserved for future
//! VM upgrades (WASM, ZK-VM, etc.).

use borsh::{BorshDeserialize, BorshSerialize};

/// Maximum script bytecode size.
pub const MAX_SCRIPT_SIZE: usize = 65_536;

/// Script VM version. Determines which evaluator to use (E3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum ScriptVmVersion {
    /// V1: Bitcoin Script extension with PQC opcodes.
    V1 = 1,
    /// Reserved for future VM (e.g., WASM).
    V2 = 2,
    /// Reserved for future VM (e.g., ZK-VM).
    V3 = 3,
}

impl BorshSerialize for ScriptVmVersion {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&[*self as u8])
    }
}

impl BorshDeserialize for ScriptVmVersion {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        match buf[0] {
            1 => Ok(ScriptVmVersion::V1),
            2 => Ok(ScriptVmVersion::V2),
            3 => Ok(ScriptVmVersion::V3),
            other => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown ScriptVmVersion: {}", other),
            )),
        }
    }
}

/// Script bytecode (opaque bytes interpreted by the VM).
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct ScriptBytecode(pub Vec<u8>);

/// A versioned script: VM version + bytecode.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct VersionedScript {
    pub vm_version: ScriptVmVersion,
    pub bytecode: ScriptBytecode,
}

impl VersionedScript {
    /// SHA3-256 hash of the versioned script.
    pub fn hash(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:script:v1:");
        h.update(&[self.vm_version as u8]);
        h.update(&self.bytecode.0);
        h.finalize().into()
    }

    pub fn is_valid_size(&self) -> bool {
        self.bytecode.0.len() <= MAX_SCRIPT_SIZE
    }
}

/// How a script is provided: inline in the output, or by reference (CIP-33).
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum ScriptSource {
    /// Script bytecode included inline.
    Inline(VersionedScript),
    /// Reference to a UTXO containing the script (CIP-33).
    /// The UTXO's script_ref field holds the actual bytecode.
    Reference(super::reference::ReferenceInput),
}
