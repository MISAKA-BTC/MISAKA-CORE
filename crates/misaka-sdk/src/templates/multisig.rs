//! Single-owner validator: owner's pubkey hash in datum, checked against required_signers.
//!
//! Bytecode:
//!   OP_DATUM            (0xC0) — push owner pubkey hash from datum
//!   OP_CHECK_REQ_SIGNER (0xC4) — check hash in required_signers
//!   OP_VERIFY           (0x69) — abort if not found
//!   OP_TRUE             (0x51) — success

use crate::script_builder::ScriptBuilder;
use misaka_types::eutxo::script::VersionedScript;

pub const SINGLE_OWNER_BYTECODE: &[u8] = &[0xC0, 0xC4, 0x69, 0x51];

pub fn single_owner_validator() -> VersionedScript {
    ScriptBuilder::new()
        .push_datum()
        .check_req_signer()
        .verify()
        .op_true()
        .build()
}
