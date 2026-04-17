//! Time-locked validator: datum contains deadline slot.
//! Tx must be valid within the slot range declared by its validity_interval.
//!
//! Bytecode:
//!   OP_DATUM             (0xC0)
//!   OP_CHECK_VALID_RANGE (0xC3)
//!   OP_VERIFY            (0x69)
//!   OP_TRUE              (0x51)

use crate::script_builder::ScriptBuilder;
use misaka_types::eutxo::script::VersionedScript;

pub const TIMELOCK_BEFORE_BYTECODE: &[u8] = &[0xC0, 0xC3, 0x69, 0x51];

pub fn timelock_before_validator() -> VersionedScript {
    ScriptBuilder::new()
        .push_datum()
        .check_valid_range()
        .verify()
        .op_true()
        .build()
}
