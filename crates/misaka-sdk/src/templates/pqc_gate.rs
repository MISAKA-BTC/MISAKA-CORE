//! PQC signature gate: verify ML-DSA-65 signature over redeemer data.
//!
//! Datum: public key (ML-DSA-65, 1952 bytes).
//! Redeemer stack layout (from OP_CHECK_ML_DSA pop order):
//!   pubkey  ← popped 3rd (bottom)
//!   message ← popped 2nd
//!   signature ← popped 1st (top)
//!
//! Bytecode (pushes in order: sig, msg, pk, then verify):
//!   OP_REDEEMER           (0xC1) — push sig || msg (single blob; real scripts split)
//!   OP_DATUM              (0xC0) — push pubkey
//!   OP_CHECK_ML_DSA       (0xB0) — verify
//!   OP_VERIFY             (0x69)
//!   OP_TRUE               (0x51)

use crate::script_builder::ScriptBuilder;
use misaka_types::eutxo::script::VersionedScript;

pub const PQC_GATE_BYTECODE: &[u8] = &[0xC1, 0xC0, 0xB0, 0x69, 0x51];

pub fn pqc_signature_gate() -> VersionedScript {
    ScriptBuilder::new()
        .push_redeemer()
        .push_datum()
        .check_ml_dsa()
        .verify()
        .op_true()
        .build()
}
