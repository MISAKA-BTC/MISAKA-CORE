//! NFT mint policy: exactly 1 unit of the asset must be minted.
//!
//! Redeemer: asset_name bytes (pushed to stack).
//! Datum: policy hash (this script's own hash).
//!
//! Bytecode:
//!   OP_DATUM      (0xC0) — push policy hash
//!   OP_REDEEMER   (0xC1) — push asset_name
//!   OP_1          (0x51) — push amount = 1
//!   OP_CHECK_MINT (0xC5) — verify mint entry (amount, asset_name, policy)
//!   OP_VERIFY     (0x69)
//!   OP_TRUE       (0x51)

use crate::script_builder::ScriptBuilder;
use misaka_types::eutxo::script::VersionedScript;

pub const NFT_MINT_BYTECODE: &[u8] = &[0xC0, 0xC1, 0x51, 0xC5, 0x69, 0x51];

pub fn nft_mint_policy() -> VersionedScript {
    ScriptBuilder::new()
        .push_datum()
        .push_redeemer()
        .push_int(1)
        .check_mint()
        .verify()
        .op_true()
        .build()
}
