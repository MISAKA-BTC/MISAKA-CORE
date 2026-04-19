//! Domain separation tags for v5 state commitment. FROZEN for v2.0 hard fork.

pub const MUHASH_UTXO_ELEMENT_V5: &[u8] = b"MISAKA:muhash:utxo:v5:";
pub const STATE_ROOT_V5: &[u8] = b"MISAKA:state_root:v5:";
pub const DATUM_BODY_HASH: &[u8] = b"MISAKA:eutxo:datum_body_hash:v1:";
pub const SCRIPT_BODY_HASH: &[u8] = b"MISAKA:eutxo:script_body_hash:v1:";
pub const EXTENDED_OUTPUT_CANONICAL: &[u8] = b"MISAKA:eutxo:extended_output:v1:";
