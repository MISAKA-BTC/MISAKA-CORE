//! Block conversion utilities.

pub fn internal_hash_to_hex(hash: &[u8; 32]) -> String {
    hex::encode(hash)
}

pub fn hex_to_hash(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}
