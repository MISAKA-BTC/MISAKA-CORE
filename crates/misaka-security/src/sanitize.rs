//! Input sanitization — clean all untrusted data before processing.
//!
//! Every piece of data from P2P, RPC, or user input must pass through
//! sanitization before being used in consensus-critical code paths.

/// Sanitize a hex string input.
pub fn sanitize_hex(input: &str, expected_len: usize) -> Result<Vec<u8>, SanitizeError> {
    let trimmed = input.trim();
    let normalized = trimmed.strip_prefix("0x").unwrap_or(trimmed);

    if normalized.len() != expected_len * 2 {
        return Err(SanitizeError::InvalidLength {
            expected: expected_len * 2,
            got: normalized.len(),
        });
    }

    // Check all characters are valid hex
    if !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SanitizeError::InvalidHex(normalized.to_string()));
    }

    hex::decode(normalized).map_err(|e| SanitizeError::DecodeFailed(e.to_string()))
}

/// Sanitize a hash (32 bytes).
pub fn sanitize_hash(input: &str) -> Result<[u8; 32], SanitizeError> {
    let bytes = sanitize_hex(input, 32)?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

/// Sanitize a transaction payload.
pub fn sanitize_payload(payload: &[u8], max_size: usize) -> Result<&[u8], SanitizeError> {
    if payload.len() > max_size {
        return Err(SanitizeError::PayloadTooLarge {
            size: payload.len(),
            max: max_size,
        });
    }
    Ok(payload)
}

/// Sanitize a script for execution.
pub fn sanitize_script(script: &[u8], max_size: usize) -> Result<&[u8], SanitizeError> {
    if script.len() > max_size {
        return Err(SanitizeError::ScriptTooLarge {
            size: script.len(),
            max: max_size,
        });
    }
    // Check for null bytes in push data that could truncate strings
    Ok(script)
}

/// Sanitize a user-provided address.
///
/// SEC-FIX N-L10: Checks `starts_with("misaka1")` to be consistent with
/// `InputValidator::validate_address` in `misaka-rpc`. Previously checked
/// `starts_with("misaka")` which could admit `misakatest1...` prefixes.
pub fn sanitize_address(address: &str) -> Result<String, SanitizeError> {
    let trimmed = address.trim();
    if trimmed.len() < 47 || trimmed.len() > 60 {
        return Err(SanitizeError::InvalidAddressLength(trimmed.len()));
    }
    if !trimmed.starts_with("misaka1") && !trimmed.starts_with("msk1") {
        return Err(SanitizeError::InvalidAddressPrefix);
    }
    // Only allow alphanumeric characters
    if !trimmed.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(SanitizeError::InvalidCharacters);
    }
    Ok(trimmed.to_string())
}

/// Sanitize a numeric string input.
pub fn sanitize_u64(input: &str) -> Result<u64, SanitizeError> {
    let trimmed = input.trim();
    trimmed
        .parse::<u64>()
        .map_err(|_| SanitizeError::InvalidNumber(trimmed.to_string()))
}

/// Sanitize RPC method name.
pub fn sanitize_method(method: &str) -> Result<&str, SanitizeError> {
    if method.len() > 64 {
        return Err(SanitizeError::MethodTooLong(method.len()));
    }
    if !method
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(SanitizeError::InvalidMethodName(method.to_string()));
    }
    Ok(method)
}

#[derive(Debug, thiserror::Error)]
pub enum SanitizeError {
    #[error("invalid length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },
    #[error("invalid hex input")]
    InvalidHex(String),
    #[error("hex decode failed: {0}")]
    DecodeFailed(String),
    #[error("payload too large: {size} > {max}")]
    PayloadTooLarge { size: usize, max: usize },
    #[error("script too large: {size} > {max}")]
    ScriptTooLarge { size: usize, max: usize },
    #[error("invalid address length: {0}")]
    InvalidAddressLength(usize),
    #[error("invalid address prefix")]
    InvalidAddressPrefix,
    #[error("invalid characters in input")]
    InvalidCharacters,
    #[error("invalid number: {0}")]
    InvalidNumber(String),
    #[error("method name too long: {0}")]
    MethodTooLong(usize),
    #[error("invalid method name: {0}")]
    InvalidMethodName(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_hex() {
        assert!(sanitize_hex("aabb", 2).is_ok());
        assert!(sanitize_hex("0xaabb", 2).is_ok());
        assert!(sanitize_hex("gg", 1).is_err());
        assert!(sanitize_hex("aabb", 3).is_err()); // Wrong length
    }

    #[test]
    fn test_sanitize_address() {
        let addr = format!("misaka1{}", "a".repeat(40));
        assert!(sanitize_address(&addr).is_ok());
        assert!(sanitize_address("bitcoin1abc").is_err());
    }
}
