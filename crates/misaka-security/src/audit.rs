//! Log sanitization and secret detection for defense-in-depth.
//!
//! Ensures that even if code accidentally passes secret material
//! toward a log sink, it is caught or redacted before emission.

/// Patterns that indicate secret material in log messages.
const SENSITIVE_PATTERNS: &[&str] = &[
    "secret_key",
    "private_key",
    "passphrase",
    "mnemonic",
    "seed_phrase",
    "api_key",
    "api_secret",
    "bearer_token",
    "auth_token",
    "password",
];

/// PEM markers that indicate raw key material.
const PEM_MARKERS: &[&str] = &[
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
];

/// Redact known sensitive patterns from a log message.
///
/// Replaces occurrences of sensitive labels with `[REDACTED]`.
/// This is best-effort defense-in-depth; do not rely on it as
/// the sole protection against secret leakage.
pub fn sanitize_log_message(msg: &str) -> String {
    let mut result = msg.to_string();
    let lower = msg.to_lowercase();

    for pattern in SENSITIVE_PATTERNS {
        if lower.contains(pattern) {
            // If ANY sensitive pattern is found, redact the ENTIRE message.
            // Partial redaction risks leaking context around the secret.
            return format!("[REDACTED: log contained '{}']", pattern);
        }
    }

    result
}

/// Simple case-insensitive redaction of `pattern=value` or `pattern: value`.
fn redact_pattern_values(input: &str, pattern: &str) -> String {
    let lower = input.to_lowercase();
    let pat_lower = pattern.to_lowercase();
    let mut result = String::with_capacity(input.len());
    let mut i = 0;
    let bytes = input.as_bytes();

    while i < bytes.len() {
        if let Some(_remaining) = lower[i..].strip_prefix(&pat_lower) {
            // Found the pattern, emit the pattern name then look for = or :
            let pat_end = i + pat_lower.len();
            result.push_str(&input[i..pat_end]);

            // Skip whitespace
            let mut j = pat_end;
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                result.push(bytes[j] as char);
                j += 1;
            }

            // If next char is = or :, redact the value
            if j < bytes.len() && (bytes[j] == b'=' || bytes[j] == b':') {
                result.push(bytes[j] as char);
                j += 1;
                // Skip whitespace after delimiter
                while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                    j += 1;
                }
                result.push_str("[REDACTED]");
                // Skip until whitespace or end
                while j < bytes.len() && bytes[j] != b' ' && bytes[j] != b'\t' && bytes[j] != b'\n' {
                    j += 1;
                }
            }

            i = j;
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }

    result
}

/// Assert that a buffer does not contain PEM key material or secret labels.
///
/// # Panics
///
/// Panics if a PEM marker or sensitive label with an assigned value is found.
/// The panic message includes the `context` string but NOT the secret material.
pub fn assert_no_secrets_in_buffer(buf: &[u8], context: &str) {
    let text = String::from_utf8_lossy(buf);
    let lower = text.to_lowercase();

    for marker in PEM_MARKERS {
        if text.contains(marker) {
            panic!(
                "SECRET DETECTED in {}: PEM private key marker found",
                context
            );
        }
    }

    for label in SENSITIVE_PATTERNS {
        // Check for label=value or label: value patterns
        let check1 = format!("{}=", label);
        let check2 = format!("{}: ", label);
        if lower.contains(&check1) || lower.contains(&check2) {
            panic!(
                "SECRET DETECTED in {}: sensitive label '{}' with value found",
                context, label
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_redacts_secret_key() {
        let msg = "config loaded secret_key=abc123def";
        let sanitized = sanitize_log_message(msg);
        assert!(!sanitized.contains("abc123def"), "value should be redacted: {}", sanitized);
        assert!(sanitized.contains("REDACTED"), "should contain REDACTED: {}", sanitized);
    }

    #[test]
    fn test_sanitize_redacts_passphrase() {
        let msg = "using passphrase=hunter2 for wallet";
        let sanitized = sanitize_log_message(msg);
        assert!(!sanitized.contains("hunter2"));
        assert!(sanitized.contains("REDACTED"));
    }

    #[test]
    fn test_sanitize_preserves_safe_messages() {
        let msg = "block 12345 validated successfully";
        let sanitized = sanitize_log_message(msg);
        assert_eq!(sanitized, msg);
    }

    #[test]
    fn test_sanitize_redacts_mnemonic() {
        let msg = "mnemonic: abandon abandon abandon";
        let sanitized = sanitize_log_message(msg);
        assert!(!sanitized.contains("abandon"));
    }

    #[test]
    fn test_assert_no_secrets_clean_buffer() {
        let buf = b"This is a normal log message with no secrets";
        // Should not panic
        assert_no_secrets_in_buffer(buf, "test");
    }

    #[test]
    #[should_panic(expected = "SECRET DETECTED")]
    fn test_assert_no_secrets_pem_key() {
        let buf = b"some text -----BEGIN PRIVATE KEY----- more text";
        assert_no_secrets_in_buffer(buf, "test-pem");
    }

    #[test]
    #[should_panic(expected = "SECRET DETECTED")]
    fn test_assert_no_secrets_labeled_value() {
        let buf = b"config secret_key=deadbeef123";
        assert_no_secrets_in_buffer(buf, "test-label");
    }

    #[test]
    fn test_assert_no_secrets_label_without_value() {
        // Just mentioning "secret_key" without = or : is OK
        let buf = b"checking if secret_key is configured";
        // Should not panic
        assert_no_secrets_in_buffer(buf, "test-mention");
    }
}
