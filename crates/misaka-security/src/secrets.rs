//! Secrets management with zeroize-on-drop and redacted display.
//!
//! Provides `Secret<T>` for holding sensitive values that are:
//! - Automatically zeroed when dropped
//! - Redacted in Debug/Display output
//! - Loaded from environment variables with validation

use std::fmt;
use zeroize::Zeroize;

/// A wrapper that zeroizes its contents on drop and redacts Debug/Display.
pub struct Secret<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> Secret<T> {
    /// Wrap a value as a secret.
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    /// Access the secret value. Callers must not log or display the result.
    pub fn expose(&self) -> &T {
        &self.inner
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: Zeroize> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Errors from secret loading and validation.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("required environment variable not set: {0}")]
    MissingEnvVar(String),
    #[error("secret validation failed: {0}")]
    ValidationFailed(String),
}

/// Load a required secret from an environment variable.
/// Returns an error if the variable is not set or is empty.
pub fn from_env(var_name: &str) -> Result<Secret<String>, SecretError> {
    match std::env::var(var_name) {
        Ok(val) if !val.is_empty() => Ok(Secret::new(val)),
        Ok(_) => Err(SecretError::MissingEnvVar(format!(
            "{} is set but empty",
            var_name
        ))),
        Err(_) => Err(SecretError::MissingEnvVar(var_name.to_string())),
    }
}

/// Load an optional secret from an environment variable.
/// Returns `None` if the variable is not set.
pub fn from_env_optional(var_name: &str) -> Option<Secret<String>> {
    std::env::var(var_name)
        .ok()
        .filter(|v| !v.is_empty())
        .map(Secret::new)
}

/// Chain IDs that require a validator passphrase.
const MAINNET_CHAIN_IDS: &[u64] = &[1, 100];

/// Validate that all required secrets are present for the given chain.
///
/// On mainnet (chain_id 1 or 100), `MISAKA_VALIDATOR_PASSPHRASE` must be set.
pub fn validate_required_secrets(chain_id: u64) -> Result<(), SecretError> {
    if MAINNET_CHAIN_IDS.contains(&chain_id) {
        from_env("MISAKA_VALIDATOR_PASSPHRASE")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_debug_is_redacted() {
        let s = Secret::new("super_secret_password".to_string());
        let debug_str = format!("{:?}", s);
        assert_eq!(debug_str, "[REDACTED]");
        assert!(!debug_str.contains("super_secret"));
    }

    #[test]
    fn test_secret_display_is_redacted() {
        let s = Secret::new("api_key_12345".to_string());
        let display_str = format!("{}", s);
        assert_eq!(display_str, "[REDACTED]");
        assert!(!display_str.contains("api_key"));
    }

    #[test]
    fn test_secret_expose() {
        let s = Secret::new("my_value".to_string());
        assert_eq!(s.expose(), "my_value");
    }

    #[test]
    fn test_from_env_missing() {
        let result = from_env("MISAKA_TEST_NONEXISTENT_VAR_12345");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_env_optional_missing() {
        let result = from_env_optional("MISAKA_TEST_NONEXISTENT_VAR_12345");
        assert!(result.is_none());
    }

    #[test]
    fn test_validate_required_secrets_devnet() {
        // Devnet (chain_id = 0) should not require passphrase
        let result = validate_required_secrets(0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_required_secrets_mainnet_missing() {
        // Remove the env var to ensure it fails
        std::env::remove_var("MISAKA_VALIDATOR_PASSPHRASE");
        let result = validate_required_secrets(1);
        assert!(result.is_err());
    }
}
