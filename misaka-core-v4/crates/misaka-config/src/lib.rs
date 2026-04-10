// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! `misaka-config` — node configuration and validation.
//!
//! Extracted from `misaka-node/src/config.rs` + `config_validation.rs`.
//!
//! Provides:
//! - `NodeConfig`: full node configuration struct (serde-based)
//! - `TestnetConfig`: testnet-specific configuration with validation
//! - `ConfigError`: structured validation errors
//! - `load_config()`: load and validate from file path

pub mod node_config;
pub mod toml_config;
pub mod validation;
pub mod error;

pub use node_config::NodeConfig;
pub use toml_config::TomlConfig;
pub use validation::TestnetConfig;
pub use error::ConfigError;

/// Load a node configuration from a JSON or TOML file.
///
/// File format is detected by extension:
/// - `.toml` -> TOML (nested sections flattened to `NodeConfig`)
/// - `.json` (or anything else) -> JSON (flat `NodeConfig`)
///
/// Validates the configuration after loading. Returns a structured
/// error if validation fails.
pub fn load_config(path: &std::path::Path) -> Result<NodeConfig, ConfigError> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| ConfigError::IoError(format!("{}: {}", path.display(), e)))?;

    let is_toml = path
        .extension()
        .map(|ext| ext.eq_ignore_ascii_case("toml"))
        .unwrap_or(false);

    let config: NodeConfig = if is_toml {
        let toml_cfg: TomlConfig = toml::from_str(&contents)
            .map_err(|e| ConfigError::ParseError(format!("TOML: {}", e)))?;
        NodeConfig::from(toml_cfg)
    } else {
        serde_json::from_str(&contents)
            .map_err(|e| ConfigError::ParseError(format!("JSON: {}", e)))?
    };

    config.validate()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_validates() {
        let config = NodeConfig::default();
        // Default config is testnet (chain_id=2), should validate
        assert!(config.validate().is_ok());
    }
}
