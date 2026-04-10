//! Relayer configuration from environment variables.
//!
//! ## Burn & Mint Model
//!
//! This config supports the Burn & Mint bridge architecture:
//! - Users burn SPL tokens on Solana
//! - Relayer detects burns and requests mints on MISAKA chain
//!
//! ## Security (Mainnet P0)
//!
//! - ALL required environment variables MUST be explicitly set.
//! - No default fallbacks for RPC URLs, program IDs, or keypair paths.
//! - Network mode (devnet/testnet/mainnet) is mandatory and validated.
//! - Tilde (~) in paths is properly expanded.
//!
//! ## SEC-FIX-4: Error Handling
//!
//! All validation errors are returned as typed `ConfigError` values
//! instead of panicking. The caller (main) can log a structured
//! error and exit cleanly, enabling systemd restart with useful logs.

use std::path::PathBuf;

/// Burn event source kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BurnSourceKind {
    /// Direct Solana RPC polling (getSignaturesForAddress). Default.
    SolanaRpc,
    // Future: Helius, Triton, CustomWebhook
}

impl BurnSourceKind {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "solana_rpc" | "solana-rpc" | "rpc" => Some(Self::SolanaRpc),
            _ => None,
        }
    }
}

/// Mint executor kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintExecutorKind {
    /// Submit mints via MISAKA chain RPC. Default.
    MisakaRpc,
    /// Mock executor for testing (always succeeds).
    Mock,
}

impl MintExecutorKind {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "misaka_rpc" | "misaka-rpc" | "rpc" => Some(Self::MisakaRpc),
            "mock" => Some(Self::Mock),
            _ => None,
        }
    }
}

/// Network mode for the relayer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    Devnet,
    Testnet,
    Mainnet,
}

impl NetworkMode {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "devnet" => Some(Self::Devnet),
            "testnet" => Some(Self::Testnet),
            "mainnet" => Some(Self::Mainnet),
            _ => None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Configuration Error (SEC-FIX-4)
// ═══════════════════════════════════════════════════════════════

/// Typed configuration error — no panics.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(
        "FATAL: Required environment variable '{name}' is not set. All relayer config must be explicit — no defaults allowed in production."
    )]
    MissingEnv { name: String },

    #[error(
        "FATAL: RELAYER_NETWORK='{value}' is invalid. Must be one of: devnet, testnet, mainnet"
    )]
    InvalidNetwork { value: String },

    #[error("FATAL: RELAYER_KEYPAIR path '{expanded}' (from '{raw}') does not exist.")]
    KeypairNotFound { raw: String, expanded: String },

    #[error("FATAL: Network consistency check failed: {message}")]
    NetworkMismatch { message: String },

    #[error("FATAL: Validation failed for '{field}': {message}")]
    InvalidField { field: String, message: String },
}

#[derive(Debug, Clone)]
pub struct RelayerConfig {
    pub network: NetworkMode,
    pub solana_rpc_url: String,
    pub misaka_rpc_url: String,
    pub bridge_program_id: String,
    pub relayer_keypair_path: String,
    pub poll_interval_secs: u64,
    /// Path to persistent SQLite database.
    pub processed_store_path: PathBuf,
    /// MISAKA chain ID for request_id derivation.
    pub misaka_chain_id: u32,
    /// The SPL token mint address for MISAKA tokens on Solana.
    /// Burns of this mint are detected and relayed.
    pub solana_misaka_mint: String,
    /// Port for the HTTP API server (default 8080).
    pub api_port: u16,
    /// Admin secret for protected API endpoints.
    pub admin_secret: String,
    /// Burn event source kind (default: SolanaRpc).
    pub burn_source: BurnSourceKind,
    /// Mint executor kind (default: MisakaRpc).
    pub mint_executor: MintExecutorKind,
    /// Attestation: required signatures (N). Default 1 (single relayer).
    pub attestation_required: usize,
    /// Attestation: total authorized relayers (M). Default 1.
    pub attestation_total: usize,
    /// Phase 3 C2: Multiple Solana RPC URLs for multi-RPC verification.
    /// From SOLANA_RPC_URLS env (comma-separated). Falls back to [solana_rpc_url].
    pub solana_rpc_urls: Vec<String>,
    /// Genesis hash of the MISAKA chain (32 bytes, hex-encoded in env).
    /// Used with `misaka_chain_id` to construct `AppId` for IntentMessage signing.
    pub genesis_hash: [u8; 32],
}

/// Expand leading `~` to the user's home directory.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}/{}", home, rest);
        }
    }
    if path == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return home;
        }
    }
    path.to_string()
}

/// Read a required environment variable, or return a typed error.
fn require_env(name: &str) -> Result<String, ConfigError> {
    std::env::var(name).map_err(|_| ConfigError::MissingEnv {
        name: name.to_string(),
    })
}

/// Validate a URL field: must not be empty, must start with http:// or https://.
fn validate_url(field: &str, value: &str) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        return Err(ConfigError::InvalidField {
            field: field.to_string(),
            message: "URL must not be empty".to_string(),
        });
    }
    if !value.starts_with("http://") && !value.starts_with("https://") {
        return Err(ConfigError::InvalidField {
            field: field.to_string(),
            message: format!("URL must start with http:// or https://, got '{}'", value),
        });
    }
    Ok(())
}

/// Validate a base58 program ID: non-empty, reasonable length.
fn validate_program_id(value: &str) -> Result<(), ConfigError> {
    if value.trim().is_empty() || value.len() < 32 || value.len() > 50 {
        return Err(ConfigError::InvalidField {
            field: "BRIDGE_PROGRAM_ID".to_string(),
            message: format!(
                "Program ID must be 32-50 chars (base58 Solana pubkey), got {} chars",
                value.len()
            ),
        });
    }
    Ok(())
}

/// Validate a base58 mint address: non-empty, reasonable length.
fn validate_mint_address(value: &str) -> Result<(), ConfigError> {
    if value.trim().is_empty() || value.len() < 32 || value.len() > 50 {
        return Err(ConfigError::InvalidField {
            field: "SOLANA_MISAKA_MINT".to_string(),
            message: format!(
                "Mint address must be 32-50 chars (base58 Solana pubkey), got {} chars",
                value.len()
            ),
        });
    }
    Ok(())
}

/// Validate network consistency (cross-check RPC URL against declared network mode).
fn validate_network_consistency(
    network: NetworkMode,
    solana_rpc_url: &str,
    bridge_program_id: &str,
    misaka_chain_id: u32,
) -> Result<(), ConfigError> {
    match network {
        NetworkMode::Mainnet => {
            if solana_rpc_url.contains("devnet") || solana_rpc_url.contains("testnet") {
                return Err(ConfigError::NetworkMismatch {
                    message: format!(
                        "RELAYER_NETWORK=mainnet but SOLANA_RPC_URL '{}' appears to be a devnet/testnet URL.",
                        solana_rpc_url
                    ),
                });
            }
            if bridge_program_id.contains("xxxxxxx") || bridge_program_id.contains("XXXXXXX") {
                return Err(ConfigError::NetworkMismatch {
                    message: format!(
                        "RELAYER_NETWORK=mainnet but BRIDGE_PROGRAM_ID '{}' looks like a placeholder.",
                        bridge_program_id
                    ),
                });
            }
            if misaka_chain_id != 1 {
                return Err(ConfigError::NetworkMismatch {
                    message: format!(
                        "RELAYER_NETWORK=mainnet but MISAKA_CHAIN_ID={} (expected 1).",
                        misaka_chain_id
                    ),
                });
            }
        }
        NetworkMode::Devnet => {
            if solana_rpc_url.contains("mainnet") {
                return Err(ConfigError::NetworkMismatch {
                    message: format!(
                        "RELAYER_NETWORK=devnet but SOLANA_RPC_URL '{}' appears to be a mainnet URL.",
                        solana_rpc_url
                    ),
                });
            }
        }
        NetworkMode::Testnet => {
            // Testnet allows both devnet and testnet Solana URLs
        }
    }
    Ok(())
}

impl RelayerConfig {
    /// Alias for bridge_program_id (used by solana_watcher).
    pub fn solana_program_id(&self) -> &str {
        &self.bridge_program_id
    }

    /// Load configuration from environment variables.
    ///
    /// Returns `Err(ConfigError)` with an operator-readable message if any
    /// required variable is missing or invalid. Never panics.
    pub fn from_env() -> Result<Self, ConfigError> {
        // ── Network mode: MANDATORY ──
        let network_str = require_env("RELAYER_NETWORK")?;
        let network =
            NetworkMode::from_str(&network_str).ok_or_else(|| ConfigError::InvalidNetwork {
                value: network_str.clone(),
            })?;

        // ── Required config ──
        let solana_rpc_url = require_env("SOLANA_RPC_URL")?;
        validate_url("SOLANA_RPC_URL", &solana_rpc_url)?;

        let misaka_rpc_url = require_env("MISAKA_RPC_URL")?;
        validate_url("MISAKA_RPC_URL", &misaka_rpc_url)?;

        let bridge_program_id = require_env("BRIDGE_PROGRAM_ID")?;
        validate_program_id(&bridge_program_id)?;

        let solana_misaka_mint = require_env("SOLANA_MISAKA_MINT")?;
        validate_mint_address(&solana_misaka_mint)?;

        let admin_secret = require_env("ADMIN_SECRET")?;
        if admin_secret.len() < 16 {
            return Err(ConfigError::InvalidField {
                field: "ADMIN_SECRET".to_string(),
                message: "Admin secret must be at least 16 characters".to_string(),
            });
        }

        let relayer_keypair_raw = require_env("RELAYER_KEYPAIR")?;
        let relayer_keypair_path = expand_tilde(&relayer_keypair_raw);

        // ── Validate keypair file exists ──
        if !std::path::Path::new(&relayer_keypair_path).exists() {
            return Err(ConfigError::KeypairNotFound {
                raw: relayer_keypair_raw,
                expanded: relayer_keypair_path,
            });
        }

        // ── Optional with safe defaults ──
        let poll_interval_secs: u64 = std::env::var("POLL_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(15);

        let processed_store_path = PathBuf::from(
            std::env::var("PROCESSED_STORE").unwrap_or_else(|_| "./relayer-processed.json".into()),
        );

        let misaka_chain_id: u32 = std::env::var("MISAKA_CHAIN_ID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2);

        let api_port: u16 = std::env::var("API_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8080);

        // ── Burn source kind (optional, default SolanaRpc) ──
        let burn_source = match std::env::var("BURN_SOURCE_KIND").ok() {
            Some(s) => BurnSourceKind::from_str(&s).ok_or_else(|| ConfigError::InvalidField {
                field: "BURN_SOURCE_KIND".to_string(),
                message: format!("unknown burn source kind: '{}'", s),
            })?,
            None => BurnSourceKind::SolanaRpc,
        };

        // ── Mint executor kind (optional, default MisakaRpc) ──
        let mint_executor = match std::env::var("MINT_EXECUTOR_KIND").ok() {
            Some(s) => {
                MintExecutorKind::from_str(&s).ok_or_else(|| ConfigError::InvalidField {
                    field: "MINT_EXECUTOR_KIND".to_string(),
                    message: format!("unknown mint executor kind: '{}'", s),
                })?
            }
            None => MintExecutorKind::MisakaRpc,
        };

        // ── Attestation config (optional, default N=1, M=1) ──
        let attestation_required: usize = std::env::var("ATTESTATION_REQUIRED")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let attestation_total: usize = std::env::var("ATTESTATION_TOTAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        if attestation_required == 0 || attestation_required > attestation_total {
            return Err(ConfigError::InvalidField {
                field: "ATTESTATION_REQUIRED".to_string(),
                message: format!(
                    "ATTESTATION_REQUIRED={} must be >= 1 and <= ATTESTATION_TOTAL={}",
                    attestation_required, attestation_total
                ),
            });
        }

        // ── Genesis hash (required for IntentMessage/AppId construction) ──
        let genesis_hash: [u8; 32] = {
            let hex_str = require_env("MISAKA_GENESIS_HASH")?;
            let bytes = hex::decode(hex_str.trim()).map_err(|_| ConfigError::InvalidField {
                field: "MISAKA_GENESIS_HASH".to_string(),
                message: "must be 64 hex characters (32 bytes)".to_string(),
            })?;
            if bytes.len() != 32 {
                return Err(ConfigError::InvalidField {
                    field: "MISAKA_GENESIS_HASH".to_string(),
                    message: format!("expected 32 bytes, got {}", bytes.len()),
                });
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        };

        // ── Phase 3 C2: Multi-RPC URLs ──
        let solana_rpc_urls: Vec<String> = match std::env::var("SOLANA_RPC_URLS") {
            Ok(s) => s.split(',').map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).collect(),
            Err(_) => vec![solana_rpc_url.clone()],
        };

        // ── Network consistency validation ──
        validate_network_consistency(
            network,
            &solana_rpc_url,
            &bridge_program_id,
            misaka_chain_id,
        )?;

        // ── Phase 3 C2: Relayer independence check ──
        check_relayer_independence(&solana_rpc_urls);

        Ok(Self {
            network,
            solana_rpc_url,
            misaka_rpc_url,
            bridge_program_id,
            relayer_keypair_path,
            poll_interval_secs,
            processed_store_path,
            misaka_chain_id,
            solana_misaka_mint,
            api_port,
            admin_secret,
            burn_source,
            mint_executor,
            attestation_required,
            attestation_total,
            solana_rpc_urls,
            genesis_hash,
        })
    }
}

/// Phase 3 C2: Check if RPC URLs share the same provider domain.
/// Emits warnings — does not fail.
fn check_relayer_independence(rpc_urls: &[String]) {
    if rpc_urls.len() < 2 {
        return;
    }
    let domains: Vec<String> = rpc_urls.iter().filter_map(|url| {
        url.split("//").nth(1)
            .and_then(|h| h.split('/').next())
            .and_then(|h| h.split(':').next())
            .map(|h| {
                let parts: Vec<&str> = h.split('.').collect();
                if parts.len() >= 2 {
                    format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
                } else {
                    h.to_string()
                }
            })
    }).collect();

    for i in 0..domains.len() {
        for j in (i + 1)..domains.len() {
            if domains[i] == domains[j] {
                tracing::warn!(
                    "INDEPENDENCE WARNING: RPC URLs {} and {} share provider domain '{}'. \
                     Architecture spec §7.3 requires each relayer to use distinct providers.",
                    rpc_urls[i], rpc_urls[j], domains[i]
                );
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_tilde_with_home() {
        std::env::set_var("HOME", "/home/testuser");
        assert_eq!(
            expand_tilde("~/keys/relayer.json"),
            "/home/testuser/keys/relayer.json"
        );
        assert_eq!(expand_tilde("~"), "/home/testuser");
        assert_eq!(expand_tilde("/absolute/path"), "/absolute/path");
        assert_eq!(expand_tilde("relative/path"), "relative/path");
    }

    #[test]
    fn test_validate_url_rejects_empty() {
        assert!(validate_url("TEST", "").is_err());
        assert!(validate_url("TEST", "   ").is_err());
    }

    #[test]
    fn test_validate_url_rejects_non_http() {
        assert!(validate_url("TEST", "ftp://example.com").is_err());
        assert!(validate_url("TEST", "ws://example.com").is_err());
    }

    #[test]
    fn test_validate_url_accepts_valid() {
        assert!(validate_url("TEST", "https://api.mainnet.solana.com").is_ok());
        assert!(validate_url("TEST", "http://127.0.0.1:8899").is_ok());
    }

    #[test]
    fn test_validate_program_id_rejects_short() {
        assert!(validate_program_id("abc").is_err());
    }

    #[test]
    fn test_validate_mint_address_rejects_short() {
        assert!(validate_mint_address("abc").is_err());
    }

    #[test]
    fn test_network_consistency_mainnet_rejects_devnet_url() {
        let result = validate_network_consistency(
            NetworkMode::Mainnet,
            "https://api.devnet.solana.com",
            "BRDGxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxaaa",
            1,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_network_consistency_mainnet_rejects_wrong_chain_id() {
        let result = validate_network_consistency(
            NetworkMode::Mainnet,
            "https://api.mainnet-beta.solana.com",
            "BRDGxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxaaa",
            2,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_network_consistency_devnet_rejects_mainnet_url() {
        let result = validate_network_consistency(
            NetworkMode::Devnet,
            "https://api.mainnet-beta.solana.com",
            "BRDGxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxaaa",
            2,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_network_consistency_mainnet_rejects_placeholder_program_id() {
        let result = validate_network_consistency(
            NetworkMode::Mainnet,
            "https://api.mainnet-beta.solana.com",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            1,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_config_error_display_messages() {
        let err = ConfigError::MissingEnv {
            name: "SOLANA_RPC_URL".into(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("SOLANA_RPC_URL"),
            "error should name the missing var"
        );
        assert!(msg.contains("FATAL"), "error should be clearly fatal");
    }

    #[test]
    fn test_from_env_missing_network_returns_error() {
        std::env::remove_var("RELAYER_NETWORK");
        let result = RelayerConfig::from_env();
        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigError::MissingEnv { name } => assert_eq!(name, "RELAYER_NETWORK"),
            other => panic!("expected MissingEnv, got: {}", other),
        }
    }

    #[test]
    fn test_from_env_invalid_network_returns_error() {
        std::env::set_var("RELAYER_NETWORK", "staging");
        let result = RelayerConfig::from_env();
        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigError::InvalidNetwork { value } => assert_eq!(value, "staging"),
            other => panic!("expected InvalidNetwork, got: {}", other),
        }
        std::env::remove_var("RELAYER_NETWORK");
    }
}
