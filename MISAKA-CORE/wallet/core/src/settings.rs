//! Wallet settings and preferences.

use serde::{Serialize, Deserialize};

/// Wallet user preferences.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSettings {
    pub display: DisplaySettings,
    pub security: SecuritySettings,
    pub network: NetworkSettings,
    pub notification: NotificationSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplaySettings {
    /// Display currency for fiat conversion.
    pub fiat_currency: String,
    /// Number format locale.
    pub number_locale: String,
    /// Show amounts in base units or MISAKA.
    pub show_base_units: bool,
    /// Theme preference.
    pub theme: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    /// Auto-lock timeout in seconds.
    pub auto_lock_seconds: u64,
    /// Require password for each transaction.
    pub require_password_per_tx: bool,
    /// Enable biometric authentication.
    pub biometric_enabled: bool,
    /// Maximum transaction amount without extra confirmation.
    pub high_value_threshold: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSettings {
    /// Preferred RPC endpoint.
    pub rpc_endpoint: String,
    /// Backup RPC endpoints.
    pub backup_endpoints: Vec<String>,
    /// Connection timeout in seconds.
    pub connection_timeout: u64,
    /// Whether to use Tor.
    pub use_tor: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationSettings {
    pub notify_incoming: bool,
    pub notify_outgoing: bool,
    pub notify_confirmation: bool,
    pub min_notify_amount: u64,
}

impl Default for WalletSettings {
    fn default() -> Self {
        Self {
            display: DisplaySettings {
                fiat_currency: "USD".to_string(),
                number_locale: "en-US".to_string(),
                show_base_units: false,
                theme: "dark".to_string(),
            },
            security: SecuritySettings {
                auto_lock_seconds: 300,
                require_password_per_tx: true,
                biometric_enabled: false,
                high_value_threshold: 1_000_000_000, // 1 MISAKA
            },
            network: NetworkSettings {
                rpc_endpoint: "https://rpc.misaka.network".to_string(),
                backup_endpoints: vec![
                    "https://rpc2.misaka.network".to_string(),
                ],
                connection_timeout: 30,
                use_tor: false,
            },
            notification: NotificationSettings {
                notify_incoming: true,
                notify_outgoing: true,
                notify_confirmation: false,
                min_notify_amount: 0,
            },
        }
    }
}
