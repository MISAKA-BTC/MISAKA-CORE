//! High-level wallet manager: multi-account, multi-network wallet.

use crate::account::bip32::{Bip32Account, ExtendedKey};
use crate::account::multisig::MultisigAccount;
use crate::account::watchonly::WatchOnlyAccount;
use crate::account::{Account, AccountId, AccountMeta};
use crate::keystore::{EncryptedKeystore, KeystoreError};
use crate::{OwnedUtxo, WalletBalance};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Wallet configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    pub network: String,
    pub default_fee_rate: f64,
    pub auto_compound: bool,
    pub dust_threshold: u64,
    pub max_utxo_per_tx: usize,
    pub confirmations_required: u64,
    pub enable_address_reuse: bool,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            network: "misaka-mainnet".to_string(),
            default_fee_rate: 1.0,
            auto_compound: false,
            dust_threshold: 100,
            max_utxo_per_tx: 100,
            confirmations_required: 10,
            enable_address_reuse: false,
        }
    }
}

/// Wallet state tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletState {
    pub is_synced: bool,
    pub sync_progress: f64,
    pub last_sync_daa_score: u64,
    pub known_daa_score: u64,
    pub pending_tx_count: usize,
}

/// Multi-account wallet manager.
pub struct Wallet {
    config: WalletConfig,
    keystore: Option<EncryptedKeystore>,
    accounts: HashMap<AccountId, Box<dyn Account>>,
    utxos: HashMap<AccountId, Vec<OwnedUtxo>>,
    next_account_id: AccountId,
    state: WalletState,
    #[allow(dead_code)]
    event_log: Vec<WalletEvent>,
}

/// Wallet lifecycle events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletEvent {
    pub timestamp: u64,
    pub kind: WalletEventKind,
    pub account_id: Option<AccountId>,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletEventKind {
    Created,
    Opened,
    Closed,
    AccountCreated,
    AccountRemoved,
    TransactionSent,
    TransactionReceived,
    BalanceChanged,
    SyncStarted,
    SyncCompleted,
    Error,
}

impl Wallet {
    /// Create a new wallet with a fresh master seed.
    pub fn create(config: WalletConfig, password: &str, name: String) -> Result<Self, WalletError> {
        let seed = generate_random_seed();
        let keystore = EncryptedKeystore::create(&seed, password, name, config.network.clone())
            .map_err(|e| WalletError::Keystore(e))?;

        Ok(Self {
            config,
            keystore: Some(keystore),
            accounts: HashMap::new(),
            utxos: HashMap::new(),
            next_account_id: 1,
            state: WalletState {
                is_synced: false,
                sync_progress: 0.0,
                last_sync_daa_score: 0,
                known_daa_score: 0,
                pending_tx_count: 0,
            },
            event_log: Vec::new(),
        })
    }

    /// Open an existing wallet from keystore.
    pub fn open(keystore: EncryptedKeystore, config: WalletConfig) -> Self {
        Self {
            config,
            keystore: Some(keystore),
            accounts: HashMap::new(),
            utxos: HashMap::new(),
            next_account_id: 1,
            state: WalletState {
                is_synced: false,
                sync_progress: 0.0,
                last_sync_daa_score: 0,
                known_daa_score: 0,
                pending_tx_count: 0,
            },
            event_log: Vec::new(),
        }
    }

    /// Create a new BIP32 account.
    pub fn create_bip32_account(
        &mut self,
        name: String,
        password: &str,
    ) -> Result<AccountId, WalletError> {
        let seed = self.decrypt_seed(password)?;
        let master = ExtendedKey::from_seed(&seed);
        let id = self.next_account_id;
        self.next_account_id += 1;

        let account = Bip32Account::new(id, name, master, id as u32 - 1);
        self.accounts.insert(id, Box::new(account));
        self.utxos.insert(id, Vec::new());
        Ok(id)
    }

    /// Create a multisig account.
    pub fn create_multisig_account(
        &mut self,
        name: String,
        required: usize,
        pubkeys: Vec<Vec<u8>>,
        own_index: Option<usize>,
    ) -> Result<AccountId, WalletError> {
        let id = self.next_account_id;
        self.next_account_id += 1;

        let account = MultisigAccount::new(id, name, required, pubkeys, own_index, true)
            .map_err(|e| WalletError::Account(e))?;
        self.accounts.insert(id, Box::new(account));
        self.utxos.insert(id, Vec::new());
        Ok(id)
    }

    /// Create a watch-only account.
    pub fn create_watchonly_account(&mut self, name: String, pubkeys: Vec<Vec<u8>>) -> AccountId {
        let id = self.next_account_id;
        self.next_account_id += 1;

        let account = WatchOnlyAccount::new(id, name, pubkeys);
        self.accounts.insert(id, Box::new(account));
        self.utxos.insert(id, Vec::new());
        id
    }

    /// Get account metadata.
    pub fn get_account(&self, id: AccountId) -> Option<&dyn Account> {
        self.accounts.get(&id).map(|a| a.as_ref())
    }

    /// List all accounts.
    pub fn list_accounts(&self) -> Vec<&AccountMeta> {
        self.accounts.values().map(|a| a.meta()).collect()
    }

    /// Get balance for an account.
    pub fn get_balance(&self, account_id: AccountId) -> WalletBalance {
        let utxos = self
            .utxos
            .get(&account_id)
            .map_or(&[] as &[OwnedUtxo], |v| v.as_slice());
        // R7 M-8: Use saturating_add to prevent wrapping overflow
        let total: u64 = utxos
            .iter()
            .filter(|u| !u.spent)
            .fold(0u64, |acc, u| acc.saturating_add(u.amount));
        let utxo_count = utxos.iter().filter(|u| !u.spent).count();
        WalletBalance {
            total,
            utxo_count,
            pending_spend: 0,
            available: total,
        }
    }

    /// Get total balance across all accounts.
    pub fn total_balance(&self) -> u64 {
        self.accounts
            .keys()
            .fold(0u64, |acc, id| acc.saturating_add(self.get_balance(*id).total))
    }

    /// Register a newly discovered UTXO.
    pub fn register_utxo(&mut self, account_id: AccountId, utxo: OwnedUtxo) {
        self.utxos.entry(account_id).or_default().push(utxo);
    }

    /// Mark a UTXO as spent.
    pub fn mark_spent(&mut self, account_id: AccountId, tx_hash: &[u8; 32], output_index: u32) {
        if let Some(utxos) = self.utxos.get_mut(&account_id) {
            for utxo in utxos.iter_mut() {
                if utxo.tx_hash == *tx_hash && utxo.output_index == output_index {
                    utxo.spent = true;
                    break;
                }
            }
        }
    }

    /// Get the receive address for an account.
    pub fn receive_address(&self, account_id: AccountId) -> Option<String> {
        self.accounts.get(&account_id).map(|a| a.receive_address())
    }

    /// Get wallet state.
    pub fn state(&self) -> &WalletState {
        &self.state
    }

    /// Get wallet config.
    pub fn config(&self) -> &WalletConfig {
        &self.config
    }

    fn decrypt_seed(&self, password: &str) -> Result<Vec<u8>, WalletError> {
        let ks = self.keystore.as_ref().ok_or(WalletError::NoKeystore)?;
        ks.decrypt(password).map_err(WalletError::Keystore)
    }
}

fn generate_random_seed() -> zeroize::Zeroizing<Vec<u8>> {
    let mut seed = vec![0u8; 64];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    zeroize::Zeroizing::new(seed)
}

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("keystore error: {0}")]
    Keystore(KeystoreError),
    #[error("no keystore loaded")]
    NoKeystore,
    #[error("account error: {0}")]
    Account(String),
    #[error("insufficient funds")]
    InsufficientFunds,
    #[error("sync required")]
    SyncRequired,
    #[error("internal error: {0}")]
    Internal(String),
}
