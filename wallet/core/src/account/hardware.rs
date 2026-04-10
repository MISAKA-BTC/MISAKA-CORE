//! Hardware wallet proxy account.

use super::{Account, AccountId, AccountKind, AccountMeta};
use serde::{Deserialize, Serialize};

/// Hardware device type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardwareDeviceType {
    Ledger,
    Trezor,
    Generic,
}

/// Proxy account for hardware wallet interaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareAccount {
    pub meta: AccountMeta,
    pub device_type: HardwareDeviceType,
    pub device_id: String,
    pub master_pubkey: Vec<u8>,
    pub derivation_path: String,
    pub cached_addresses: Vec<String>,
}

impl HardwareAccount {
    pub fn new(
        id: AccountId,
        name: String,
        device_type: HardwareDeviceType,
        device_id: String,
        master_pubkey: Vec<u8>,
    ) -> Self {
        Self {
            meta: AccountMeta::new(id, name, AccountKind::Hardware),
            device_type,
            device_id,
            master_pubkey,
            derivation_path: "m/44'/4935963'/0'".to_string(),
            cached_addresses: Vec::new(),
        }
    }
}

impl Account for HardwareAccount {
    fn meta(&self) -> &AccountMeta {
        &self.meta
    }
    fn kind(&self) -> AccountKind {
        AccountKind::Hardware
    }
    fn receive_address(&self) -> String {
        self.cached_addresses.first().cloned().unwrap_or_default()
    }
    fn change_address(&self) -> String {
        self.receive_address()
    }
    fn next_receive_address(&mut self) -> String {
        self.receive_address()
    }
    fn next_change_address(&mut self) -> String {
        self.receive_address()
    }
    fn can_sign(&self) -> bool {
        false
    } // Signing delegated to device
}
