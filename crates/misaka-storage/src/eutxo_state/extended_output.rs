//! ExtendedOutput: unified v1/v2 representation for state commitment.

use borsh::{BorshDeserialize, BorshSerialize};
use misaka_types::eutxo::datum::DatumOrHash;
use misaka_types::eutxo::script::VersionedScript;
use misaka_types::eutxo::value::AssetValue;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ExtendedOutput {
    pub address: [u8; 32],
    pub value: AssetValue,
    pub spending_pubkey: Option<Vec<u8>>,
    pub datum: Option<DatumOrHash>,
    pub script_ref: Option<VersionedScript>,
}

impl ExtendedOutput {
    pub fn from_v1(v1: &misaka_types::utxo::TxOutput) -> Self {
        Self {
            address: v1.address,
            value: AssetValue {
                mlp: v1.amount,
                native_assets: BTreeMap::new(),
            },
            spending_pubkey: v1.spending_pubkey.clone(),
            datum: None,
            script_ref: None,
        }
    }

    pub fn from_v2(v2: &misaka_types::eutxo::tx_v2::TxOutputV2) -> Self {
        Self {
            address: v2.address,
            value: v2.value.clone(),
            spending_pubkey: v2.spending_pubkey.clone(),
            datum: v2.datum.clone(),
            script_ref: v2.script_ref.clone(),
        }
    }

    pub fn has_v2_features(&self) -> bool {
        self.datum.is_some() || self.script_ref.is_some() || !self.value.native_assets.is_empty()
    }

    pub fn try_to_v1(&self) -> Option<misaka_types::utxo::TxOutput> {
        if self.has_v2_features() {
            return None;
        }
        Some(misaka_types::utxo::TxOutput {
            amount: self.value.mlp,
            address: self.address,
            spending_pubkey: self.spending_pubkey.clone(),
        })
    }
}
