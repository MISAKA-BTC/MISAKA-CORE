//! Bridge asset registry — tracks which tokens are bridgeable.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgedAsset {
    pub asset_id: String,
    pub source_chain: u32,
    pub source_address: String,
    pub decimals: u8,
    pub is_active: bool,
}

pub struct AssetRegistry {
    assets: HashMap<String, BridgedAsset>,
}

impl AssetRegistry {
    pub fn new() -> Self {
        Self {
            assets: HashMap::new(),
        }
    }

    pub fn register(&mut self, asset_id: String, source_chain: u32, source_address: String) {
        self.assets.insert(
            asset_id.clone(),
            BridgedAsset {
                asset_id,
                source_chain,
                source_address,
                decimals: 9,
                is_active: true,
            },
        );
    }

    pub fn is_registered(&self, asset_id: &str) -> bool {
        self.assets
            .get(asset_id)
            .map(|a| a.is_active)
            .unwrap_or(false)
    }

    pub fn get(&self, asset_id: &str) -> Option<&BridgedAsset> {
        self.assets.get(asset_id)
    }

    pub fn deactivate(&mut self, asset_id: &str) {
        if let Some(a) = self.assets.get_mut(asset_id) {
            a.is_active = false;
        }
    }
}
