use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub network_id: String,
    pub is_testnet: bool,
    pub suffix: Option<u32>,
}
