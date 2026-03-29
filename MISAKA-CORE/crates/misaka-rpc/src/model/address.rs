use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcAddress {
    pub prefix: String,
    pub payload: String,
    pub version: u8,
}
