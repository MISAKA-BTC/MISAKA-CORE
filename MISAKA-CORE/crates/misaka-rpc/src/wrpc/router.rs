//! wRPC method router: dispatches RPC methods to handlers.

use std::collections::HashMap;
use crate::error::{RpcError, RpcResult};

/// Method handler function type.
pub type HandlerFn = Box<dyn Fn(serde_json::Value) -> RpcResult<serde_json::Value> + Send + Sync>;

/// RPC method router.
pub struct MethodRouter {
    handlers: HashMap<String, HandlerFn>,
}

impl MethodRouter {
    pub fn new() -> Self { Self { handlers: HashMap::new() } }

    pub fn register<F>(&mut self, method: &str, handler: F)
    where F: Fn(serde_json::Value) -> RpcResult<serde_json::Value> + Send + Sync + 'static
    {
        self.handlers.insert(method.to_string(), Box::new(handler));
    }

    pub fn dispatch(&self, method: &str, params: serde_json::Value) -> RpcResult<serde_json::Value> {
        match self.handlers.get(method) {
            Some(handler) => handler(params),
            None => Err(RpcError::MethodNotFound(method.to_string())),
        }
    }

    pub fn has_method(&self, method: &str) -> bool {
        self.handlers.contains_key(method)
    }

    pub fn methods(&self) -> Vec<&str> {
        self.handlers.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for MethodRouter {
    fn default() -> Self { Self::new() }
}
