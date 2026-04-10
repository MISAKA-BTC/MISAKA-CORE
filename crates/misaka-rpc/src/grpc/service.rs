//! gRPC service implementation stubs.

use super::GrpcConfig;

/// gRPC server wrapper.
pub struct GrpcServer {
    config: GrpcConfig,
}

impl GrpcServer {
    pub fn new(config: GrpcConfig) -> Self {
        Self { config }
    }
    pub fn config(&self) -> &GrpcConfig {
        &self.config
    }
}
