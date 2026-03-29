//! RPC control channel for internal node management.

/// RPC server control commands.
#[derive(Debug)]
pub enum RpcCtl {
    Shutdown,
    PauseSubscriptions,
    ResumeSubscriptions,
    RefreshPeers,
}
