//! Error types for the transaction script engine.

#[derive(Debug, Clone, thiserror::Error)]
pub enum TxScriptError {
    #[error("invalid opcode: 0x{0:02x}")]
    InvalidOpcode(u8),

    #[error("disabled opcode: {0}")]
    DisabledOpcode(String),

    #[error("script too long: {0} bytes (max {1})")]
    ScriptTooLong(usize, usize),

    #[error("stack underflow: needed {needed}, got {got}")]
    StackUnderflow { needed: usize, got: usize },

    #[error("stack overflow: {0} items (max {1})")]
    StackOverflow(usize, usize),

    #[error("invalid stack operation")]
    InvalidStackOperation,

    #[error("invalid alt stack operation")]
    InvalidAltStackOperation,

    #[error("script verification failed")]
    VerifyFailed,

    #[error("equal-verify failed")]
    EqualVerifyFailed,

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("PQ signature verification failed: {0}")]
    PqSignatureVerificationFailed(String),

    #[error("multi-sig verification failed")]
    MultiSigVerificationFailed,

    #[error("op count exceeded: {0} (max {1})")]
    OpCountExceeded(usize, usize),

    #[error("sig op count exceeded: {0} (max {1})")]
    SigOpCountExceeded(usize, usize),

    #[error("push size exceeded: {0}")]
    PushSizeExceeded(usize),

    #[error("number too large: {0}")]
    NumberTooLarge(usize),

    #[error("negative lock time")]
    NegativeLockTime,

    #[error("unsatisfied lock time")]
    UnsatisfiedLockTime,

    #[error("unbalanced conditional")]
    UnbalancedConditional,

    #[error("clean stack violation: {0} items remaining")]
    CleanStackViolation(usize),

    #[error("early return")]
    EarlyReturn,

    #[error("minimal data not satisfied")]
    MinimalDataNotSatisfied,

    #[error("pubkey count out of range: {0}")]
    PubKeyCountOutOfRange(usize),

    #[error("sig count out of range: {0}")]
    SigCountOutOfRange(usize),

    #[error("internal error: {0}")]
    InternalError(String),
}
