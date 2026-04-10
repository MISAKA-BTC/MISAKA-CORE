//! Mining subsystem error types.

#[derive(Debug, thiserror::Error)]
pub enum MiningError {
    #[error("block template build failed: {0}")]
    TemplateBuildFailed(String),

    #[error("mempool rule violation: {0}")]
    MempoolRule(#[from] MempoolRuleError),

    #[error("transaction validation failed: {0}")]
    TxValidationFailed(String),

    #[error("transaction already in mempool: {0}")]
    TxAlreadyExists(String),

    #[error("orphan pool full ({0} entries)")]
    OrphanPoolFull(usize),

    #[error("fee rate too low: {got} < {minimum}")]
    FeeRateTooLow { got: f64, minimum: f64 },

    #[error("transaction too large: {0} mass units")]
    TxTooLarge(u64),

    #[error("consensus error: {0}")]
    Consensus(String),

    #[error("cache error: {0}")]
    Cache(String),

    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug, thiserror::Error)]
pub enum MempoolRuleError {
    #[error("transaction mass exceeds limit: {mass} > {max}")]
    MassExceeded { mass: u64, max: u64 },

    #[error("insufficient fee: {fee} for mass {mass}")]
    InsufficientFee { fee: u64, mass: u64 },

    #[error("too many inputs: {0}")]
    TooManyInputs(usize),

    #[error("too many outputs: {0}")]
    TooManyOutputs(usize),

    #[error("double spend detected: output {0}")]
    DoubleSpend(String),

    #[error("non-standard transaction: {0}")]
    NonStandard(String),

    #[error("script validation failed: {0}")]
    ScriptFailed(String),

    #[error("expired transaction: age {0}s")]
    Expired(u64),

    #[error("RBF policy violation: {0}")]
    RbfViolation(String),

    #[error("replace-by-fee: new fee {new} must exceed old fee {old} + {min_increment}")]
    RbfInsufficientFee {
        old: u64,
        new: u64,
        min_increment: u64,
    },
}

pub type MiningResult<T> = Result<T, MiningError>;
