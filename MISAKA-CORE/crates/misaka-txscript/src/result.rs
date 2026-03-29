//! Result type alias for script operations.

pub type TxScriptResult<T> = std::result::Result<T, crate::TxScriptError>;
