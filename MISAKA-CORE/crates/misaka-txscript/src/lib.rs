//! # misaka-txscript
//!
//! Transaction script engine for MISAKA Network. Implements a stack-based
//! script language compatible with Kaspa's transaction validation model,
//! extended with post-quantum signature verification opcodes.
//!
//! ## Architecture
//! - Stack machine with data stack and alt stack
//! - Opcode-based execution with strict validation
//! - Script class detection (P2PK, P2PKH, P2SH, multisig, PQ variants)
//! - Script builder for programmatic construction
//! - Signature operation counting for DoS protection

pub mod caches;
pub mod data_stack;
pub mod error;
pub mod opcodes;
pub mod result;
pub mod runtime_sig_op_counter;
pub mod script_builder;
pub mod script_class;
pub mod script_engine;
pub mod standard;

pub use error::TxScriptError;
pub use result::TxScriptResult;
pub use script_engine::ScriptEngine;
pub use script_builder::ScriptBuilder;
pub use script_class::ScriptClass;
pub use data_stack::DataStack;
