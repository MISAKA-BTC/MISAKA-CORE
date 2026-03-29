//! Runtime signature operation counter for DoS protection.

use crate::error::TxScriptError;
use crate::result::TxScriptResult;

/// Tracks signature operations during script execution.
pub struct SigOpCounter {
    count: usize,
    max: usize,
}

impl SigOpCounter {
    pub fn new(max: usize) -> Self {
        Self { count: 0, max }
    }

    /// Increment the counter by one.
    pub fn increment(&mut self) -> TxScriptResult<()> {
        self.count += 1;
        if self.count > self.max {
            Err(TxScriptError::SigOpCountExceeded(self.count, self.max))
        } else {
            Ok(())
        }
    }

    /// Add n to the counter.
    pub fn add(&mut self, n: usize) -> TxScriptResult<()> {
        self.count += n;
        if self.count > self.max {
            Err(TxScriptError::SigOpCountExceeded(self.count, self.max))
        } else {
            Ok(())
        }
    }

    pub fn count(&self) -> usize { self.count }
    pub fn remaining(&self) -> usize { self.max.saturating_sub(self.count) }
    pub fn is_exceeded(&self) -> bool { self.count > self.max }
}
