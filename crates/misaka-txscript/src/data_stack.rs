//! Stack implementation for the script engine.

use crate::error::TxScriptError;
use crate::result::TxScriptResult;

/// Maximum number of items on the stack.
pub const MAX_STACK_SIZE: usize = 1000;

/// Maximum size of a single stack element in bytes.
pub const MAX_ELEMENT_SIZE: usize = 520;

/// Script number maximum byte length (8 bytes = i64).
pub const MAX_SCRIPT_NUM_LEN: usize = 8;

/// The data stack used by the script engine.
#[derive(Debug, Clone)]
pub struct DataStack {
    items: Vec<Vec<u8>>,
}

impl DataStack {
    pub fn new() -> Self {
        Self {
            items: Vec::with_capacity(64),
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Push data onto the stack.
    pub fn push(&mut self, data: Vec<u8>) -> TxScriptResult<()> {
        if self.items.len() >= MAX_STACK_SIZE {
            return Err(TxScriptError::StackOverflow(
                self.items.len() + 1,
                MAX_STACK_SIZE,
            ));
        }
        if data.len() > MAX_ELEMENT_SIZE {
            return Err(TxScriptError::PushSizeExceeded(data.len()));
        }
        self.items.push(data);
        Ok(())
    }

    /// Pop the top element.
    pub fn pop(&mut self) -> TxScriptResult<Vec<u8>> {
        self.items
            .pop()
            .ok_or(TxScriptError::StackUnderflow { needed: 1, got: 0 })
    }

    /// Peek at the top element without removing it.
    pub fn peek(&self) -> TxScriptResult<&Vec<u8>> {
        self.items
            .last()
            .ok_or(TxScriptError::StackUnderflow { needed: 1, got: 0 })
    }

    /// Peek at the n-th element from the top (0 = top).
    pub fn peek_at(&self, n: usize) -> TxScriptResult<&Vec<u8>> {
        if n >= self.items.len() {
            return Err(TxScriptError::StackUnderflow {
                needed: n + 1,
                got: self.items.len(),
            });
        }
        Ok(&self.items[self.items.len() - 1 - n])
    }

    /// Push a boolean value.
    pub fn push_bool(&mut self, val: bool) -> TxScriptResult<()> {
        self.push(if val { vec![1] } else { vec![] })
    }

    /// Pop and interpret as boolean.
    pub fn pop_bool(&mut self) -> TxScriptResult<bool> {
        let data = self.pop()?;
        Ok(stack_bool(&data))
    }

    /// Push a script number.
    pub fn push_number(&mut self, val: i64) -> TxScriptResult<()> {
        self.push(encode_script_num(val))
    }

    /// Pop and interpret as script number.
    pub fn pop_number(&mut self, max_len: usize) -> TxScriptResult<i64> {
        let data = self.pop()?;
        decode_script_num(&data, max_len)
    }

    /// Duplicate the top n elements.
    pub fn dup_n(&mut self, n: usize) -> TxScriptResult<()> {
        if n > self.items.len() {
            return Err(TxScriptError::StackUnderflow {
                needed: n,
                got: self.items.len(),
            });
        }
        let start = self.items.len() - n;
        let to_dup: Vec<Vec<u8>> = self.items[start..].to_vec();
        for item in to_dup {
            self.push(item)?;
        }
        Ok(())
    }

    /// Rotate the top 3 elements.
    pub fn rot(&mut self) -> TxScriptResult<()> {
        if self.items.len() < 3 {
            return Err(TxScriptError::StackUnderflow {
                needed: 3,
                got: self.items.len(),
            });
        }
        let len = self.items.len();
        self.items[len - 3..].rotate_left(1);
        Ok(())
    }

    /// Swap the top two elements.
    pub fn swap(&mut self) -> TxScriptResult<()> {
        let len = self.items.len();
        if len < 2 {
            return Err(TxScriptError::StackUnderflow {
                needed: 2,
                got: len,
            });
        }
        self.items.swap(len - 1, len - 2);
        Ok(())
    }

    /// Move the element at depth n to the top.
    pub fn roll(&mut self, n: usize) -> TxScriptResult<()> {
        if n >= self.items.len() {
            return Err(TxScriptError::StackUnderflow {
                needed: n + 1,
                got: self.items.len(),
            });
        }
        let idx = self.items.len() - 1 - n;
        let item = self.items.remove(idx);
        self.items.push(item);
        Ok(())
    }

    /// Remove the second-to-top element.
    pub fn nip(&mut self) -> TxScriptResult<()> {
        if self.items.len() < 2 {
            return Err(TxScriptError::StackUnderflow {
                needed: 2,
                got: self.items.len(),
            });
        }
        let idx = self.items.len() - 2;
        self.items.remove(idx);
        Ok(())
    }

    /// Copy the second-to-top element to the top.
    pub fn over(&mut self) -> TxScriptResult<()> {
        let data = self.peek_at(1)?.clone();
        self.push(data)
    }

    /// Pick the n-th element and copy to top.
    pub fn pick(&mut self, n: usize) -> TxScriptResult<()> {
        let data = self.peek_at(n)?.clone();
        self.push(data)
    }

    /// Tuck: put top element below second.
    pub fn tuck(&mut self) -> TxScriptResult<()> {
        if self.items.len() < 2 {
            return Err(TxScriptError::StackUnderflow {
                needed: 2,
                got: self.items.len(),
            });
        }
        let top = self.items.last().cloned().unwrap_or_default();
        let idx = self.items.len() - 2;
        self.items.insert(idx, top);
        Ok(())
    }

    /// Drop the top element.
    pub fn drop_top(&mut self) -> TxScriptResult<()> {
        self.pop().map(|_| ())
    }

    /// Drop the top 2 elements.
    pub fn drop2(&mut self) -> TxScriptResult<()> {
        self.pop()?;
        self.pop()?;
        Ok(())
    }

    /// Clear the stack.
    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// Get all items (for debugging/inspection).
    pub fn items(&self) -> &[Vec<u8>] {
        &self.items
    }
}

impl Default for DataStack {
    fn default() -> Self {
        Self::new()
    }
}

/// Interpret stack data as a boolean.
pub fn stack_bool(data: &[u8]) -> bool {
    for (i, byte) in data.iter().enumerate() {
        if *byte != 0 {
            // Negative zero is still false
            if i == data.len() - 1 && *byte == 0x80 {
                return false;
            }
            return true;
        }
    }
    false
}

/// Encode an i64 as a minimal script number.
pub fn encode_script_num(val: i64) -> Vec<u8> {
    if val == 0 {
        return vec![];
    }

    let negative = val < 0;
    let mut abs_val = val.unsigned_abs();
    let mut result = Vec::with_capacity(9);

    while abs_val > 0 {
        result.push((abs_val & 0xff) as u8);
        abs_val >>= 8;
    }

    // If the high bit is set, add an extra byte for the sign.
    if result.last().map_or(false, |b| b & 0x80 != 0) {
        result.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        let last = result.last_mut().expect(
            "INVARIANT: result.last().map_or(false, ..) on line 251 returned true; non-empty",
        );
        *last |= 0x80;
    }

    result
}

/// Decode a script number from stack data.
pub fn decode_script_num(data: &[u8], max_len: usize) -> TxScriptResult<i64> {
    if data.is_empty() {
        return Ok(0);
    }
    if data.len() > max_len {
        return Err(TxScriptError::NumberTooLarge(data.len()));
    }

    // Check minimal encoding
    if data.last().map_or(false, |b| b & 0x7f == 0) {
        if data.len() <= 1 || data[data.len() - 2] & 0x80 == 0 {
            return Err(TxScriptError::MinimalDataNotSatisfied);
        }
    }

    let mut result: i64 = 0;
    for (i, byte) in data.iter().enumerate() {
        result |= (*byte as i64) << (8 * i);
    }

    let negative = data.last().map_or(false, |b| b & 0x80 != 0);
    if negative {
        let mask = 0x80i64 << (8 * (data.len() - 1));
        result &= !mask;
        result = -result;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_num_round_trip() {
        for val in [-1000i64, -1, 0, 1, 127, 128, 255, 256, 65535, i64::MAX / 2] {
            let encoded = encode_script_num(val);
            let decoded = decode_script_num(&encoded, 8).unwrap();
            assert_eq!(decoded, val, "failed for {val}");
        }
    }

    #[test]
    fn test_stack_operations() {
        let mut stack = DataStack::new();
        stack.push(vec![1]).unwrap();
        stack.push(vec![2]).unwrap();
        stack.push(vec![3]).unwrap();

        stack.swap().unwrap();
        assert_eq!(stack.pop().unwrap(), vec![2]);
        assert_eq!(stack.pop().unwrap(), vec![3]);

        stack.push(vec![10]).unwrap();
        stack.push(vec![20]).unwrap();
        stack.over().unwrap();
        assert_eq!(stack.pop().unwrap(), vec![10]);
    }

    #[test]
    fn test_stack_overflow() {
        let mut stack = DataStack::new();
        for i in 0..MAX_STACK_SIZE {
            stack.push(vec![0]).unwrap();
        }
        assert!(stack.push(vec![0]).is_err());
    }

    #[test]
    fn test_bool_encoding() {
        assert!(!stack_bool(&[]));
        assert!(!stack_bool(&[0]));
        assert!(!stack_bool(&[0x80])); // Negative zero
        assert!(stack_bool(&[1]));
        assert!(stack_bool(&[0x80, 0x00]));
    }
}
