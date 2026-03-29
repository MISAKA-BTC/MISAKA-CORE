//! Script execution engine.
//!
//! Executes transaction scripts through a stack-based virtual machine,
//! validating signatures, enforcing locktime constraints, and counting
//! signature operations for DoS protection.

use crate::data_stack::{DataStack, MAX_SCRIPT_NUM_LEN, stack_bool, decode_script_num, encode_script_num};
use crate::error::TxScriptError;
use crate::opcodes::*;
use crate::result::TxScriptResult;
use crate::runtime_sig_op_counter::SigOpCounter;

/// Configuration flags for script execution.
#[derive(Debug, Clone)]
pub struct ScriptFlags {
    /// Require minimal push encodings.
    pub verify_minimal_data: bool,
    /// Require clean stack after execution.
    pub verify_clean_stack: bool,
    /// Enable CHECKLOCKTIMEVERIFY.
    pub verify_checklocktimeverify: bool,
    /// Enable CHECKSEQUENCEVERIFY.
    pub verify_checksequenceverify: bool,
    /// Enable PQ signature opcodes.
    pub verify_pq_signatures: bool,
    /// Maximum allowed script size.
    pub max_script_size: usize,
    /// Maximum allowed stack size after execution.
    pub max_stack_size: usize,
}

impl Default for ScriptFlags {
    fn default() -> Self {
        Self {
            verify_minimal_data: true,
            verify_clean_stack: true,
            verify_checklocktimeverify: true,
            verify_checksequenceverify: true,
            verify_pq_signatures: true,
            max_script_size: MAX_SCRIPT_SIZE,
            max_stack_size: 1000,
        }
    }
}

/// Transaction signing context needed for signature verification.
#[derive(Debug, Clone)]
pub struct SigContext {
    /// The serialized transaction data for signature verification.
    pub tx_sig_hash: Vec<u8>,
    /// Lock time from the transaction.
    pub lock_time: u64,
    /// Sequence number from the input.
    pub sequence: u64,
}

/// The script execution engine.
pub struct ScriptEngine {
    /// Main data stack.
    stack: DataStack,
    /// Alternate stack (for OP_TOALTSTACK/OP_FROMALTSTACK).
    alt_stack: DataStack,
    /// Condition stack for nested IF/ELSE/ENDIF.
    cond_stack: Vec<ConditionState>,
    /// Script being executed.
    script: Vec<u8>,
    /// Current program counter.
    pc: usize,
    /// Execution flags.
    flags: ScriptFlags,
    /// Signature context for verification.
    sig_context: Option<SigContext>,
    /// Signature operation counter.
    sig_op_counter: SigOpCounter,
    /// Number of non-push opcodes executed.
    op_count: usize,
    /// Last code separator index.
    last_code_sep: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConditionState {
    True,
    False,
    Skip, // Nested inside a false branch
}

impl ScriptEngine {
    pub fn new(script: Vec<u8>, flags: ScriptFlags, sig_context: Option<SigContext>) -> TxScriptResult<Self> {
        if script.len() > flags.max_script_size {
            return Err(TxScriptError::ScriptTooLong(script.len(), flags.max_script_size));
        }
        Ok(Self {
            stack: DataStack::new(),
            alt_stack: DataStack::new(),
            cond_stack: Vec::new(),
            script,
            pc: 0,
            flags,
            sig_context,
            sig_op_counter: SigOpCounter::new(MAX_SIG_OPS_PER_SCRIPT),
            op_count: 0,
            last_code_sep: 0,
        })
    }

    /// Execute the entire script and return whether it succeeded.
    pub fn execute(&mut self) -> TxScriptResult<bool> {
        while self.pc < self.script.len() {
            self.step()?;
        }

        if !self.cond_stack.is_empty() {
            return Err(TxScriptError::UnbalancedConditional);
        }

        if self.flags.verify_clean_stack && self.stack.len() != 1 {
            return Err(TxScriptError::CleanStackViolation(self.stack.len()));
        }

        if self.stack.is_empty() {
            return Ok(false);
        }

        let top = self.stack.peek()?;
        Ok(stack_bool(top))
    }

    /// Execute a single step (one opcode).
    pub fn step(&mut self) -> TxScriptResult<()> {
        if self.pc >= self.script.len() {
            return Ok(());
        }

        let op = self.script[self.pc];
        self.pc += 1;

        // Check if we're in a non-executing branch
        let executing = self.is_executing();

        // Conditionals are always processed
        if is_conditional(op) {
            return self.execute_conditional(op);
        }

        // If not executing, skip everything except conditionals
        if !executing {
            // Still need to skip push data properly
            if op >= 0x01 && op <= 0x4b {
                self.pc += op as usize;
            } else if op == OP_PUSHDATA1 && self.pc < self.script.len() {
                let len = self.script[self.pc] as usize;
                self.pc += 1 + len;
            } else if op == OP_PUSHDATA2 && self.pc + 1 < self.script.len() {
                let len = u16::from_le_bytes([self.script[self.pc], self.script[self.pc + 1]]) as usize;
                self.pc += 2 + len;
            } else if op == OP_PUSHDATA4 && self.pc + 3 < self.script.len() {
                let len = u32::from_le_bytes([
                    self.script[self.pc], self.script[self.pc + 1],
                    self.script[self.pc + 2], self.script[self.pc + 3],
                ]) as usize;
                self.pc += 4 + len;
            }
            return Ok(());
        }

        // Check for disabled opcodes
        if is_disabled(op) {
            return Err(TxScriptError::DisabledOpcode(opcode_name(op).to_string()));
        }

        // Count non-push operations
        if !is_push_op(op) {
            self.op_count += 1;
            if self.op_count > MAX_OPS_PER_SCRIPT {
                return Err(TxScriptError::OpCountExceeded(self.op_count, MAX_OPS_PER_SCRIPT));
            }
        }

        self.dispatch(op)
    }

    fn is_executing(&self) -> bool {
        self.cond_stack.iter().all(|c| *c == ConditionState::True)
    }

    fn execute_conditional(&mut self, op: u8) -> TxScriptResult<()> {
        match op {
            OP_IF | OP_NOTIF => {
                let mut val = false;
                if self.is_executing() {
                    val = self.stack.pop_bool()?;
                    if op == OP_NOTIF {
                        val = !val;
                    }
                }
                if self.is_executing() {
                    self.cond_stack.push(if val { ConditionState::True } else { ConditionState::False });
                } else {
                    self.cond_stack.push(ConditionState::Skip);
                }
            }
            OP_ELSE => {
                if self.cond_stack.is_empty() {
                    return Err(TxScriptError::UnbalancedConditional);
                }
                let last = self.cond_stack.last_mut().expect("checked");
                *last = match *last {
                    ConditionState::True => ConditionState::False,
                    ConditionState::False => ConditionState::True,
                    ConditionState::Skip => ConditionState::Skip,
                };
            }
            OP_ENDIF => {
                if self.cond_stack.is_empty() {
                    return Err(TxScriptError::UnbalancedConditional);
                }
                self.cond_stack.pop();
            }
            _ => return Err(TxScriptError::InternalError("not a conditional".to_string())),
        }
        Ok(())
    }

    fn dispatch(&mut self, op: u8) -> TxScriptResult<()> {
        match op {
            // Push data (1..75 bytes)
            0x01..=0x4b => {
                let len = op as usize;
                self.push_data(len)?;
            }
            OP_0 => { self.stack.push(vec![])?; }
            OP_PUSHDATA1 => {
                if self.pc >= self.script.len() {
                    return Err(TxScriptError::InternalError("PUSHDATA1 truncated".into()));
                }
                let len = self.script[self.pc] as usize;
                self.pc += 1;
                self.push_data(len)?;
            }
            OP_PUSHDATA2 => {
                if self.pc + 1 >= self.script.len() {
                    return Err(TxScriptError::InternalError("PUSHDATA2 truncated".into()));
                }
                let len = u16::from_le_bytes([self.script[self.pc], self.script[self.pc + 1]]) as usize;
                self.pc += 2;
                self.push_data(len)?;
            }
            OP_PUSHDATA4 => {
                if self.pc + 3 >= self.script.len() {
                    return Err(TxScriptError::InternalError("PUSHDATA4 truncated".into()));
                }
                let len = u32::from_le_bytes([
                    self.script[self.pc], self.script[self.pc + 1],
                    self.script[self.pc + 2], self.script[self.pc + 3],
                ]) as usize;
                self.pc += 4;
                self.push_data(len)?;
            }
            OP_1NEGATE => { self.stack.push_number(-1)?; }
            OP_1..=OP_16 => {
                let val = (op - OP_1 + 1) as i64;
                self.stack.push_number(val)?;
            }

            // Flow
            OP_NOP | OP_NOP1 | OP_NOP4..=OP_NOP10 => { /* No-op */ }
            OP_VERIFY => {
                let val = self.stack.pop_bool()?;
                if !val { return Err(TxScriptError::VerifyFailed); }
            }
            OP_RETURN => { return Err(TxScriptError::EarlyReturn); }

            // Stack operations
            OP_TOALTSTACK => {
                let data = self.stack.pop()?;
                self.alt_stack.push(data)?;
            }
            OP_FROMALTSTACK => {
                let data = self.alt_stack.pop().map_err(|_| TxScriptError::InvalidAltStackOperation)?;
                self.stack.push(data)?;
            }
            OP_2DROP => { self.stack.drop2()?; }
            OP_2DUP => { self.stack.dup_n(2)?; }
            OP_3DUP => { self.stack.dup_n(3)?; }
            OP_DEPTH => {
                let depth = self.stack.len() as i64;
                self.stack.push_number(depth)?;
            }
            OP_DROP => { self.stack.drop_top()?; }
            OP_DUP => { self.stack.dup_n(1)?; }
            OP_NIP => { self.stack.nip()?; }
            OP_OVER => { self.stack.over()?; }
            OP_PICK => {
                let n = self.stack.pop_number(MAX_SCRIPT_NUM_LEN)? as usize;
                self.stack.pick(n)?;
            }
            OP_ROLL => {
                let n = self.stack.pop_number(MAX_SCRIPT_NUM_LEN)? as usize;
                self.stack.roll(n)?;
            }
            OP_ROT => { self.stack.rot()?; }
            OP_SWAP => { self.stack.swap()?; }
            OP_TUCK => { self.stack.tuck()?; }
            OP_IFDUP => {
                let top = self.stack.peek()?.clone();
                if stack_bool(&top) {
                    self.stack.push(top)?;
                }
            }
            OP_SIZE => {
                let top = self.stack.peek()?;
                let size = top.len() as i64;
                self.stack.push_number(size)?;
            }

            // Comparison
            OP_EQUAL => {
                let b = self.stack.pop()?;
                let a = self.stack.pop()?;
                self.stack.push_bool(a == b)?;
            }
            OP_EQUALVERIFY => {
                let b = self.stack.pop()?;
                let a = self.stack.pop()?;
                if a != b { return Err(TxScriptError::EqualVerifyFailed); }
            }

            // Arithmetic
            OP_1ADD => { crate::unary_op!(self.stack, |a: i64| a + 1); }
            OP_1SUB => { crate::unary_op!(self.stack, |a: i64| a - 1); }
            OP_NEGATE => { crate::unary_op!(self.stack, |a: i64| -a); }
            OP_ABS => { crate::unary_op!(self.stack, |a: i64| a.abs()); }
            OP_NOT => {
                let a = self.stack.pop_number(MAX_SCRIPT_NUM_LEN)?;
                self.stack.push_bool(a == 0)?;
            }
            OP_0NOTEQUAL => {
                let a = self.stack.pop_number(MAX_SCRIPT_NUM_LEN)?;
                self.stack.push_bool(a != 0)?;
            }
            OP_ADD => { crate::arith_op!(self.stack, +); }
            OP_SUB => { crate::arith_op!(self.stack, -); }
            OP_BOOLAND => {
                let b = self.stack.pop_number(MAX_SCRIPT_NUM_LEN)?;
                let a = self.stack.pop_number(MAX_SCRIPT_NUM_LEN)?;
                self.stack.push_bool(a != 0 && b != 0)?;
            }
            OP_BOOLOR => {
                let b = self.stack.pop_number(MAX_SCRIPT_NUM_LEN)?;
                let a = self.stack.pop_number(MAX_SCRIPT_NUM_LEN)?;
                self.stack.push_bool(a != 0 || b != 0)?;
            }
            OP_NUMEQUAL => { crate::compare_op!(self.stack, ==); }
            OP_NUMEQUALVERIFY => {
                let b = self.stack.pop_number(MAX_SCRIPT_NUM_LEN)?;
                let a = self.stack.pop_number(MAX_SCRIPT_NUM_LEN)?;
                if a != b { return Err(TxScriptError::EqualVerifyFailed); }
            }
            OP_NUMNOTEQUAL => { crate::compare_op!(self.stack, !=); }
            OP_LESSTHAN => { crate::compare_op!(self.stack, <); }
            OP_GREATERTHAN => { crate::compare_op!(self.stack, >); }
            OP_LESSTHANOREQUAL => { crate::compare_op!(self.stack, <=); }
            OP_GREATERTHANOREQUAL => { crate::compare_op!(self.stack, >=); }
            OP_MIN => {
                let b = self.stack.pop_number(MAX_SCRIPT_NUM_LEN)?;
                let a = self.stack.pop_number(MAX_SCRIPT_NUM_LEN)?;
                self.stack.push_number(a.min(b))?;
            }
            OP_MAX => {
                let b = self.stack.pop_number(MAX_SCRIPT_NUM_LEN)?;
                let a = self.stack.pop_number(MAX_SCRIPT_NUM_LEN)?;
                self.stack.push_number(a.max(b))?;
            }
            OP_WITHIN => {
                let max = self.stack.pop_number(MAX_SCRIPT_NUM_LEN)?;
                let min = self.stack.pop_number(MAX_SCRIPT_NUM_LEN)?;
                let val = self.stack.pop_number(MAX_SCRIPT_NUM_LEN)?;
                self.stack.push_bool(val >= min && val < max)?;
            }

            // Crypto
            OP_SHA3_256 => {
                let data = self.stack.pop()?;
                let hash = sha3_256(&data);
                self.stack.push(hash.to_vec())?;
            }
            OP_BLAKE3_256 => {
                let data = self.stack.pop()?;
                let hash = blake3_256(&data);
                self.stack.push(hash.to_vec())?;
            }
            OP_HASH256 => {
                let data = self.stack.pop()?;
                let h1 = sha3_256(&data);
                let h2 = sha3_256(&h1);
                self.stack.push(h2.to_vec())?;
            }
            OP_CODESEPARATOR => {
                self.last_code_sep = self.pc;
            }
            OP_CHECKSIG => {
                self.sig_op_counter.increment()?;
                let pubkey = self.stack.pop()?;
                let sig = self.stack.pop()?;
                let valid = self.verify_signature(&sig, &pubkey)?;
                self.stack.push_bool(valid)?;
            }
            OP_CHECKSIGVERIFY => {
                self.sig_op_counter.increment()?;
                let pubkey = self.stack.pop()?;
                let sig = self.stack.pop()?;
                if !self.verify_signature(&sig, &pubkey)? {
                    return Err(TxScriptError::SignatureVerificationFailed);
                }
            }
            OP_CHECKMULTISIG => {
                self.execute_checkmultisig(false)?;
            }
            OP_CHECKMULTISIGVERIFY => {
                self.execute_checkmultisig(true)?;
            }

            // PQ Crypto extensions
            OP_CHECKSIG_PQ => {
                self.sig_op_counter.increment()?;
                let pubkey = self.stack.pop()?;
                let sig = self.stack.pop()?;
                let valid = self.verify_pq_signature(&sig, &pubkey)?;
                self.stack.push_bool(valid)?;
            }
            OP_CHECKSIGVERIFY_PQ => {
                self.sig_op_counter.increment()?;
                let pubkey = self.stack.pop()?;
                let sig = self.stack.pop()?;
                if !self.verify_pq_signature(&sig, &pubkey)? {
                    return Err(TxScriptError::PqSignatureVerificationFailed("verify failed".into()));
                }
            }

            // Lock time
            OP_CHECKLOCKTIMEVERIFY => {
                if !self.flags.verify_checklocktimeverify { return Ok(()); }
                let lock_time = self.stack.pop_number(5)?;
                if lock_time < 0 { return Err(TxScriptError::NegativeLockTime); }
                let lock_time = lock_time as u64;
                if let Some(ref ctx) = self.sig_context {
                    if lock_time > ctx.lock_time {
                        return Err(TxScriptError::UnsatisfiedLockTime);
                    }
                }
                // Push it back (CLTV doesn't consume)
                self.stack.push_number(lock_time as i64)?;
            }
            OP_CHECKSEQUENCEVERIFY => {
                if !self.flags.verify_checksequenceverify { return Ok(()); }
                let sequence = self.stack.pop_number(5)?;
                if sequence < 0 { return Err(TxScriptError::NegativeLockTime); }
                let sequence = sequence as u64;
                if let Some(ref ctx) = self.sig_context {
                    if sequence > ctx.sequence {
                        return Err(TxScriptError::UnsatisfiedLockTime);
                    }
                }
                self.stack.push_number(sequence as i64)?;
            }

            _ => {
                return Err(TxScriptError::InvalidOpcode(op));
            }
        }
        Ok(())
    }

    fn push_data(&mut self, len: usize) -> TxScriptResult<()> {
        if self.pc + len > self.script.len() {
            return Err(TxScriptError::InternalError("push data truncated".into()));
        }
        let data = self.script[self.pc..self.pc + len].to_vec();
        self.pc += len;
        self.stack.push(data)
    }

    fn verify_signature(&self, sig: &[u8], pubkey: &[u8]) -> TxScriptResult<bool> {
        if sig.is_empty() || pubkey.is_empty() {
            return Ok(false);
        }
        let ctx = self.sig_context.as_ref().ok_or(TxScriptError::InternalError("no sig context".into()))?;
        // Hash the transaction data with the script for verification
        let mut msg = ctx.tx_sig_hash.clone();
        msg.extend_from_slice(&self.script[self.last_code_sep..]);
        let msg_hash = blake3_256(&msg);
        // Verify ML-DSA-65 (stub: actual PQC verification in misaka-pqc)
        Ok(verify_mldsa65(pubkey, &msg_hash, sig))
    }

    fn verify_pq_signature(&self, sig: &[u8], pubkey: &[u8]) -> TxScriptResult<bool> {
        if !self.flags.verify_pq_signatures {
            return Ok(true); // PQ verification disabled
        }
        self.verify_signature(sig, pubkey)
    }

    fn execute_checkmultisig(&mut self, verify: bool) -> TxScriptResult<()> {
        let n_keys = self.stack.pop_number(MAX_SCRIPT_NUM_LEN)? as usize;
        if n_keys > MAX_MULTISIG_KEYS {
            return Err(TxScriptError::PubKeyCountOutOfRange(n_keys));
        }
        self.sig_op_counter.add(n_keys)?;

        let mut pubkeys = Vec::with_capacity(n_keys);
        for _ in 0..n_keys {
            pubkeys.push(self.stack.pop()?);
        }

        let n_sigs = self.stack.pop_number(MAX_SCRIPT_NUM_LEN)? as usize;
        if n_sigs > n_keys {
            return Err(TxScriptError::SigCountOutOfRange(n_sigs));
        }

        let mut sigs = Vec::with_capacity(n_sigs);
        for _ in 0..n_sigs {
            sigs.push(self.stack.pop()?);
        }

        // Dummy byte (bug compatibility)
        let _ = self.stack.pop()?;

        // Verify: each sig must match the next unused pubkey
        let mut key_idx = 0;
        let mut success = true;
        for sig in &sigs {
            let mut matched = false;
            while key_idx < pubkeys.len() {
                if self.verify_signature(sig, &pubkeys[key_idx]).unwrap_or(false) {
                    matched = true;
                    key_idx += 1;
                    break;
                }
                key_idx += 1;
            }
            if !matched {
                success = false;
                break;
            }
        }

        if verify {
            if !success {
                return Err(TxScriptError::MultiSigVerificationFailed);
            }
        } else {
            self.stack.push_bool(success)?;
        }
        Ok(())
    }

    // ─── Accessors ─────────────────────────────────────

    pub fn stack(&self) -> &DataStack { &self.stack }
    pub fn alt_stack(&self) -> &DataStack { &self.alt_stack }
    pub fn op_count(&self) -> usize { self.op_count }
    pub fn sig_op_count(&self) -> usize { self.sig_op_counter.count() }
}

// ─── Hash helpers ──────────────────────────────────────

fn sha3_256(data: &[u8]) -> [u8; 32] {
    use sha3::{Sha3_256, Digest};
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

fn blake3_256(data: &[u8]) -> [u8; 32] {
    let out = blake3::hash(data);
    *out.as_bytes()
}

/// Stub ML-DSA-65 verification (delegates to misaka-pqc in production).
fn verify_mldsa65(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    // In production, this calls misaka_pqc::mldsa65::verify()
    // For now, accept if lengths match expected ML-DSA-65 sizes
    pubkey.len() == 1952 && signature.len() >= 3293
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_engine(script: Vec<u8>) -> ScriptEngine {
        let mut flags = ScriptFlags::default();
        flags.verify_clean_stack = false;
        ScriptEngine::new(script, flags, None).unwrap()
    }

    #[test]
    fn test_push_and_equal() {
        // PUSH 0x42, PUSH 0x42, OP_EQUAL
        let script = vec![0x01, 0x42, 0x01, 0x42, OP_EQUAL];
        let mut engine = simple_engine(script);
        let result = engine.execute().unwrap();
        assert!(result);
    }

    #[test]
    fn test_arithmetic() {
        // PUSH 3, PUSH 4, OP_ADD => 7
        let script = vec![OP_3, OP_4, OP_ADD];
        let mut engine = simple_engine(script);
        engine.execute().unwrap();
        let val = engine.stack().peek().unwrap();
        assert_eq!(decode_script_num(val, 8).unwrap(), 7);
    }

    #[test]
    fn test_if_else() {
        // OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        let script = vec![OP_1, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF];
        let mut engine = simple_engine(script);
        engine.execute().unwrap();
        let val = engine.stack().peek().unwrap();
        assert_eq!(decode_script_num(val, 8).unwrap(), 2);
    }

    #[test]
    fn test_op_return() {
        let script = vec![OP_RETURN];
        let mut engine = simple_engine(script);
        assert!(engine.execute().is_err());
    }

    #[test]
    fn test_disabled_opcode() {
        let script = vec![OP_CAT];
        let mut engine = simple_engine(script);
        assert!(engine.execute().is_err());
    }
}
