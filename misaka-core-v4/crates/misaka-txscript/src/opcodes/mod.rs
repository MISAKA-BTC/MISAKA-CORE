//! Opcode definitions and dispatch for the MISAKA script engine.
//!
//! Opcodes are organized into categories:
//! - Push data (OP_0 .. OP_PUSHDATA4)
//! - Flow control (OP_IF, OP_ELSE, OP_ENDIF, OP_VERIFY, OP_RETURN)
//! - Stack operations (OP_DUP, OP_DROP, OP_SWAP, OP_OVER, etc.)
//! - Arithmetic (OP_ADD, OP_SUB, OP_MUL, etc.)
//! - Crypto (OP_SHA3_256, OP_BLAKE3, OP_CHECKSIG, OP_CHECKMULTISIG)
//! - PQ extensions (OP_CHECKSIG_PQ, OP_CHECKMULTISIG_PQ)
//! - Locktime (OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY)

pub mod macros;

// ─── Opcode constants ─────────────────────────────────────────

// Push value
pub const OP_0: u8 = 0x00;
pub const OP_FALSE: u8 = 0x00;
pub const OP_PUSHDATA1: u8 = 0x4c;
pub const OP_PUSHDATA2: u8 = 0x4d;
pub const OP_PUSHDATA4: u8 = 0x4e;
pub const OP_1NEGATE: u8 = 0x4f;
pub const OP_RESERVED: u8 = 0x50;
pub const OP_1: u8 = 0x51;
pub const OP_TRUE: u8 = 0x51;
pub const OP_2: u8 = 0x52;
pub const OP_3: u8 = 0x53;
pub const OP_4: u8 = 0x54;
pub const OP_5: u8 = 0x55;
pub const OP_6: u8 = 0x56;
pub const OP_7: u8 = 0x57;
pub const OP_8: u8 = 0x58;
pub const OP_9: u8 = 0x59;
pub const OP_10: u8 = 0x5a;
pub const OP_11: u8 = 0x5b;
pub const OP_12: u8 = 0x5c;
pub const OP_13: u8 = 0x5d;
pub const OP_14: u8 = 0x5e;
pub const OP_15: u8 = 0x5f;
pub const OP_16: u8 = 0x60;

// Flow control
pub const OP_NOP: u8 = 0x61;
pub const OP_VER: u8 = 0x62;
pub const OP_IF: u8 = 0x63;
pub const OP_NOTIF: u8 = 0x64;
pub const OP_VERIF: u8 = 0x65;
pub const OP_VERNOTIF: u8 = 0x66;
pub const OP_ELSE: u8 = 0x67;
pub const OP_ENDIF: u8 = 0x68;
pub const OP_VERIFY: u8 = 0x69;
pub const OP_RETURN: u8 = 0x6a;

// Stack
pub const OP_TOALTSTACK: u8 = 0x6b;
pub const OP_FROMALTSTACK: u8 = 0x6c;
pub const OP_2DROP: u8 = 0x6d;
pub const OP_2DUP: u8 = 0x6e;
pub const OP_3DUP: u8 = 0x6f;
pub const OP_2OVER: u8 = 0x70;
pub const OP_2ROT: u8 = 0x71;
pub const OP_2SWAP: u8 = 0x72;
pub const OP_IFDUP: u8 = 0x73;
pub const OP_DEPTH: u8 = 0x74;
pub const OP_DROP: u8 = 0x75;
pub const OP_DUP: u8 = 0x76;
pub const OP_NIP: u8 = 0x77;
pub const OP_OVER: u8 = 0x78;
pub const OP_PICK: u8 = 0x79;
pub const OP_ROLL: u8 = 0x7a;
pub const OP_ROT: u8 = 0x7b;
pub const OP_SWAP: u8 = 0x7c;
pub const OP_TUCK: u8 = 0x7d;

// Splice
pub const OP_CAT: u8 = 0x7e; // Disabled
pub const OP_SUBSTR: u8 = 0x7f; // Disabled
pub const OP_LEFT: u8 = 0x80; // Disabled
pub const OP_RIGHT: u8 = 0x81; // Disabled
pub const OP_SIZE: u8 = 0x82;

// Bitwise logic
pub const OP_INVERT: u8 = 0x83; // Disabled
pub const OP_AND: u8 = 0x84; // Disabled
pub const OP_OR: u8 = 0x85; // Disabled
pub const OP_XOR: u8 = 0x86; // Disabled
pub const OP_EQUAL: u8 = 0x87;
pub const OP_EQUALVERIFY: u8 = 0x88;
pub const OP_RESERVED1: u8 = 0x89;
pub const OP_RESERVED2: u8 = 0x8a;

// Arithmetic
pub const OP_1ADD: u8 = 0x8b;
pub const OP_1SUB: u8 = 0x8c;
pub const OP_2MUL: u8 = 0x8d; // Disabled
pub const OP_2DIV: u8 = 0x8e; // Disabled
pub const OP_NEGATE: u8 = 0x8f;
pub const OP_ABS: u8 = 0x90;
pub const OP_NOT: u8 = 0x91;
pub const OP_0NOTEQUAL: u8 = 0x92;
pub const OP_ADD: u8 = 0x93;
pub const OP_SUB: u8 = 0x94;
pub const OP_MUL: u8 = 0x95; // Disabled
pub const OP_DIV: u8 = 0x96; // Disabled
pub const OP_MOD: u8 = 0x97; // Disabled
pub const OP_LSHIFT: u8 = 0x98; // Disabled
pub const OP_RSHIFT: u8 = 0x99; // Disabled
pub const OP_BOOLAND: u8 = 0x9a;
pub const OP_BOOLOR: u8 = 0x9b;
pub const OP_NUMEQUAL: u8 = 0x9c;
pub const OP_NUMEQUALVERIFY: u8 = 0x9d;
pub const OP_NUMNOTEQUAL: u8 = 0x9e;
pub const OP_LESSTHAN: u8 = 0x9f;
pub const OP_GREATERTHAN: u8 = 0xa0;
pub const OP_LESSTHANOREQUAL: u8 = 0xa1;
pub const OP_GREATERTHANOREQUAL: u8 = 0xa2;
pub const OP_MIN: u8 = 0xa3;
pub const OP_MAX: u8 = 0xa4;
pub const OP_WITHIN: u8 = 0xa5;

// Crypto
pub const OP_SHA3_256: u8 = 0xa6;
pub const OP_BLAKE3_256: u8 = 0xa7;
pub const OP_HASH256: u8 = 0xa8; // Double SHA3
pub const OP_CODESEPARATOR: u8 = 0xa9;
pub const OP_CHECKSIG: u8 = 0xac;
pub const OP_CHECKSIGVERIFY: u8 = 0xad;
pub const OP_CHECKMULTISIG: u8 = 0xae;
pub const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;

// Lock time
pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;

// PQ Extensions (MISAKA-specific, 0xc0-0xcf range)
pub const OP_CHECKSIG_PQ: u8 = 0xc0;
pub const OP_CHECKSIGVERIFY_PQ: u8 = 0xc1;
pub const OP_CHECKMULTISIG_PQ: u8 = 0xc2;
pub const OP_CHECKMULTISIGVERIFY_PQ: u8 = 0xc3;
pub const OP_CHECKKYBER: u8 = 0xc4;

// NOPs for future soft-fork upgrades
pub const OP_NOP1: u8 = 0xb0;
pub const OP_NOP4: u8 = 0xb3;
pub const OP_NOP5: u8 = 0xb4;
pub const OP_NOP6: u8 = 0xb5;
pub const OP_NOP7: u8 = 0xb6;
pub const OP_NOP8: u8 = 0xb7;
pub const OP_NOP9: u8 = 0xb8;
pub const OP_NOP10: u8 = 0xb9;

/// Maximum number of opcodes in a script.
pub const MAX_OPS_PER_SCRIPT: usize = 201;

/// Maximum signature operations per script.
pub const MAX_SIG_OPS_PER_SCRIPT: usize = 20;

/// Maximum script size in bytes.
pub const MAX_SCRIPT_SIZE: usize = 10_000;

/// Maximum number of public keys in a multisig.
pub const MAX_MULTISIG_KEYS: usize = 20;

/// Returns the name of an opcode.
pub fn opcode_name(op: u8) -> &'static str {
    match op {
        OP_0 => "OP_0",
        0x01..=0x4b => "OP_DATA",
        OP_PUSHDATA1 => "OP_PUSHDATA1",
        OP_PUSHDATA2 => "OP_PUSHDATA2",
        OP_PUSHDATA4 => "OP_PUSHDATA4",
        OP_1NEGATE => "OP_1NEGATE",
        OP_RESERVED => "OP_RESERVED",
        OP_1 => "OP_1",
        OP_2 => "OP_2",
        OP_3 => "OP_3",
        OP_4 => "OP_4",
        OP_5 => "OP_5",
        OP_6 => "OP_6",
        OP_7 => "OP_7",
        OP_8 => "OP_8",
        OP_9 => "OP_9",
        OP_10 => "OP_10",
        OP_11 => "OP_11",
        OP_12 => "OP_12",
        OP_13 => "OP_13",
        OP_14 => "OP_14",
        OP_15 => "OP_15",
        OP_16 => "OP_16",
        OP_NOP => "OP_NOP",
        OP_IF => "OP_IF",
        OP_NOTIF => "OP_NOTIF",
        OP_ELSE => "OP_ELSE",
        OP_ENDIF => "OP_ENDIF",
        OP_VERIFY => "OP_VERIFY",
        OP_RETURN => "OP_RETURN",
        OP_TOALTSTACK => "OP_TOALTSTACK",
        OP_FROMALTSTACK => "OP_FROMALTSTACK",
        OP_DROP => "OP_DROP",
        OP_DUP => "OP_DUP",
        OP_NIP => "OP_NIP",
        OP_OVER => "OP_OVER",
        OP_PICK => "OP_PICK",
        OP_ROLL => "OP_ROLL",
        OP_ROT => "OP_ROT",
        OP_SWAP => "OP_SWAP",
        OP_TUCK => "OP_TUCK",
        OP_SIZE => "OP_SIZE",
        OP_EQUAL => "OP_EQUAL",
        OP_EQUALVERIFY => "OP_EQUALVERIFY",
        OP_1ADD => "OP_1ADD",
        OP_1SUB => "OP_1SUB",
        OP_NEGATE => "OP_NEGATE",
        OP_ABS => "OP_ABS",
        OP_NOT => "OP_NOT",
        OP_0NOTEQUAL => "OP_0NOTEQUAL",
        OP_ADD => "OP_ADD",
        OP_SUB => "OP_SUB",
        OP_BOOLAND => "OP_BOOLAND",
        OP_BOOLOR => "OP_BOOLOR",
        OP_NUMEQUAL => "OP_NUMEQUAL",
        OP_NUMEQUALVERIFY => "OP_NUMEQUALVERIFY",
        OP_NUMNOTEQUAL => "OP_NUMNOTEQUAL",
        OP_LESSTHAN => "OP_LESSTHAN",
        OP_GREATERTHAN => "OP_GREATERTHAN",
        OP_LESSTHANOREQUAL => "OP_LESSTHANOREQUAL",
        OP_GREATERTHANOREQUAL => "OP_GREATERTHANOREQUAL",
        OP_MIN => "OP_MIN",
        OP_MAX => "OP_MAX",
        OP_WITHIN => "OP_WITHIN",
        OP_SHA3_256 => "OP_SHA3_256",
        OP_BLAKE3_256 => "OP_BLAKE3_256",
        OP_HASH256 => "OP_HASH256",
        OP_CHECKSIG => "OP_CHECKSIG",
        OP_CHECKSIGVERIFY => "OP_CHECKSIGVERIFY",
        OP_CHECKMULTISIG => "OP_CHECKMULTISIG",
        OP_CHECKMULTISIGVERIFY => "OP_CHECKMULTISIGVERIFY",
        OP_CHECKLOCKTIMEVERIFY => "OP_CHECKLOCKTIMEVERIFY",
        OP_CHECKSEQUENCEVERIFY => "OP_CHECKSEQUENCEVERIFY",
        OP_CHECKSIG_PQ => "OP_CHECKSIG_PQ",
        OP_CHECKSIGVERIFY_PQ => "OP_CHECKSIGVERIFY_PQ",
        OP_CHECKMULTISIG_PQ => "OP_CHECKMULTISIG_PQ",
        OP_CHECKMULTISIGVERIFY_PQ => "OP_CHECKMULTISIGVERIFY_PQ",
        OP_CHECKKYBER => "OP_CHECKKYBER",
        _ => "OP_UNKNOWN",
    }
}

/// Check if an opcode is disabled.
pub fn is_disabled(op: u8) -> bool {
    matches!(
        op,
        OP_CAT
            | OP_SUBSTR
            | OP_LEFT
            | OP_RIGHT
            | OP_INVERT
            | OP_AND
            | OP_OR
            | OP_XOR
            | OP_2MUL
            | OP_2DIV
            | OP_MUL
            | OP_DIV
            | OP_MOD
            | OP_LSHIFT
            | OP_RSHIFT
            | OP_VER
            | OP_VERIF
            | OP_VERNOTIF
    )
}

/// Check if an opcode is a push operation (data or small int).
pub fn is_push_op(op: u8) -> bool {
    op <= OP_16
}

/// Check if an opcode is a conditional (IF/ELSE/ENDIF).
pub fn is_conditional(op: u8) -> bool {
    matches!(op, OP_IF | OP_NOTIF | OP_ELSE | OP_ENDIF)
}

/// Count the signature operations in a script.
pub fn count_sig_ops(script: &[u8]) -> usize {
    let mut count = 0;
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        match op {
            0x01..=0x4b => {
                i += op as usize;
            }
            OP_PUSHDATA1 => {
                if i + 1 < script.len() {
                    i += 1 + script[i + 1] as usize;
                }
            }
            OP_PUSHDATA2 => {
                if i + 2 < script.len() {
                    let len = u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize;
                    i += 2 + len;
                }
            }
            OP_CHECKSIG | OP_CHECKSIGVERIFY | OP_CHECKSIG_PQ | OP_CHECKSIGVERIFY_PQ => {
                count += 1;
            }
            OP_CHECKMULTISIG
            | OP_CHECKMULTISIGVERIFY
            | OP_CHECKMULTISIG_PQ
            | OP_CHECKMULTISIGVERIFY_PQ => {
                count += MAX_MULTISIG_KEYS; // Worst case
            }
            _ => {}
        }
        i += 1;
    }
    count
}
