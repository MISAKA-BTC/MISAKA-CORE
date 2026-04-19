//! Per-opcode cost table V1.
//! FROZEN for v2.0 launch (暫定値 — testnet 実測補正後に再凍結).

use misaka_types::eutxo::cost_model::OpcodeCost;

// ── Opcode constants (番号予約、E3 で実装と同期) ──
pub const OPCODE_SHA3: u16 = 0xA8;
pub const OPCODE_KECCAK: u16 = 0xA9;
pub const OPCODE_CHECK_ML_DSA: u16 = 0xB0;
pub const OPCODE_CHECK_ML_KEM: u16 = 0xB1;
pub const OPCODE_DATUM: u16 = 0xC0;
pub const OPCODE_REDEEMER: u16 = 0xC1;
pub const OPCODE_REF_INPUT: u16 = 0xC2;
pub const OPCODE_CHECK_VALID_RANGE: u16 = 0xC3;
pub const OPCODE_CHECK_REQ_SIGNER: u16 = 0xC4;
pub const OPCODE_CHECK_MINT: u16 = 0xC5;
pub const OPCODE_VALUE_OF: u16 = 0xC6;

fn tier1(cpu: u64, mem: u64) -> OpcodeCost {
    OpcodeCost {
        cpu_per_call: cpu,
        cpu_per_byte: 0,
        mem_per_call: mem,
        mem_per_byte: 0,
    }
}

fn tier_hash(cpu_call: u64, cpu_byte: u64) -> OpcodeCost {
    OpcodeCost {
        cpu_per_call: cpu_call,
        cpu_per_byte: cpu_byte,
        mem_per_call: 32,
        mem_per_byte: 0,
    }
}

fn tier_ctx(cpu_call: u64, cpu_byte: u64, mem_call: u64, mem_byte: u64) -> OpcodeCost {
    OpcodeCost {
        cpu_per_call: cpu_call,
        cpu_per_byte: cpu_byte,
        mem_per_call: mem_call,
        mem_per_byte: mem_byte,
    }
}

/// Build the V1 opcode cost table.
/// Returns Vec<(opcode, cost)> sorted by opcode for deterministic borsh.
pub fn cost_model_v1_table() -> Vec<(u16, OpcodeCost)> {
    let mut t: Vec<(u16, OpcodeCost)> = Vec::new();

    // Tier 1: stack / basic arithmetic (OP_0..OP_16, push ops)
    for op in 0x00u16..=0x60 {
        t.push((op, tier1(100, 1)));
    }
    // OP_NOP..OP_ENDIF (control flow)
    for op in 0x61u16..=0x68 {
        t.push((op, tier1(150, 2)));
    }
    // OP_VERIFY, OP_RETURN
    t.push((0x69, tier1(100, 1)));
    t.push((0x6A, tier1(100, 1)));
    // Stack ops: OP_TOALTSTACK..OP_TUCK (0x6B..0x7D)
    for op in 0x6Bu16..=0x7D {
        t.push((op, tier1(200, 5)));
    }
    // OP_SIZE
    t.push((0x82, tier1(300, 5)));
    // Bitwise: OP_EQUAL, OP_EQUALVERIFY
    t.push((0x87, tier1(500, 10)));
    t.push((0x88, tier1(500, 10)));
    // Arithmetic: OP_1ADD..OP_WITHIN (0x8B..0xA5)
    for op in 0x8Bu16..=0xA5 {
        t.push((op, tier1(500, 10)));
    }
    // Tier 2: OP_MUL, OP_DIV, OP_MOD (re-enabled)
    t.push((0x95, tier1(5_000, 100)));
    t.push((0x96, tier1(5_000, 100)));
    t.push((0x97, tier1(5_000, 100)));

    // Tier 3: Hash opcodes
    t.push((OPCODE_SHA3, tier_hash(10_000, 100)));
    t.push((OPCODE_KECCAK, tier_hash(12_000, 100)));

    // Tier 5: PQC signature opcodes
    t.push((OPCODE_CHECK_ML_DSA, tier1(5_000_000, 4_000)));
    t.push((OPCODE_CHECK_ML_KEM, tier1(3_000_000, 2_000)));

    // Tier 6: eUTXO context read opcodes
    t.push((OPCODE_DATUM, tier_ctx(5_000, 10, 0, 1)));
    t.push((OPCODE_REDEEMER, tier_ctx(5_000, 10, 0, 1)));
    t.push((OPCODE_REF_INPUT, tier_ctx(10_000, 50, 0, 1)));
    t.push((OPCODE_CHECK_VALID_RANGE, tier1(1_000, 0)));
    t.push((OPCODE_CHECK_REQ_SIGNER, tier1(2_000, 32)));
    t.push((OPCODE_CHECK_MINT, tier1(3_000, 64)));
    t.push((OPCODE_VALUE_OF, tier1(2_000, 16)));

    t.sort_by_key(|(op, _)| *op);
    t
}
