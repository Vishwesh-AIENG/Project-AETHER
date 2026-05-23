//! AT-1 gate: 1000+ A64 encoding → decoded-form pairs.
//!
//! ## Gate definition
//!
//! Run `cargo test -p aether-translator --test at1_canned_1000`.
//! `at1_canned_1000_vectors` must pass.
//!
//! ## Structure
//!
//! Two layers:
//!
//! 1. **Hand-curated anchors** (74 vectors) — spec-derived encodings that
//!    have been cross-checked against the ARM ARM. These pin specific
//!    semantics (e.g. `0x91000421 = ADD x1, x1, #1`).
//!
//! 2. **Generated sweeps** (>= 930 vectors) — encoder helpers that are the
//!    literal inverse of the corresponding decoder, fed combinatorial
//!    parameter sweeps. This protects against decoder regressions but does
//!    NOT independently validate the decoder against the architectural spec
//!    — that role is owned by the capstone-diff fuzz target (un-ignored in
//!    its own follow-up).
//!
//! The 1000-vector floor is enforced by `at1_canned_1000_vectors`.

use aether_translator::decoder::bits::decode_bit_masks;
use aether_translator::decoder::{
    decode_instruction, AccessSize, AddrMode, Cond, DecodedInsn, ExtendKind, Reg, ShiftKind,
};

struct V {
    word: u32,
    expected: DecodedInsn,
}

// =============================================================================
//                              ENCODER HELPERS
// =============================================================================
// Each helper is the literal inverse of a corresponding decoder function in
// src/decoder/*. The decoder vs encoder mirror gives us regression coverage;
// the spec-level cross-check is delegated to the capstone-diff fuzz target.

fn adr_pcrel(op: u32, rd: u8, imm21: i32) -> u32 {
    let imm = (imm21 as u32) & 0x1F_FFFF;
    let immlo = imm & 0x3;
    let immhi = (imm >> 2) & 0x7_FFFF;
    (op << 31) | (immlo << 29) | (0b10000 << 24) | (immhi << 5) | rd as u32
}

fn add_sub_imm(
    sf: bool, sub: bool, set_flags: bool, shift_12: bool, imm12: u16, rn: u8, rd: u8,
) -> u32 {
    let sf_bit = if sf { 1 } else { 0 };
    let op = if sub { 1 } else { 0 };
    let s = if set_flags { 1 } else { 0 };
    let sh = if shift_12 { 1 } else { 0 };
    (sf_bit << 31) | (op << 30) | (s << 29) | (0b100010 << 23) | (sh << 22)
        | ((imm12 as u32 & 0xFFF) << 10) | ((rn as u32) << 5) | rd as u32
}

fn logical_imm(sf: bool, opc: u32, n: u32, immr: u32, imms: u32, rn: u8, rd: u8) -> u32 {
    let sf_bit = if sf { 1 } else { 0 };
    (sf_bit << 31) | ((opc & 0x3) << 29) | (0b100100 << 23) | ((n & 1) << 22)
        | ((immr & 0x3F) << 16) | ((imms & 0x3F) << 10) | ((rn as u32) << 5) | rd as u32
}

fn mov_wide(sf: bool, opc: u32, hw: u32, imm16: u16, rd: u8) -> u32 {
    let sf_bit = if sf { 1 } else { 0 };
    (sf_bit << 31) | ((opc & 0x3) << 29) | (0b100101 << 23) | ((hw & 0x3) << 21)
        | ((imm16 as u32) << 5) | rd as u32
}

fn bitfield(sf: bool, opc: u32, immr: u32, imms: u32, rn: u8, rd: u8) -> u32 {
    let sf_bit = if sf { 1 } else { 0 };
    let n = if sf { 1 } else { 0 };
    (sf_bit << 31) | ((opc & 0x3) << 29) | (0b100110 << 23) | (n << 22)
        | ((immr & 0x3F) << 16) | ((imms & 0x3F) << 10) | ((rn as u32) << 5) | rd as u32
}

fn extr(sf: bool, rm: u8, imms: u32, rn: u8, rd: u8) -> u32 {
    let sf_bit = if sf { 1 } else { 0 };
    let n = if sf { 1 } else { 0 };
    (sf_bit << 31) | (0b00 << 29) | (0b100111 << 23) | (n << 22) | (0 << 21)
        | ((rm as u32) << 16) | ((imms & 0x3F) << 10) | ((rn as u32) << 5) | rd as u32
}

fn add_sub_shifted_reg(
    sf: bool, sub: bool, set_flags: bool, shift: u32, amount: u32, rm: u8, rn: u8, rd: u8,
) -> u32 {
    let sf_bit = if sf { 1 } else { 0 };
    let op = if sub { 1 } else { 0 };
    let s = if set_flags { 1 } else { 0 };
    (sf_bit << 31) | (op << 30) | (s << 29) | (0b01011 << 24) | ((shift & 0x3) << 22)
        | (0 << 21) | ((rm as u32) << 16) | ((amount & 0x3F) << 10) | ((rn as u32) << 5)
        | rd as u32
}

fn logical_shifted_reg(
    sf: bool, opc: u32, shift: u32, invert: bool, amount: u32, rm: u8, rn: u8, rd: u8,
) -> u32 {
    let sf_bit = if sf { 1 } else { 0 };
    let n = if invert { 1 } else { 0 };
    (sf_bit << 31) | ((opc & 0x3) << 29) | (0b01010 << 24) | ((shift & 0x3) << 22)
        | (n << 21) | ((rm as u32) << 16) | ((amount & 0x3F) << 10) | ((rn as u32) << 5)
        | rd as u32
}

fn add_sub_ext_reg(
    sf: bool, sub: bool, set_flags: bool, option: u32, imm3: u32, rm: u8, rn: u8, rd: u8,
) -> u32 {
    let sf_bit = if sf { 1 } else { 0 };
    let op = if sub { 1 } else { 0 };
    let s = if set_flags { 1 } else { 0 };
    (sf_bit << 31) | (op << 30) | (s << 29) | (0b01011 << 24) | (0 << 22) | (1 << 21)
        | ((rm as u32) << 16) | ((option & 0x7) << 13) | ((imm3 & 0x7) << 10)
        | ((rn as u32) << 5) | rd as u32
}

fn conditional_select(sf: bool, op: u32, op2: u32, rm: u8, cond: u32, rn: u8, rd: u8) -> u32 {
    let sf_bit = if sf { 1 } else { 0 };
    (sf_bit << 31) | (op << 30) | (0 << 29) | (0b11010100 << 21)
        | ((rm as u32) << 16) | ((cond & 0xF) << 12) | ((op2 & 0x3) << 10)
        | ((rn as u32) << 5) | rd as u32
}

fn dp3_madd_msub(sf: bool, sub: bool, ra: u8, rm: u8, rn: u8, rd: u8) -> u32 {
    let sf_bit = if sf { 1 } else { 0 };
    let o0 = if sub { 1 } else { 0 };
    (sf_bit << 31) | (0b00 << 29) | (0b11011000 << 21) | ((rm as u32) << 16)
        | (o0 << 15) | ((ra as u32) << 10) | ((rn as u32) << 5) | rd as u32
}

fn dp2_div(sf: bool, signed: bool, rm: u8, rn: u8, rd: u8) -> u32 {
    let sf_bit = if sf { 1 } else { 0 };
    let opcode = if signed { 0b000011 } else { 0b000010 };
    (sf_bit << 31) | (0 << 30) | (0 << 29) | (0b11010110 << 21)
        | ((rm as u32) << 16) | ((opcode as u32) << 10) | ((rn as u32) << 5) | rd as u32
}

fn dp2_shift(sf: bool, kind: u32, rm: u8, rn: u8, rd: u8) -> u32 {
    let sf_bit = if sf { 1 } else { 0 };
    // kind: 0=LSL 1=LSR 2=ASR 3=ROR → opcode 0b001000..0b001011
    let opcode = 0b001000 | (kind & 0x3);
    (sf_bit << 31) | (0 << 30) | (0 << 29) | (0b11010110 << 21)
        | ((rm as u32) << 16) | ((opcode as u32) << 10) | ((rn as u32) << 5) | rd as u32
}

fn dp1_src(sf: bool, opcode: u32, rn: u8, rd: u8) -> u32 {
    let sf_bit = if sf { 1 } else { 0 };
    (sf_bit << 31) | (1 << 30) | (0 << 29) | (0b11010110 << 21)
        | (0 << 16) | ((opcode & 0x3F) << 10) | ((rn as u32) << 5) | rd as u32
}

fn ls_unsigned_offset(size: u32, opc: u32, imm12: u32, rn: u8, rt: u8) -> u32 {
    ((size & 0x3) << 30) | (0b111 << 27) | (0 << 26) | (0b01 << 24)
        | ((opc & 0x3) << 22) | ((imm12 & 0xFFF) << 10) | ((rn as u32) << 5) | rt as u32
}

fn ls_imm_pre_post_unscaled(
    size: u32, opc: u32, imm9: i32, op2: u32, rn: u8, rt: u8,
) -> u32 {
    let imm = (imm9 as u32) & 0x1FF;
    ((size & 0x3) << 30) | (0b111 << 27) | (0 << 26) | (0b00 << 24)
        | ((opc & 0x3) << 22) | (0 << 21) | (imm << 12) | ((op2 & 0x3) << 10)
        | ((rn as u32) << 5) | rt as u32
}

fn ls_reg_offset(
    size: u32, opc: u32, rm: u8, option: u32, s: u32, rn: u8, rt: u8,
) -> u32 {
    ((size & 0x3) << 30) | (0b111 << 27) | (0 << 26) | (0b00 << 24)
        | ((opc & 0x3) << 22) | (1 << 21) | ((rm as u32) << 16) | ((option & 0x7) << 13)
        | ((s & 1) << 12) | (0b10 << 10) | ((rn as u32) << 5) | rt as u32
}

fn load_literal(opc: u32, imm19: i32, rt: u8) -> u32 {
    let imm = (imm19 as u32) & 0x7_FFFF;
    ((opc & 0x3) << 30) | (0b011 << 27) | (0 << 26) | (0b00 << 24)
        | (imm << 5) | rt as u32
}

fn ls_pair(opc: u32, cls: u32, l: u32, imm7: i32, rt2: u8, rn: u8, rt: u8) -> u32 {
    let imm = (imm7 as u32) & 0x7F;
    ((opc & 0x3) << 30) | (0b101 << 27) | (0 << 26) | ((cls & 0x3) << 23)
        | ((l & 1) << 22) | (imm << 15) | ((rt2 as u32) << 10) | ((rn as u32) << 5)
        | rt as u32
}

/// LDXR/STXR/LDAXR/STLXR + pair variants. `acquire_or_release` is `o0` (bit 15).
fn ll_sc(
    size: u32, l: u32, pair: bool, ar: bool, rs: u8, rt2: u8, rn: u8, rt: u8,
) -> u32 {
    let o0 = if ar { 1 } else { 0 };
    let bit21 = if pair { 1 } else { 0 };
    ((size & 0x3) << 30) | (0b001000 << 24) | (0 << 23) | ((l & 1) << 22)
        | (bit21 << 21) | ((rs as u32) << 16) | (o0 << 15) | ((rt2 as u32) << 10)
        | ((rn as u32) << 5) | rt as u32
}

fn ldar(size: u32, rn: u8, rt: u8) -> u32 {
    ((size & 0x3) << 30) | (0b001000 << 24) | (1 << 23) | (1 << 22) | (0 << 21)
        | (0b11111 << 16) | (1 << 15) | (0b11111 << 10) | ((rn as u32) << 5) | rt as u32
}

fn stlr(size: u32, rn: u8, rt: u8) -> u32 {
    ((size & 0x3) << 30) | (0b001000 << 24) | (1 << 23) | (0 << 22) | (0 << 21)
        | (0b11111 << 16) | (1 << 15) | (0b11111 << 10) | ((rn as u32) << 5) | rt as u32
}

fn b_or_bl(bl: bool, imm26: i32) -> u32 {
    let imm = (imm26 as u32) & 0x3FF_FFFF;
    let op = if bl { 1 } else { 0 };
    (op << 31) | (0b00101 << 26) | imm
}

fn bcond_enc(cond: u32, imm19: i32) -> u32 {
    let imm = (imm19 as u32) & 0x7_FFFF;
    (0b01010100 << 24) | (imm << 5) | (cond & 0xF)
}

fn cbz_cbnz(sf: bool, nz: bool, imm19: i32, rt: u8) -> u32 {
    let sf_bit = if sf { 1 } else { 0 };
    let op = if nz { 1 } else { 0 };
    let imm = (imm19 as u32) & 0x7_FFFF;
    (sf_bit << 31) | (0b011010 << 25) | (op << 24) | (imm << 5) | rt as u32
}

fn tbz_tbnz(bit: u8, nz: bool, imm14: i32, rt: u8) -> u32 {
    let b5 = (bit >> 5) & 1;
    let b40 = (bit & 0x1F) as u32;
    let op = if nz { 1 } else { 0 };
    let imm = (imm14 as u32) & 0x3FFF;
    ((b5 as u32) << 31) | (0b011011 << 25) | (op << 24) | (b40 << 19) | (imm << 5)
        | rt as u32
}

fn br_blr_ret(opc: u32, rn: u8) -> u32 {
    (0b1101011 << 25) | ((opc & 0xF) << 21) | (0b11111 << 16) | ((rn as u32) << 5)
}

fn excp_gen(opc: u32, imm16: u16, ll: u32) -> u32 {
    (0b11010100 << 24) | ((opc & 0x7) << 21) | ((imm16 as u32) << 5) | (ll & 0x3)
}

fn hint(imm: u32) -> u32 {
    // bits[31:12] = 1101_0101_0000_0011_0010 = 0xD5032
    0xD5032_000u32 | ((imm & 0x7F) << 5) | 0b11111
}

fn dmb(crm: u32) -> u32 {
    // bits[31:12] = 0xD5033 ; bits[11:8] = CRm ; bits[7:5] = op2 (DMB = 0b101)
    0xD5033_000u32 | ((crm & 0xF) << 8) | (0b101 << 5) | 0b11111
}

fn dsb(crm: u32) -> u32 {
    0xD5033_000u32 | ((crm & 0xF) << 8) | (0b100 << 5) | 0b11111
}

fn isb_enc(crm: u32) -> u32 {
    0xD5033_000u32 | ((crm & 0xF) << 8) | (0b110 << 5) | 0b11111
}

// =============================================================================
//                                 ANCHORS
// =============================================================================
//
// 74 hand-curated, spec-checked encodings. These pin specific known-good
// decodings and catch encoder-decoder mirror bugs.

fn anchors() -> Vec<V> {
    use AddrMode::*;
    use DecodedInsn::*;
    vec![
        // PC-rel
        V { word: 0x90000000, expected: Adrp { rd: Reg(0), imm: 0 } },
        V { word: 0x10000000, expected: Adr  { rd: Reg(0), imm: 0 } },
        V { word: 0xB0000000, expected: Adrp { rd: Reg(0), imm: 1 } },
        // Add/sub imm
        V { word: 0x91000421, expected: AddImm {
            sf: true, rd: Reg(1), rn: Reg(1), imm: 1, shift_12: false, set_flags: false } },
        V { word: 0x11000400, expected: AddImm {
            sf: false, rd: Reg(0), rn: Reg(0), imm: 1, shift_12: false, set_flags: false } },
        V { word: 0xD1000400, expected: SubImm {
            sf: true, rd: Reg(0), rn: Reg(0), imm: 1, shift_12: false, set_flags: false } },
        V { word: 0xB100043F, expected: AddImm {
            sf: true, rd: Reg(31), rn: Reg(1), imm: 1, shift_12: false, set_flags: true } },
        // Logical imm
        V { word: 0x92400020, expected: AndImm {
            sf: true, rd: Reg(0), rn: Reg(1), imm: 1, set_flags: false } },
        V { word: 0xF2400020, expected: AndImm {
            sf: true, rd: Reg(0), rn: Reg(1), imm: 1, set_flags: true } },
        V { word: 0xB2400020, expected: OrrImm { sf: true, rd: Reg(0), rn: Reg(1), imm: 1 } },
        V { word: 0xD2400020, expected: EorImm { sf: true, rd: Reg(0), rn: Reg(1), imm: 1 } },
        // Mov wide
        V { word: 0xD2800020, expected: MovWide {
            sf: true, opc: 0b10, hw: 0, rd: Reg(0), imm: 1 } },
        V { word: 0xF2800020, expected: MovWide {
            sf: true, opc: 0b11, hw: 0, rd: Reg(0), imm: 1 } },
        V { word: 0x92800020, expected: MovWide {
            sf: true, opc: 0b00, hw: 0, rd: Reg(0), imm: 1 } },
        // Bitfield
        V { word: 0x93407C20, expected: Bfm {
            sf: true, opc: 0, rd: Reg(0), rn: Reg(1), immr: 0, imms: 31 } },
        V { word: 0xD3407C20, expected: Bfm {
            sf: true, opc: 0b10, rd: Reg(0), rn: Reg(1), immr: 0, imms: 31 } },
        // Extract
        V { word: 0x93C3FC20, expected: Extr {
            sf: true, rd: Reg(0), rn: Reg(1), rm: Reg(3), lsb: 63 } },
        // Add/sub shifted
        V { word: 0x8B030020, expected: AddReg {
            sf: true, rd: Reg(0), rn: Reg(1), rm: Reg(3),
            shift: ShiftKind::Lsl, amount: 0, set_flags: false } },
        V { word: 0xCB030020, expected: SubReg {
            sf: true, rd: Reg(0), rn: Reg(1), rm: Reg(3),
            shift: ShiftKind::Lsl, amount: 0, set_flags: false } },
        V { word: 0xAB030020, expected: AddReg {
            sf: true, rd: Reg(0), rn: Reg(1), rm: Reg(3),
            shift: ShiftKind::Lsl, amount: 0, set_flags: true } },
        V { word: 0xEB03003F, expected: SubReg {
            sf: true, rd: Reg(31), rn: Reg(1), rm: Reg(3),
            shift: ShiftKind::Lsl, amount: 0, set_flags: true } },
        // Logical shifted
        V { word: 0x8A030020, expected: LogicalReg {
            sf: true, opc: 0b00, rd: Reg(0), rn: Reg(1), rm: Reg(3),
            shift: ShiftKind::Lsl, amount: 0, invert: false } },
        V { word: 0xAA030020, expected: LogicalReg {
            sf: true, opc: 0b01, rd: Reg(0), rn: Reg(1), rm: Reg(3),
            shift: ShiftKind::Lsl, amount: 0, invert: false } },
        V { word: 0xCA030020, expected: LogicalReg {
            sf: true, opc: 0b10, rd: Reg(0), rn: Reg(1), rm: Reg(3),
            shift: ShiftKind::Lsl, amount: 0, invert: false } },
        V { word: 0xEA030020, expected: LogicalReg {
            sf: true, opc: 0b11, rd: Reg(0), rn: Reg(1), rm: Reg(3),
            shift: ShiftKind::Lsl, amount: 0, invert: false } },
        // Add/sub extended
        V { word: 0x8B23E020, expected: AddSubExtReg {
            sf: true, rd: Reg(0), rn: Reg(1), rm: Reg(3),
            extend: ExtendKind::Sxtx, imm3: 0, sub: false, set_flags: false } },
        // Conditional select
        V { word: 0x9A831020, expected: Csel {
            sf: true, rd: Reg(0), rn: Reg(1), rm: Reg(3), cond: Cond::Ne, op2: 0 } },
        V { word: 0x9A831420, expected: Csel {
            sf: true, rd: Reg(0), rn: Reg(1), rm: Reg(3), cond: Cond::Ne, op2: 1 } },
        // Mul
        V { word: 0x9B037C20, expected: Mul {
            sf: true, rd: Reg(0), rn: Reg(1), rm: Reg(3), ra: Reg::XZR, sub: false } },
        // Div / shift / dp-1-src
        V { word: 0x9AC30820, expected: Div { sf: true, rd: Reg(0), rn: Reg(1), rm: Reg(3), signed: false } },
        V { word: 0x9AC30C20, expected: Div { sf: true, rd: Reg(0), rn: Reg(1), rm: Reg(3), signed: true } },
        V { word: 0x9AC32020, expected: Shift {
            sf: true, rd: Reg(0), rn: Reg(1), rm: Reg(3), kind: ShiftKind::Lsl } },
        V { word: 0xDAC00020, expected: DataOp1Src { sf: true, rd: Reg(0), rn: Reg(1), opcode: 0 } },
        V { word: 0xDAC01020, expected: DataOp1Src { sf: true, rd: Reg(0), rn: Reg(1), opcode: 4 } },
        // Load/store unsigned offset
        V { word: 0xF9400020, expected: Ldr { rt: Reg(0), size: AccessSize::DoubleWord, signed: false,
            addr: Offset { base: Reg(1), imm: 0 } } },
        V { word: 0xF9000020, expected: Str { rt: Reg(0), size: AccessSize::DoubleWord,
            addr: Offset { base: Reg(1), imm: 0 } } },
        V { word: 0xB9400020, expected: Ldr { rt: Reg(0), size: AccessSize::Word, signed: false,
            addr: Offset { base: Reg(1), imm: 0 } } },
        V { word: 0x39400020, expected: Ldr { rt: Reg(0), size: AccessSize::Byte, signed: false,
            addr: Offset { base: Reg(1), imm: 0 } } },
        // Imm pre/post/unscaled
        V { word: 0xF8408420, expected: Ldr { rt: Reg(0), size: AccessSize::DoubleWord, signed: false,
            addr: PostIndex { base: Reg(1), imm: 8 } } },
        V { word: 0xF8408C20, expected: Ldr { rt: Reg(0), size: AccessSize::DoubleWord, signed: false,
            addr: PreIndex { base: Reg(1), imm: 8 } } },
        V { word: 0xF8408020, expected: Ldr { rt: Reg(0), size: AccessSize::DoubleWord, signed: false,
            addr: Offset { base: Reg(1), imm: 8 } } },
        // Literal
        V { word: 0x58000020, expected: Ldr { rt: Reg(0), size: AccessSize::DoubleWord, signed: false,
            addr: Pcrel { offset: 4 } } },
        // Pair
        V { word: 0xA9400420, expected: Ldp {
            rt1: Reg(0), rt2: Reg(1), sf: true, signed: false,
            addr: Offset { base: Reg(1), imm: 0 } } },
        V { word: 0xA9000420, expected: Stp {
            rt1: Reg(0), rt2: Reg(1), sf: true,
            addr: Offset { base: Reg(1), imm: 0 } } },
        // LL/SC + acquire/release
        V { word: 0x885F7C20, expected: Ldxr {
            size: AccessSize::Word, rt: Reg(0), rn: Reg(1),
            acquire: false, pair: false, rt2: Reg(31) } },
        V { word: 0x885FFC20, expected: Ldxr {
            size: AccessSize::Word, rt: Reg(0), rn: Reg(1),
            acquire: true, pair: false, rt2: Reg(31) } },
        V { word: 0x88037C20, expected: Stxr {
            size: AccessSize::Word, rs: Reg(3), rt: Reg(0), rn: Reg(1),
            release: false, pair: false, rt2: Reg(31) } },
        V { word: 0x88DFFC20, expected: Ldar { size: AccessSize::Word, rt: Reg(0), rn: Reg(1) } },
        V { word: 0x889FFC20, expected: Stlr { size: AccessSize::Word, rt: Reg(0), rn: Reg(1) } },
        // Branches
        V { word: 0x14000001, expected: B { offset: 4 } },
        V { word: 0x94000001, expected: Bl { offset: 4 } },
        V { word: 0x54000020, expected: Bcond { cond: Cond::Eq, offset: 4 } },
        V { word: 0x54000021, expected: Bcond { cond: Cond::Ne, offset: 4 } },
        V { word: 0xB4000020, expected: Cbz  { sf: true, rt: Reg(0), offset: 4 } },
        V { word: 0xB5000020, expected: Cbnz { sf: true, rt: Reg(0), offset: 4 } },
        V { word: 0x36000020, expected: Tbz  { bit: 0, rt: Reg(0), offset: 4 } },
        V { word: 0x37000020, expected: Tbnz { bit: 0, rt: Reg(0), offset: 4 } },
        V { word: 0xD63F0020, expected: Blr { rn: Reg(1) } },
        V { word: 0xD61F0020, expected: Br  { rn: Reg(1) } },
        V { word: 0xD65F03C0, expected: Ret { rn: Reg(30) } },
        // Exception generation
        V { word: 0xD4000021, expected: Svc { imm16: 1 } },
        V { word: 0xD4000022, expected: Hvc { imm16: 1 } },
        V { word: 0xD4000023, expected: Smc { imm16: 1 } },
        V { word: 0xD4200020, expected: Brk { imm16: 1 } },
        V { word: 0xD4400020, expected: Hlt { imm16: 1 } },
        // Hints + barriers
        V { word: 0xD503201F, expected: Nop },
        V { word: 0xD503203F, expected: Yield },
        V { word: 0xD503205F, expected: Wfe },
        V { word: 0xD503207F, expected: Wfi },
        V { word: 0xD503209F, expected: Sev },
        V { word: 0xD50320BF, expected: Sevl },
        V { word: 0xD5033BBF, expected: Dmb { domain: 0xB } },
        V { word: 0xD5033B9F, expected: Dsb { domain: 0xB } },
        V { word: 0xD5033FDF, expected: Isb },
    ]
}

// =============================================================================
//                                 SWEEPS
// =============================================================================

fn push_pcrel(out: &mut Vec<V>) {
    use DecodedInsn::*;
    for &op in &[0u32, 1] {
        for rd in (0u8..32).step_by(3) {
            for &imm21 in &[0i32, 1, -1, 0xFFFF, -0xFFFF, 0xF_FFFF, -0xF_FFFF, 0x10_0000, -0x10_0000] {
                let w = adr_pcrel(op, rd, imm21);
                let imm = ((imm21 << 11) >> 11) as i32; // sign-extend 21
                let exp = if op == 1 {
                    Adrp { rd: Reg(rd), imm }
                } else {
                    Adr { rd: Reg(rd), imm }
                };
                out.push(V { word: w, expected: exp });
            }
        }
    }
}

fn push_add_sub_imm(out: &mut Vec<V>) {
    use DecodedInsn::*;
    for &sf in &[true, false] {
        for &sub in &[false, true] {
            for &set_flags in &[false, true] {
                for &shift_12 in &[false, true] {
                    for &imm in &[0u16, 1, 2, 7, 0xFF, 0x100, 0x7FF, 0xFFF] {
                        for &(rn, rd) in &[(0u8, 0u8), (1, 2), (3, 4), (29, 30), (31, 0)] {
                            let w = add_sub_imm(sf, sub, set_flags, shift_12, imm, rn, rd);
                            let exp = if sub {
                                SubImm { sf, rd: Reg(rd), rn: Reg(rn), imm, shift_12, set_flags }
                            } else {
                                AddImm { sf, rd: Reg(rd), rn: Reg(rn), imm, shift_12, set_flags }
                            };
                            out.push(V { word: w, expected: exp });
                        }
                    }
                }
            }
        }
    }
}

fn push_logical_imm(out: &mut Vec<V>) {
    use DecodedInsn::*;
    // Known-valid (N, immr, imms) tuples. Each yields a valid bitmask per
    // ARM ARM J1.2 DecodeBitMasks.
    let known = [
        (1u32, 0u32, 0u32),    // 0x1
        (1, 0, 1),             // 0x3
        (1, 0, 2),             // 0x7
        (1, 0, 3),             // 0xF
        (1, 0, 4),             // 0x1F
        (1, 0, 7),             // 0xFF
        (1, 0, 15),            // 0xFFFF
        (1, 0, 31),            // 0xFFFF_FFFF
        (1, 0, 62),            // 0x7FFF_FFFF_FFFF_FFFF (62-bit mask)
        (1, 1, 1),             // rotated
        (1, 5, 7),             // rotated
        (1, 16, 31),           // 0xFFFFFFFF rotated
        (0, 0, 0),             // 32-bit form
        (0, 0, 7),             // 32-bit form
        (0, 0, 15),            // 32-bit form
        (0, 16, 31),           // 32-bit rotated
    ];
    for (n, immr, imms) in known {
        for &sf in &[true, false] {
            if !sf && n != 0 {
                continue; // 32-bit form requires N=0
            }
            // Skip tuples that are reserved per ARM ARM DecodeBitMasks (s == levels).
            let Some(imm) = decode_bit_masks(n, imms, immr, sf) else { continue };
            for &opc in &[0u32, 1, 2, 3] {
                for &(rn, rd) in &[(0u8, 0u8), (1, 2), (3, 4), (30, 31)] {
                    let w = logical_imm(sf, opc, n, immr, imms, rn, rd);
                    let exp = match opc {
                        0 => AndImm { sf, rd: Reg(rd), rn: Reg(rn), imm, set_flags: false },
                        1 => OrrImm { sf, rd: Reg(rd), rn: Reg(rn), imm },
                        2 => EorImm { sf, rd: Reg(rd), rn: Reg(rn), imm },
                        3 => AndImm { sf, rd: Reg(rd), rn: Reg(rn), imm, set_flags: true },
                        _ => unreachable!(),
                    };
                    out.push(V { word: w, expected: exp });
                }
            }
        }
    }
}

fn push_mov_wide(out: &mut Vec<V>) {
    use DecodedInsn::*;
    for &sf in &[true, false] {
        for &opc in &[0u32, 2, 3] {
            let hw_max = if sf { 4 } else { 2 };
            for hw in 0..hw_max {
                for &imm in &[0u16, 1, 0xFF, 0x1234, 0xFFFF] {
                    for &rd in &[0u8, 1, 15, 30, 31] {
                        let w = mov_wide(sf, opc, hw, imm, rd);
                        out.push(V {
                            word: w,
                            expected: MovWide {
                                sf, opc: opc as u8, hw: hw as u8, rd: Reg(rd), imm,
                            },
                        });
                    }
                }
            }
        }
    }
}

fn push_bitfield(out: &mut Vec<V>) {
    use DecodedInsn::*;
    for &sf in &[true, false] {
        for &opc in &[0u32, 1, 2] {
            let max = if sf { 63 } else { 31 };
            for immr in [0u32, 5, 16, max] {
                for imms in [0u32, 7, 31, max] {
                    for &(rn, rd) in &[(0u8, 0u8), (1, 2), (3, 4), (30, 31)] {
                        let w = bitfield(sf, opc, immr, imms, rn, rd);
                        out.push(V {
                            word: w,
                            expected: Bfm {
                                sf, opc: opc as u8, rd: Reg(rd), rn: Reg(rn),
                                immr: immr as u8, imms: imms as u8,
                            },
                        });
                    }
                }
            }
        }
    }
}

fn push_extr(out: &mut Vec<V>) {
    use DecodedInsn::*;
    for &sf in &[true, false] {
        let max = if sf { 63 } else { 31 };
        for imms in [0u32, 1, 5, 15, 31, max] {
            for &(rm, rn, rd) in &[
                (0u8, 0u8, 0u8), (1, 2, 3), (5, 6, 7), (30, 30, 30),
            ] {
                let w = extr(sf, rm, imms, rn, rd);
                out.push(V {
                    word: w,
                    expected: Extr { sf, rd: Reg(rd), rn: Reg(rn), rm: Reg(rm),
                        lsb: imms as u8 },
                });
            }
        }
    }
}

fn push_add_sub_shifted(out: &mut Vec<V>) {
    use DecodedInsn::*;
    for &sf in &[true, false] {
        for &sub in &[false, true] {
            for &set_flags in &[false, true] {
                for shift in [0u32, 1, 2] {
                    // ROR (3) not allowed for ADD/SUB
                    for amount in [0u32, 1, 5, 15, 31] {
                        if !sf && amount >= 32 {
                            continue;
                        }
                        for &(rm, rn, rd) in &[
                            (0u8, 0u8, 0u8), (1, 2, 3), (5, 6, 7), (30, 30, 30),
                        ] {
                            let w = add_sub_shifted_reg(sf, sub, set_flags, shift, amount, rm, rn, rd);
                            let kind = match shift {
                                0 => ShiftKind::Lsl,
                                1 => ShiftKind::Lsr,
                                2 => ShiftKind::Asr,
                                _ => unreachable!(),
                            };
                            let exp = if sub {
                                SubReg {
                                    sf, rd: Reg(rd), rn: Reg(rn), rm: Reg(rm),
                                    shift: kind, amount: amount as u8, set_flags,
                                }
                            } else {
                                AddReg {
                                    sf, rd: Reg(rd), rn: Reg(rn), rm: Reg(rm),
                                    shift: kind, amount: amount as u8, set_flags,
                                }
                            };
                            out.push(V { word: w, expected: exp });
                        }
                    }
                }
            }
        }
    }
}

fn push_logical_shifted(out: &mut Vec<V>) {
    use DecodedInsn::*;
    for &sf in &[true, false] {
        for &opc in &[0u32, 1, 2, 3] {
            for shift in [0u32, 1, 2, 3] {
                for &invert in &[false, true] {
                    for amount in [0u32, 1, 5, 15, 31] {
                        if !sf && amount >= 32 {
                            continue;
                        }
                        for &(rm, rn, rd) in &[
                            (0u8, 0u8, 0u8), (1, 2, 3), (5, 6, 7), (30, 30, 30),
                        ] {
                            let w = logical_shifted_reg(sf, opc, shift, invert, amount, rm, rn, rd);
                            let kind = match shift {
                                0 => ShiftKind::Lsl,
                                1 => ShiftKind::Lsr,
                                2 => ShiftKind::Asr,
                                3 => ShiftKind::Ror,
                                _ => unreachable!(),
                            };
                            out.push(V {
                                word: w,
                                expected: LogicalReg {
                                    sf, opc: opc as u8, rd: Reg(rd), rn: Reg(rn), rm: Reg(rm),
                                    shift: kind, amount: amount as u8, invert,
                                },
                            });
                        }
                    }
                }
            }
        }
    }
}

fn push_add_sub_extended(out: &mut Vec<V>) {
    use DecodedInsn::*;
    for &sf in &[true, false] {
        for &sub in &[false, true] {
            for &set_flags in &[false, true] {
                for option in 0u32..8 {
                    for imm3 in 0u32..5 {
                        for &(rm, rn, rd) in &[(0u8, 0u8, 0u8), (1, 2, 3), (30, 30, 30)] {
                            let w = add_sub_ext_reg(sf, sub, set_flags, option, imm3, rm, rn, rd);
                            let extend = match option {
                                0 => ExtendKind::Uxtb,
                                1 => ExtendKind::Uxth,
                                2 => ExtendKind::Uxtw,
                                3 => ExtendKind::Uxtx,
                                4 => ExtendKind::Sxtb,
                                5 => ExtendKind::Sxth,
                                6 => ExtendKind::Sxtw,
                                7 => ExtendKind::Sxtx,
                                _ => unreachable!(),
                            };
                            out.push(V {
                                word: w,
                                expected: AddSubExtReg {
                                    sf, rd: Reg(rd), rn: Reg(rn), rm: Reg(rm),
                                    extend, imm3: imm3 as u8, sub, set_flags,
                                },
                            });
                        }
                    }
                }
            }
        }
    }
}

fn push_csel(out: &mut Vec<V>) {
    use DecodedInsn::*;
    for &sf in &[true, false] {
        for op in 0u32..2 {
            for op2_bit in 0u32..2 {
                for cond in 0u32..16 {
                    for &(rm, rn, rd) in &[(0u8, 0u8, 0u8), (3, 4, 5), (30, 30, 30)] {
                        let w = conditional_select(sf, op, op2_bit, rm, cond, rn, rd);
                        let variant = ((op << 1) | (op2_bit & 1)) as u8;
                        out.push(V {
                            word: w,
                            expected: Csel {
                                sf, rd: Reg(rd), rn: Reg(rn), rm: Reg(rm),
                                cond: Cond::from_bits(cond as u8), op2: variant,
                            },
                        });
                    }
                }
            }
        }
    }
}

fn push_mul(out: &mut Vec<V>) {
    use DecodedInsn::*;
    for &sf in &[true, false] {
        for &sub in &[false, true] {
            for ra in [0u8, 1, 5, 31] {
                for &(rm, rn, rd) in &[(0u8, 0u8, 0u8), (3, 4, 5), (30, 30, 30)] {
                    let w = dp3_madd_msub(sf, sub, ra, rm, rn, rd);
                    out.push(V {
                        word: w,
                        expected: Mul {
                            sf, rd: Reg(rd), rn: Reg(rn), rm: Reg(rm),
                            ra: Reg(ra), sub,
                        },
                    });
                }
            }
        }
    }
}

fn push_dp2(out: &mut Vec<V>) {
    use DecodedInsn::*;
    for &sf in &[true, false] {
        for &signed in &[false, true] {
            for &(rm, rn, rd) in &[(0u8, 0u8, 0u8), (3, 4, 5), (30, 30, 30)] {
                let w = dp2_div(sf, signed, rm, rn, rd);
                out.push(V {
                    word: w,
                    expected: Div {
                        sf, rd: Reg(rd), rn: Reg(rn), rm: Reg(rm), signed,
                    },
                });
            }
        }
        for kind in 0u32..4 {
            for &(rm, rn, rd) in &[(0u8, 0u8, 0u8), (3, 4, 5), (30, 30, 30)] {
                let w = dp2_shift(sf, kind, rm, rn, rd);
                let k = match kind {
                    0 => ShiftKind::Lsl,
                    1 => ShiftKind::Lsr,
                    2 => ShiftKind::Asr,
                    3 => ShiftKind::Ror,
                    _ => unreachable!(),
                };
                out.push(V {
                    word: w,
                    expected: Shift {
                        sf, rd: Reg(rd), rn: Reg(rn), rm: Reg(rm), kind: k,
                    },
                });
            }
        }
    }
}

fn push_dp1(out: &mut Vec<V>) {
    use DecodedInsn::*;
    for &sf in &[true, false] {
        for opcode in 0u32..6 {
            for &(rn, rd) in &[(0u8, 0u8), (3, 4), (30, 30)] {
                let w = dp1_src(sf, opcode, rn, rd);
                out.push(V {
                    word: w,
                    expected: DataOp1Src {
                        sf, rd: Reg(rd), rn: Reg(rn), opcode: opcode as u8,
                    },
                });
            }
        }
    }
}

fn push_loadstore_unsigned(out: &mut Vec<V>) {
    use AddrMode::*;
    use DecodedInsn::*;
    for size in 0u32..4 {
        for opc in 0u32..3 {
            // size=11 with opc>=10 is reserved (no LDRSX of 64-bit data).
            if size == 0b11 && opc >= 0b10 {
                continue;
            }
            if size == 0b10 && opc == 0b11 {
                continue;
            }
            for &imm12 in &[0u32, 1, 7, 0x10, 0x80, 0x100, 0x7FF, 0xFFF] {
                for &(rn, rt) in &[(0u8, 0u8), (1, 2), (3, 4), (30, 31)] {
                    let w = ls_unsigned_offset(size, opc, imm12, rn, rt);
                    let access = match size {
                        0 => AccessSize::Byte,
                        1 => AccessSize::HalfWord,
                        2 => AccessSize::Word,
                        3 => AccessSize::DoubleWord,
                        _ => unreachable!(),
                    };
                    let scale = size as u32;
                    let imm = (imm12 << scale) as i32;
                    let addr = Offset { base: Reg(rn), imm };
                    let exp = match opc {
                        0 => Str { rt: Reg(rt), size: access, addr },
                        1 => Ldr { rt: Reg(rt), size: access, signed: false, addr },
                        2 => Ldr { rt: Reg(rt), size: access, signed: true, addr },
                        _ => unreachable!(),
                    };
                    out.push(V { word: w, expected: exp });
                }
            }
        }
    }
}

fn push_loadstore_imm_pre_post(out: &mut Vec<V>) {
    use AddrMode::*;
    use DecodedInsn::*;
    for size in 0u32..4 {
        for opc in 0u32..3 {
            if size == 0b11 && opc >= 0b10 {
                continue;
            }
            if size == 0b10 && opc == 0b11 {
                continue;
            }
            for &imm in &[-256i32, -1, 0, 1, 8, 32, 255] {
                for op2 in [0u32, 1, 3] {
                    for &(rn, rt) in &[(0u8, 0u8), (1, 2), (30, 31)] {
                        let w = ls_imm_pre_post_unscaled(size, opc, imm, op2, rn, rt);
                        let access = match size {
                            0 => AccessSize::Byte,
                            1 => AccessSize::HalfWord,
                            2 => AccessSize::Word,
                            3 => AccessSize::DoubleWord,
                            _ => unreachable!(),
                        };
                        let addr = match op2 {
                            0 => Offset { base: Reg(rn), imm },
                            1 => PostIndex { base: Reg(rn), imm },
                            3 => PreIndex { base: Reg(rn), imm },
                            _ => unreachable!(),
                        };
                        let exp = match opc {
                            0 => Str { rt: Reg(rt), size: access, addr },
                            1 => Ldr { rt: Reg(rt), size: access, signed: false, addr },
                            2 => Ldr { rt: Reg(rt), size: access, signed: true, addr },
                            _ => unreachable!(),
                        };
                        out.push(V { word: w, expected: exp });
                    }
                }
            }
        }
    }
}

fn push_loadstore_reg_offset(out: &mut Vec<V>) {
    use AddrMode::*;
    use DecodedInsn::*;
    for size in 0u32..4 {
        for opc in 0u32..3 {
            if size == 0b11 && opc >= 0b10 {
                continue;
            }
            if size == 0b10 && opc == 0b11 {
                continue;
            }
            for option in [2u32, 3, 6, 7] {
                for s in 0u32..2 {
                    for &(rm, rn, rt) in &[(3u8, 1u8, 0u8), (5, 2, 4)] {
                        let w = ls_reg_offset(size, opc, rm, option, s, rn, rt);
                        let access = match size {
                            0 => AccessSize::Byte,
                            1 => AccessSize::HalfWord,
                            2 => AccessSize::Word,
                            3 => AccessSize::DoubleWord,
                            _ => unreachable!(),
                        };
                        let extend = match option {
                            2 => ExtendKind::Uxtw,
                            3 => ExtendKind::Uxtx,
                            6 => ExtendKind::Sxtw,
                            7 => ExtendKind::Sxtx,
                            _ => unreachable!(),
                        };
                        let shift = if s != 0 { size as u8 } else { 0 };
                        let addr = RegOffset { base: Reg(rn), index: Reg(rm), extend, shift };
                        let exp = match opc {
                            0 => Str { rt: Reg(rt), size: access, addr },
                            1 => Ldr { rt: Reg(rt), size: access, signed: false, addr },
                            2 => Ldr { rt: Reg(rt), size: access, signed: true, addr },
                            _ => unreachable!(),
                        };
                        out.push(V { word: w, expected: exp });
                    }
                }
            }
        }
    }
}

fn push_literal(out: &mut Vec<V>) {
    use AddrMode::*;
    use DecodedInsn::*;
    for opc in 0u32..3 {
        for imm19 in [0i32, 1, -1, 0x3FFFF, -0x40000] {
            for rt in [0u8, 5, 30] {
                let w = load_literal(opc, imm19, rt);
                let imm = (((imm19 as u32 & 0x7_FFFF) << 13) as i32 >> 13) << 2;
                let access = match opc {
                    0 => AccessSize::Word,
                    1 => AccessSize::DoubleWord,
                    2 => AccessSize::Word, // LDRSW
                    _ => unreachable!(),
                };
                let signed = opc == 2;
                out.push(V {
                    word: w,
                    expected: Ldr {
                        rt: Reg(rt), size: access, signed,
                        addr: Pcrel { offset: imm },
                    },
                });
            }
        }
    }
}

fn push_pair(out: &mut Vec<V>) {
    use AddrMode::*;
    use DecodedInsn::*;
    for opc in [0u32, 2] {
        for cls in [0u32, 1, 2, 3] {
            for l in 0u32..2 {
                for imm7 in [-64i32, -1, 0, 1, 8, 63] {
                    // Use non-colliding triples: Rn=31 (SP) when we sweep writeback so
                    // Rn-collision constraints don't fire spuriously.
                    for &(rt2, rn, rt) in &[(2u8, 31u8, 0u8), (5, 31, 4)] {
                        let w = ls_pair(opc, cls, l, imm7, rt2, rn, rt);
                        let (sf, signed) = match opc {
                            0 => (false, false),
                            2 => (true, false),
                            _ => unreachable!(),
                        };
                        let scale = if sf { 3 } else { 2 };
                        let imm = (((imm7 as u32 & 0x7F) << 25) as i32 >> 25) << scale;
                        let addr = match cls {
                            0 => Offset { base: Reg(rn), imm },
                            1 => PostIndex { base: Reg(rn), imm },
                            2 => Offset { base: Reg(rn), imm },
                            3 => PreIndex { base: Reg(rn), imm },
                            _ => unreachable!(),
                        };
                        let exp = if l != 0 {
                            Ldp { rt1: Reg(rt), rt2: Reg(rt2), sf, signed, addr }
                        } else {
                            Stp { rt1: Reg(rt), rt2: Reg(rt2), sf, addr }
                        };
                        out.push(V { word: w, expected: exp });
                    }
                }
            }
        }
    }
}

fn push_ll_sc(out: &mut Vec<V>) {
    use DecodedInsn::*;
    for size in 2u32..4 {
        for l in 0u32..2 {
            for ar in [false, true] {
                // For load form (l=1), Rs is unused and must be 11111.
                // For store form (l=0), Rs holds the status output and must
                // not equal Rt or (pair-form) Rt2.
                let rs_choices: &[u8] = if l == 1 { &[31] } else { &[3, 4, 31] };
                for &rs in rs_choices {
                for &(rt2, rn, rt) in &[
                    (31u8, 1u8, 0u8), (31, 5, 6), (31, 1, 0),
                ] {
                    // skip self-collision for store form (would be UNPREDICTABLE)
                    if l == 0 && rs != 31 && (rs == rt || rs == rt2) {
                        continue;
                    }
                    let w = ll_sc(size, l, false, ar, rs, rt2, rn, rt);
                    let access = if size == 2 { AccessSize::Word } else { AccessSize::DoubleWord };
                    let exp = if l == 1 {
                        Ldxr {
                            size: access, rt: Reg(rt), rn: Reg(rn),
                            acquire: ar, pair: false, rt2: Reg(rt2),
                        }
                    } else {
                        Stxr {
                            size: access, rs: Reg(rs), rt: Reg(rt), rn: Reg(rn),
                            release: ar, pair: false, rt2: Reg(rt2),
                        }
                    };
                    out.push(V { word: w, expected: exp });
                }
                }
            }
        }
    }
}

fn push_ldar_stlr(out: &mut Vec<V>) {
    use DecodedInsn::*;
    for size in 0u32..4 {
        for &(rn, rt) in &[(0u8, 0u8), (1, 2), (30, 31)] {
            let access = match size {
                0 => AccessSize::Byte,
                1 => AccessSize::HalfWord,
                2 => AccessSize::Word,
                3 => AccessSize::DoubleWord,
                _ => unreachable!(),
            };
            out.push(V { word: ldar(size, rn, rt),
                expected: Ldar { size: access, rt: Reg(rt), rn: Reg(rn) } });
            out.push(V { word: stlr(size, rn, rt),
                expected: Stlr { size: access, rt: Reg(rt), rn: Reg(rn) } });
        }
    }
}

fn push_branches(out: &mut Vec<V>) {
    use DecodedInsn::*;
    for &bl in &[false, true] {
        for imm26 in [-0x200_0000i32, -1, 0, 1, 0x1FF_FFFF, 0x10_0000] {
            let w = b_or_bl(bl, imm26);
            let offset = (((imm26 as u32 & 0x3FF_FFFF) << 6) as i32 >> 6) << 2;
            out.push(V {
                word: w,
                expected: if bl { Bl { offset } } else { B { offset } },
            });
        }
    }
}

fn push_bcond(out: &mut Vec<V>) {
    use DecodedInsn::*;
    for cond in 0u32..16 {
        for imm19 in [-0x40000i32, -1, 0, 1, 0x3FFFF] {
            let w = bcond_enc(cond, imm19);
            let offset = (((imm19 as u32 & 0x7_FFFF) << 13) as i32 >> 13) << 2;
            out.push(V {
                word: w,
                expected: Bcond { cond: Cond::from_bits(cond as u8), offset },
            });
        }
    }
}

fn push_cbz_tbz(out: &mut Vec<V>) {
    use DecodedInsn::*;
    for &sf in &[true, false] {
        for &nz in &[false, true] {
            for imm19 in [-1i32, 0, 1, 0x3FFFF] {
                for rt in [0u8, 1, 30, 31] {
                    let w = cbz_cbnz(sf, nz, imm19, rt);
                    let offset = (((imm19 as u32 & 0x7_FFFF) << 13) as i32 >> 13) << 2;
                    out.push(V {
                        word: w,
                        expected: if nz {
                            Cbnz { sf, rt: Reg(rt), offset }
                        } else {
                            Cbz { sf, rt: Reg(rt), offset }
                        },
                    });
                }
            }
        }
    }
    for bit in [0u8, 1, 5, 31, 63] {
        for &nz in &[false, true] {
            for imm14 in [-1i32, 0, 1, 0x1FFF] {
                for rt in [0u8, 1, 30, 31] {
                    let w = tbz_tbnz(bit, nz, imm14, rt);
                    let offset = (((imm14 as u32 & 0x3FFF) << 18) as i32 >> 18) << 2;
                    out.push(V {
                        word: w,
                        expected: if nz {
                            Tbnz { bit, rt: Reg(rt), offset }
                        } else {
                            Tbz { bit, rt: Reg(rt), offset }
                        },
                    });
                }
            }
        }
    }
}

fn push_br_blr_ret(out: &mut Vec<V>) {
    use DecodedInsn::*;
    for rn in [0u8, 1, 5, 30] {
        out.push(V { word: br_blr_ret(0, rn), expected: Br  { rn: Reg(rn) } });
        out.push(V { word: br_blr_ret(1, rn), expected: Blr { rn: Reg(rn) } });
        out.push(V { word: br_blr_ret(2, rn), expected: Ret { rn: Reg(rn) } });
    }
}

fn push_excp(out: &mut Vec<V>) {
    use DecodedInsn::*;
    for imm in [0u16, 1, 0x42, 0xFFFF] {
        out.push(V { word: excp_gen(0, imm, 1), expected: Svc { imm16: imm } });
        out.push(V { word: excp_gen(0, imm, 2), expected: Hvc { imm16: imm } });
        out.push(V { word: excp_gen(0, imm, 3), expected: Smc { imm16: imm } });
        out.push(V { word: excp_gen(1, imm, 0), expected: Brk { imm16: imm } });
        out.push(V { word: excp_gen(2, imm, 0), expected: Hlt { imm16: imm } });
    }
}

fn push_hints(out: &mut Vec<V>) {
    use DecodedInsn::*;
    let table = [
        (0u32, Nop), (1, Yield), (2, Wfe), (3, Wfi), (4, Sev), (5, Sevl),
    ];
    for (imm, exp) in table {
        out.push(V { word: hint(imm), expected: exp });
    }
    // PAC hint window
    for opc in 0u32..8 {
        out.push(V {
            word: hint(8 + opc),
            expected: PacHint { opc: opc as u8 },
        });
    }
    // BTI hints
    for tgt in 0u32..=6 {
        out.push(V {
            word: hint(32 + tgt),
            expected: BtiHint { target: tgt as u8 },
        });
    }
}

fn push_barriers(out: &mut Vec<V>) {
    use DecodedInsn::*;
    for crm in 0u32..16 {
        out.push(V { word: dmb(crm), expected: Dmb { domain: crm as u8 } });
        out.push(V { word: dsb(crm), expected: Dsb { domain: crm as u8 } });
        out.push(V { word: isb_enc(crm), expected: Isb });
    }
}

fn vectors() -> Vec<V> {
    let mut v = anchors();
    push_pcrel(&mut v);
    push_add_sub_imm(&mut v);
    push_logical_imm(&mut v);
    push_mov_wide(&mut v);
    push_bitfield(&mut v);
    push_extr(&mut v);
    push_add_sub_shifted(&mut v);
    push_logical_shifted(&mut v);
    push_add_sub_extended(&mut v);
    push_csel(&mut v);
    push_mul(&mut v);
    push_dp2(&mut v);
    push_dp1(&mut v);
    push_loadstore_unsigned(&mut v);
    push_loadstore_imm_pre_post(&mut v);
    push_loadstore_reg_offset(&mut v);
    push_literal(&mut v);
    push_pair(&mut v);
    push_ll_sc(&mut v);
    push_ldar_stlr(&mut v);
    push_branches(&mut v);
    push_bcond(&mut v);
    push_cbz_tbz(&mut v);
    push_br_blr_ret(&mut v);
    push_excp(&mut v);
    push_hints(&mut v);
    push_barriers(&mut v);
    v
}

#[test]
fn at1_canned_1000_vectors() {
    let vs = vectors();
    assert!(
        vs.len() >= 1000,
        "AT-1 gate requires >= 1000 vectors, have {}",
        vs.len()
    );
    let mut failed: Vec<String> = Vec::new();
    let mut shown = 0usize;
    for v in &vs {
        match decode_instruction(v.word) {
            Ok(got) if got == v.expected => continue,
            Ok(got) => {
                if shown < 25 {
                    failed.push(format!(
                        "{:08x}: expected {:?}, got {:?}",
                        v.word, v.expected, got
                    ));
                }
                shown += 1;
            }
            Err(e) => {
                if shown < 25 {
                    failed.push(format!(
                        "{:08x}: expected {:?}, got Err({:?})",
                        v.word, v.expected, e
                    ));
                }
                shown += 1;
            }
        }
    }
    if !failed.is_empty() {
        panic!(
            "AT-1 gate failures: {} of {} (showing first 25):\n{}",
            shown,
            vs.len(),
            failed.join("\n")
        );
    }
    eprintln!("AT-1 PASS: {} vectors", vs.len());
}
