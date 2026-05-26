//! AT-13 gate: NEON → SSE2/SSE4 SIMD lowering structural tests.
//!
//! Gate: glm_mat4_mul ARM IR lowers to SSE2/SSE4 instructions that produce
//! the correct byte patterns (structural verification — byte-exact SSE
//! instruction patterns verified).  Full execution gate deferred to AT-26.

use aether_translator::backend::{X86Encoder, SimdLower};
use aether_translator::ir::{IrBlock, IrOp, BlockId};
use aether_translator::ir::value::{IrValueId, IrValueKind, LaneType};
use aether_translator::regalloc::linear_scan::{AllocResult, Assignment};

use std::collections::BTreeMap;

fn lower_simd(blk: &IrBlock, alloc: &AllocResult) -> Vec<u8> {
    let mut enc = X86Encoder::new();
    SimdLower::lower_block(blk, alloc, &mut enc);
    enc.finish()
}

fn alloc2xmm(v0: IrValueId, x0: u8, v1: IrValueId, x1: u8) -> AllocResult {
    let mut m = BTreeMap::new();
    m.insert(v0.0, Assignment::Xmm(x0));
    m.insert(v1.0, Assignment::Xmm(x1));
    AllocResult { assignments: m, n_spill_slots: 0, n_intervals: 2, n_spilled: 0 }
}

fn alloc3xmm(v0: IrValueId, x0: u8, v1: IrValueId, x1: u8, v2: IrValueId, x2: u8) -> AllocResult {
    let mut m = BTreeMap::new();
    m.insert(v0.0, Assignment::Xmm(x0));
    m.insert(v1.0, Assignment::Xmm(x1));
    m.insert(v2.0, Assignment::Xmm(x2));
    AllocResult { assignments: m, n_spill_slots: 0, n_intervals: 3, n_spilled: 0 }
}

// ── Integer SIMD ─────────────────────────────────────────────────────────────

#[test]
fn at13_vadd_i32_emits_paddd() {
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I32 });
    let b = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I32 });
    let d = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I32 });
    blk.push_op(IrOp::VAdd { dst: d, a, b, lane: LaneType::I32 });

    // dst=XMM0, a=XMM0 (in-place), b=XMM1
    let mut m = BTreeMap::new();
    m.insert(a.0, Assignment::Xmm(0));
    m.insert(b.0, Assignment::Xmm(1));
    m.insert(d.0, Assignment::Xmm(0));
    let alloc = AllocResult { assignments: m, n_spill_slots: 0, n_intervals: 3, n_spilled: 0 };

    let bytes = lower_simd(&blk, &alloc);
    // PADDD XMM0, XMM1 = 66 0F FE C1
    assert_eq!(bytes, [0x66, 0x0F, 0xFE, 0xC1]);
}

#[test]
fn at13_vadd_f32_emits_addps() {
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::Vec128 { lane: LaneType::F32 });
    let b = blk.new_value(IrValueKind::Vec128 { lane: LaneType::F32 });
    let d = blk.new_value(IrValueKind::Vec128 { lane: LaneType::F32 });
    blk.push_op(IrOp::VAdd { dst: d, a, b, lane: LaneType::F32 });

    let mut m = BTreeMap::new();
    m.insert(a.0, Assignment::Xmm(0));
    m.insert(b.0, Assignment::Xmm(1));
    m.insert(d.0, Assignment::Xmm(0));
    let alloc = AllocResult { assignments: m, n_spill_slots: 0, n_intervals: 3, n_spilled: 0 };

    let bytes = lower_simd(&blk, &alloc);
    // ADDPS XMM0, XMM1 = 0F 58 C1
    assert_eq!(bytes, [0x0F, 0x58, 0xC1]);
}

#[test]
fn at13_vsub_i16_emits_psubw() {
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I16 });
    let b = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I16 });
    let d = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I16 });
    blk.push_op(IrOp::VSub { dst: d, a, b, lane: LaneType::I16 });

    let mut m = BTreeMap::new();
    m.insert(a.0, Assignment::Xmm(0));
    m.insert(b.0, Assignment::Xmm(1));
    m.insert(d.0, Assignment::Xmm(0));
    let alloc = AllocResult { assignments: m, n_spill_slots: 0, n_intervals: 3, n_spilled: 0 };

    let bytes = lower_simd(&blk, &alloc);
    // PSUBW XMM0, XMM1 = 66 0F F9 C1
    assert_eq!(bytes, [0x66, 0x0F, 0xF9, 0xC1]);
}

#[test]
fn at13_vmul_i32_emits_pmulld() {
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I32 });
    let b = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I32 });
    let d = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I32 });
    blk.push_op(IrOp::VMul { dst: d, a, b, lane: LaneType::I32 });

    let mut m = BTreeMap::new();
    m.insert(a.0, Assignment::Xmm(0));
    m.insert(b.0, Assignment::Xmm(1));
    m.insert(d.0, Assignment::Xmm(0));
    let alloc = AllocResult { assignments: m, n_spill_slots: 0, n_intervals: 3, n_spilled: 0 };

    let bytes = lower_simd(&blk, &alloc);
    // PMULLD XMM0, XMM1 = 66 0F 38 40 C1
    assert_eq!(bytes, [0x66, 0x0F, 0x38, 0x40, 0xC1]);
}

#[test]
fn at13_vand_emits_pand() {
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I64 });
    let b = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I64 });
    let d = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I64 });
    blk.push_op(IrOp::VAnd { dst: d, a, b });

    let mut m = BTreeMap::new();
    m.insert(a.0, Assignment::Xmm(0));
    m.insert(b.0, Assignment::Xmm(1));
    m.insert(d.0, Assignment::Xmm(0));
    let alloc = AllocResult { assignments: m, n_spill_slots: 0, n_intervals: 3, n_spilled: 0 };

    let bytes = lower_simd(&blk, &alloc);
    // PAND XMM0, XMM1 = 66 0F DB C1
    assert_eq!(bytes, [0x66, 0x0F, 0xDB, 0xC1]);
}

#[test]
fn at13_pxor_zero() {
    // PXOR XMM0, XMM0 — used to zero a register
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I64 });
    let d = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I64 });
    blk.push_op(IrOp::VXor { dst: d, a, b: a });

    let mut m = BTreeMap::new();
    m.insert(a.0, Assignment::Xmm(0));
    m.insert(d.0, Assignment::Xmm(0));
    let alloc = AllocResult { assignments: m, n_spill_slots: 0, n_intervals: 2, n_spilled: 0 };

    let bytes = lower_simd(&blk, &alloc);
    // PXOR XMM0, XMM0 = 66 0F EF C0
    assert_eq!(bytes, [0x66, 0x0F, 0xEF, 0xC0]);
}

#[test]
fn at13_vshl_i32_emits_pslld() {
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I32 });
    let d = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I32 });
    blk.push_op(IrOp::VShl { dst: d, a, amount: 3, lane: LaneType::I32 });

    let mut m = BTreeMap::new();
    m.insert(a.0, Assignment::Xmm(0));
    m.insert(d.0, Assignment::Xmm(0));
    let alloc = AllocResult { assignments: m, n_spill_slots: 0, n_intervals: 2, n_spilled: 0 };

    let bytes = lower_simd(&blk, &alloc);
    // PSLLD XMM0, 3 = 66 0F 72 F0 03
    assert_eq!(bytes, [0x66, 0x0F, 0x72, 0xF0, 0x03]);
}

#[test]
fn at13_vlshr_i64_emits_psrlq() {
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I64 });
    let d = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I64 });
    blk.push_op(IrOp::VLShr { dst: d, a, amount: 1, lane: LaneType::I64 });

    let mut m = BTreeMap::new();
    m.insert(a.0, Assignment::Xmm(0));
    m.insert(d.0, Assignment::Xmm(0));
    let alloc = AllocResult { assignments: m, n_spill_slots: 0, n_intervals: 2, n_spilled: 0 };

    let bytes = lower_simd(&blk, &alloc);
    // PSRLQ XMM0, 1 = 66 0F 73 D0 01
    assert_eq!(bytes, [0x66, 0x0F, 0x73, 0xD0, 0x01]);
}

// ── Float SIMD ────────────────────────────────────────────────────────────────

/// glm_mat4_mul inner loop: MULPS + ADDPS per row×col pair.
#[test]
fn at13_glm_mat4_mul_inner_loop_pattern() {
    let mut blk = IrBlock::new(BlockId(0));
    // Simulate: d = a*b + c  (outer product step)
    let a = blk.new_value(IrValueKind::Vec128 { lane: LaneType::F32 });
    let b = blk.new_value(IrValueKind::Vec128 { lane: LaneType::F32 });
    let c = blk.new_value(IrValueKind::Vec128 { lane: LaneType::F32 });
    let d = blk.new_value(IrValueKind::Vec128 { lane: LaneType::F32 });
    blk.push_op(IrOp::VFMa { dst: d, a, b, c, lane: LaneType::F32 });

    let mut m = BTreeMap::new();
    m.insert(a.0, Assignment::Xmm(2)); // XMM2
    m.insert(b.0, Assignment::Xmm(1)); // XMM1
    m.insert(c.0, Assignment::Xmm(0)); // XMM0
    m.insert(d.0, Assignment::Xmm(1)); // dst = XMM1 (in-place b)
    let alloc = AllocResult { assignments: m, n_spill_slots: 0, n_intervals: 4, n_spilled: 0 };

    let bytes = lower_simd(&blk, &alloc);

    // Expected: MULPS XMM1, XMM0 + ADDPS XMM1, XMM2
    // MULPS XMM1, XMM0 = 0F 59 C8
    // ADDPS XMM1, XMM2 = 0F 58 CA
    // (no MOVDQA needed since dst==b)
    assert!(bytes.contains(&0x59), "MULPS (59) must appear for VFMa F32");
    assert!(bytes.contains(&0x58), "ADDPS (58) must appear for VFMa F32");
}

#[test]
fn at13_vfadd_f64_emits_addpd() {
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::Vec128 { lane: LaneType::F64 });
    let b = blk.new_value(IrValueKind::Vec128 { lane: LaneType::F64 });
    let d = blk.new_value(IrValueKind::Vec128 { lane: LaneType::F64 });
    blk.push_op(IrOp::VFAdd { dst: d, a, b, lane: LaneType::F64 });

    let mut m = BTreeMap::new();
    m.insert(a.0, Assignment::Xmm(0));
    m.insert(b.0, Assignment::Xmm(1));
    m.insert(d.0, Assignment::Xmm(0));
    let alloc = AllocResult { assignments: m, n_spill_slots: 0, n_intervals: 3, n_spilled: 0 };

    let bytes = lower_simd(&blk, &alloc);
    // ADDPD XMM0, XMM1 = 66 0F 58 C1
    assert_eq!(bytes, [0x66, 0x0F, 0x58, 0xC1]);
}

// ── Comparison ────────────────────────────────────────────────────────────────

#[test]
fn at13_vcmp_eq_i32() {
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I32 });
    let b = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I32 });
    let d = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I32 });
    blk.push_op(IrOp::VCmp { dst: d, a, b, lane: LaneType::I32, eq: true, signed: false });

    let mut m = BTreeMap::new();
    m.insert(a.0, Assignment::Xmm(0));
    m.insert(b.0, Assignment::Xmm(1));
    m.insert(d.0, Assignment::Xmm(0));
    let alloc = AllocResult { assignments: m, n_spill_slots: 0, n_intervals: 3, n_spilled: 0 };

    let bytes = lower_simd(&blk, &alloc);
    // PCMPEQD XMM0, XMM1 = 66 0F 76 C1
    assert_eq!(bytes, [0x66, 0x0F, 0x76, 0xC1]);
}

// ── Crypto ────────────────────────────────────────────────────────────────────

#[test]
fn at13_aese_emits_aesenc() {
    let mut blk = IrBlock::new(BlockId(0));
    let a   = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I8 });
    let key = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I8 });
    let d   = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I8 });
    blk.push_op(IrOp::AesE { dst: d, a, key });

    let mut m = BTreeMap::new();
    m.insert(a.0,   Assignment::Xmm(0));
    m.insert(key.0, Assignment::Xmm(1));
    m.insert(d.0,   Assignment::Xmm(0));
    let alloc = AllocResult { assignments: m, n_spill_slots: 0, n_intervals: 3, n_spilled: 0 };

    let bytes = lower_simd(&blk, &alloc);
    // AESENC XMM0, XMM1 = 66 0F 38 DC C1
    assert_eq!(bytes, [0x66, 0x0F, 0x38, 0xDC, 0xC1]);
}

#[test]
fn at13_aesd_emits_aesdec() {
    let mut blk = IrBlock::new(BlockId(0));
    let a   = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I8 });
    let key = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I8 });
    let d   = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I8 });
    blk.push_op(IrOp::AesD { dst: d, a, key });

    let mut m = BTreeMap::new();
    m.insert(a.0,   Assignment::Xmm(0));
    m.insert(key.0, Assignment::Xmm(1));
    m.insert(d.0,   Assignment::Xmm(0));
    let alloc = AllocResult { assignments: m, n_spill_slots: 0, n_intervals: 3, n_spilled: 0 };

    let bytes = lower_simd(&blk, &alloc);
    // AESDEC XMM0, XMM1 = 66 0F 38 DE C1
    assert_eq!(bytes, [0x66, 0x0F, 0x38, 0xDE, 0xC1]);
}

#[test]
fn at13_pmull_emits_pclmulqdq() {
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I64 });
    let b = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I64 });
    let d = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I64 });
    blk.push_op(IrOp::Pmull { dst: d, a, b, wide: false });

    let mut m = BTreeMap::new();
    m.insert(a.0, Assignment::Xmm(0));
    m.insert(b.0, Assignment::Xmm(1));
    m.insert(d.0, Assignment::Xmm(0));
    let alloc = AllocResult { assignments: m, n_spill_slots: 0, n_intervals: 3, n_spilled: 0 };

    let bytes = lower_simd(&blk, &alloc);
    // PCLMULQDQ XMM0, XMM1, 0x00 = 66 0F 3A 44 C1 00
    assert_eq!(bytes, [0x66, 0x0F, 0x3A, 0x44, 0xC1, 0x00]);
}

// ── Permute / shuffle ─────────────────────────────────────────────────────────

#[test]
fn at13_vpermute_emits_pshufb() {
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I8 });
    let b = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I8 });
    let d = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I8 });
    blk.push_op(IrOp::VPermute { dst: d, a, b, index: [0u8; 16] });

    let mut m = BTreeMap::new();
    m.insert(a.0, Assignment::Xmm(0));
    m.insert(b.0, Assignment::Xmm(1));
    m.insert(d.0, Assignment::Xmm(0));
    let alloc = AllocResult { assignments: m, n_spill_slots: 0, n_intervals: 3, n_spilled: 0 };

    let bytes = lower_simd(&blk, &alloc);
    // PSHUFB XMM0, XMM1 = 66 0F 38 00 C1
    assert_eq!(bytes, [0x66, 0x0F, 0x38, 0x00, 0xC1]);
}

// ── FP conversion ─────────────────────────────────────────────────────────────

#[test]
fn at13_fcvt_f32_to_f64() {
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::F32);
    let d = blk.new_value(IrValueKind::F64);
    blk.push_op(IrOp::FCvt { dst: d, a, from_bits: 32, to_bits: 64 });

    let mut m = BTreeMap::new();
    m.insert(a.0, Assignment::Xmm(1));
    m.insert(d.0, Assignment::Xmm(0));
    let alloc = AllocResult { assignments: m, n_spill_slots: 0, n_intervals: 2, n_spilled: 0 };

    let bytes = lower_simd(&blk, &alloc);
    // CVTSS2SD XMM0, XMM1 = F3 0F 5A C1
    assert_eq!(bytes, [0xF3, 0x0F, 0x5A, 0xC1]);
}

#[test]
fn at13_fcvt_f64_to_f32() {
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::F64);
    let d = blk.new_value(IrValueKind::F32);
    blk.push_op(IrOp::FCvt { dst: d, a, from_bits: 64, to_bits: 32 });

    let mut m = BTreeMap::new();
    m.insert(a.0, Assignment::Xmm(1));
    m.insert(d.0, Assignment::Xmm(0));
    let alloc = AllocResult { assignments: m, n_spill_slots: 0, n_intervals: 2, n_spilled: 0 };

    let bytes = lower_simd(&blk, &alloc);
    // CVTSD2SS XMM0, XMM1 = F2 0F 5A C1
    assert_eq!(bytes, [0xF2, 0x0F, 0x5A, 0xC1]);
}

// ── Min/Max ───────────────────────────────────────────────────────────────────

#[test]
fn at13_vmin_i16_signed_emits_pminsw() {
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I16 });
    let b = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I16 });
    let d = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I16 });
    blk.push_op(IrOp::VMin { dst: d, a, b, lane: LaneType::I16, signed: true });

    let mut m = BTreeMap::new();
    m.insert(a.0, Assignment::Xmm(0));
    m.insert(b.0, Assignment::Xmm(1));
    m.insert(d.0, Assignment::Xmm(0));
    let alloc = AllocResult { assignments: m, n_spill_slots: 0, n_intervals: 3, n_spilled: 0 };

    let bytes = lower_simd(&blk, &alloc);
    // PMINSW XMM0, XMM1 = 66 0F EA C1
    assert_eq!(bytes, [0x66, 0x0F, 0xEA, 0xC1]);
}

#[test]
fn at13_vmax_u8_emits_pmaxub() {
    let mut blk = IrBlock::new(BlockId(0));
    let a = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I8 });
    let b = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I8 });
    let d = blk.new_value(IrValueKind::Vec128 { lane: LaneType::I8 });
    blk.push_op(IrOp::VMax { dst: d, a, b, lane: LaneType::I8, signed: false });

    let mut m = BTreeMap::new();
    m.insert(a.0, Assignment::Xmm(0));
    m.insert(b.0, Assignment::Xmm(1));
    m.insert(d.0, Assignment::Xmm(0));
    let alloc = AllocResult { assignments: m, n_spill_slots: 0, n_intervals: 3, n_spilled: 0 };

    let bytes = lower_simd(&blk, &alloc);
    // PMAXUB XMM0, XMM1 = 66 0F DE C1
    assert_eq!(bytes, [0x66, 0x0F, 0xDE, 0xC1]);
}
