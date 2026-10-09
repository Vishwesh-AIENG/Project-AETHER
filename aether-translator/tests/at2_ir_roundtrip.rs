//! AT-2 gate: every IR variant must serialize and parse back to an
//! identical value.
//!
//! Phase A AT-2 fill: codec implemented for the integer / branch /
//! load-store / atomics / system / barrier / hint / extension variants
//! (~60 of the ~140 total). Remaining variants (NEON, scalar FP, crypto,
//! sysreg-bearing) defer to the AT-3/4 fill prompts.

use aether_translator::decoder::Cond;
use aether_translator::ir::memory::{AtomicOp, BarrierDomain, LoadTy, MemOrder, StoreTy};
use aether_translator::ir::ops::{
    FpBinOp, FpFmaOp, FpUnOp, RoundMode, VecBinOp, VecCmpOp, VecFpOp, VecPairOp, VecReduceOp,
    VecShiftOp, VecUnOp,
};
use aether_translator::ir::serialize::{decode, encode, is_codec_implemented, variant_tag};
use aether_translator::ir::{BlockId, IrFlagsId, IrOp, IrValueId, NzcvBit};

fn samples() -> Vec<IrOp> {
    let v = IrValueId;
    let f = IrFlagsId;
    let b = BlockId;
    vec![
        IrOp::ConstI32 { dst: v(0), val: -1 },
        IrOp::ConstI64 { dst: v(0), val: 0x1234_5678_9ABC_DEF0u64 as i64 },
        IrOp::Add { dst: v(0), a: v(1), b: v(2) },
        IrOp::Sub { dst: v(0), a: v(1), b: v(2) },
        IrOp::And { dst: v(0), a: v(1), b: v(2) },
        IrOp::Or  { dst: v(0), a: v(1), b: v(2) },
        IrOp::Xor { dst: v(0), a: v(1), b: v(2) },
        IrOp::Shl { dst: v(0), a: v(1), b: v(2) },
        IrOp::LShr { dst: v(0), a: v(1), b: v(2) },
        IrOp::AShr { dst: v(0), a: v(1), b: v(2) },
        IrOp::Ror { dst: v(0), a: v(1), b: v(2) },
        IrOp::Mul { dst: v(0), a: v(1), b: v(2) },
        IrOp::MulHU { dst: v(0), a: v(1), b: v(2) },
        IrOp::MulHS { dst: v(0), a: v(1), b: v(2) },
        IrOp::SDiv { dst: v(0), a: v(1), b: v(2) },
        IrOp::UDiv { dst: v(0), a: v(1), b: v(2) },
        IrOp::Madd { dst: v(0), a: v(1), b: v(2), c: v(3) },
        IrOp::Msub { dst: v(0), a: v(1), b: v(2), c: v(3) },
        IrOp::Neg  { dst: v(0), a: v(1) },
        IrOp::Not  { dst: v(0), a: v(1) },
        IrOp::Rbit { dst: v(0), a: v(1), sf: true },
        IrOp::Rbit { dst: v(0), a: v(1), sf: false },
        IrOp::Clz  { dst: v(0), a: v(1), sf: true },
        IrOp::Clz  { dst: v(0), a: v(1), sf: false },
        IrOp::Cls  { dst: v(0), a: v(1), sf: true },
        IrOp::Cls  { dst: v(0), a: v(1), sf: false },
        IrOp::Bswap16 { dst: v(0), a: v(1) },
        IrOp::Bswap32 { dst: v(0), a: v(1) },
        IrOp::Bswap64 { dst: v(0), a: v(1) },
        IrOp::AddS { dst: v(0), flags: f(0), a: v(1), b: v(2), sf: true },
        IrOp::SubS { dst: v(0), flags: f(0), a: v(1), b: v(2), sf: false },
        IrOp::AndS { dst: v(0), flags: f(0), a: v(1), b: v(2), sf: true },
        IrOp::Cmp { flags: f(0), a: v(1), b: v(2), sf: false },
        IrOp::Cmn { flags: f(0), a: v(1), b: v(2), sf: true },
        IrOp::Tst { flags: f(0), a: v(1), b: v(2), sf: false },
        IrOp::NzcvBitOp { dst: v(0), flags: f(0), bit: NzcvBit::Z },
        IrOp::Sext { dst: v(0), a: v(1), from_bits: 8, to_bits: 64 },
        IrOp::Zext { dst: v(0), a: v(1), from_bits: 16, to_bits: 32 },
        IrOp::Trunc { dst: v(0), a: v(1), to_bits: 32 },
        IrOp::Load {
            dst: v(0), addr: v(1), ty: LoadTy::U64, order: MemOrder::Relaxed,
        },
        IrOp::Store {
            val: v(0), addr: v(1), ty: StoreTy::U64, order: MemOrder::Release,
        },
        IrOp::LoadExclusive { dst: v(0), addr: v(1), ty: LoadTy::U32 },
        IrOp::StoreExclusive {
            status: v(0), val: v(1), addr: v(2), ty: StoreTy::U32,
        },
        IrOp::AtomicRmw {
            dst: v(0), op: AtomicOp::Add, addr: v(1), val: v(2),
            order: MemOrder::AcqRel, size: 8,
        },
        IrOp::AtomicCas {
            dst: v(0), addr: v(1), expected: v(2), new: v(3),
            order: MemOrder::SeqCst, size: 4,
        },
        IrOp::Branch { target: b(7) },
        IrOp::CondBranch {
            cond: Cond::Ne, flags: f(0), taken: b(2), fallthru: b(3),
        },
        IrOp::IndirectBranch { target: v(0) },
        IrOp::Call { target: v(0), link_pc: 0x4000_0000_0000_0000 },
        IrOp::Return { target: v(0) },
        IrOp::Cbz  { a: v(0), taken: b(1), fallthru: b(2) },
        IrOp::Cbnz { a: v(0), taken: b(1), fallthru: b(2) },
        IrOp::Tbz  { a: v(0), bit: 5, taken: b(1), fallthru: b(2) },
        IrOp::Tbnz { a: v(0), bit: 5, taken: b(1), fallthru: b(2) },
        IrOp::Hvc { imm16: 0x42 },
        IrOp::Svc { imm16: 0 },
        IrOp::Smc { imm16: 0xFFFF },
        IrOp::EretRt,
        IrOp::Brk { imm16: 0x1234 },
        IrOp::Hlt { imm16: 0 },
        IrOp::Dmb { domain: BarrierDomain::Ish },
        IrOp::Dsb { domain: BarrierDomain::Sy },
        IrOp::Isb,
        IrOp::Sb,
        IrOp::Hint { imm: 0 },
        IrOp::Hint { imm: 200 },
        // ── M4b-6 SIMD/FP/crypto ctx-template ops (one per tag) ──
        IrOp::VecBin { op: VecBinOp::SqAdd, size: 2, q: true, d: 0, n: 1, m: 2 },
        IrOp::VecUn { op: VecUnOp::Abs, size: 1, q: false, d: 3, n: 4 },
        IrOp::VecShift { op: VecShiftOp::SShr, size: 2, q: true, d: 5, n: 6, amount: 7 },
        IrOp::VecCmp { op: VecCmpOp::UGt, size: 0, q: true, d: 8, n: 9, m: 10 },
        IrOp::VecPair { op: VecPairOp::Add, size: 1, q: false, d: 11, n: 12, m: 13 },
        IrOp::VecReduce { op: VecReduceOp::UMax, size: 2, q: true, d: 14, n: 15 },
        IrOp::VecAddLong { across: true, signed: false, size: 0, q: true, d: 16, n: 17 },
        IrOp::VecFp { op: VecFpOp::Div, dbl: true, q: true, d: 18, n: 19, m: 20 },
        IrOp::FpFromInt { d: 1, n_gpr: 2, from_bits: 64, to_bits: 32, signed: true },
        IrOp::FpToIntR { d_gpr: 3, n: 4, from_bits: 32, to_bits: 64, signed: false, round: RoundMode::Zero },
        IrOp::FpRound { d: 5, n: 6, dbl: false, round: RoundMode::NearestTiesAway, raise_inexact: true },
        IrOp::VecFpRound { d: 5, n: 6, dbl: false, q: true, round: RoundMode::NearestTiesAway },
        IrOp::VecFpCvtWidth { d: 5, n: 6, widen: false, half: true, upper: true },
        IrOp::FpCvt2 { d: 7, n: 8, from_bits: 32, to_bits: 64 },
        IrOp::FpMov { d: 9, n: 10, width_bits: 64 },
        IrOp::FpBin { op: FpBinOp::NMul, dbl: true, d: 11, n: 12, m: 13 },
        IrOp::FpFma { op: FpFmaOp::NMsub, dbl: true, d: 11, n: 12, m: 13, a: 14 },
        IrOp::FpUn { op: FpUnOp::Sqrt, dbl: false, d: 14, n: 15 },
        IrOp::FpCmpN { n: 16, m: 17, dbl: true, zero: true },
        IrOp::FpToGpr { d_gpr: 18, n: 19, bits: 64, high_half: true },
        IrOp::FpFromGpr { d: 20, n_gpr: 21, bits: 32, high_half: false },
        IrOp::CryptoAesR { kind: 4, d: 22, n: 23, m: 24 },
        IrOp::CryptoShaR { kind: 1, d: 25, n: 26, m: 27 },
        IrOp::Unimplemented(0xDEAD_BEEF),
    ]
}

#[test]
fn at2_every_implemented_variant_roundtrips() {
    let mut buf = Vec::with_capacity(64);
    for op in samples() {
        assert!(is_codec_implemented(&op), "codec missing for {:?}", op);
        buf.clear();
        encode(&op, &mut buf).unwrap_or_else(|e| panic!("encode {:?}: {:?}", op, e));
        let (got, len) = decode(&buf).unwrap_or_else(|e| panic!("decode {:?}: {:?}", op, e));
        assert_eq!(len, buf.len(), "trailing bytes for {:?}", op);
        assert_eq!(got, op, "round-trip mismatch (tag {:#x})", variant_tag(&op));
    }
}

#[test]
fn at2_tag_smoke() {
    let op = IrOp::Add {
        dst: IrValueId(0),
        a: IrValueId(1),
        b: IrValueId(2),
    };
    assert_eq!(variant_tag(&op), 0x10);
}

/// Stable tag uniqueness across the sample set (proxy for "no aliasing
/// among implemented variants until next prompt covers the rest").
/// Same-variant samples (Hint imm pairs, Rbit/Clz/Cls sf pairs) legitimately
/// share their tag — aliasing is only a bug when two DIFFERENT variants map
/// to the same tag, so uniqueness is checked per (tag -> variant).
#[test]
fn at2_implemented_tags_unique() {
    use std::collections::HashMap;
    let s = samples();
    let mut by_tag: HashMap<u8, core::mem::Discriminant<IrOp>> = HashMap::new();
    for op in &s {
        let t = variant_tag(op);
        let d = core::mem::discriminant(op);
        if let Some(prev) = by_tag.insert(t, d) {
            assert_eq!(prev, d, "tag {t:#x} aliased by two different variants");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Defensive-hardening: total variant coverage.
//
// `all_variants()` builds one representative value of EVERY `IrOp` variant
// (dummy fields). It is the source of truth for both the tag-injectivity test
// (TASK 1) and the now-total round-trip test.
// ─────────────────────────────────────────────────────────────────────────

use aether_translator::decoder::sysreg::SysReg;
use aether_translator::ir::ops::{VecFpCmpOp, VecFpUnOp};
use aether_translator::ir::LaneType;

fn all_variants() -> Vec<IrOp> {
    let v = IrValueId;
    let f = IrFlagsId;
    let b = BlockId;
    vec![
        // ----- Constants -----
        IrOp::ConstI32 { dst: v(0), val: -7 },
        IrOp::ConstI64 { dst: v(0), val: 0x0123_4567_89AB_CDEFu64 as i64 },
        IrOp::ConstF32 { dst: v(0), bits: 0x3F80_0000 },
        IrOp::ConstF64 { dst: v(0), bits: 0x3FF0_0000_0000_0000 },
        IrOp::ConstVec128 { dst: v(0), bytes: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] },
        // ----- Pure integer ALU -----
        IrOp::Add { dst: v(0), a: v(1), b: v(2) },
        IrOp::Sub { dst: v(0), a: v(1), b: v(2) },
        IrOp::Neg { dst: v(0), a: v(1) },
        IrOp::And { dst: v(0), a: v(1), b: v(2) },
        IrOp::Or { dst: v(0), a: v(1), b: v(2) },
        IrOp::Xor { dst: v(0), a: v(1), b: v(2) },
        IrOp::Not { dst: v(0), a: v(1) },
        IrOp::Shl { dst: v(0), a: v(1), b: v(2) },
        IrOp::LShr { dst: v(0), a: v(1), b: v(2) },
        IrOp::AShr { dst: v(0), a: v(1), b: v(2) },
        IrOp::Ror { dst: v(0), a: v(1), b: v(2) },
        IrOp::Mul { dst: v(0), a: v(1), b: v(2) },
        IrOp::MulHU { dst: v(0), a: v(1), b: v(2) },
        IrOp::MulHS { dst: v(0), a: v(1), b: v(2) },
        IrOp::SDiv { dst: v(0), a: v(1), b: v(2) },
        IrOp::UDiv { dst: v(0), a: v(1), b: v(2) },
        IrOp::Madd { dst: v(0), a: v(1), b: v(2), c: v(3) },
        IrOp::Msub { dst: v(0), a: v(1), b: v(2), c: v(3) },
        IrOp::Rbit { dst: v(0), a: v(1), sf: true },
        IrOp::Rev { dst: v(0), a: v(1), bytes: 8 },
        IrOp::Clz { dst: v(0), a: v(1), sf: false },
        IrOp::Cls { dst: v(0), a: v(1), sf: true },
        IrOp::Bswap16 { dst: v(0), a: v(1) },
        IrOp::Bswap32 { dst: v(0), a: v(1) },
        IrOp::Bswap64 { dst: v(0), a: v(1) },
        // ----- Flag-producing ALU -----
        IrOp::AddS { dst: v(0), flags: f(0), a: v(1), b: v(2), sf: true },
        IrOp::SubS { dst: v(0), flags: f(0), a: v(1), b: v(2), sf: false },
        IrOp::AndS { dst: v(0), flags: f(0), a: v(1), b: v(2), sf: true },
        IrOp::Adcs { dst: v(0), flags: f(0), a: v(1), b: v(2), c_in: f(1), sf: true },
        IrOp::Sbcs { dst: v(0), flags: f(0), a: v(1), b: v(2), c_in: f(1), sf: false },
        IrOp::Cmp { flags: f(0), a: v(1), b: v(2), sf: false },
        IrOp::Cmn { flags: f(0), a: v(1), b: v(2), sf: true },
        IrOp::Tst { flags: f(0), a: v(1), b: v(2), sf: false },
        IrOp::CCmp {
            flags_out: f(0), a: v(1), b: v(2), cond: Cond::Ge,
            nzcv_if_false: 0xF, flags_in: f(1), is_neg: true, sf: true,
        },
        IrOp::Csel { dst: v(0), a: v(1), b: v(2), cond: Cond::Lt, flags: f(0), variant: 3 },
        IrOp::NzcvBitOp { dst: v(0), flags: f(0), bit: NzcvBit::Z },
        // ----- Sign/zero extension -----
        IrOp::Sext { dst: v(0), a: v(1), from_bits: 8, to_bits: 64 },
        IrOp::Zext { dst: v(0), a: v(1), from_bits: 16, to_bits: 32 },
        IrOp::Trunc { dst: v(0), a: v(1), to_bits: 32 },
        IrOp::StampFaultPc(0xDEAD_BEEF_0000_1234),
        // ----- Memory -----
        IrOp::Load { dst: v(0), addr: v(1), ty: LoadTy::U64, order: MemOrder::Relaxed },
        IrOp::Store { val: v(0), addr: v(1), ty: StoreTy::U64, order: MemOrder::Release },
        IrOp::LoadExclusive { dst: v(0), addr: v(1), ty: LoadTy::U32 },
        IrOp::StoreExclusive { status: v(0), val: v(1), addr: v(2), ty: StoreTy::U32 },
        IrOp::LoadPair { dst_a: v(0), dst_b: v(1), addr: v(2), ty: LoadTy::U64 },
        IrOp::StorePair { val_a: v(0), val_b: v(1), addr: v(2), ty: StoreTy::U64 },
        IrOp::VecMoviImm { d: 0, lo: 0x1111, hi: 0x2222 },
        IrOp::VecDupGpr { d: 1, src: v(0), size: 2, q: true },
        IrOp::VecExtractLane { dst: v(0), n: 1, lane: 2, size: 4, signed: true },
        IrOp::VecInsGpr { d: 1, lane: 0, src: v(0), size: 8 },
        IrOp::VecCnt { d: 1, n: 2, q: false },
        IrOp::VecAddvLong { d: 1, n: 2, esize: 1, q: true, signed: false },
        IrOp::VecCmpZero { op: VecCmpOp::Eq, size: 0, q: true, d: 1, n: 2 },
        IrOp::VecShiftNarrow { d: 1, n: 2, shift: 4, esize_out: 1, high: false },
        IrOp::VecShiftLong { d: 1, n: 2, shift: 3, esize_in: 1, high: true, signed: false },
        IrOp::VecShiftReg { d: 1, n: 2, m: 3, size: 2, q: true, signed: false },
        IrOp::VecShiftIns { d: 4, n: 5, shift: 3, size: 0, q: false, left: true },
        IrOp::VecShiftNarrowSat {
            d: 6, n: 7, shift: 5, esize_out: 2, high: true,
            round: true, src_signed: true, dst_signed: false, modular: false,
        },
        IrOp::VecExt { d: 1, n: 2, m: 3, imm: 4, q: true },
        IrOp::VecTbl1 { d: 1, n: 2, m: 3, q: false },
        IrOp::VecTblN { d: 1, n: 2, m: 3, len: 2, op: 1, q: true },
        IrOp::VecDupElem { d: 1, n: 2, size: 2, lane: 1, q: true },
        IrOp::VecPmull { d: 1, n: 2, m: 3, high: true },
        IrOp::VecMulLong { d: 1, n: 2, m: 3, size: 1, q: true, signed: false, accum: true, sub: false },
        IrOp::VecRev64 { d: 1, n: 2, size: 1, q: true, container: 8 },
        IrOp::CryptoSha256 { kind: 2, d: 1, n: 2, m: 3 },
        IrOp::SimdInterp { word: 0x2EE2_1C20 },
        IrOp::VecBicOrrImm { d: 1, imm: 0xF0, is_bic: true, q: false },
        IrOp::VecAddLongPair { d: 1, n: 2, esize_in: 1, q: true, signed: false },
        IrOp::VecUnzip { d: 1, n: 2, m: 3, esize: 4, q: true, odd: false },
        IrOp::VecReduceAdd { d: 1, n: 2, esize: 4, q: true },
        IrOp::ZeroBlock { addr: v(0) },
        // ----- Atomics -----
        IrOp::AtomicRmw { dst: v(0), op: AtomicOp::Add, addr: v(1), val: v(2), order: MemOrder::AcqRel, size: 8 },
        IrOp::AtomicCas { dst: v(0), addr: v(1), expected: v(2), new: v(3), order: MemOrder::SeqCst, size: 4 },
        IrOp::AtomicCasPair {
            dst_a: v(0), dst_b: v(1), addr: v(2), expected_a: v(3), expected_b: v(4),
            new_a: v(5), new_b: v(6), order: MemOrder::SeqCst, size: 8,
        },
        // ----- Control flow -----
        IrOp::Branch { target: b(7) },
        IrOp::CondBranch { cond: Cond::Ne, flags: f(0), taken: b(2), fallthru: b(3) },
        IrOp::IndirectBranch { target: v(0) },
        IrOp::Call { target: v(0), link_pc: 0x4000_0000_0000_0000 },
        IrOp::Return { target: v(0) },
        IrOp::Cbz { a: v(0), taken: b(1), fallthru: b(2) },
        IrOp::Cbnz { a: v(0), taken: b(1), fallthru: b(2) },
        IrOp::Tbz { a: v(0), bit: 5, taken: b(1), fallthru: b(2) },
        IrOp::Tbnz { a: v(0), bit: 5, taken: b(1), fallthru: b(2) },
        // ----- Vector / NEON (IrValueId-keyed) -----
        IrOp::VAdd { dst: v(0), a: v(1), b: v(2), lane: LaneType::I32 },
        IrOp::VSub { dst: v(0), a: v(1), b: v(2), lane: LaneType::I16 },
        IrOp::VMul { dst: v(0), a: v(1), b: v(2), lane: LaneType::I8 },
        IrOp::VAnd { dst: v(0), a: v(1), b: v(2) },
        IrOp::VOr { dst: v(0), a: v(1), b: v(2) },
        IrOp::VXor { dst: v(0), a: v(1), b: v(2) },
        IrOp::VShl { dst: v(0), a: v(1), amount: 3, lane: LaneType::I32 },
        IrOp::VLShr { dst: v(0), a: v(1), amount: 3, lane: LaneType::I32 },
        IrOp::VAShr { dst: v(0), a: v(1), amount: 3, lane: LaneType::I32 },
        IrOp::VNeg { dst: v(0), a: v(1), lane: LaneType::I32 },
        IrOp::VAbs { dst: v(0), a: v(1), lane: LaneType::I32 },
        IrOp::VMin { dst: v(0), a: v(1), b: v(2), lane: LaneType::I32, signed: true },
        IrOp::VMax { dst: v(0), a: v(1), b: v(2), lane: LaneType::I32, signed: false },
        IrOp::VCmp { dst: v(0), a: v(1), b: v(2), lane: LaneType::I32, eq: true, signed: false },
        IrOp::VDup { dst: v(0), a: v(1), lane: LaneType::I64 },
        IrOp::VInsLane { dst: v(0), src: v(1), scalar: v(2), lane_idx: 1, lane: LaneType::I32 },
        IrOp::VExtractLane { dst: v(0), a: v(1), lane_idx: 2, lane: LaneType::I16 },
        IrOp::VPermute { dst: v(0), a: v(1), b: v(2), index: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] },
        IrOp::VTbl { dst: v(0), table_lo: v(1), table_hi: v(2), index: v(3) },
        IrOp::VTbx { dst: v(0), prev: v(1), table_lo: v(2), table_hi: v(3), index: v(4) },
        IrOp::VModImm { dst: v(0), imm: 0xAABB, lane: LaneType::I32 },
        IrOp::VConvert { dst: v(0), a: v(1), from: LaneType::I32, to: LaneType::F32 },
        IrOp::VFAdd { dst: v(0), a: v(1), b: v(2), lane: LaneType::F32 },
        IrOp::VFSub { dst: v(0), a: v(1), b: v(2), lane: LaneType::F32 },
        IrOp::VFMul { dst: v(0), a: v(1), b: v(2), lane: LaneType::F64 },
        IrOp::VFDiv { dst: v(0), a: v(1), b: v(2), lane: LaneType::F64 },
        IrOp::VFMa { dst: v(0), a: v(1), b: v(2), c: v(3), lane: LaneType::F32 },
        // ----- Scalar FP (IrValueId-keyed) -----
        IrOp::FAdd { dst: v(0), a: v(1), b: v(2) },
        IrOp::FSub { dst: v(0), a: v(1), b: v(2) },
        IrOp::FMul { dst: v(0), a: v(1), b: v(2) },
        IrOp::FDiv { dst: v(0), a: v(1), b: v(2) },
        IrOp::FNeg { dst: v(0), a: v(1) },
        IrOp::FAbs { dst: v(0), a: v(1) },
        IrOp::FSqrt { dst: v(0), a: v(1) },
        IrOp::FCvt { dst: v(0), a: v(1), from_bits: 32, to_bits: 64 },
        IrOp::FToInt { dst: v(0), a: v(1), to_bits: 64, signed: true },
        IrOp::IntToF { dst: v(0), a: v(1), from_bits: 32, signed: false },
        IrOp::FCmp { flags: f(0), a: v(1), b: v(2) },
        // ----- Crypto (IrValueId-keyed) -----
        IrOp::AesE { dst: v(0), a: v(1), key: v(2) },
        IrOp::AesD { dst: v(0), a: v(1), key: v(2) },
        IrOp::AesMc { dst: v(0), a: v(1) },
        IrOp::AesImc { dst: v(0), a: v(1) },
        IrOp::Sha1c { dst: v(0), a: v(1), b: v(2), c: v(3) },
        IrOp::Sha1m { dst: v(0), a: v(1), b: v(2), c: v(3) },
        IrOp::Sha1p { dst: v(0), a: v(1), b: v(2), c: v(3) },
        IrOp::Sha256h { dst: v(0), a: v(1), b: v(2), c: v(3) },
        IrOp::Sha256h2 { dst: v(0), a: v(1), b: v(2), c: v(3) },
        IrOp::Sha256su0 { dst: v(0), a: v(1), b: v(2) },
        IrOp::Sha256su1 { dst: v(0), a: v(1), b: v(2), c: v(3) },
        IrOp::Pmull { dst: v(0), a: v(1), b: v(2), wide: true },
        IrOp::Crc32 { dst: v(0), a: v(1), b: v(2), size: 4, castagnoli: true },
        // ----- System / barriers -----
        IrOp::Hvc { imm16: 0x42 },
        IrOp::Svc { imm16: 0 },
        IrOp::Smc { imm16: 0xFFFF },
        IrOp::Brk { imm16: 0x1234 },
        IrOp::Hlt { imm16: 0 },
        IrOp::EretRt,
        IrOp::Mrs { dst: v(0), reg: SysReg::MidrEl1 },
        IrOp::Msr { reg: SysReg::HcrEl2, val: v(0) },
        IrOp::Dmb { domain: BarrierDomain::Ish },
        IrOp::Dsb { domain: BarrierDomain::Sy },
        IrOp::Isb,
        IrOp::Sb,
        IrOp::TlbInval { va: Some(v(0)) },
        IrOp::AtS1E1 { va: v(0), is_write: true, at_el0: false },
        IrOp::Hint { imm: 200 },
        // ----- Guest CPU state access -----
        IrOp::ReadGpr { dst: v(0), reg: 3, sf: true },
        IrOp::WriteGpr { reg: 3, src: v(0), sf: false },
        IrOp::ReadSp { dst: v(0), sf: true },
        IrOp::WriteSp { src: v(0), sf: true },
        IrOp::ReadFpr { dst: v(0), reg: 5 },
        IrOp::WriteFpr { reg: 5, src: v(0) },
        IrOp::ReadFlags { dst: f(0) },
        IrOp::WriteFlags { src: f(0) },
        IrOp::ReadPc { dst: v(0) },
        IrOp::WritePc { src: v(0) },
        // ----- x86 TSO lowered -----
        IrOp::X86Mfence,
        IrOp::X86Cpuid,
        // ----- M4b-6 V-register-numbered SIMD/FP/crypto ctx templates -----
        IrOp::VecBin { op: VecBinOp::SqAdd, size: 2, q: true, d: 0, n: 1, m: 2 },
        IrOp::VecUn { op: VecUnOp::Abs, size: 1, q: false, d: 3, n: 4 },
        IrOp::VecShift { op: VecShiftOp::SShr, size: 2, q: true, d: 5, n: 6, amount: 7 },
        IrOp::VecShiftAcc { signed: true, size: 2, q: true, d: 5, n: 6, amount: 3 },
        IrOp::VecCmp { op: VecCmpOp::UGt, size: 0, q: true, d: 8, n: 9, m: 10 },
        IrOp::VecPair { op: VecPairOp::Add, size: 1, q: false, d: 11, n: 12, m: 13 },
        IrOp::VecReduce { op: VecReduceOp::UMax, size: 2, q: true, d: 14, n: 15 },
        IrOp::VecAddLong { across: true, signed: false, size: 0, q: true, d: 16, n: 17 },
        IrOp::VecFp { op: VecFpOp::Div, dbl: true, q: true, d: 18, n: 19, m: 20 },
        IrOp::VecFpCmp { op: VecFpCmpOp::Gt, dbl: false, q: true, d: 1, n: 2, m: 3, zero: false },
        IrOp::VecFpUn { op: VecFpUnOp::Sqrt, dbl: true, q: true, d: 1, n: 2 },
        IrOp::VecByElem { op: VecFpOp::Mla, is_fp: true, dbl: false, size: 2, q: true, d: 1, n: 2, m: 3, idx: 1 },
        IrOp::VecCvtFp { to_fp: true, signed: true, dbl: false, q: true, d: 1, n: 2 },
        IrOp::VecZipTrn { kind: 2, size: 1, q: true, d: 1, n: 2, m: 3 },
        IrOp::VecScalarPair { is_fp: true, dbl: true, d: 1, n: 2 },
        IrOp::FpFromInt { d: 1, n_gpr: 2, from_bits: 64, to_bits: 32, signed: true },
        IrOp::FpToIntR { d_gpr: 3, n: 4, from_bits: 32, to_bits: 64, signed: false, round: RoundMode::Zero },
        IrOp::FpRound { d: 5, n: 6, dbl: false, round: RoundMode::NearestTiesAway, raise_inexact: true },
        IrOp::VecFpRound { d: 5, n: 6, dbl: false, q: true, round: RoundMode::NearestTiesAway },
        IrOp::VecFpCvtWidth { d: 5, n: 6, widen: false, half: true, upper: true },
        IrOp::FpCvt2 { d: 7, n: 8, from_bits: 32, to_bits: 64 },
        IrOp::FpCsel { d: 1, n: 2, m: 3, cond: Cond::Mi, dbl: true },
        IrOp::FpMov { d: 9, n: 10, width_bits: 64 },
        IrOp::FpBin { op: FpBinOp::NMul, dbl: true, d: 11, n: 12, m: 13 },
        IrOp::FpFma { op: FpFmaOp::Madd, dbl: false, d: 4, n: 5, m: 6, a: 7 },
        IrOp::FpUn { op: FpUnOp::Sqrt, dbl: false, d: 14, n: 15 },
        IrOp::FpCmpN { n: 16, m: 17, dbl: true, zero: true },
        IrOp::FpCvtIntScalar { d: 1, src: v(0), to_dbl: true, signed: false, src_64: true, fbits: 24 },
        IrOp::FpCvtToIntScalar { dst: v(0), n: 1, from_dbl: true, to_64: false, round: RoundMode::Nearest, signed: true, fbits: 20 },
        IrOp::FpToGpr { d_gpr: 18, n: 19, bits: 64, high_half: true },
        IrOp::FpFromGpr { d: 20, n_gpr: 21, bits: 32, high_half: false },
        IrOp::CryptoAesR { kind: 4, d: 22, n: 23, m: 24 },
        IrOp::CryptoShaR { kind: 1, d: 25, n: 26, m: 27 },
        // ----- Sentinel -----
        IrOp::Unimplemented(0xDEAD_BEEF),
    ]
}

/// TASK 1: `variant_tag` must be injective — no two distinct `IrOp` variants
/// may map to the same byte tag, or a serialized op decodes back to the WRONG
/// variant (silent AOT-cache mis-decode). Catches the 0xCD AtS1E1/VecBin
/// collision found in the static review.
#[test]
fn variant_tag_is_injective() {
    use std::collections::HashMap;
    let ops = all_variants();

    // Sanity: the sample set must cover every variant exactly once. (198 is the
    // current IrOp variant count; bump this if a variant is added — and add its
    // sample above so the tag stays unique.)
    assert_eq!(ops.len(), 201, "all_variants() must hold one of every IrOp variant");

    let mut by_tag: HashMap<u8, &'static str> = HashMap::new();
    let mut collisions: Vec<String> = Vec::new();
    for op in &ops {
        let tag = variant_tag(op);
        let name = variant_name(op);
        if let Some(prev) = by_tag.insert(tag, name) {
            if prev != name {
                collisions.push(format!("tag {tag:#04X} shared by {prev} and {name}"));
            }
        }
    }
    assert!(
        collisions.is_empty(),
        "variant_tag is NOT injective:\n  {}",
        collisions.join("\n  ")
    );
}

/// Now that every variant has an encode + decode arm, the full sweep is total:
/// every variant must encode then decode back to an identical value with no
/// trailing bytes.
#[test]
fn at2_every_variant_roundtrips() {
    let mut buf = Vec::with_capacity(64);
    for op in all_variants() {
        assert!(is_codec_implemented(&op), "codec missing for {op:?}");
        buf.clear();
        encode(&op, &mut buf).unwrap_or_else(|e| panic!("encode {op:?}: {e:?}"));
        let (got, len) = decode(&buf).unwrap_or_else(|e| panic!("decode {op:?}: {e:?}"));
        assert_eq!(len, buf.len(), "trailing bytes for {op:?}");
        assert_eq!(got, op, "round-trip mismatch (tag {:#x})", variant_tag(&op));
    }
}

/// Static variant name for collision diagnostics. One arm per `IrOp` variant.
fn variant_name(op: &IrOp) -> &'static str {
    match op {
        IrOp::ConstI32 { .. } => "ConstI32",
        IrOp::ConstI64 { .. } => "ConstI64",
        IrOp::ConstF32 { .. } => "ConstF32",
        IrOp::ConstF64 { .. } => "ConstF64",
        IrOp::ConstVec128 { .. } => "ConstVec128",
        IrOp::Add { .. } => "Add",
        IrOp::Sub { .. } => "Sub",
        IrOp::Neg { .. } => "Neg",
        IrOp::And { .. } => "And",
        IrOp::Or { .. } => "Or",
        IrOp::Xor { .. } => "Xor",
        IrOp::Not { .. } => "Not",
        IrOp::Shl { .. } => "Shl",
        IrOp::LShr { .. } => "LShr",
        IrOp::AShr { .. } => "AShr",
        IrOp::Ror { .. } => "Ror",
        IrOp::Mul { .. } => "Mul",
        IrOp::MulHU { .. } => "MulHU",
        IrOp::MulHS { .. } => "MulHS",
        IrOp::SDiv { .. } => "SDiv",
        IrOp::UDiv { .. } => "UDiv",
        IrOp::Madd { .. } => "Madd",
        IrOp::Msub { .. } => "Msub",
        IrOp::Rbit { .. } => "Rbit",
        IrOp::Rev { .. } => "Rev",
        IrOp::Clz { .. } => "Clz",
        IrOp::Cls { .. } => "Cls",
        IrOp::Bswap16 { .. } => "Bswap16",
        IrOp::Bswap32 { .. } => "Bswap32",
        IrOp::Bswap64 { .. } => "Bswap64",
        IrOp::AddS { .. } => "AddS",
        IrOp::SubS { .. } => "SubS",
        IrOp::AndS { .. } => "AndS",
        IrOp::Adcs { .. } => "Adcs",
        IrOp::Sbcs { .. } => "Sbcs",
        IrOp::Cmp { .. } => "Cmp",
        IrOp::Cmn { .. } => "Cmn",
        IrOp::Tst { .. } => "Tst",
        IrOp::CCmp { .. } => "CCmp",
        IrOp::Csel { .. } => "Csel",
        IrOp::NzcvBitOp { .. } => "NzcvBitOp",
        IrOp::Sext { .. } => "Sext",
        IrOp::Zext { .. } => "Zext",
        IrOp::Trunc { .. } => "Trunc",
        IrOp::StampFaultPc(_) => "StampFaultPc",
        IrOp::Load { .. } => "Load",
        IrOp::Store { .. } => "Store",
        IrOp::LoadExclusive { .. } => "LoadExclusive",
        IrOp::StoreExclusive { .. } => "StoreExclusive",
        IrOp::LoadPair { .. } => "LoadPair",
        IrOp::StorePair { .. } => "StorePair",
        IrOp::VecMoviImm { .. } => "VecMoviImm",
        IrOp::VecDupGpr { .. } => "VecDupGpr",
        IrOp::VecExtractLane { .. } => "VecExtractLane",
        IrOp::VecInsGpr { .. } => "VecInsGpr",
        IrOp::VecCnt { .. } => "VecCnt",
        IrOp::VecAddvLong { .. } => "VecAddvLong",
        IrOp::VecCmpZero { .. } => "VecCmpZero",
        IrOp::VecShiftNarrow { .. } => "VecShiftNarrow",
        IrOp::VecShiftLong { .. } => "VecShiftLong",
        IrOp::VecShiftReg { .. } => "VecShiftReg",
        IrOp::VecShiftIns { .. } => "VecShiftIns",
        IrOp::VecShiftNarrowSat { .. } => "VecShiftNarrowSat",
        IrOp::VecExt { .. } => "VecExt",
        IrOp::VecTbl1 { .. } => "VecTbl1",
        IrOp::VecTblN { .. } => "VecTblN",
        IrOp::VecDupElem { .. } => "VecDupElem",
        IrOp::VecPmull { .. } => "VecPmull",
        IrOp::VecMulLong { .. } => "VecMulLong",
        IrOp::VecRev64 { .. } => "VecRev64",
        IrOp::CryptoSha256 { .. } => "CryptoSha256",
        IrOp::SimdInterp { .. } => "SimdInterp",
        IrOp::VecBicOrrImm { .. } => "VecBicOrrImm",
        IrOp::VecAddLongPair { .. } => "VecAddLongPair",
        IrOp::VecUnzip { .. } => "VecUnzip",
        IrOp::VecReduceAdd { .. } => "VecReduceAdd",
        IrOp::ZeroBlock { .. } => "ZeroBlock",
        IrOp::AtomicRmw { .. } => "AtomicRmw",
        IrOp::AtomicCas { .. } => "AtomicCas",
        IrOp::AtomicCasPair { .. } => "AtomicCasPair",
        IrOp::Branch { .. } => "Branch",
        IrOp::CondBranch { .. } => "CondBranch",
        IrOp::IndirectBranch { .. } => "IndirectBranch",
        IrOp::Call { .. } => "Call",
        IrOp::Return { .. } => "Return",
        IrOp::Cbz { .. } => "Cbz",
        IrOp::Cbnz { .. } => "Cbnz",
        IrOp::Tbz { .. } => "Tbz",
        IrOp::Tbnz { .. } => "Tbnz",
        IrOp::VAdd { .. } => "VAdd",
        IrOp::VSub { .. } => "VSub",
        IrOp::VMul { .. } => "VMul",
        IrOp::VAnd { .. } => "VAnd",
        IrOp::VOr { .. } => "VOr",
        IrOp::VXor { .. } => "VXor",
        IrOp::VShl { .. } => "VShl",
        IrOp::VLShr { .. } => "VLShr",
        IrOp::VAShr { .. } => "VAShr",
        IrOp::VNeg { .. } => "VNeg",
        IrOp::VAbs { .. } => "VAbs",
        IrOp::VMin { .. } => "VMin",
        IrOp::VMax { .. } => "VMax",
        IrOp::VCmp { .. } => "VCmp",
        IrOp::VDup { .. } => "VDup",
        IrOp::VInsLane { .. } => "VInsLane",
        IrOp::VExtractLane { .. } => "VExtractLane",
        IrOp::VPermute { .. } => "VPermute",
        IrOp::VTbl { .. } => "VTbl",
        IrOp::VTbx { .. } => "VTbx",
        IrOp::VModImm { .. } => "VModImm",
        IrOp::VConvert { .. } => "VConvert",
        IrOp::VFAdd { .. } => "VFAdd",
        IrOp::VFSub { .. } => "VFSub",
        IrOp::VFMul { .. } => "VFMul",
        IrOp::VFDiv { .. } => "VFDiv",
        IrOp::VFMa { .. } => "VFMa",
        IrOp::FAdd { .. } => "FAdd",
        IrOp::FSub { .. } => "FSub",
        IrOp::FMul { .. } => "FMul",
        IrOp::FDiv { .. } => "FDiv",
        IrOp::FNeg { .. } => "FNeg",
        IrOp::FAbs { .. } => "FAbs",
        IrOp::FSqrt { .. } => "FSqrt",
        IrOp::FCvt { .. } => "FCvt",
        IrOp::FToInt { .. } => "FToInt",
        IrOp::IntToF { .. } => "IntToF",
        IrOp::FCmp { .. } => "FCmp",
        IrOp::AesE { .. } => "AesE",
        IrOp::AesD { .. } => "AesD",
        IrOp::AesMc { .. } => "AesMc",
        IrOp::AesImc { .. } => "AesImc",
        IrOp::Sha1c { .. } => "Sha1c",
        IrOp::Sha1m { .. } => "Sha1m",
        IrOp::Sha1p { .. } => "Sha1p",
        IrOp::Sha256h { .. } => "Sha256h",
        IrOp::Sha256h2 { .. } => "Sha256h2",
        IrOp::Sha256su0 { .. } => "Sha256su0",
        IrOp::Sha256su1 { .. } => "Sha256su1",
        IrOp::Pmull { .. } => "Pmull",
        IrOp::Crc32 { .. } => "Crc32",
        IrOp::Hvc { .. } => "Hvc",
        IrOp::Svc { .. } => "Svc",
        IrOp::Smc { .. } => "Smc",
        IrOp::Brk { .. } => "Brk",
        IrOp::Hlt { .. } => "Hlt",
        IrOp::EretRt => "EretRt",
        IrOp::Mrs { .. } => "Mrs",
        IrOp::Msr { .. } => "Msr",
        IrOp::Dmb { .. } => "Dmb",
        IrOp::Dsb { .. } => "Dsb",
        IrOp::Isb => "Isb",
        IrOp::Sb => "Sb",
        IrOp::TlbInval { .. } => "TlbInval",
        IrOp::AtS1E1 { .. } => "AtS1E1",
        IrOp::Hint { .. } => "Hint",
        IrOp::ReadGpr { .. } => "ReadGpr",
        IrOp::WriteGpr { .. } => "WriteGpr",
        IrOp::ReadSp { .. } => "ReadSp",
        IrOp::WriteSp { .. } => "WriteSp",
        IrOp::ReadFpr { .. } => "ReadFpr",
        IrOp::WriteFpr { .. } => "WriteFpr",
        IrOp::ReadFlags { .. } => "ReadFlags",
        IrOp::WriteFlags { .. } => "WriteFlags",
        IrOp::ReadPc { .. } => "ReadPc",
        IrOp::WritePc { .. } => "WritePc",
        IrOp::X86Mfence => "X86Mfence",
        IrOp::X86Cpuid => "X86Cpuid",
        IrOp::VecBin { .. } => "VecBin",
        IrOp::VecUn { .. } => "VecUn",
        IrOp::VecShift { .. } => "VecShift",
        IrOp::VecShiftAcc { .. } => "VecShiftAcc",
        IrOp::VecCmp { .. } => "VecCmp",
        IrOp::VecPair { .. } => "VecPair",
        IrOp::VecReduce { .. } => "VecReduce",
        IrOp::VecAddLong { .. } => "VecAddLong",
        IrOp::VecFp { .. } => "VecFp",
        IrOp::VecFpCmp { .. } => "VecFpCmp",
        IrOp::VecFpUn { .. } => "VecFpUn",
        IrOp::VecByElem { .. } => "VecByElem",
        IrOp::VecCvtFp { .. } => "VecCvtFp",
        IrOp::VecZipTrn { .. } => "VecZipTrn",
        IrOp::VecScalarPair { .. } => "VecScalarPair",
        IrOp::FpFromInt { .. } => "FpFromInt",
        IrOp::FpToIntR { .. } => "FpToIntR",
        IrOp::FpRound { .. } => "FpRound",
        IrOp::VecFpRound { .. } => "VecFpRound",
        IrOp::VecFpCvtWidth { .. } => "VecFpCvtWidth",
        IrOp::FpCvt2 { .. } => "FpCvt2",
        IrOp::FpCsel { .. } => "FpCsel",
        IrOp::FpMov { .. } => "FpMov",
        IrOp::FpBin { .. } => "FpBin",
        IrOp::FpFma { .. } => "FpFma",
        IrOp::FpUn { .. } => "FpUn",
        IrOp::FpCmpN { .. } => "FpCmpN",
        IrOp::FpCvtIntScalar { .. } => "FpCvtIntScalar",
        IrOp::FpCvtToIntScalar { .. } => "FpCvtToIntScalar",
        IrOp::FpToGpr { .. } => "FpToGpr",
        IrOp::FpFromGpr { .. } => "FpFromGpr",
        IrOp::CryptoAesR { .. } => "CryptoAesR",
        IrOp::CryptoShaR { .. } => "CryptoShaR",
        IrOp::Unimplemented(_) => "Unimplemented",
    }
}
