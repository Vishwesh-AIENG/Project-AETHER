//! AT-2 gate: every IR variant must serialize and parse back to an
//! identical value.
//!
//! Phase A AT-2 fill: codec implemented for the integer / branch /
//! load-store / atomics / system / barrier / hint / extension variants
//! (~60 of the ~140 total). Remaining variants (NEON, scalar FP, crypto,
//! sysreg-bearing) defer to the AT-3/4 fill prompts.

use aether_translator::decoder::Cond;
use aether_translator::ir::memory::{AtomicOp, BarrierDomain, LoadTy, MemOrder, StoreTy};
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
        IrOp::Rbit { dst: v(0), a: v(1) },
        IrOp::Clz  { dst: v(0), a: v(1) },
        IrOp::Cls  { dst: v(0), a: v(1) },
        IrOp::Bswap16 { dst: v(0), a: v(1) },
        IrOp::Bswap32 { dst: v(0), a: v(1) },
        IrOp::Bswap64 { dst: v(0), a: v(1) },
        IrOp::AddS { dst: v(0), flags: f(0), a: v(1), b: v(2) },
        IrOp::SubS { dst: v(0), flags: f(0), a: v(1), b: v(2) },
        IrOp::AndS { dst: v(0), flags: f(0), a: v(1), b: v(2) },
        IrOp::Cmp { flags: f(0), a: v(1), b: v(2) },
        IrOp::Cmn { flags: f(0), a: v(1), b: v(2) },
        IrOp::Tst { flags: f(0), a: v(1), b: v(2) },
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
            order: MemOrder::AcqRel,
        },
        IrOp::AtomicCas {
            dst: v(0), addr: v(1), expected: v(2), new: v(3),
            order: MemOrder::SeqCst,
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
        IrOp::Brk { imm16: 0x1234 },
        IrOp::Hlt { imm16: 0 },
        IrOp::Dmb { domain: BarrierDomain::Ish },
        IrOp::Dsb { domain: BarrierDomain::Sy },
        IrOp::Isb,
        IrOp::Sb,
        IrOp::Hint { imm: 0 },
        IrOp::Hint { imm: 200 },
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
#[test]
fn at2_implemented_tags_unique() {
    let s = samples();
    let mut tags: Vec<u8> = s.iter().map(variant_tag).collect();
    tags.sort_unstable();
    let mut dedup = tags.clone();
    dedup.dedup();
    // Hint{imm: 0} and Hint{imm: 200} share their tag; account for one allowed dup.
    assert!(tags.len() - dedup.len() <= 1, "duplicate tags: {:?}", tags);
}

#[test]
#[ignore = "AT-2 full gate; un-ignore when NEON/FP/crypto/sysreg codecs land"]
fn at2_every_variant_roundtrips() {
    // Full 140-variant sweep deferred to next fill prompt.
}
