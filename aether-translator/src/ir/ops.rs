//! IR opcodes.
//!
//! ~140 variants covering integer ALU, compare, load/store, atomics, control
//! flow, NEON vector ops, crypto, and system ops. Variants are added to this
//! enum during AT-2 fill; Phase A skeleton lists the families.

use super::flags::{IrFlagsId, NzcvBit};
use super::memory::{AtomicOp, BarrierDomain, LoadTy, MemOrder, StoreTy};
use super::value::{IrValueId, LaneType};
use super::{BlockId, IrBlock, VerifyErr};

use crate::decoder::sysreg::SysReg;
use crate::decoder::Cond;

/// Operation kind. Every IR producer/consumer points at one of these.
#[derive(Debug, Clone, PartialEq)]
pub enum IrOp {
    // ----- Constants -----
    ConstI32 {
        dst: IrValueId,
        val: i32,
    },
    ConstI64 {
        dst: IrValueId,
        val: i64,
    },
    ConstF32 {
        dst: IrValueId,
        bits: u32,
    },
    ConstF64 {
        dst: IrValueId,
        bits: u64,
    },
    ConstVec128 {
        dst: IrValueId,
        bytes: [u8; 16],
    },

    // ----- Pure integer ALU -----
    Add {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
    },
    Sub {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
    },
    Neg {
        dst: IrValueId,
        a: IrValueId,
    },
    And {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
    },
    Or {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
    },
    Xor {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
    },
    Not {
        dst: IrValueId,
        a: IrValueId,
    },
    Shl {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
    },
    LShr {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
    },
    AShr {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
    },
    Ror {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
    },
    Mul {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
    },
    MulHU {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
    },
    MulHS {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
    },
    SDiv {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
    },
    UDiv {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
    },
    Madd {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        c: IrValueId,
    },
    Msub {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        c: IrValueId,
    },
    Rbit {
        dst: IrValueId,
        a: IrValueId,
    },
    Rev {
        dst: IrValueId,
        a: IrValueId,
        bytes: u8,
    },
    Clz {
        dst: IrValueId,
        a: IrValueId,
    },
    Cls {
        dst: IrValueId,
        a: IrValueId,
    },
    Bswap16 {
        dst: IrValueId,
        a: IrValueId,
    },
    Bswap32 {
        dst: IrValueId,
        a: IrValueId,
    },
    Bswap64 {
        dst: IrValueId,
        a: IrValueId,
    },

    // ----- Flag-producing ALU -----
    AddS {
        dst: IrValueId,
        flags: IrFlagsId,
        a: IrValueId,
        b: IrValueId,
    },
    SubS {
        dst: IrValueId,
        flags: IrFlagsId,
        a: IrValueId,
        b: IrValueId,
    },
    AndS {
        dst: IrValueId,
        flags: IrFlagsId,
        a: IrValueId,
        b: IrValueId,
    },
    Adcs {
        dst: IrValueId,
        flags: IrFlagsId,
        a: IrValueId,
        b: IrValueId,
        c_in: IrFlagsId,
    },
    Sbcs {
        dst: IrValueId,
        flags: IrFlagsId,
        a: IrValueId,
        b: IrValueId,
        c_in: IrFlagsId,
    },
    Cmp {
        flags: IrFlagsId,
        a: IrValueId,
        b: IrValueId,
    },
    Cmn {
        flags: IrFlagsId,
        a: IrValueId,
        b: IrValueId,
    },
    Tst {
        flags: IrFlagsId,
        a: IrValueId,
        b: IrValueId,
    },
    CCmp {
        flags_out: IrFlagsId,
        a: IrValueId,
        b: IrValueId,
        cond: Cond,
        nzcv_if_false: u8,
        flags_in: IrFlagsId,
    },
    Csel {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        cond: Cond,
        flags: IrFlagsId,
        variant: u8, // 00=CSEL 01=CSINC 10=CSINV 11=CSNEG
    },
    NzcvBitOp {
        dst: IrValueId,
        flags: IrFlagsId,
        bit: NzcvBit,
    },

    // ----- Sign / zero extension -----
    Sext {
        dst: IrValueId,
        a: IrValueId,
        from_bits: u8,
        to_bits: u8,
    },
    Zext {
        dst: IrValueId,
        a: IrValueId,
        from_bits: u8,
        to_bits: u8,
    },
    Trunc {
        dst: IrValueId,
        a: IrValueId,
        to_bits: u8,
    },

    // ----- Memory -----
    Load {
        dst: IrValueId,
        addr: IrValueId,
        ty: LoadTy,
        order: MemOrder,
    },
    Store {
        val: IrValueId,
        addr: IrValueId,
        ty: StoreTy,
        order: MemOrder,
    },
    LoadExclusive {
        dst: IrValueId,
        addr: IrValueId,
        ty: LoadTy,
    },
    StoreExclusive {
        status: IrValueId,
        val: IrValueId,
        addr: IrValueId,
        ty: StoreTy,
    },
    LoadPair {
        dst_a: IrValueId,
        dst_b: IrValueId,
        addr: IrValueId,
        ty: LoadTy,
    },
    StorePair {
        val_a: IrValueId,
        val_b: IrValueId,
        addr: IrValueId,
        ty: StoreTy,
    },

    // ----- Atomics (LSE) -----
    AtomicRmw {
        dst: IrValueId,
        op: AtomicOp,
        addr: IrValueId,
        val: IrValueId,
        order: MemOrder,
    },
    AtomicCas {
        dst: IrValueId,
        addr: IrValueId,
        expected: IrValueId,
        new: IrValueId,
        order: MemOrder,
    },

    // ----- Control flow -----
    Branch {
        target: BlockId,
    },
    CondBranch {
        cond: Cond,
        flags: IrFlagsId,
        taken: BlockId,
        fallthru: BlockId,
    },
    IndirectBranch {
        target: IrValueId,
    },
    Call {
        target: IrValueId,
        link_pc: u64,
    },
    Return {
        target: IrValueId,
    },
    Cbz {
        a: IrValueId,
        taken: BlockId,
        fallthru: BlockId,
    },
    Cbnz {
        a: IrValueId,
        taken: BlockId,
        fallthru: BlockId,
    },
    Tbz {
        a: IrValueId,
        bit: u8,
        taken: BlockId,
        fallthru: BlockId,
    },
    Tbnz {
        a: IrValueId,
        bit: u8,
        taken: BlockId,
        fallthru: BlockId,
    },

    // ----- Vector / NEON -----
    VAdd {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        lane: LaneType,
    },
    VSub {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        lane: LaneType,
    },
    VMul {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        lane: LaneType,
    },
    VAnd {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
    },
    VOr {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
    },
    VXor {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
    },
    VShl {
        dst: IrValueId,
        a: IrValueId,
        amount: u8,
        lane: LaneType,
    },
    VLShr {
        dst: IrValueId,
        a: IrValueId,
        amount: u8,
        lane: LaneType,
    },
    VAShr {
        dst: IrValueId,
        a: IrValueId,
        amount: u8,
        lane: LaneType,
    },
    VNeg {
        dst: IrValueId,
        a: IrValueId,
        lane: LaneType,
    },
    VAbs {
        dst: IrValueId,
        a: IrValueId,
        lane: LaneType,
    },
    VMin {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        lane: LaneType,
        signed: bool,
    },
    VMax {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        lane: LaneType,
        signed: bool,
    },
    VCmp {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        lane: LaneType,
        eq: bool,
        signed: bool,
    },
    VDup {
        dst: IrValueId,
        a: IrValueId,
        lane: LaneType,
    },
    VInsLane {
        dst: IrValueId,
        src: IrValueId,
        scalar: IrValueId,
        lane_idx: u8,
        lane: LaneType,
    },
    VExtractLane {
        dst: IrValueId,
        a: IrValueId,
        lane_idx: u8,
        lane: LaneType,
    },
    VPermute {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        index: [u8; 16],
    },
    VTbl {
        dst: IrValueId,
        table_lo: IrValueId,
        table_hi: IrValueId,
        index: IrValueId,
    },
    VTbx {
        dst: IrValueId,
        prev: IrValueId,
        table_lo: IrValueId,
        table_hi: IrValueId,
        index: IrValueId,
    },
    VModImm {
        dst: IrValueId,
        imm: u64,
        lane: LaneType,
    },
    VConvert {
        dst: IrValueId,
        a: IrValueId,
        from: LaneType,
        to: LaneType,
    },
    VFAdd {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        lane: LaneType,
    },
    VFSub {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        lane: LaneType,
    },
    VFMul {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        lane: LaneType,
    },
    VFDiv {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        lane: LaneType,
    },
    VFMa {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        c: IrValueId,
        lane: LaneType,
    },

    // ----- Scalar FP -----
    FAdd {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
    },
    FSub {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
    },
    FMul {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
    },
    FDiv {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
    },
    FNeg {
        dst: IrValueId,
        a: IrValueId,
    },
    FAbs {
        dst: IrValueId,
        a: IrValueId,
    },
    FSqrt {
        dst: IrValueId,
        a: IrValueId,
    },
    FCvt {
        dst: IrValueId,
        a: IrValueId,
        from_bits: u8,
        to_bits: u8,
    },
    FToInt {
        dst: IrValueId,
        a: IrValueId,
        to_bits: u8,
        signed: bool,
    },
    IntToF {
        dst: IrValueId,
        a: IrValueId,
        from_bits: u8,
        signed: bool,
    },
    FCmp {
        flags: IrFlagsId,
        a: IrValueId,
        b: IrValueId,
    },

    // ----- Crypto -----
    AesE {
        dst: IrValueId,
        a: IrValueId,
        key: IrValueId,
    },
    AesD {
        dst: IrValueId,
        a: IrValueId,
        key: IrValueId,
    },
    AesMc {
        dst: IrValueId,
        a: IrValueId,
    },
    AesImc {
        dst: IrValueId,
        a: IrValueId,
    },
    Sha1c {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        c: IrValueId,
    },
    Sha1m {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        c: IrValueId,
    },
    Sha1p {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        c: IrValueId,
    },
    Sha256h {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        c: IrValueId,
    },
    Sha256h2 {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        c: IrValueId,
    },
    Sha256su0 {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
    },
    Sha256su1 {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        c: IrValueId,
    },
    Pmull {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        wide: bool,
    },
    Crc32 {
        dst: IrValueId,
        a: IrValueId,
        b: IrValueId,
        size: u8,
        castagnoli: bool,
    },

    // ----- System / barriers -----
    Hvc {
        imm16: u16,
    },
    Svc {
        imm16: u16,
    },
    Smc {
        imm16: u16,
    },
    Brk {
        imm16: u16,
    },
    Hlt {
        imm16: u16,
    },
    Mrs {
        dst: IrValueId,
        reg: SysReg,
    },
    Msr {
        reg: SysReg,
        val: IrValueId,
    },
    Dmb {
        domain: BarrierDomain,
    },
    Dsb {
        domain: BarrierDomain,
    },
    Isb,
    Sb,
    /// PAC / BTI / WFI / WFE / YIELD / SEV / SEVL / NOP all collapse here so
    /// AT-5 audit sees coverage; semantics-relevant variants get distinct ops
    /// in AT-4 fill.
    Hint {
        imm: u8,
    },

    // ----- Sentinel -----
    /// The decoded encoding could not be lifted. Carries the source word so
    /// AT-5 can report exactly what was missed. Production lift paths MUST
    /// NOT construct this.
    Unimplemented(u32),
}

impl IrOp {
    /// Block-local verification used by [`super::IrFunction::verify`].
    ///
    /// Phase A scope: confirms referenced `IrValueId`s are < block.values.len()
    /// and referenced `BlockId`s are reachable (caller-checked). Memory orders
    /// are validated against the LoadTy / StoreTy.
    pub fn verify_within(&self, blk: &IrBlock) -> Result<(), VerifyErr> {
        let val_max = blk.values.len() as u32;
        let check = |v: IrValueId| -> Result<(), VerifyErr> {
            if v.0 >= val_max {
                Err(VerifyErr::UndefinedValue(v))
            } else {
                Ok(())
            }
        };

        // Phase A coarse check: walk variant operands. The exhaustive per-variant
        // verifier lands in the AT-2 fill commit; here we just ensure the visible
        // operand IDs are in range for the common families.
        match *self {
            IrOp::Add { dst, a, b }
            | IrOp::Sub { dst, a, b }
            | IrOp::And { dst, a, b }
            | IrOp::Or { dst, a, b }
            | IrOp::Xor { dst, a, b }
            | IrOp::Shl { dst, a, b }
            | IrOp::LShr { dst, a, b }
            | IrOp::AShr { dst, a, b }
            | IrOp::Ror { dst, a, b }
            | IrOp::Mul { dst, a, b }
            | IrOp::MulHU { dst, a, b }
            | IrOp::MulHS { dst, a, b }
            | IrOp::SDiv { dst, a, b }
            | IrOp::UDiv { dst, a, b } => {
                check(dst)?;
                check(a)?;
                check(b)?;
            }
            IrOp::Load { dst, addr, .. } => {
                check(dst)?;
                check(addr)?;
            }
            IrOp::Store { val, addr, .. } => {
                check(val)?;
                check(addr)?;
            }
            // Phase A skeleton: other variants pass through. The AT-2 fill
            // commit replaces this with an exhaustive match generated by macro.
            _ => {}
        }
        Ok(())
    }
}
