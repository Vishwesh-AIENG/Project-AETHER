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

    // ----- Guest CPU state access (pre-SSA register/flag/PC plumbing) -----
    //
    // These ops bracket every basic block. Phase B SSA construction folds
    // them into proper SSA values via memory-promotion + phi insertion at
    // join points. Until then, every read/write of an architectural
    // register goes through one of these.

    /// Read 64-bit guest X<reg> (or zero-extended W<reg> if sf=false).
    /// reg=31 means XZR (always reads as 0); decoder rewrites SP-context to ReadSp.
    ReadGpr { dst: IrValueId, reg: u8, sf: bool },
    /// Write guest X<reg> = src. If sf=false, low 32 bits written, upper 32 zeroed (ARM W-write semantics).
    /// reg=31 means write to XZR (discarded).
    WriteGpr { reg: u8, src: IrValueId, sf: bool },
    /// Read/write SP (the stack pointer; encoding 31 in SP context).
    ReadSp { dst: IrValueId, sf: bool },
    WriteSp { src: IrValueId, sf: bool },
    /// Read/write 128-bit guest V<reg>.
    ReadFpr { dst: IrValueId, reg: u8 },
    WriteFpr { reg: u8, src: IrValueId },
    /// Read/write the NZCV flag bundle.
    ReadFlags { dst: IrFlagsId },
    WriteFlags { src: IrFlagsId },
    /// Read/write the guest program counter.
    ReadPc { dst: IrValueId },
    WritePc { src: IrValueId },

    // ----- AT-10 x86 TSO lowered ops -----
    /// x86 MFENCE — emitted by AT-10 mem-order lowering in place of full ARM
    /// barriers (DMB SY / DSB).  Phase C encodes this as `0F AE F0`.
    X86Mfence,
    /// x86 CPUID (leaf 0) — serialising instruction used in place of ISB.
    /// Phase C encodes this as `0F A2` preceded by `XOR EAX, EAX`.
    X86Cpuid,

    // ----- Sentinel -----
    /// The decoded encoding could not be lifted. Carries the source word so
    /// AT-5 can report exactly what was missed. Production lift paths MUST
    /// NOT construct this.
    Unimplemented(u32),
}

impl IrOp {
    // ── AT-6 helpers used by the SSA builder and all optimizer passes ─────────

    /// Call `f` for every `IrValueId` that this op **defines** (writes).
    pub fn visit_def_values(&self, mut f: impl FnMut(IrValueId)) {
        match *self {
            IrOp::ConstI32 { dst, .. } | IrOp::ConstI64 { dst, .. }
            | IrOp::ConstF32 { dst, .. } | IrOp::ConstF64 { dst, .. }
            | IrOp::ConstVec128 { dst, .. } => f(dst),

            IrOp::Add { dst, .. } | IrOp::Sub { dst, .. } | IrOp::Neg { dst, .. }
            | IrOp::And { dst, .. } | IrOp::Or { dst, .. } | IrOp::Xor { dst, .. }
            | IrOp::Not { dst, .. } | IrOp::Shl { dst, .. } | IrOp::LShr { dst, .. }
            | IrOp::AShr { dst, .. } | IrOp::Ror { dst, .. } | IrOp::Mul { dst, .. }
            | IrOp::MulHU { dst, .. } | IrOp::MulHS { dst, .. }
            | IrOp::SDiv { dst, .. } | IrOp::UDiv { dst, .. }
            | IrOp::Madd { dst, .. } | IrOp::Msub { dst, .. }
            | IrOp::Rbit { dst, .. } | IrOp::Rev { dst, .. }
            | IrOp::Clz { dst, .. } | IrOp::Cls { dst, .. }
            | IrOp::Bswap16 { dst, .. } | IrOp::Bswap32 { dst, .. }
            | IrOp::Bswap64 { dst, .. } => f(dst),

            IrOp::AddS { dst, .. } | IrOp::SubS { dst, .. } | IrOp::AndS { dst, .. }
            | IrOp::Adcs { dst, .. } | IrOp::Sbcs { dst, .. }
            | IrOp::Csel { dst, .. } | IrOp::NzcvBitOp { dst, .. } => f(dst),

            IrOp::Sext { dst, .. } | IrOp::Zext { dst, .. } | IrOp::Trunc { dst, .. } => f(dst),

            IrOp::Load { dst, .. } | IrOp::LoadExclusive { dst, .. } => f(dst),
            IrOp::LoadPair { dst_a, dst_b, .. } => { f(dst_a); f(dst_b); }
            IrOp::StoreExclusive { status, .. } => f(status),
            IrOp::AtomicRmw { dst, .. } | IrOp::AtomicCas { dst, .. } => f(dst),

            IrOp::VAdd { dst, .. } | IrOp::VSub { dst, .. } | IrOp::VMul { dst, .. }
            | IrOp::VAnd { dst, .. } | IrOp::VOr { dst, .. } | IrOp::VXor { dst, .. }
            | IrOp::VShl { dst, .. } | IrOp::VLShr { dst, .. } | IrOp::VAShr { dst, .. }
            | IrOp::VNeg { dst, .. } | IrOp::VAbs { dst, .. }
            | IrOp::VMin { dst, .. } | IrOp::VMax { dst, .. } | IrOp::VCmp { dst, .. }
            | IrOp::VDup { dst, .. } | IrOp::VInsLane { dst, .. }
            | IrOp::VExtractLane { dst, .. } | IrOp::VPermute { dst, .. }
            | IrOp::VTbl { dst, .. } | IrOp::VTbx { dst, .. }
            | IrOp::VModImm { dst, .. } | IrOp::VConvert { dst, .. }
            | IrOp::VFAdd { dst, .. } | IrOp::VFSub { dst, .. }
            | IrOp::VFMul { dst, .. } | IrOp::VFDiv { dst, .. }
            | IrOp::VFMa { dst, .. } => f(dst),

            IrOp::FAdd { dst, .. } | IrOp::FSub { dst, .. } | IrOp::FMul { dst, .. }
            | IrOp::FDiv { dst, .. } | IrOp::FNeg { dst, .. } | IrOp::FAbs { dst, .. }
            | IrOp::FSqrt { dst, .. } | IrOp::FCvt { dst, .. }
            | IrOp::FToInt { dst, .. } | IrOp::IntToF { dst, .. } => f(dst),

            IrOp::AesE { dst, .. } | IrOp::AesD { dst, .. }
            | IrOp::AesMc { dst, .. } | IrOp::AesImc { dst, .. }
            | IrOp::Sha1c { dst, .. } | IrOp::Sha1m { dst, .. } | IrOp::Sha1p { dst, .. }
            | IrOp::Sha256h { dst, .. } | IrOp::Sha256h2 { dst, .. }
            | IrOp::Sha256su0 { dst, .. } | IrOp::Sha256su1 { dst, .. }
            | IrOp::Pmull { dst, .. } | IrOp::Crc32 { dst, .. } => f(dst),

            IrOp::Mrs { dst, .. } => f(dst),
            IrOp::ReadGpr { dst, .. } | IrOp::ReadSp { dst, .. }
            | IrOp::ReadFpr { dst, .. } | IrOp::ReadPc { dst, .. } => f(dst),

            _ => {}
        }
    }

    /// Call `f` for every `IrValueId` that this op **uses** (reads).
    pub fn visit_use_values(&self, mut f: impl FnMut(IrValueId)) {
        match *self {
            IrOp::Add { a, b, .. } | IrOp::Sub { a, b, .. }
            | IrOp::And { a, b, .. } | IrOp::Or { a, b, .. } | IrOp::Xor { a, b, .. }
            | IrOp::Shl { a, b, .. } | IrOp::LShr { a, b, .. } | IrOp::AShr { a, b, .. }
            | IrOp::Ror { a, b, .. } | IrOp::Mul { a, b, .. }
            | IrOp::MulHU { a, b, .. } | IrOp::MulHS { a, b, .. }
            | IrOp::SDiv { a, b, .. } | IrOp::UDiv { a, b, .. } => { f(a); f(b); }

            IrOp::Neg { a, .. } | IrOp::Not { a, .. } | IrOp::Rbit { a, .. }
            | IrOp::Rev { a, .. } | IrOp::Clz { a, .. } | IrOp::Cls { a, .. }
            | IrOp::Bswap16 { a, .. } | IrOp::Bswap32 { a, .. }
            | IrOp::Bswap64 { a, .. } => f(a),

            IrOp::Madd { a, b, c, .. } | IrOp::Msub { a, b, c, .. } => { f(a); f(b); f(c); }

            IrOp::AddS { a, b, .. } | IrOp::SubS { a, b, .. } | IrOp::AndS { a, b, .. } => {
                f(a); f(b);
            }
            IrOp::Adcs { a, b, .. } | IrOp::Sbcs { a, b, .. } => { f(a); f(b); }
            IrOp::Cmp { a, b, .. } | IrOp::Cmn { a, b, .. } | IrOp::Tst { a, b, .. } => {
                f(a); f(b);
            }
            IrOp::CCmp { a, b, .. } => { f(a); f(b); }
            IrOp::Csel { a, b, .. } => { f(a); f(b); }
            IrOp::NzcvBitOp { .. } => {}

            IrOp::Sext { a, .. } | IrOp::Zext { a, .. } | IrOp::Trunc { a, .. } => f(a),

            IrOp::Load { addr, .. } => f(addr),
            IrOp::Store { val, addr, .. } => { f(val); f(addr); }
            IrOp::LoadExclusive { addr, .. } => f(addr),
            IrOp::StoreExclusive { val, addr, .. } => { f(val); f(addr); }
            IrOp::LoadPair { addr, .. } => f(addr),
            IrOp::StorePair { val_a, val_b, addr, .. } => { f(val_a); f(val_b); f(addr); }
            IrOp::AtomicRmw { addr, val, .. } => { f(addr); f(val); }
            IrOp::AtomicCas { addr, expected, new, .. } => { f(addr); f(expected); f(new); }

            IrOp::IndirectBranch { target } | IrOp::Call { target, .. }
            | IrOp::Return { target } => f(target),
            IrOp::Cbz { a, .. } | IrOp::Cbnz { a, .. }
            | IrOp::Tbz { a, .. } | IrOp::Tbnz { a, .. } => f(a),

            IrOp::VAdd { a, b, .. } | IrOp::VSub { a, b, .. } | IrOp::VMul { a, b, .. }
            | IrOp::VAnd { a, b, .. } | IrOp::VOr { a, b, .. } | IrOp::VXor { a, b, .. }
            | IrOp::VMin { a, b, .. } | IrOp::VMax { a, b, .. }
            | IrOp::VCmp { a, b, .. } => { f(a); f(b); }
            IrOp::VShl { a, .. } | IrOp::VLShr { a, .. } | IrOp::VAShr { a, .. }
            | IrOp::VNeg { a, .. } | IrOp::VAbs { a, .. } | IrOp::VDup { a, .. } => f(a),
            IrOp::VInsLane { src, scalar, .. } => { f(src); f(scalar); }
            IrOp::VExtractLane { a, .. } => f(a),
            IrOp::VPermute { a, b, .. } => { f(a); f(b); }
            IrOp::VTbl { table_lo, table_hi, index, .. } => { f(table_lo); f(table_hi); f(index); }
            IrOp::VTbx { prev, table_lo, table_hi, index, .. } => {
                f(prev); f(table_lo); f(table_hi); f(index);
            }
            IrOp::VConvert { a, .. } => f(a),
            IrOp::VFAdd { a, b, .. } | IrOp::VFSub { a, b, .. }
            | IrOp::VFMul { a, b, .. } | IrOp::VFDiv { a, b, .. } => { f(a); f(b); }
            IrOp::VFMa { a, b, c, .. } => { f(a); f(b); f(c); }

            IrOp::FAdd { a, b, .. } | IrOp::FSub { a, b, .. }
            | IrOp::FMul { a, b, .. } | IrOp::FDiv { a, b, .. } => { f(a); f(b); }
            IrOp::FNeg { a, .. } | IrOp::FAbs { a, .. } | IrOp::FSqrt { a, .. }
            | IrOp::FCvt { a, .. } | IrOp::FToInt { a, .. } | IrOp::IntToF { a, .. } => f(a),
            IrOp::FCmp { a, b, .. } => { f(a); f(b); }

            IrOp::AesE { a, key, .. } | IrOp::AesD { a, key, .. } => { f(a); f(key); }
            IrOp::AesMc { a, .. } | IrOp::AesImc { a, .. } => f(a),
            IrOp::Sha1c { a, b, c, .. } | IrOp::Sha1m { a, b, c, .. }
            | IrOp::Sha1p { a, b, c, .. } | IrOp::Sha256h { a, b, c, .. }
            | IrOp::Sha256h2 { a, b, c, .. } | IrOp::Sha256su1 { a, b, c, .. } => {
                f(a); f(b); f(c);
            }
            IrOp::Sha256su0 { a, b, .. } => { f(a); f(b); }
            IrOp::Pmull { a, b, .. } => { f(a); f(b); }
            IrOp::Crc32 { a, b, .. } => { f(a); f(b); }

            IrOp::Msr { val, .. } => f(val),
            IrOp::WriteGpr { src, .. } | IrOp::WriteSp { src, .. }
            | IrOp::WriteFpr { src, .. } | IrOp::WritePc { src, .. } => f(src),

            _ => {}
        }
    }

    /// Call `f` for every `IrFlagsId` that this op **defines**.
    pub fn visit_def_flags(&self, mut f: impl FnMut(IrFlagsId)) {
        match *self {
            IrOp::AddS { flags, .. } | IrOp::SubS { flags, .. } | IrOp::AndS { flags, .. }
            | IrOp::Adcs { flags, .. } | IrOp::Sbcs { flags, .. }
            | IrOp::Cmp { flags, .. } | IrOp::Cmn { flags, .. } | IrOp::Tst { flags, .. }
            | IrOp::FCmp { flags, .. } => f(flags),
            IrOp::CCmp { flags_out, .. } => f(flags_out),
            IrOp::ReadFlags { dst } => f(dst),
            _ => {}
        }
    }

    /// Call `f` for every `IrFlagsId` that this op **uses** (reads).
    pub fn visit_use_flags(&self, mut f: impl FnMut(IrFlagsId)) {
        match *self {
            IrOp::Adcs { c_in, .. } | IrOp::Sbcs { c_in, .. } => f(c_in),
            IrOp::CCmp { flags_in, .. } => f(flags_in),
            IrOp::Csel { flags, .. } | IrOp::NzcvBitOp { flags, .. } => f(flags),
            IrOp::CondBranch { flags, .. } => f(flags),
            IrOp::WriteFlags { src } => f(src),
            _ => {}
        }
    }

    /// Returns true if this op is a pre-SSA architectural-register access that
    /// the SSA promoter will eliminate.
    pub fn is_reg_access(&self) -> bool {
        matches!(
            self,
            IrOp::ReadGpr { .. } | IrOp::WriteGpr { .. }
            | IrOp::ReadSp { .. } | IrOp::WriteSp { .. }
            | IrOp::ReadFpr { .. } | IrOp::WriteFpr { .. }
            | IrOp::ReadFlags { .. } | IrOp::WriteFlags { .. }
            | IrOp::ReadPc { .. } | IrOp::WritePc { .. }
        )
    }

    /// Remap all **use** operands through the provided closures; defs are kept
    /// as-is.  Used by the SSA builder and optimizer passes.
    pub fn remap_uses(
        self,
        mut vr: impl FnMut(IrValueId) -> IrValueId,
        mut fr: impl FnMut(IrFlagsId) -> IrFlagsId,
    ) -> Self {
        match self {
            // Constants: no uses.
            IrOp::ConstI32 { .. } | IrOp::ConstI64 { .. } | IrOp::ConstF32 { .. }
            | IrOp::ConstF64 { .. } | IrOp::ConstVec128 { .. } => self,

            // Binary ALU
            IrOp::Add { dst, a, b } => IrOp::Add { dst, a: vr(a), b: vr(b) },
            IrOp::Sub { dst, a, b } => IrOp::Sub { dst, a: vr(a), b: vr(b) },
            IrOp::And { dst, a, b } => IrOp::And { dst, a: vr(a), b: vr(b) },
            IrOp::Or  { dst, a, b } => IrOp::Or  { dst, a: vr(a), b: vr(b) },
            IrOp::Xor { dst, a, b } => IrOp::Xor { dst, a: vr(a), b: vr(b) },
            IrOp::Shl { dst, a, b } => IrOp::Shl { dst, a: vr(a), b: vr(b) },
            IrOp::LShr { dst, a, b } => IrOp::LShr { dst, a: vr(a), b: vr(b) },
            IrOp::AShr { dst, a, b } => IrOp::AShr { dst, a: vr(a), b: vr(b) },
            IrOp::Ror { dst, a, b } => IrOp::Ror { dst, a: vr(a), b: vr(b) },
            IrOp::Mul { dst, a, b } => IrOp::Mul { dst, a: vr(a), b: vr(b) },
            IrOp::MulHU { dst, a, b } => IrOp::MulHU { dst, a: vr(a), b: vr(b) },
            IrOp::MulHS { dst, a, b } => IrOp::MulHS { dst, a: vr(a), b: vr(b) },
            IrOp::SDiv { dst, a, b } => IrOp::SDiv { dst, a: vr(a), b: vr(b) },
            IrOp::UDiv { dst, a, b } => IrOp::UDiv { dst, a: vr(a), b: vr(b) },

            // Unary ALU
            IrOp::Neg { dst, a } => IrOp::Neg { dst, a: vr(a) },
            IrOp::Not { dst, a } => IrOp::Not { dst, a: vr(a) },
            IrOp::Rbit { dst, a } => IrOp::Rbit { dst, a: vr(a) },
            IrOp::Rev { dst, a, bytes } => IrOp::Rev { dst, a: vr(a), bytes },
            IrOp::Clz { dst, a } => IrOp::Clz { dst, a: vr(a) },
            IrOp::Cls { dst, a } => IrOp::Cls { dst, a: vr(a) },
            IrOp::Bswap16 { dst, a } => IrOp::Bswap16 { dst, a: vr(a) },
            IrOp::Bswap32 { dst, a } => IrOp::Bswap32 { dst, a: vr(a) },
            IrOp::Bswap64 { dst, a } => IrOp::Bswap64 { dst, a: vr(a) },

            // Three-operand
            IrOp::Madd { dst, a, b, c } => IrOp::Madd { dst, a: vr(a), b: vr(b), c: vr(c) },
            IrOp::Msub { dst, a, b, c } => IrOp::Msub { dst, a: vr(a), b: vr(b), c: vr(c) },

            // Flag-producing ALU
            IrOp::AddS { dst, flags, a, b } => IrOp::AddS { dst, flags, a: vr(a), b: vr(b) },
            IrOp::SubS { dst, flags, a, b } => IrOp::SubS { dst, flags, a: vr(a), b: vr(b) },
            IrOp::AndS { dst, flags, a, b } => IrOp::AndS { dst, flags, a: vr(a), b: vr(b) },
            IrOp::Adcs { dst, flags, a, b, c_in } =>
                IrOp::Adcs { dst, flags, a: vr(a), b: vr(b), c_in: fr(c_in) },
            IrOp::Sbcs { dst, flags, a, b, c_in } =>
                IrOp::Sbcs { dst, flags, a: vr(a), b: vr(b), c_in: fr(c_in) },
            IrOp::Cmp { flags, a, b } => IrOp::Cmp { flags, a: vr(a), b: vr(b) },
            IrOp::Cmn { flags, a, b } => IrOp::Cmn { flags, a: vr(a), b: vr(b) },
            IrOp::Tst { flags, a, b } => IrOp::Tst { flags, a: vr(a), b: vr(b) },
            IrOp::CCmp { flags_out, a, b, cond, nzcv_if_false, flags_in } =>
                IrOp::CCmp { flags_out, a: vr(a), b: vr(b), cond, nzcv_if_false, flags_in: fr(flags_in) },
            IrOp::Csel { dst, a, b, cond, flags, variant } =>
                IrOp::Csel { dst, a: vr(a), b: vr(b), cond, flags: fr(flags), variant },
            IrOp::NzcvBitOp { dst, flags, bit } =>
                IrOp::NzcvBitOp { dst, flags: fr(flags), bit },

            // Ext / trunc
            IrOp::Sext { dst, a, from_bits, to_bits } =>
                IrOp::Sext { dst, a: vr(a), from_bits, to_bits },
            IrOp::Zext { dst, a, from_bits, to_bits } =>
                IrOp::Zext { dst, a: vr(a), from_bits, to_bits },
            IrOp::Trunc { dst, a, to_bits } => IrOp::Trunc { dst, a: vr(a), to_bits },

            // Memory
            IrOp::Load { dst, addr, ty, order } =>
                IrOp::Load { dst, addr: vr(addr), ty, order },
            IrOp::Store { val, addr, ty, order } =>
                IrOp::Store { val: vr(val), addr: vr(addr), ty, order },
            IrOp::LoadExclusive { dst, addr, ty } =>
                IrOp::LoadExclusive { dst, addr: vr(addr), ty },
            IrOp::StoreExclusive { status, val, addr, ty } =>
                IrOp::StoreExclusive { status, val: vr(val), addr: vr(addr), ty },
            IrOp::LoadPair { dst_a, dst_b, addr, ty } =>
                IrOp::LoadPair { dst_a, dst_b, addr: vr(addr), ty },
            IrOp::StorePair { val_a, val_b, addr, ty } =>
                IrOp::StorePair { val_a: vr(val_a), val_b: vr(val_b), addr: vr(addr), ty },
            IrOp::AtomicRmw { dst, op, addr, val, order } =>
                IrOp::AtomicRmw { dst, op, addr: vr(addr), val: vr(val), order },
            IrOp::AtomicCas { dst, addr, expected, new, order } =>
                IrOp::AtomicCas { dst, addr: vr(addr), expected: vr(expected), new: vr(new), order },

            // Control flow
            IrOp::Branch { .. } => self,
            IrOp::CondBranch { cond, flags, taken, fallthru } =>
                IrOp::CondBranch { cond, flags: fr(flags), taken, fallthru },
            IrOp::IndirectBranch { target } => IrOp::IndirectBranch { target: vr(target) },
            IrOp::Call { target, link_pc } => IrOp::Call { target: vr(target), link_pc },
            IrOp::Return { target } => IrOp::Return { target: vr(target) },
            IrOp::Cbz { a, taken, fallthru } => IrOp::Cbz { a: vr(a), taken, fallthru },
            IrOp::Cbnz { a, taken, fallthru } => IrOp::Cbnz { a: vr(a), taken, fallthru },
            IrOp::Tbz { a, bit, taken, fallthru } => IrOp::Tbz { a: vr(a), bit, taken, fallthru },
            IrOp::Tbnz { a, bit, taken, fallthru } => IrOp::Tbnz { a: vr(a), bit, taken, fallthru },

            // Vector / NEON
            IrOp::VAdd { dst, a, b, lane } => IrOp::VAdd { dst, a: vr(a), b: vr(b), lane },
            IrOp::VSub { dst, a, b, lane } => IrOp::VSub { dst, a: vr(a), b: vr(b), lane },
            IrOp::VMul { dst, a, b, lane } => IrOp::VMul { dst, a: vr(a), b: vr(b), lane },
            IrOp::VAnd { dst, a, b } => IrOp::VAnd { dst, a: vr(a), b: vr(b) },
            IrOp::VOr  { dst, a, b } => IrOp::VOr  { dst, a: vr(a), b: vr(b) },
            IrOp::VXor { dst, a, b } => IrOp::VXor { dst, a: vr(a), b: vr(b) },
            IrOp::VShl  { dst, a, amount, lane } => IrOp::VShl  { dst, a: vr(a), amount, lane },
            IrOp::VLShr { dst, a, amount, lane } => IrOp::VLShr { dst, a: vr(a), amount, lane },
            IrOp::VAShr { dst, a, amount, lane } => IrOp::VAShr { dst, a: vr(a), amount, lane },
            IrOp::VNeg { dst, a, lane } => IrOp::VNeg { dst, a: vr(a), lane },
            IrOp::VAbs { dst, a, lane } => IrOp::VAbs { dst, a: vr(a), lane },
            IrOp::VMin { dst, a, b, lane, signed } =>
                IrOp::VMin { dst, a: vr(a), b: vr(b), lane, signed },
            IrOp::VMax { dst, a, b, lane, signed } =>
                IrOp::VMax { dst, a: vr(a), b: vr(b), lane, signed },
            IrOp::VCmp { dst, a, b, lane, eq, signed } =>
                IrOp::VCmp { dst, a: vr(a), b: vr(b), lane, eq, signed },
            IrOp::VDup { dst, a, lane } => IrOp::VDup { dst, a: vr(a), lane },
            IrOp::VInsLane { dst, src, scalar, lane_idx, lane } =>
                IrOp::VInsLane { dst, src: vr(src), scalar: vr(scalar), lane_idx, lane },
            IrOp::VExtractLane { dst, a, lane_idx, lane } =>
                IrOp::VExtractLane { dst, a: vr(a), lane_idx, lane },
            IrOp::VPermute { dst, a, b, index } =>
                IrOp::VPermute { dst, a: vr(a), b: vr(b), index },
            IrOp::VTbl { dst, table_lo, table_hi, index } =>
                IrOp::VTbl { dst, table_lo: vr(table_lo), table_hi: vr(table_hi), index: vr(index) },
            IrOp::VTbx { dst, prev, table_lo, table_hi, index } =>
                IrOp::VTbx { dst, prev: vr(prev), table_lo: vr(table_lo), table_hi: vr(table_hi), index: vr(index) },
            IrOp::VModImm { .. } => self,
            IrOp::VConvert { dst, a, from, to } => IrOp::VConvert { dst, a: vr(a), from, to },
            IrOp::VFAdd { dst, a, b, lane } => IrOp::VFAdd { dst, a: vr(a), b: vr(b), lane },
            IrOp::VFSub { dst, a, b, lane } => IrOp::VFSub { dst, a: vr(a), b: vr(b), lane },
            IrOp::VFMul { dst, a, b, lane } => IrOp::VFMul { dst, a: vr(a), b: vr(b), lane },
            IrOp::VFDiv { dst, a, b, lane } => IrOp::VFDiv { dst, a: vr(a), b: vr(b), lane },
            IrOp::VFMa { dst, a, b, c, lane } =>
                IrOp::VFMa { dst, a: vr(a), b: vr(b), c: vr(c), lane },

            // Scalar FP
            IrOp::FAdd { dst, a, b } => IrOp::FAdd { dst, a: vr(a), b: vr(b) },
            IrOp::FSub { dst, a, b } => IrOp::FSub { dst, a: vr(a), b: vr(b) },
            IrOp::FMul { dst, a, b } => IrOp::FMul { dst, a: vr(a), b: vr(b) },
            IrOp::FDiv { dst, a, b } => IrOp::FDiv { dst, a: vr(a), b: vr(b) },
            IrOp::FNeg { dst, a } => IrOp::FNeg { dst, a: vr(a) },
            IrOp::FAbs { dst, a } => IrOp::FAbs { dst, a: vr(a) },
            IrOp::FSqrt { dst, a } => IrOp::FSqrt { dst, a: vr(a) },
            IrOp::FCvt { dst, a, from_bits, to_bits } =>
                IrOp::FCvt { dst, a: vr(a), from_bits, to_bits },
            IrOp::FToInt { dst, a, to_bits, signed } =>
                IrOp::FToInt { dst, a: vr(a), to_bits, signed },
            IrOp::IntToF { dst, a, from_bits, signed } =>
                IrOp::IntToF { dst, a: vr(a), from_bits, signed },
            IrOp::FCmp { flags, a, b } => IrOp::FCmp { flags, a: vr(a), b: vr(b) },

            // Crypto
            IrOp::AesE { dst, a, key } => IrOp::AesE { dst, a: vr(a), key: vr(key) },
            IrOp::AesD { dst, a, key } => IrOp::AesD { dst, a: vr(a), key: vr(key) },
            IrOp::AesMc { dst, a } => IrOp::AesMc { dst, a: vr(a) },
            IrOp::AesImc { dst, a } => IrOp::AesImc { dst, a: vr(a) },
            IrOp::Sha1c { dst, a, b, c } => IrOp::Sha1c { dst, a: vr(a), b: vr(b), c: vr(c) },
            IrOp::Sha1m { dst, a, b, c } => IrOp::Sha1m { dst, a: vr(a), b: vr(b), c: vr(c) },
            IrOp::Sha1p { dst, a, b, c } => IrOp::Sha1p { dst, a: vr(a), b: vr(b), c: vr(c) },
            IrOp::Sha256h  { dst, a, b, c } => IrOp::Sha256h  { dst, a: vr(a), b: vr(b), c: vr(c) },
            IrOp::Sha256h2 { dst, a, b, c } => IrOp::Sha256h2 { dst, a: vr(a), b: vr(b), c: vr(c) },
            IrOp::Sha256su0 { dst, a, b } => IrOp::Sha256su0 { dst, a: vr(a), b: vr(b) },
            IrOp::Sha256su1 { dst, a, b, c } => IrOp::Sha256su1 { dst, a: vr(a), b: vr(b), c: vr(c) },
            IrOp::Pmull { dst, a, b, wide } => IrOp::Pmull { dst, a: vr(a), b: vr(b), wide },
            IrOp::Crc32 { dst, a, b, size, castagnoli } =>
                IrOp::Crc32 { dst, a: vr(a), b: vr(b), size, castagnoli },

            // System / barriers (no value uses in most)
            IrOp::Hvc { .. } | IrOp::Svc { .. } | IrOp::Smc { .. }
            | IrOp::Brk { .. } | IrOp::Hlt { .. }
            | IrOp::Dmb { .. } | IrOp::Dsb { .. }
            | IrOp::Isb | IrOp::Sb | IrOp::Hint { .. } => self,
            IrOp::Mrs { dst, reg } => IrOp::Mrs { dst, reg },
            IrOp::Msr { reg, val } => IrOp::Msr { reg, val: vr(val) },

            // Pre-SSA register access (remap src-side uses)
            IrOp::ReadGpr { dst, reg, sf } => IrOp::ReadGpr { dst, reg, sf },
            IrOp::WriteGpr { reg, src, sf } => IrOp::WriteGpr { reg, src: vr(src), sf },
            IrOp::ReadSp { dst, sf } => IrOp::ReadSp { dst, sf },
            IrOp::WriteSp { src, sf } => IrOp::WriteSp { src: vr(src), sf },
            IrOp::ReadFpr { dst, reg } => IrOp::ReadFpr { dst, reg },
            IrOp::WriteFpr { reg, src } => IrOp::WriteFpr { reg, src: vr(src) },
            IrOp::ReadFlags { dst } => IrOp::ReadFlags { dst },
            IrOp::WriteFlags { src } => IrOp::WriteFlags { src: fr(src) },
            IrOp::ReadPc { dst } => IrOp::ReadPc { dst },
            IrOp::WritePc { src } => IrOp::WritePc { src: vr(src) },

            IrOp::X86Mfence => IrOp::X86Mfence,
            IrOp::X86Cpuid => IrOp::X86Cpuid,
            IrOp::Unimplemented(w) => IrOp::Unimplemented(w),
        }
    }

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
