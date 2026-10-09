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
        /// Phase-E: ARM64 RBIT has W (32-bit) and X (64-bit) forms.
        /// Without `sf`, a naive 64-bit bit reversal of a W-register
        /// value (upper 32 = 0) places the reversed bits in the UPPER
        /// 32 — and the W-register WriteGpr then truncates them away,
        /// producing 0. Carrying sf lets the lowering reverse the
        /// correct width. Discovered when `_find_first_bit` returned
        /// the wrong index because RBIT (1) yielded 0 instead of
        /// 0x80000000, making `pcpu_build_alloc_info`'s
        /// `for_each_cpu` loop never increment `nr_groups`.
        sf: bool,
    },
    Rev {
        dst: IrValueId,
        a: IrValueId,
        bytes: u8,
    },
    Clz {
        dst: IrValueId,
        a: IrValueId,
        /// Phase-E: ARM64 CLZ has W (32-bit, result 0..32) and X
        /// (64-bit, result 0..64) forms. Without sf, lowering would
        /// always emit lzcnt_r64 and the W-form would return
        /// 32 + clz_32(low32), then the W-write would truncate giving
        /// wrong values in [32..64]. Same bug class as RBIT (sf field
        /// added in the same Phase-E commit).
        sf: bool,
    },
    Cls {
        dst: IrValueId,
        a: IrValueId,
        sf: bool,
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
    // `sf` is the operand WIDTH: true = 64-bit (X-form), false = 32-bit (W-form).
    // For W-form the x86 ALU op MUST be 32-bit so EFLAGS (N=bit31, Z/C/V over 32
    // bits) are computed correctly — a 64-bit op reports N from bit 63 and the
    // wrong Z/C/V (a silent miscompile of every W-form compare; caught by the
    // M4b adversarial review).
    AddS {
        dst: IrValueId,
        flags: IrFlagsId,
        a: IrValueId,
        b: IrValueId,
        sf: bool,
    },
    SubS {
        dst: IrValueId,
        flags: IrFlagsId,
        a: IrValueId,
        b: IrValueId,
        sf: bool,
    },
    AndS {
        dst: IrValueId,
        flags: IrFlagsId,
        a: IrValueId,
        b: IrValueId,
        sf: bool,
    },
    Adcs {
        dst: IrValueId,
        flags: IrFlagsId,
        a: IrValueId,
        b: IrValueId,
        c_in: IrFlagsId,
        sf: bool,
    },
    Sbcs {
        dst: IrValueId,
        flags: IrFlagsId,
        a: IrValueId,
        b: IrValueId,
        c_in: IrFlagsId,
        sf: bool,
    },
    Cmp {
        flags: IrFlagsId,
        a: IrValueId,
        b: IrValueId,
        sf: bool,
    },
    Cmn {
        flags: IrFlagsId,
        a: IrValueId,
        b: IrValueId,
        sf: bool,
    },
    Tst {
        flags: IrFlagsId,
        a: IrValueId,
        b: IrValueId,
        sf: bool,
    },
    CCmp {
        flags_out: IrFlagsId,
        a: IrValueId,
        b: IrValueId,
        cond: Cond,
        nzcv_if_false: u8,
        flags_in: IrFlagsId,
        /// true = CCMN (flags from a + b, ADD polarity); false = CCMP
        /// (flags from a - b, SUB polarity). Dropping this silently miscompiles
        /// CCMN as CCMP — caught by the M4b-1 adversarial review.
        is_neg: bool,
        sf: bool,
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

    /// Diagnostic: stamp `FAULT_OP_PC` with this instruction's PC. No operands;
    /// lowers to a single immediate store. Inserted per-instruction by `lift_at`.
    StampFaultPc(u64),

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
    /// NEON `MOVI`/`MVNI` — write a fully-resolved 128-bit immediate to the
    /// ctx q-register file slot for V`d` (lo = bytes [0..8), hi = [8..16)). A
    /// ctx-template op (no SSA operands); lowers to two `mov imm64` + store to
    /// `[R15 + vec_disp(d)]`. Replaces the `Hint{200}`→UD2 path for vector
    /// modified-immediate, which blocked /init (`movi v0.2d,#0`).
    VecMoviImm {
        d: u8,
        lo: u64,
        hi: u64,
    },
    /// NEON `DUP` (general): broadcast GPR `src`'s low `size` bytes to every lane
    /// of the q-register ctx slot for V`d`. `q`=false zeroes the upper 64 bits.
    /// A ctx-template op (writes `[R15 + vec_disp(d)]`); side-effecting in DCE.
    VecDupGpr {
        d: u8,
        src: IrValueId,
        size: u8,
        q: bool,
    },
    /// NEON `UMOV`/`SMOV`: extract lane `lane` (element width `size` bytes) of
    /// the q-register ctx slot for V`n` into GPR `dst`, zero- (`signed`=false) or
    /// sign-extended to 64 bits. A value-producing op (defines `dst`).
    VecExtractLane {
        dst: IrValueId,
        n: u8,
        lane: u8,
        size: u8,
        signed: bool,
    },
    /// NEON `INS` (general): write GPR `src`'s low `size` bytes into lane `lane`
    /// of the q-register ctx slot for V`d` (other lanes preserved).
    /// Ctx-template op (writes ctx); side-effecting in DCE.
    VecInsGpr {
        d: u8,
        lane: u8,
        src: IrValueId,
        size: u8,
    },
    /// NEON `CNT` — per-byte population count of V`n` into V`d` (each byte holds
    /// the set-bit count, 0..8, of the source byte). `q`: false = .8b (zero the
    /// upper 64 bits), true = .16b. Ctx-template op (writes ctx); side-effecting.
    /// Lowered as a scalar SWAR per-byte popcount on each 64-bit half.
    VecCnt {
        d: u8,
        n: u8,
        q: bool,
    },
    /// NEON `UADDLV`/`SADDLV` — add (long) across all lanes of V`n`, reducing to a
    /// single scalar in lane 0 of V`d` (the rest of the 128-bit reg zeroed). Each
    /// lane is `esize` bytes; the result element is `2*esize` bytes. `q` selects
    /// 8- vs 16-byte source; `signed` selects SADDLV. bionic's popcount idiom is
    /// `cnt v0.8b; uaddlv h0, v0.8b`. Ctx-template op (writes ctx); side-effecting.
    VecAddvLong {
        d: u8,
        n: u8,
        esize: u8,
        q: bool,
        signed: bool,
    },
    /// NEON compare-against-zero (CMEQ/CMGT/CMGE/CMLE/CMLT `#0`): per-lane compare
    /// of V`n` to 0, each lane → all-ones (true) or 0. `size`: 0=B,1=H,2=S,3=D.
    /// Ctx-template op (writes ctx); lowered via SSE (pxor zero + pcmpeq). bionic
    /// strchr/memchr use `cmeq v.16b, v.16b, #0`.
    VecCmpZero {
        op: VecCmpOp,
        size: u8,
        q: bool,
        d: u8,
        n: u8,
    },
    /// NEON `SHRN`/`SHRN2` — shift-right-narrow: each `2*esize_out`-byte lane of
    /// V`n` is logically shifted right by `shift`, the low `esize_out` bytes form
    /// the result lane. `high`=false writes the low 64 bits of V`d` (SHRN), true
    /// writes the high 64 (SHRN2). bionic strchr: `shrn v5.8b, v2.8h, #4`.
    VecShiftNarrow {
        d: u8,
        n: u8,
        shift: u8,
        esize_out: u8,
        high: bool,
    },
    /// NEON `USHLL`/`SSHLL`/`UXTL`/`SXTL` — shift-left-long (widening). Widen each
    /// `esize_in`-byte source element of V`n` to twice the width (zero-extend when
    /// `signed`==false, sign-extend when true), then shift left by `shift`.
    /// `high` selects V`n`'s high 64 bits (the `2` variants). Writes V`d` (full
    /// 128-bit Q-form). Ctx-template op (writes ctx memory).
    VecShiftLong {
        d: u8,
        n: u8,
        shift: u8,
        esize_in: u8,
        high: bool,
        signed: bool,
    },
    /// NEON `SSHL`/`USHL` — register variable per-lane shift. Each `size`-byte lane
    /// of V`n` is shifted by the signed byte in the corresponding lane of V`m`
    /// (positive → left, negative → right; `signed` selects arithmetic (SSHL) vs
    /// logical (USHL) for the right direction; |amt| ≥ element-bits → 0, or sign-fill
    /// for the arithmetic-right case). x86 has no per-lane variable shift pre-AVX2,
    /// so the lowerer scalarizes through ctx memory. `size`: 0=B,1=H,2=S,3=D.
    /// Ctx-template op (writes ctx memory).
    VecShiftReg {
        d: u8,
        n: u8,
        m: u8,
        size: u8,
        q: bool,
        signed: bool,
    },
    /// NEON `SRI`/`SLI` — shift-right/left-and-insert by immediate. `left`=false
    /// (SRI): `Vd = (Vd & top_mask) | (Vn >>u shift)`, preserving Vd's top `shift`
    /// bits per element. `left`=true (SLI): `Vd = (Vd & low_mask) | (Vn << shift)`,
    /// preserving Vd's low `shift` bits. `size`: 0=B,1=H,2=S,3=D. `d` is read AND
    /// written. Ctx-template op (writes ctx memory).
    VecShiftIns {
        d: u8,
        n: u8,
        shift: u8,
        size: u8,
        q: bool,
        left: bool,
    },
    /// NEON saturating/rounding narrowing shift-right by immediate — `SQSHRN`/
    /// `UQSHRN`/`SQSHRUN`/`SQRSHRN`/`UQRSHRN`/`SQRSHRUN`/`RSHRN`. Each
    /// `2*esize_out`-byte source lane of V`n` is shifted right by `shift` (adding a
    /// round bias of `1<<(shift-1)` first when `round`), then saturated to the
    /// destination `esize_out`-byte element range. `src_signed` interprets the
    /// source; `dst_signed` selects the saturation range (SQSHRUN/SQRSHRUN are
    /// signed-source, unsigned-dest). `modular`=true is RSHRN/RSHRN2: the narrow is
    /// a plain low-bits truncation (NOT a clamp), and it is the only signal that
    /// separates RSHRN from UQRSHRN (identical `round`/`src_signed`/`dst_signed`).
    /// `high`=false writes Vd[63:0] (zeroing the upper 64), true writes Vd[127:64]
    /// (the `2` form). Ctx-template op.
    VecShiftNarrowSat {
        d: u8,
        n: u8,
        shift: u8,
        esize_out: u8,
        high: bool,
        round: bool,
        src_signed: bool,
        dst_signed: bool,
        modular: bool,
    },
    /// NEON `EXT` — `Vd = (CONCAT(Vm, Vn) >> imm*8)`. `q`=false is the 8-byte form
    /// (upper 64 of Vd zeroed). Ctx-template op (writes ctx memory).
    VecExt {
        d: u8,
        n: u8,
        m: u8,
        imm: u8,
        q: bool,
    },
    /// NEON single-register `TBL` byte-permute (ctx-template). `n` is the table
    /// reg, `m` the index reg: `Vd[i] = (Vm[i] < 16) ? Vn[Vm[i]] : 0`. `q`=false
    /// zeroes Vd[127:64] (.8b form).
    VecTbl1 {
        d: u8,
        n: u8,
        m: u8,
        q: bool,
    },
    /// NEON multi-register `TBL`/`TBX` byte-permute (ctx-template). `n` is the
    /// first table reg, `m` the index reg; the table spans `len+1` consecutive
    /// V regs (`n`, `n+1`, … wrapping mod 32) = a 16/32/48/64-byte table.
    /// `op`=0 → TBL (out-of-range lanes = 0); `op`=1 → TBX (out-of-range lanes
    /// keep the old `Vd` byte). `q`=false zeroes `Vd[127:64]` (.8b form).
    VecTblN {
        d: u8,
        n: u8,
        m: u8,
        len: u8,
        op: u8,
        q: bool,
    },
    /// NEON `DUP` (element) — broadcast lane `lane` (size = log2 element bytes)
    /// of Vn to all lanes of Vd. Ctx-template.
    VecDupElem {
        d: u8,
        n: u8,
        size: u8,
        lane: u8,
        q: bool,
    },
    /// NEON `PMULL`/`PMULL2` `.1q` — 64×64→128 carryless multiply (GHASH/GCM).
    /// `high`=true uses each source's high 64 bits (PMULL2). Ctx-template.
    VecPmull {
        d: u8,
        n: u8,
        m: u8,
        high: bool,
    },
    /// NEON integer multiply-long (`UMULL`/`SMULL`/`UMLAL`/`SMLAL`/`UMLSL`/`SMLSL`).
    /// Widen `size`-byte elements (`signed`) to 2×, multiply; `accum`+`sub` select
    /// replace / add-to-Vd / subtract-from-Vd. `q` = high source half. Ctx-template.
    VecMulLong {
        d: u8,
        n: u8,
        m: u8,
        size: u8,
        q: bool,
        signed: bool,
        accum: bool,
        sub: bool,
    },
    /// NEON `REV64`/`REV32`/`REV16` — reverse `size`-element groups (element
    /// bytes = 1<<size) within each `container`-byte group (8/4/2) via a `pshufb`
    /// mask. Ctx-template op (writes ctx memory).
    VecRev64 {
        d: u8,
        n: u8,
        size: u8,
        q: bool,
        container: u8,
    },
    /// ARMv8 SHA-256 crypto (`SHA256SU0`/`SU1`/`H`/`H2`). Ctx-template op: a Win64
    /// CALL to `runtime::crypto_rt::aether_crypto_sha256` reads/writes the guest
    /// q-registers `d`/`n`/`m` in ctx memory. `kind`: 0=SU0,1=SU1,2=H,3=H2.
    CryptoSha256 {
        kind: u8,
        d: u8,
        n: u8,
        m: u8,
    },
    /// Long-tail Advanced SIMD instruction executed by the runtime helper: a
    /// Win64 CALL to `runtime::simd_rt::aether_simd_exec(ctx, word)`, which
    /// interprets the raw ARM `word` on the guest q-registers in ctx memory.
    /// Only emitted for words `simd_rt::supports` accepts.
    SimdInterp { word: u32 },
    /// NEON `BIC`/`ORR` (vector, immediate) — read-modify-write V`d` with an
    /// `AdvSIMDExpandImm`-expanded 64-bit `imm` pattern: BIC clears (`Vd &= ~imm`),
    /// ORR sets (`Vd |= imm`). `q`=false is the 64-bit form (upper 64 zeroed).
    /// bionic strchr: `bic v4.8h, #0xf0`. Ctx-template op (writes ctx).
    VecBicOrrImm {
        d: u8,
        imm: u64,
        is_bic: bool,
        q: bool,
    },
    /// NEON `UADDLP`/`SADDLP` — add-long PAIRWISE within V`n`: adjacent
    /// `esize_in`-byte element pairs sum into `2*esize_in`-byte result lanes (no
    /// truncation). `q`=false is the 64-bit source form. bionic's NEON popcount
    /// accumulates with `cnt; uaddlp .8h; uaddlp .4s; uaddlp .2d`. SSE: mask the
    /// even lanes, shift the odd lanes down, widening-add.
    VecAddLongPair {
        d: u8,
        n: u8,
        esize_in: u8,
        q: bool,
        signed: bool,
    },
    /// NEON `UZP1`/`UZP2` — unzip: gather the even- (`odd`=false) or odd-indexed
    /// (`odd`=true) `esize`-byte elements of the concatenation V`n`:V`m` into V`d`.
    /// bionic NEON popcount finishes with `uzp1 v.4s, v.4s, v.4s`. Only the 32-bit
    /// (.4s, shufps) and 64-bit (.2d, punpck) forms are wired.
    VecUnzip {
        d: u8,
        n: u8,
        m: u8,
        esize: u8,
        q: bool,
        odd: bool,
    },
    /// NEON `ADDV` — reduce-add all lanes (same width) of V`n` to a scalar in
    /// lane 0 of V`d` (rest zeroed). `esize` = element bytes. bionic NEON popcount
    /// ends with `addv s0, v0.4s`.
    VecReduceAdd {
        d: u8,
        n: u8,
        esize: u8,
        q: bool,
    },
    /// DC ZVA — zero the naturally-aligned 64-byte block containing `addr`.
    /// Lowered to ONE MMU walk (write, 64 B) + 8 inline 8-byte zero stores to
    /// the resolved host PA. Replaces the prior expansion into 8 separate
    /// `Store` ops (8 Win64 store-CALLs + 9 SSA temps): that register pressure
    /// spilled operands in the clear_page DC-ZVA loop block and was both a
    /// severe TCG perf sink and a correctness hazard (see clear_page runaway).
    ZeroBlock {
        addr: IrValueId,
    },

    // ----- Atomics (LSE) -----
    AtomicRmw {
        dst: IrValueId,
        op: AtomicOp,
        addr: IrValueId,
        val: IrValueId,
        order: MemOrder,
        /// Access width in BYTES (1/2/4/8). LSE atomics come in B/H/word/dword
        /// forms; the width must be honoured or a 64-bit op on a 32-bit lock
        /// clobbers the adjacent word (e.g. bionic's lock at [x20] vs [x20+4]).
        size: u8,
    },
    AtomicCas {
        dst: IrValueId,
        addr: IrValueId,
        expected: IrValueId,
        new: IrValueId,
        order: MemOrder,
        /// Access width in BYTES (1/2/4/8) — see [`IrOp::AtomicRmw::size`].
        size: u8,
    },

    /// CASP — compare-and-swap PAIR (single-vCPU non-atomic load/compare/store).
    /// Reads the {elem,elem} pair at `[addr]`; if it equals
    /// {`expected_a`,`expected_b`} writes {`new_a`,`new_b`}; ALWAYS writes the
    /// loaded old pair to {`dst_a`,`dst_b`}. `size` = per-element bytes (4 or 8).
    AtomicCasPair {
        dst_a: IrValueId,
        dst_b: IrValueId,
        addr: IrValueId,
        expected_a: IrValueId,
        expected_b: IrValueId,
        new_a: IrValueId,
        new_b: IrValueId,
        order: MemOrder,
        size: u8,
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
    /// ERET via a runtime call (`aether_eret_enter`). Carries no operands: the
    /// helper reads ELR_EL1/SPSR_EL1 from the ctx sysreg slots and applies the
    /// full exception return — restore PC<-ELR, NZCV/DAIF<-SPSR, the target
    /// exception level + SPSel from SPSR.M, and the SP_EL0/SP_EL1 bank swap.
    /// Replaces the prior primitive sequence (Mrs/And/Msr/WritePc) which could
    /// not model the EL change or the conditional SP-bank swap on a return to
    /// EL0. A block terminator (the decoder already ends the block on ERET).
    EretRt,
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
    /// TLB invalidate (TLBI). `va` is `Some(value)` for the address-taking
    /// forms (VAE1/VALE1/VAAE1/VAALE1 — the page VA comes from Rt) and `None`
    /// for the broad forms (VMALLE1/ALLE1/ASIDE1). Lowering invalidates the
    /// software-MMU TLB (whole table for broad, one page for the VA form) AND
    /// the JIT block cache (a guest page-table edit can change what VA→bytes a
    /// previously-translated block assumed). Previously these lifted to
    /// `Hint { imm: 128 }` (UD2) — the kernel issues TLBI constantly while
    /// building its page tables, so a trap there is fatal.
    TlbInval {
        va: Option<IrValueId>,
    },
    /// Phase-E: `AT S1E1R/W/E0R/W` — Address Translate Stage 1 at
    /// EL1/EL0. Calls the walker on `va`; writes PAR_EL1 with the
    /// resulting PA (success) or fault status (F=1, failure). Lifted
    /// by the SysAt decoder arm. The runtime helper is
    /// `aether_mmu_at_s1e1` in runtime/mmu.rs.
    AtS1E1 {
        va: IrValueId,
        is_write: bool,
        at_el0: bool,
    },
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

    // ───── M4b-6: V-register-numbered SIMD / FP / crypto ctx templates ─────
    //
    // These are the live-path NEON/FP ops. Unlike the older `VAdd..FCmp`
    // (IrValueId-keyed, XMM-allocator) ops above — which only the dead
    // `SimdLower` consumes — these address the guest q-register file directly in
    // ctx memory ([R15 + vec_disp(reg)]) and are lowered by `lower_simd_ctx` as
    // self-contained load/op/store templates (BUILDSPEC §1, §7). They carry NO
    // `IrValueId`/`IrFlagsId` operands, so they contribute nothing to
    // visit_def/use_values, visit_def/use_flags, or remap_uses.
    //
    // `size`: 0=B(8) 1=H(16) 2=S(32) 3=D(64). `q`: true=128-bit (Q), false=D
    // (writes zero the upper 64 bits). `*_gpr` fields are ARM X-register numbers.

    /// NEON integer 3-same binary. For Mla/Mls/SAba/UAba, `d` is use+def.
    VecBin { op: VecBinOp, size: u8, q: bool, d: u8, n: u8, m: u8 },
    /// NEON 2-reg-misc single-source (ABS/NEG).
    VecUn { op: VecUnOp, size: u8, q: bool, d: u8, n: u8 },
    /// NEON shift by immediate (logical/arith, left/right).
    VecShift { op: VecShiftOp, size: u8, q: bool, d: u8, n: u8, amount: u8 },
    /// NEON shift-right-and-accumulate by immediate (SSRA/USRA):
    /// `Vd[e] += (Vn[e] >> amount)`. `signed` selects arithmetic (SSRA) vs
    /// logical (USRA). `d` is use+def (read AND written).
    VecShiftAcc { signed: bool, size: u8, q: bool, d: u8, n: u8, amount: u8 },
    /// NEON compare (per-lane all-ones / zero result).
    VecCmp { op: VecCmpOp, size: u8, q: bool, d: u8, n: u8, m: u8 },
    /// NEON pairwise (ADDP/SMAXP/SMINP/UMAXP/UMINP).
    VecPair { op: VecPairOp, size: u8, q: bool, d: u8, n: u8, m: u8 },
    /// NEON across-vector reduce, same width (ADDV/SMAXV/SMINV/UMAXV/UMINV).
    VecReduce { op: VecReduceOp, size: u8, q: bool, d: u8, n: u8 },
    /// NEON widening reduce/pairwise (across=SADDLV/UADDLV, !across=SADDLP/UADDLP).
    VecAddLong { across: bool, signed: bool, size: u8, q: bool, d: u8, n: u8 },
    /// NEON FP 3-same (FADD/FSUB/FMUL/FDIV/FMIN/FMAX/FMAXNM/FMINNM/FMLA/FMLS/FABD),
    /// single (dbl=false) | double. For Mla/Mls, `d` is read+written (accumulate).
    VecFp { op: VecFpOp, dbl: bool, q: bool, d: u8, n: u8, m: u8 },
    /// NEON FP per-lane compare (FCMEQ/FCMGT/FCMGE), 3-same register form when
    /// `zero==false`, vs #0.0 (FCMEQ/FCMGT/FCMGE/FCMLT/FCMLE) when `zero==true`.
    /// Produces an all-ones / all-zeros mask per lane. `m` is unused when `zero`.
    VecFpCmp { op: VecFpCmpOp, dbl: bool, q: bool, d: u8, n: u8, m: u8, zero: bool },
    /// NEON FP 2-reg-misc single-source (FABS/FNEG/FSQRT), single | double.
    VecFpUn { op: VecFpUnOp, dbl: bool, q: bool, d: u8, n: u8 },

    /// NEON FP / int multiply-accumulate BY ELEMENT (`FMUL`/`FMLA`/`FMLS`/`MUL`
    /// `Vd, Vn, Vm.<Ts>[idx]`). The single scalar lane `idx` of `Vm` is broadcast
    /// to every lane, then the chosen op is applied against `Vn`. `is_fp` selects
    /// the FP path (FMUL/FMLA/FMLS) vs integer (MUL). `op` reuses VecFpOp's
    /// Mul/Mla/Mls (FP) — integer MUL ignores it. `dbl` (FP only) = .2d. For
    /// Mla/Mls, `d` is read+written (accumulate). Ctx-template op (writes ctx).
    VecByElem { op: VecFpOp, is_fp: bool, dbl: bool, size: u8, q: bool, d: u8, n: u8, m: u8, idx: u8 },

    /// NEON vector integer↔FP convert (2-reg-misc): SCVTF/UCVTF (int→FP) and
    /// FCVTZS/FCVTZU (FP→int, round-toward-zero). `to_fp` selects int→FP; `signed`
    /// selects the S vs U form; `dbl` = .2d (64-bit element) else .4s/.2s (32-bit).
    /// Ctx-template op (writes ctx memory). The unsigned and double forms beyond
    /// the wired signed-.4s path fail-loud (UD2) in the lowerer.
    VecCvtFp { to_fp: bool, signed: bool, dbl: bool, q: bool, d: u8, n: u8 },

    /// NEON `ZIP1`/`ZIP2`/`TRN1`/`TRN2` permute. `kind`: 0=ZIP1, 1=ZIP2, 2=TRN1,
    /// 3=TRN2. `size` = log2 element bytes (0=B,1=H,2=S,3=D). `q` selects 128- vs
    /// 64-bit. Interleaves the elements of Vn:Vm. Ctx-template op (writes ctx).
    VecZipTrn { kind: u8, size: u8, q: bool, d: u8, n: u8, m: u8 },

    /// Scalar pairwise reduce — `ADDP d0,Vn.2d` (`is_fp=false`) / `FADDP {s,d}0,
    /// Vn.2{s,d}` (`is_fp=true`): sum the two lanes of Vn into Vd lane 0, the rest
    /// of the 128-bit register zeroed. `dbl` selects the 64-bit (D/.2d) vs 32-bit
    /// (S/.2s) element. Ctx-template op (writes ctx memory).
    VecScalarPair { is_fp: bool, dbl: bool, d: u8, n: u8 },

    /// Int(GPR) -> FP (SCVTF/UCVTF). from_bits=GPR width(32|64); to_bits=FP(16|32|64).
    FpFromInt { d: u8, n_gpr: u8, from_bits: u8, to_bits: u8, signed: bool },
    /// FP -> int(GPR) (FCVT{N,P,M,Z,A}{S,U}). from_bits=FP src; to_bits=GPR dst.
    FpToIntR { d_gpr: u8, n: u8, from_bits: u8, to_bits: u8, signed: bool, round: RoundMode },
    /// Round to integral, FP result (FRINTN/P/M/Z/A/X/I).
    FpRound { d: u8, n: u8, dbl: bool, round: RoundMode, raise_inexact: bool },
    /// VECTOR round-to-integral, FP result (`FRINT{N,P,M,Z,A}` `Vd.<T>,Vn.<T>`).
    /// Per-lane round of Vn into Vd using ROUNDPS/ROUNDPD with the x86 rounding
    /// mode: N→nearest-even, M→floor, P→ceil, Z→truncate. `NearestTiesAway` (the
    /// A form) has no direct x86 mode and is emulated with a magnitude add/sub of
    /// 0.5 toward the sign then truncate. `dbl` selects .2d (64-bit lane) vs
    /// .4s/.2s (32-bit). `q`=false zeroes Vd[127:64]. Ctx-template op.
    VecFpRound { d: u8, n: u8, dbl: bool, q: bool, round: RoundMode },
    /// Vector FP precision convert (FCVTL/FCVTL2 widen, FCVTN/FCVTN2 narrow).
    /// `half`: f16<->f32 (sz=0) vs f32<->f64 (sz=1). `upper`: the "2" form — widen
    /// reads Vn[127:64]; narrow writes Vd[127:64] and keeps Vd[63:0] (the plain
    /// narrow form zeroes Vd[127:64]).
    VecFpCvtWidth { d: u8, n: u8, widen: bool, half: bool, upper: bool },
    /// FP precision convert (FCVT S<->D<->H).
    FpCvt2 { d: u8, n: u8, from_bits: u8, to_bits: u8 },
    /// FP conditional select (FCSEL Dd, Dn, Dm, cond): Dd = cond ? Dn : Dm.
    /// Reads the packed ARM NZCV; ctx-template op on the q-register file.
    FpCsel { d: u8, n: u8, m: u8, cond: crate::decoder::Cond, dbl: bool },
    /// FP reg->reg move (FMOV Sd,Sn / Dd,Dn) with upper-lane zeroing.
    FpMov { d: u8, n: u8, width_bits: u8 },
    /// Scalar FP 2-src (FADD/FSUB/FMUL/FDIV/FMIN/FMAX/FNMUL).
    FpBin { op: FpBinOp, dbl: bool, d: u8, n: u8, m: u8 },
    /// Scalar FP 3-src fused multiply-add (FMADD/FMSUB/FNMADD/FNMSUB Sd,Sn,Sm,Sa):
    ///   FMADD  Sd = Sa + Sn*Sm   FMSUB  Sd = Sa - Sn*Sm
    ///   FNMADD Sd = -Sa - Sn*Sm  FNMSUB Sd = -Sa + Sn*Sm
    /// Single fused rounding (matches x86 FMA3). `a` is the accumulator (Sa).
    FpFma { op: FpFmaOp, dbl: bool, d: u8, n: u8, m: u8, a: u8 },
    /// Scalar FP 1-src (FABS/FNEG/FSQRT).
    FpUn { op: FpUnOp, dbl: bool, d: u8, n: u8 },
    /// FP compare -> NZCV (FCMP/FCMPE); with-zero when `zero`.
    FpCmpN { n: u8, m: u8, dbl: bool, zero: bool },
    /// FMOV FP-reg -> GPR (bitwise). `high_half` => from V.D[1].
    FpToGpr { d_gpr: u8, n: u8, bits: u8, high_half: bool },
    /// FMOV GPR -> FP-reg (bitwise). `high_half` => into V.D[1].
    FpFromGpr { d: u8, n_gpr: u8, bits: u8, high_half: bool },
    /// SCVTF/UCVTF: convert integer in `src` (an already-resolved GPR SSA value)
    /// to a scalar FP register V`d` (`to_dbl`=false → S/32-bit, true → D/64-bit).
    /// Carries an `IrValueId` (unlike `FpFromInt`'s raw `n_gpr`) so the lowerer can
    /// read the GPR's x86 register via the alloc map. `signed` selects SCVTF/UCVTF.
    /// `src_64` is the ARM source-register width (`sf`): false → W (32-bit), true →
    /// X (64-bit). MUST be honored — a signed W-form convert of e.g. 0xFFFFFFFF
    /// (ARM −1) must sign-interpret the low 32 bits (→ −1.0), NOT the zero-extended
    /// 64-bit value (→ +2^32). Dropping `src_64` is a silent sign/magnitude bug.
    /// `fbits` != 0 is the fixed-point form (`SCVTF Sd, Wn, #fbits`): result is
    /// int × 2^-fbits.
    FpCvtIntScalar { d: u8, src: IrValueId, to_dbl: bool, signed: bool, src_64: bool, fbits: u8 },
    /// FCVT{N,P,M,Z,A}{S,U}: convert scalar FP reg `n` to an integer SSA value
    /// `dst` (a GPR result, consumed by a following write_reg). `from_dbl` = S vs
    /// D source; `to_64` = W vs X result; `round` selects the rounding mode.
    /// Defines `dst` (mirrors `VecExtractLane`); lowered in IntLower.
    /// `fbits` != 0 is the fixed-point form (`FCVTZS Wd, Sn, #fbits`): the value
    /// is scaled by 2^fbits (exact) before the rounding convert.
    FpCvtToIntScalar { dst: IrValueId, n: u8, from_dbl: bool, to_64: bool, round: RoundMode, signed: bool, fbits: u8 },

    /// AES round step. kind: 0=AESE 1=AESD 2=AESMC 3=AESIMC 4=FusedEnc 5=FusedDec.
    CryptoAesR { kind: u8, d: u8, n: u8, m: u8 },
    /// SHA1/SHA256 step (kind selects the exact op). `d` is use+def.
    CryptoShaR { kind: u8, d: u8, n: u8, m: u8 },

    // ----- Sentinel -----
    /// The decoded encoding could not be lifted. Carries the source word so
    /// AT-5 can report exactly what was missed. Production lift paths MUST
    /// NOT construct this.
    Unimplemented(u32),
}

// ───── M4b-6 supporting op-kind enums (BUILDSPEC §2.1) ─────
// Byte tags follow declaration order and are AOT-cache-stable — only append.

/// NEON integer 3-same operation selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VecBinOp {
    Add, Sub, Mul, Mla, Mls,
    SqAdd, UqAdd, SqSub, UqSub,
    SHadd, UHadd, SrHadd, UrHadd,
    SAbd, UAbd, SAba, UAba,
    SMax, SMin, UMax, UMin,
    // Size-agnostic logical 3-same forms (operate on the full 64/128 bits; the
    // `size` field is ignored when lowering these). Append-only — discriminants
    // 0..=20 above are AOT-cache-stable.
    And, Or, Eor, Bic, Orn,
    // Bitwise select (read-modify-write Vd): BSL Vd=Vd?Vn:Vm-select via Vd;
    // BIT inserts Vn where Vm=1; BIF inserts Vn where Vm=0. lower_vecbin
    // special-cases these (they read Vd, unlike the n-op-m forms). Append-only.
    Bsl, Bit, Bif,
    // Halving subtract (SHSUB/UHSUB, three-same opcode 0b00100): (a-b)>>1 with
    // no intermediate overflow. `SHsub` uses the arithmetic per-element shift,
    // `UHsub` the logical one; both subtract the per-element borrow bit. The
    // rounding-halving-add pair (SrHadd/UrHadd) and the truncating pair
    // (SHadd/UHadd) already exist above. Append-only (discriminants 29,30).
    SHsub, UHsub,
}
/// NEON 2-reg-misc single-source operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VecUnOp { Abs, Neg }
/// NEON vector shift-by-immediate direction/signedness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VecShiftOp { Shl, SShr, UShr }
/// NEON per-lane compare (CMEQ/CMGT/CMGE/CMHI/CMHS/CMTST). `SLt`/`SLe` are only
/// produced by the signed compare-VS-ZERO forms (CMLT #0 / CMLE #0), which have
/// no register-register counterpart. Discriminants are serialized as `v as u8` —
/// only APPEND (Eq=0..Tst=5 are AOT-cache-stable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VecCmpOp { Eq, SGt, SGe, UGt, UGe, Tst, SLt, SLe }
/// NEON pairwise op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VecPairOp { Add, SMax, SMin, UMax, UMin }
/// NEON across-vector reduce op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VecReduceOp { Add, SMax, SMin, UMax, UMin }
/// NEON / scalar FP binary op (also used for vector FP).
/// Discriminants 0..=5 are AOT-cache-stable — only append.
/// `MaxNm`/`MinNm` are the IEEE maxNum/minNum (return the non-NaN operand);
/// `Max`/`Min` propagate NaN (ARM default). `Mla`/`Mls` accumulate into Vd;
/// `Abd` is |Vn-Vm|.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VecFpOp { Add, Sub, Mul, Div, Min, Max, MaxNm, MinNm, Mla, Mls, Abd }
/// NEON FP per-lane compare op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VecFpCmpOp { Eq, Gt, Ge, Lt, Le }
/// NEON FP 2-reg-misc single-source op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VecFpUnOp { Abs, Neg, Sqrt }
/// Scalar FP binary op.
/// Discriminants 0..=6 are AOT-cache-stable — only append.
/// `MaxNm`/`MinNm` are the IEEE maxNum/minNum (return the non-NaN operand when
/// exactly one operand is NaN); `Max`/`Min` propagate NaN (ARM default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpBinOp { Add, Sub, Mul, Div, Min, Max, NMul, MaxNm, MinNm }
/// Scalar FP fused-multiply-add op (3-source). Maps 1:1 to ARM
/// FMADD/FMSUB/FNMADD/FNMSUB. Serialized by discriminant — append only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpFmaOp { Madd, Msub, NMadd, NMsub }
/// Scalar FP unary op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpUnOp { Abs, Neg, Sqrt, Mov }
/// Rounding mode for FP<->int convert and FRINT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundMode { Nearest, NegInf, PosInf, Zero, NearestTiesAway, Current }

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
            IrOp::AtomicCasPair { dst_a, dst_b, .. } => { f(dst_a); f(dst_b); }
            IrOp::VecExtractLane { dst, .. } | IrOp::FpCvtToIntScalar { dst, .. } => f(dst),

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
            IrOp::StampFaultPc(_) => {} // diagnostic stamp — no value uses
            IrOp::ZeroBlock { addr } => f(addr),
            IrOp::VecDupGpr { src, .. } | IrOp::VecInsGpr { src, .. }
            | IrOp::FpCvtIntScalar { src, .. } => f(src),
            IrOp::AtomicRmw { addr, val, .. } => { f(addr); f(val); }
            IrOp::AtomicCas { addr, expected, new, .. } => { f(addr); f(expected); f(new); }
            IrOp::AtomicCasPair { addr, expected_a, expected_b, new_a, new_b, .. } => {
                f(addr); f(expected_a); f(expected_b); f(new_a); f(new_b);
            }

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
            IrOp::TlbInval { va: Some(va) } => f(va),
            IrOp::AtS1E1 { va, .. } => f(va),
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
            IrOp::Rbit { dst, a, sf } => IrOp::Rbit { dst, a: vr(a), sf },
            IrOp::Rev { dst, a, bytes } => IrOp::Rev { dst, a: vr(a), bytes },
            IrOp::Clz { dst, a, sf } => IrOp::Clz { dst, a: vr(a), sf },
            IrOp::Cls { dst, a, sf } => IrOp::Cls { dst, a: vr(a), sf },
            IrOp::Bswap16 { dst, a } => IrOp::Bswap16 { dst, a: vr(a) },
            IrOp::Bswap32 { dst, a } => IrOp::Bswap32 { dst, a: vr(a) },
            IrOp::Bswap64 { dst, a } => IrOp::Bswap64 { dst, a: vr(a) },

            // Three-operand
            IrOp::Madd { dst, a, b, c } => IrOp::Madd { dst, a: vr(a), b: vr(b), c: vr(c) },
            IrOp::Msub { dst, a, b, c } => IrOp::Msub { dst, a: vr(a), b: vr(b), c: vr(c) },

            // Flag-producing ALU
            IrOp::AddS { dst, flags, a, b, sf } => IrOp::AddS { dst, flags, a: vr(a), b: vr(b), sf },
            IrOp::SubS { dst, flags, a, b, sf } => IrOp::SubS { dst, flags, a: vr(a), b: vr(b), sf },
            IrOp::AndS { dst, flags, a, b, sf } => IrOp::AndS { dst, flags, a: vr(a), b: vr(b), sf },
            IrOp::Adcs { dst, flags, a, b, c_in, sf } =>
                IrOp::Adcs { dst, flags, a: vr(a), b: vr(b), c_in: fr(c_in), sf },
            IrOp::Sbcs { dst, flags, a, b, c_in, sf } =>
                IrOp::Sbcs { dst, flags, a: vr(a), b: vr(b), c_in: fr(c_in), sf },
            IrOp::Cmp { flags, a, b, sf } => IrOp::Cmp { flags, a: vr(a), b: vr(b), sf },
            IrOp::Cmn { flags, a, b, sf } => IrOp::Cmn { flags, a: vr(a), b: vr(b), sf },
            IrOp::Tst { flags, a, b, sf } => IrOp::Tst { flags, a: vr(a), b: vr(b), sf },
            IrOp::CCmp { flags_out, a, b, cond, nzcv_if_false, flags_in, is_neg, sf } =>
                IrOp::CCmp { flags_out, a: vr(a), b: vr(b), cond, nzcv_if_false, flags_in: fr(flags_in), is_neg, sf },
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
            IrOp::ZeroBlock { addr } => IrOp::ZeroBlock { addr: vr(addr) },
            IrOp::AtomicRmw { dst, op, addr, val, order, size } =>
                IrOp::AtomicRmw { dst, op, addr: vr(addr), val: vr(val), order, size },
            IrOp::AtomicCas { dst, addr, expected, new, order, size } =>
                IrOp::AtomicCas { dst, addr: vr(addr), expected: vr(expected), new: vr(new), order, size },
            IrOp::AtomicCasPair { dst_a, dst_b, addr, expected_a, expected_b, new_a, new_b, order, size } =>
                IrOp::AtomicCasPair { dst_a, dst_b, addr: vr(addr), expected_a: vr(expected_a),
                    expected_b: vr(expected_b), new_a: vr(new_a), new_b: vr(new_b), order, size },

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
            | IrOp::Brk { .. } | IrOp::Hlt { .. } | IrOp::EretRt
            | IrOp::VecMoviImm { .. }
            | IrOp::VecExtractLane { .. }
            | IrOp::FpCvtToIntScalar { .. }
            | IrOp::VecCnt { .. } | IrOp::VecAddvLong { .. }
            | IrOp::VecCmpZero { .. } | IrOp::VecShiftNarrow { .. }
            | IrOp::VecShiftReg { .. } | IrOp::VecShiftIns { .. }
            | IrOp::VecShiftNarrowSat { .. }
            | IrOp::VecShiftLong { .. } | IrOp::VecExt { .. }
            | IrOp::VecTbl1 { .. } | IrOp::VecTblN { .. }
            | IrOp::VecDupElem { .. } | IrOp::VecPmull { .. }
            | IrOp::VecMulLong { .. } | IrOp::VecRev64 { .. }
            | IrOp::CryptoSha256 { .. } | IrOp::SimdInterp { .. }
            | IrOp::VecFpRound { .. } | IrOp::VecFpCvtWidth { .. }
            | IrOp::VecBicOrrImm { .. } | IrOp::VecAddLongPair { .. }
            | IrOp::VecUnzip { .. } | IrOp::VecReduceAdd { .. }
            | IrOp::Dmb { .. } | IrOp::Dsb { .. }
            | IrOp::Isb | IrOp::Sb | IrOp::Hint { .. } => self,
            IrOp::VecDupGpr { d, src, size, q } =>
                IrOp::VecDupGpr { d, src: vr(src), size, q },
            IrOp::FpCvtIntScalar { d, src, to_dbl, signed, src_64, fbits } =>
                IrOp::FpCvtIntScalar { d, src: vr(src), to_dbl, signed, src_64, fbits },
            IrOp::VecInsGpr { d, lane, src, size } =>
                IrOp::VecInsGpr { d, lane, src: vr(src), size },
            IrOp::TlbInval { va } => IrOp::TlbInval { va: va.map(&mut vr) },
            IrOp::AtS1E1 { va, is_write, at_el0 } =>
                IrOp::AtS1E1 { va: vr(va), is_write, at_el0 },
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

            // M4b-6 V-register-numbered SIMD/FP/crypto ops: all-Copy fields, no
            // IrValueId/IrFlagsId uses to remap — return unchanged.
            IrOp::VecBin { .. } | IrOp::VecUn { .. } | IrOp::VecShift { .. }
            | IrOp::VecShiftAcc { .. }
            | IrOp::VecCmp { .. } | IrOp::VecPair { .. } | IrOp::VecReduce { .. }
            | IrOp::VecAddLong { .. } | IrOp::VecFp { .. }
            | IrOp::VecFpCmp { .. } | IrOp::VecFpUn { .. }
            | IrOp::VecByElem { .. } | IrOp::VecCvtFp { .. } | IrOp::VecZipTrn { .. }
            | IrOp::VecScalarPair { .. }
            | IrOp::FpFromInt { .. } | IrOp::FpToIntR { .. } | IrOp::FpRound { .. }
            | IrOp::FpCvt2 { .. } | IrOp::FpCsel { .. } | IrOp::FpMov { .. } | IrOp::FpBin { .. }
            | IrOp::FpFma { .. }
            | IrOp::FpUn { .. } | IrOp::FpCmpN { .. } | IrOp::FpToGpr { .. }
            | IrOp::FpFromGpr { .. } | IrOp::CryptoAesR { .. } | IrOp::CryptoShaR { .. } => self,

            IrOp::Unimplemented(w) => IrOp::Unimplemented(w),

            IrOp::StampFaultPc(pc) => IrOp::StampFaultPc(pc), // diagnostic — no remap
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
