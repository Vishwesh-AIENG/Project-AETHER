//! A64 instruction decoder.
//!
//! Entry point: [`decode_instruction`]. Dispatches on the top-level `op0`
//! field (bits [28:25] of the instruction word) per ARM ARM DDI 0487J §C4.1
//! to one of eight family decoders.
//!
//! Phase A status: skeleton. Family modules return [`DecodeErr::Unimplemented`]
//! until filled in.

pub mod top_level;

pub mod bits;
pub mod branch_sys;
pub mod dp_immediate;
pub mod dp_register;
pub mod dp_simd_fp;
pub mod load_store;
pub mod sysreg;

/// 5-bit register index (`x0`..`x30`, plus encoding-31 = `xzr`/`sp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Reg(pub u8);

impl Reg {
    pub const XZR: Reg = Reg(31);
    pub const SP: Reg = Reg(31); // disambiguated by instruction context

    pub const fn idx(self) -> u8 {
        self.0
    }
    pub const fn is_zr_or_sp(self) -> bool {
        self.0 == 31
    }
}

/// 5-bit vector register index (`v0`..`v31`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct VReg(pub u8);

/// ARM condition code (4 bits, bits [3:0] of `B.cond` / `CSEL` / etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Cond {
    Eq = 0x0,
    Ne = 0x1,
    Cs = 0x2,
    Cc = 0x3,
    Mi = 0x4,
    Pl = 0x5,
    Vs = 0x6,
    Vc = 0x7,
    Hi = 0x8,
    Ls = 0x9,
    Ge = 0xA,
    Lt = 0xB,
    Gt = 0xC,
    Le = 0xD,
    Al = 0xE,
    Nv = 0xF,
}

impl Cond {
    pub const fn from_bits(b: u8) -> Self {
        // SAFETY: caller masks to 4 bits; #[deny(unsafe_code)] forbids transmute,
        // so use an explicit match.
        match b & 0xF {
            0x0 => Cond::Eq,
            0x1 => Cond::Ne,
            0x2 => Cond::Cs,
            0x3 => Cond::Cc,
            0x4 => Cond::Mi,
            0x5 => Cond::Pl,
            0x6 => Cond::Vs,
            0x7 => Cond::Vc,
            0x8 => Cond::Hi,
            0x9 => Cond::Ls,
            0xA => Cond::Ge,
            0xB => Cond::Lt,
            0xC => Cond::Gt,
            0xD => Cond::Le,
            0xE => Cond::Al,
            _ => Cond::Nv,
        }
    }
}

/// Shift kind for register-form data-processing ops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShiftKind {
    Lsl,
    Lsr,
    Asr,
    Ror,
}

/// Extend kind for `ADD (extended register)` and friends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendKind {
    Uxtb,
    Uxth,
    Uxtw,
    Uxtx,
    Sxtb,
    Sxth,
    Sxtw,
    Sxtx,
}

/// Memory addressing modes for loads/stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrMode {
    /// `[Xn, #imm]` (offset form, includes signed and unsigned variants).
    Offset { base: Reg, imm: i32 },
    /// `[Xn, #imm]!` (pre-indexed: base updated before access).
    PreIndex { base: Reg, imm: i32 },
    /// `[Xn], #imm` (post-indexed: base updated after access).
    PostIndex { base: Reg, imm: i32 },
    /// `[Xn, Xm, {ext|shift}]` (register-offset form).
    RegOffset {
        base: Reg,
        index: Reg,
        extend: ExtendKind,
        shift: u8,
    },
    /// PC-relative literal (LDR literal).
    Pcrel { offset: i32 },
}

/// Width of a load/store memory access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessSize {
    Byte,
    HalfWord,
    Word,
    DoubleWord,
    QuadWord, // 128-bit (NEON / pair)
}

/// Top-level decoded instruction. Variants are added family-by-family; the
/// `Unknown(word)` sentinel exists only to feed the AT-5 coverage report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedInsn {
    // ----- Phase A AT-1 (data-processing immediate, register, load/store) -----
    AddImm {
        sf: bool,
        rd: Reg,
        rn: Reg,
        imm: u16,
        shift_12: bool,
        set_flags: bool,
    },
    SubImm {
        sf: bool,
        rd: Reg,
        rn: Reg,
        imm: u16,
        shift_12: bool,
        set_flags: bool,
    },
    AndImm {
        sf: bool,
        rd: Reg,
        rn: Reg,
        imm: u64,
        set_flags: bool,
    },
    OrrImm {
        sf: bool,
        rd: Reg,
        rn: Reg,
        imm: u64,
    },
    EorImm {
        sf: bool,
        rd: Reg,
        rn: Reg,
        imm: u64,
    },
    MovWide {
        sf: bool,
        opc: u8, // 00=MOVN, 10=MOVZ, 11=MOVK
        hw: u8,
        rd: Reg,
        imm: u16,
    },
    Bfm {
        sf: bool,
        opc: u8, // 00=SBFM, 01=BFM, 10=UBFM
        rd: Reg,
        rn: Reg,
        immr: u8,
        imms: u8,
    },
    Adr {
        rd: Reg,
        imm: i32,
    },
    Adrp {
        rd: Reg,
        imm: i32, // 21-bit signed page offset
    },
    AddReg {
        sf: bool,
        rd: Reg,
        rn: Reg,
        rm: Reg,
        shift: ShiftKind,
        amount: u8,
        set_flags: bool,
    },
    /// ADCS / SBCS — add/subtract (with carry), flag-setting. The plain
    /// ADC/SBC (no-S) forms are intentionally not decoded here (rare; they
    /// would need a non-flag-setting carry IR op). `sub` selects SBCS.
    AdcSub {
        sf: bool,
        rd: Reg,
        rn: Reg,
        rm: Reg,
        sub: bool,
        /// `true` = ADCS/SBCS (write NZCV); `false` = ADC/SBC (NZCV preserved).
        /// `NGC`/`NGCS` are the `Rn==xzr` aliases of `SBC`/`SBCS`.
        set_flags: bool,
    },
    SubReg {
        sf: bool,
        rd: Reg,
        rn: Reg,
        rm: Reg,
        shift: ShiftKind,
        amount: u8,
        set_flags: bool,
    },
    LogicalReg {
        sf: bool,
        opc: u8, // 00=AND, 01=OR, 10=EOR, 11=ANDS
        rd: Reg,
        rn: Reg,
        rm: Reg,
        shift: ShiftKind,
        amount: u8,
        invert: bool,
    },
    Csel {
        sf: bool,
        rd: Reg,
        rn: Reg,
        rm: Reg,
        cond: Cond,
        op2: u8, // 00=CSEL, 01=CSINC, 10=CSINV, 11=CSNEG
    },
    Mul {
        sf: bool,
        rd: Reg,
        rn: Reg,
        rm: Reg,
        ra: Reg, // MADD / MSUB family; pure MUL has ra=XZR
        sub: bool,
    },
    /// SMADDL / UMADDL / SMSUBL / UMSUBL: 32×32→64 multiply, signed or
    /// unsigned, with optional add or subtract of a 64-bit accumulator.
    /// `Rn` and `Rm` are READ AS 32-BIT W-REGISTERS (low half only, the
    /// upper 32 of Xn/Xm is IGNORED). `Ra` is read as 64-bit. `Rd` is
    /// written 64-bit. The decoded form replaces what was previously a
    /// `Mul { sf=true }` — Phase E found that this lumping produced
    /// wrong results when the kernel's `__next_mem_range_rev` ran
    /// `umaddl x15, w28, w11, x9` with x28's upper half holding live
    /// bits, because reading as Xn polluted the multiply.
    MulLong {
        rd: Reg,
        rn: Reg,
        rm: Reg,
        ra: Reg, // XZR for the MUL alias (no accumulator)
        sub: bool,
        signed: bool,
    },
    /// SMULH / UMULH: 64×64 multiply, return the HIGH 64 bits of the
    /// 128-bit product. No accumulator. signed = SMULH.
    MulHigh {
        rd: Reg,
        rn: Reg,
        rm: Reg,
        signed: bool,
    },
    Div {
        sf: bool,
        rd: Reg,
        rn: Reg,
        rm: Reg,
        signed: bool,
    },
    Shift {
        sf: bool,
        rd: Reg,
        rn: Reg,
        rm: Reg,
        kind: ShiftKind,
    },
    Extr {
        sf: bool,
        rd: Reg,
        rn: Reg,
        rm: Reg,
        lsb: u8,
    },
    DataOp1Src {
        sf: bool,
        rd: Reg,
        rn: Reg,
        opcode: u8, // 0=RBIT 1=REV16 2=REV32 3=REV (sf-form) 4=CLZ 5=CLS
    },
    AddSubExtReg {
        sf: bool,
        rd: Reg,
        rn: Reg,
        rm: Reg,
        extend: ExtendKind,
        imm3: u8,
        sub: bool,
        set_flags: bool,
    },
    Ccmp {
        sf: bool,
        rn: Reg,
        rm_or_imm: u8,
        cond: Cond,
        nzcv: u8,
        is_neg: bool,    // CCMN vs CCMP
        is_imm: bool,    // CCMP (imm) vs CCMP (reg)
    },
    Crc32 {
        sf: bool,
        rd: Reg,
        rn: Reg,
        rm: Reg,
        sz: u8,         // 00=B 01=H 10=W 11=X
        castagnoli: bool,
    },

    // ----- Load/Store -----
    Ldr {
        rt: Reg,
        size: AccessSize,
        signed: bool,
        addr: AddrMode,
        /// `rt` names an FP/SIMD register (V=1 encoding: `LDR Sn/Dn/Qn`), not a
        /// GPR. The lift routes the loaded value into the ctx q-register file via
        /// `WriteFpr` instead of `write_reg`; without this an `ldr d1,[..]` would
        /// land in integer x1 and a later `mov x1,..` would silently clobber it.
        is_fp: bool,
        /// True = the destination is the full 64-bit Xt; false = the 32-bit Wt
        /// (bits [63:32] zeroed). Matters for SIGNED sub-word loads: `LDRSB Xt`
        /// (opc=0b10) sign-extends to 64, but `LDRSB Wt` (opc=0b11) sign-extends
        /// to 32 then zeroes [63:32]. Without this the W-form wrongly kept the
        /// sign bits in the upper 32. (Unsigned loads zero-extend either way.)
        is_64: bool,
    },
    Str {
        rt: Reg,
        size: AccessSize,
        addr: AddrMode,
        /// `rt` names an FP/SIMD register (V=1: `STR Sn/Dn/Qn`). The lift reads
        /// the value from the ctx q-register file via `ReadFpr`, not `read_reg`.
        is_fp: bool,
    },
    Ldp {
        rt1: Reg,
        rt2: Reg,
        sf: bool,
        signed: bool,
        addr: AddrMode,
    },
    Stp {
        rt1: Reg,
        rt2: Reg,
        sf: bool,
        addr: AddrMode,
    },
    /// SIMD&FP load pair (`LDP {St,Dt,Qt}, ...`). `rt1`/`rt2` are SIMD&FP
    /// register numbers (NOT GPRs); `access` is the element width (Word=S,
    /// DoubleWord=D, QuadWord=Q). Distinct from `Ldp` because the destinations
    /// are the q-register file, not GPRs — decoding these as integer `Ldp`
    /// loaded the FP data into GPRs and, when a destination aliased the base
    /// (e.g. `ldp q0,q1,[x0]`), clobbered the base mid-block → fpsimd faults.
    LdpFp {
        rt1: Reg,
        rt2: Reg,
        access: AccessSize,
        addr: AddrMode,
    },
    /// SIMD&FP store pair (`STP {St,Dt,Qt}, ...`). See [`DecodedInsn::LdpFp`].
    StpFp {
        rt1: Reg,
        rt2: Reg,
        access: AccessSize,
        addr: AddrMode,
    },
    /// NEON `MOVI` / `MVNI` (Advanced SIMD modified immediate, setting forms).
    /// The 128-bit value is fully resolved at decode time (`lo`/`hi`); for the
    /// Q=0 forms `hi` is 0 (upper lanes zeroed). Writes V`rd` only — no source
    /// register. The register-modifying ORR/BIC and the FMOV-vector forms stay
    /// the coarse `AdvSimd`.
    SimdMoviImm {
        rd: u8,
        lo: u64,
        hi: u64,
    },
    /// NEON `DUP` (general): broadcast GPR `rn`'s low element to every lane of
    /// V`rd`. `size`: 0=B,1=H,2=S,3=D. `q`: false = 64-bit (8B/4H/2S), true =
    /// 128-bit. bionic `__memset_aarch64` opens with `dup v0.16b, w1`.
    SimdDupGen {
        rd: VReg,
        rn: Reg,
        size: u8,
        q: bool,
    },
    /// NEON `UMOV`/`SMOV`: V`rn`.<T>[`lane`] -> GPR `rd`. `signed` ⇒ SMOV
    /// (sign-extend) else UMOV (zero-extend). `dst_x` ⇒ Xd (64-bit) else Wd.
    /// `size`: 0=B,1=H,2=S,3=D. bionic memset uses `mov x1, v0.d[0]` (UMOV).
    SimdMovToGen {
        rd: Reg,
        rn: VReg,
        lane: u8,
        size: u8,
        signed: bool,
        dst_x: bool,
    },
    /// NEON `INS` (general): GPR `rn` -> V`rd`.<T>[`lane`] (other lanes kept).
    /// `size`: 0=B,1=H,2=S,3=D. Used by bionic `__memcpy` tail handling.
    SimdInsGen {
        rd: VReg,
        lane: u8,
        rn: Reg,
        size: u8,
    },
    /// `FMOV` (general) — pure bit-move between a GPR and an FP/SIMD register
    /// (no numeric conversion). Forms: `FMOV Sd,Wn`/`Dd,Xn` (GPR→FP lane 0,
    /// zeroing the rest), `FMOV Wd,Sn`/`Xd,Dn` (FP lane 0→GPR), and the
    /// 128-bit high-half `FMOV Vd.D[1],Xn` / `FMOV Xd,Vn.D[1]` (lane 1, no
    /// zeroing). `to_gpr` selects direction; `rd` is the GPR, `vn` the FP reg;
    /// `size` is bytes (4=S/W, 8=D/X); `zero_rest` clears the other lanes on a
    /// GPR→FP lane-0 write. bionic FP setup emits `fmov d0, x8`.
    FmovGen {
        to_gpr: bool,
        rd: Reg,
        vn: VReg,
        lane: u8,
        size: u8,
        zero_rest: bool,
    },
    /// NEON `CNT` — per-byte population count V`rn` → V`rd`. `q`: false=.8b,
    /// true=.16b. bionic's popcount idiom opens with `cnt v0.8b, v0.8b`.
    SimdCnt {
        rd: VReg,
        rn: VReg,
        q: bool,
    },
    /// NEON `UADDLV`/`SADDLV` — add-long across all lanes of V`rn` → scalar in
    /// V`rd` lane 0. `size`: 0=B,1=H,2=S (log2 element); result is 2× wide.
    /// `signed` ⇒ SADDLV. The popcount idiom's `uaddlv h0, v0.8b` sums the bytes.
    SimdAddvLong {
        rd: VReg,
        rn: VReg,
        size: u8,
        q: bool,
        signed: bool,
    },
    /// NEON integer per-lane compare-against-zero (`CMEQ`/`CMGT`/`CMGE`/`CMLT`/
    /// `CMLE` `Vd, Vn, #0`). `op`: 0=Eq 1=Gt(signed) 2=Ge(signed) 3=Lt(signed)
    /// 4=Le(signed). `size`: 0=B,1=H,2=S,3=D. bionic strchr/memchr:
    /// `cmeq v2.16b, v1.16b, #0`; ART sign tests use the ordered forms.
    SimdIntCmpZero {
        rd: VReg,
        rn: VReg,
        op: u8,
        size: u8,
        q: bool,
    },
    /// NEON vector FP 2-reg-misc unary (`FABS`/`FNEG`/`FSQRT`). `op`: 0=Abs 1=Neg
    /// 2=Sqrt. `dbl` selects double (.2d) vs single (.4s/.2s).
    SimdFpUn {
        rd: VReg,
        rn: VReg,
        op: u8,
        dbl: bool,
        q: bool,
    },
    /// NEON vector FP per-lane compare against `#0.0` (`FCMEQ`/`FCMGT`/`FCMGE`/
    /// `FCMLT`/`FCMLE`). `op`: 0=Eq 1=Gt 2=Ge 3=Lt 4=Le. `dbl` selects double.
    SimdFpCmpZero {
        rd: VReg,
        rn: VReg,
        op: u8,
        dbl: bool,
        q: bool,
    },
    /// NEON vector FP round-to-integral (`FRINT{N,P,M,Z,A}` `Vd.<T>,Vn.<T>`).
    /// `round`: 0=N(nearest-even) 1=M(floor) 2=P(ceil) 3=Z(trunc) 4=A(ties-away).
    /// `dbl` selects double (.2d) vs single (.4s/.2s). (FRINTX/FRINTI — the
    /// inexact-raising / current-mode forms — stay coarse `AdvSimd` for now; they
    /// do not appear on the framework render path per the oracle sweep.)
    SimdFpRound {
        rd: VReg,
        rn: VReg,
        round: u8,
        dbl: bool,
        q: bool,
    },
    /// NEON `SHRN`/`SHRN2` — shift-right-narrow. `shift` ∈ 1..=2*esize_out*8;
    /// `esize_out` = result element bytes; `high` = SHRN2 (writes Vd high 64).
    SimdShrn {
        rd: VReg,
        rn: VReg,
        shift: u8,
        esize_out: u8,
        high: bool,
    },
    /// NEON `USHLL`/`SSHLL`/`USHLL2`/`SSHLL2` (also `UXTL`/`SXTL` when shift==0) —
    /// shift-left-long: widen each source element (`esize_in` bytes) to twice the
    /// width with zero (`signed=false`) or sign (`signed=true`) extension, then
    /// shift left by `shift`. `high` selects the high 64 bits of Vn (the `2`
    /// variants). Result is always a full 128-bit Q-form register.
    SimdUshll {
        rd: VReg,
        rn: VReg,
        shift: u8,
        esize_in: u8,
        high: bool,
        signed: bool,
    },
    /// NEON single-register `TBL` (table byte-permute, 1 table reg):
    /// `Vd[i] = (Vm[i] < 16) ? Vn[Vm[i]] : 0`. bionic's AES key schedule uses
    /// `tbl v.16b, {v.16b}, v.16b` to permute bytes.
    SimdTbl1 {
        rd: VReg,
        rn: VReg,
        rm: VReg,
        q: bool,
    },
    /// NEON multi-register `TBL`/`TBX` (table byte-permute over 1..4 consecutive
    /// table regs, wrapping mod 32). `len` is the table-reg count − 1 (0..=3),
    /// `op` selects TBL (0) vs TBX (1). For TBL, out-of-range index lanes write 0;
    /// for TBX they retain the old `Vd` byte. `rn` is the first table reg, `rm` the
    /// index reg. (The `len==0 && op==0` case is covered by `SimdTbl1`.)
    SimdTblN {
        rd: VReg,
        rn: VReg,
        rm: VReg,
        len: u8,
        op: u8,
        q: bool,
    },
    /// NEON `SHL` (vector shift-left by immediate). `size` = log2(element bytes):
    /// 0=8-bit, 1=16-bit, 2=32-bit, 3=64-bit.
    SimdShlImm {
        rd: VReg,
        rn: VReg,
        shift: u8,
        size: u8,
        q: bool,
    },
    /// NEON `SSHR`/`USHR` (vector shift-right by immediate). `signed` selects
    /// arithmetic (SSHR) vs logical (USHR). `size` = log2(element bytes).
    SimdShrImm {
        rd: VReg,
        rn: VReg,
        shift: u8,
        size: u8,
        q: bool,
        signed: bool,
    },
    /// NEON `SSRA`/`USRA` (vector shift-right-and-accumulate by immediate).
    /// `Vd[e] += (Vn[e] >> shift)`. `signed` selects arithmetic (SSRA) vs logical
    /// (USRA). `size` = log2(element bytes); `rd` is read AND written.
    SimdSraImm {
        rd: VReg,
        rn: VReg,
        shift: u8,
        size: u8,
        q: bool,
        signed: bool,
    },
    /// NEON `SSHL`/`USHL` — register variable per-lane shift. Each `size`-byte
    /// lane of Vn is shifted by the SIGNED byte in the corresponding lane of Vm
    /// (positive = left, negative = right; SSHL uses an arithmetic right shift,
    /// USHL a logical one). `size` = log2(element bytes: 0=B,1=H,2=S,3=D).
    SimdShlReg {
        rd: VReg,
        rn: VReg,
        rm: VReg,
        size: u8,
        q: bool,
        signed: bool,
    },
    /// NEON `SRI`/`SLI` — shift-right-and-insert / shift-left-and-insert by
    /// immediate. `left`=false (SRI): `Vd = (Vd & top_mask) | (Vn >>u shift)`,
    /// preserving Vd's top `shift` bits of each element. `left`=true (SLI):
    /// `Vd = (Vd & low_mask) | (Vn << shift)`, preserving Vd's low `shift` bits.
    /// `size` = log2(element bytes). `rd` is read AND written.
    SimdShiftIns {
        rd: VReg,
        rn: VReg,
        shift: u8,
        size: u8,
        q: bool,
        left: bool,
    },
    /// NEON `SQSHRN`/`UQSHRN`/`SQSHRUN`/`SQRSHRN`/`UQRSHRN`/`SQRSHRUN`/`RSHRN` —
    /// saturating (and/or rounding) narrowing shift-right by immediate. Each
    /// `2*esize_out`-byte source lane is shifted right by `shift` (rounding when
    /// `round`), then saturated to the destination element range. `src_signed`
    /// selects the source interpretation (S vs U); `dst_signed` selects the
    /// destination saturation range (SQSHRUN/SQRSHRUN are signed-source →
    /// unsigned-dest). `high` = the `2` (SQSHRN2 etc.) form (writes Vd[127:64]).
    /// RSHRN/SHRN (plain narrow, no saturation) set `modular=true`: the result is
    /// the low `esize_out*8` bits of `(element + round) >> shift` — truncated, NOT
    /// clamped. All the saturating members (SQSHRN/UQSHRN/SQSHRUN/… and their
    /// rounding variants) set `modular=false`. `modular` is required to tell RSHRN
    /// apart from UQRSHRN: both carry `round=true, src_signed=false,
    /// dst_signed=false`, so the signedness flags alone cannot distinguish the
    /// truncating op from the saturating one.
    SimdShrnSat {
        rd: VReg,
        rn: VReg,
        shift: u8,
        esize_out: u8,
        high: bool,
        round: bool,
        src_signed: bool,
        dst_signed: bool,
        modular: bool,
    },
    /// NEON `DUP` (element) — broadcast `Vn.<Ts>[lane]` to all lanes of Vd.
    /// `size` = log2(element bytes); `lane` = source index.
    SimdDupElem {
        rd: VReg,
        rn: VReg,
        size: u8,
        lane: u8,
        q: bool,
    },
    /// NEON `PMULL`/`PMULL2` `.1q` — 64×64→128 carryless (polynomial) multiply.
    /// `high`=true is PMULL2 (uses each source's high 64 bits). GHASH/GCM core.
    SimdPmull {
        rd: VReg,
        rn: VReg,
        rm: VReg,
        high: bool,
    },
    /// Scalar `DUP`/`MOV` (element) — `mov dN, vM.<T>[lane]`: copy one lane into
    /// the scalar (lane 0) of Vd, zeroing the rest. `size`=log2(element bytes).
    SimdScalarDup {
        rd: VReg,
        rn: VReg,
        size: u8,
        lane: u8,
    },
    /// Scalar `SHL` — `shl dN, dM, #shift` (64-bit, D-form only); zeroes Vd[127:64].
    SimdScalarShl {
        rd: VReg,
        rn: VReg,
        shift: u8,
    },
    /// NEON `EXT` (extract) — `Vd = (CONCAT(Vm, Vn) >> imm*8)`, i.e. the 16 (`q`)
    /// or 8 bytes starting at byte `imm` of the Vn:Vm concatenation. bionic
    /// memmove/string routines use it heavily (e.g. `ext v7.16b, v1.16b, v1.16b, #8`).
    SimdExt {
        rd: VReg,
        rn: VReg,
        rm: VReg,
        imm: u8,
        q: bool,
    },
    /// NEON integer multiply-long: `UMULL`/`SMULL` (replace), `UMLAL`/`SMLAL`
    /// (`accum`, add), `UMLSL`/`SMLSL` (`accum`+`sub`, subtract). Widens each
    /// `size`-byte source element (`signed`) to 2× and multiplies; `q` selects
    /// the high source half (the `2` variant).
    SimdMulLong {
        rd: VReg,
        rn: VReg,
        rm: VReg,
        size: u8,
        q: bool,
        signed: bool,
        accum: bool,
        sub: bool,
    },
    /// NEON `REV64`/`REV32`/`REV16` — reverse the order of `size`-element groups
    /// (element bytes = 1<<size) within each `container`-byte group (8=REV64,
    /// 4=REV32, 2=REV16). `q`=false is the 64-bit (D) form.
    SimdRev64 {
        rd: VReg,
        rn: VReg,
        size: u8,
        q: bool,
        container: u8,
    },
    /// NEON `LD1`/`ST1` (multiple structures, no de-interleave). `regs` ∈ 1..=4
    /// consecutive V-regs from/to [Xn]; `q` selects 16B (.16b) vs 8B (.8b) each.
    /// `writeback` = post-index (rm==31 → += regs*bytes, else += X`rm`).
    SimdLd1Multi {
        is_load: bool,
        regs: u8,
        q: bool,
        rt: VReg,
        rn: Reg,
        writeback: bool,
        rm: u8,
    },
    /// NEON `LD1R` — load one `size`-byte element from `[Xn]` and replicate it to
    /// every lane of V`t` (`q` = 16 vs 8 bytes); optional post-index writeback.
    SimdLd1Rep {
        rt: VReg,
        rn: Reg,
        size: u8,
        q: bool,
        writeback: bool,
        rm: u8,
    },
    /// NEON single-lane `LD1`/`ST1` — `ld1/st1 {Vt.<T>}[lane], [Xn]`. Loads/stores
    /// one `esize`-byte element to/from a single vector lane (other lanes kept).
    /// `is_load` selects LD1 vs ST1; optional post-index writeback.
    SimdLd1Lane {
        rt: VReg,
        rn: Reg,
        esize: u8,
        lane: u8,
        is_load: bool,
        writeback: bool,
        rm: u8,
    },
    /// NEON `BIC`/`ORR` (vector, immediate): RMW V`rd` with the expanded 64-bit
    /// `imm` pattern. `is_bic` clears (`&~imm`) else sets (`|imm`). bionic strchr
    /// `bic v4.8h, #0xf0`.
    SimdBicOrrImm {
        rd: VReg,
        imm: u64,
        is_bic: bool,
        q: bool,
    },
    /// NEON `UADDLP`/`SADDLP` — add-long pairwise within V`rn`. `size` (log2 of
    /// the SOURCE element: 0=B,1=H,2=S) widens to a `2×` result element.
    /// `signed` ⇒ SADDLP. bionic NEON popcount accumulation.
    SimdAddLongPair {
        rd: VReg,
        rn: VReg,
        size: u8,
        q: bool,
        signed: bool,
    },
    /// NEON `UZP1`/`UZP2` — unzip even/odd `size`-log2 elements of V`rn`:V`rm`.
    SimdUnzip {
        rd: VReg,
        rn: VReg,
        rm: VReg,
        size: u8,
        q: bool,
        odd: bool,
    },
    /// NEON `ADDV` — reduce-add all lanes (same width) of V`rn` to a scalar.
    SimdReduceAdd {
        rd: VReg,
        rn: VReg,
        size: u8,
        q: bool,
    },
    /// NEON across-lanes min/max reduction (SMAXV/UMAXV/SMINV/UMINV) — B20/B29.
    /// Reduces all lanes (element bytes = `1<<size`) to a single scalar in
    /// V`rd` lane 0 (rest zeroed). `is_min` selects MINV vs MAXV; `signed`
    /// selects the S vs U form (U bit of the encoding).
    SimdReduceMinMax {
        rd: VReg,
        rn: VReg,
        size: u8,
        q: bool,
        is_min: bool,
        signed: bool,
    },
    /// NEON `INS` (element): V`rd`.<T>[`dst_lane`] <- V`rn`.<T>[`src_lane`].
    /// `size`: 0=B,1=H,2=S,3=D (log2 element). bionic `mov v0.d[1], v1.d[0]`.
    SimdInsElem {
        rd: VReg,
        rn: VReg,
        dst_lane: u8,
        src_lane: u8,
        size: u8,
    },
    /// NEON multiply-accumulate BY ELEMENT — `FMUL`/`FMLA`/`FMLS` (FP) and `MUL`
    /// (integer) `Vd, Vn, Vm.<Ts>[idx]`. `fp_op`: 0=Mul 1=Mla 2=Mls (FP only;
    /// integer MUL ignores it). `is_fp` selects the FP path. `dbl` (FP) = .2d.
    /// `size`: log2 element bytes (int H=1/S=2; FP S=2/D=3). `idx` = the source
    /// lane of Vm broadcast to every lane. Graphics/matrix-math hot path.
    SimdByElem {
        rd: VReg,
        rn: VReg,
        rm: VReg,
        fp_op: u8,
        is_fp: bool,
        dbl: bool,
        size: u8,
        q: bool,
        idx: u8,
    },
    /// NEON vector integer↔FP convert (2-reg-misc): `SCVTF`/`UCVTF` (int→FP) and
    /// `FCVTZS`/`FCVTZU` (FP→int, round-toward-zero). `to_fp` selects int→FP;
    /// `signed` the S vs U form; `dbl` the .2d (64-bit) vs .4s/.2s (32-bit) form.
    SimdCvtFp {
        rd: VReg,
        rn: VReg,
        to_fp: bool,
        signed: bool,
        dbl: bool,
        q: bool,
    },
    /// Scalar SIMD `SCVTF`/`UCVTF` `Sd,Sn` / `Dd,Dn` (2-reg-misc scalar, opcode 11101):
    /// int→FP where the integer is the low element of a vector register. `dbl`
    /// selects the 64-bit (D) form, which is also the integer width.
    SimdScalarCvtIntFp {
        rd: VReg,
        rn: VReg,
        signed: bool,
        dbl: bool,
    },
    /// Vector FP precision convert: FCVTL{2} (`widen`) / FCVTN{2}. `half`: sz=0
    /// (f16<->f32); else f32<->f64. `upper`: Q=1 ("2" form, high half).
    SimdFpCvtWidth {
        rd: VReg,
        rn: VReg,
        widen: bool,
        half: bool,
        upper: bool,
    },
    /// Scalar FP by element: `FMUL/FMLA/FMLS Sd,Sn,Vm.S[idx]` (and the D forms).
    /// `fp_op`: 0=FMUL 1=FMLA 2=FMLS (as in `SimdByElem`).
    SimdScalarByElem {
        rd: VReg,
        rn: VReg,
        rm: VReg,
        fp_op: u8,
        dbl: bool,
        idx: u8,
    },
    /// Scalar SIMD `FABD Sd,Sn,Sm` / `Dd,Dn,Dm` (scalar 3-same, U=1 a=1 opcode 11010):
    /// `|Sn - Sm|`, defined by ARM as FPAbs(FPSub(n, m)).
    SimdScalarFabd {
        rd: VReg,
        rn: VReg,
        rm: VReg,
        dbl: bool,
    },
    /// NEON `ZIP1`/`ZIP2`/`TRN1`/`TRN2` permute. `kind`: 0=ZIP1 1=ZIP2 2=TRN1
    /// 3=TRN2. `size`: log2 element bytes. Interleaves the lanes of V`rn`:V`rm`.
    /// RGBA channel interleave + matrix transpose (graphics).
    SimdZipTrn {
        rd: VReg,
        rn: VReg,
        rm: VReg,
        kind: u8,
        size: u8,
        q: bool,
    },
    /// NEON integer `ABS` (`neg=false`) / `NEG` (`neg=true`) — 2-reg-misc unary.
    /// `size`: log2 element bytes (0=B,1=H,2=S,3=D).
    SimdAbsNeg {
        rd: VReg,
        rn: VReg,
        size: u8,
        q: bool,
        neg: bool,
    },
    /// Scalar integer 3-same `ADD`/`SUB` (D-form, 64-bit): `add d0,d1,d2`. The
    /// lane-0 version of the vector op (lowers to a D-form VecBin). `sub` selects SUB.
    SimdScalar3Same {
        rd: VReg,
        rn: VReg,
        rm: VReg,
        sub: bool,
    },
    /// Scalar pairwise reduce: `ADDP d0,v1.2d` (`is_fp=false`) or `FADDP {s,d}0,
    /// v1.2{s,d}` (`is_fp=true`). Sums the two lanes of Vn into Vd lane 0 (rest
    /// zeroed). `dbl` selects the 64-bit (D / .2d) vs 32-bit (S / .2s) element.
    SimdScalarPair {
        rd: VReg,
        rn: VReg,
        is_fp: bool,
        dbl: bool,
    },

    // ----- AT-4: branches / system / exceptions / barriers / atomics -----
    B {
        offset: i32,
    },
    Bl {
        offset: i32,
    },
    Bcond {
        cond: Cond,
        offset: i32,
    },
    Br {
        rn: Reg,
    },
    Blr {
        rn: Reg,
    },
    Ret {
        rn: Reg,
    },
    /// `ERET` — exception return. PC <- ELR_EL1, PSTATE <- SPSR_EL1. For the
    /// DBT this is a block terminator: it loads the next guest PC from ELR_EL1
    /// and restores the NZCV flags from SPSR_EL1[31:28]. No operands (the plain
    /// non-PAC encoding; ERETAA/ERETAB are not decoded here).
    Eret,
    Cbz {
        sf: bool,
        rt: Reg,
        offset: i32,
    },
    Cbnz {
        sf: bool,
        rt: Reg,
        offset: i32,
    },
    Tbz {
        bit: u8,
        rt: Reg,
        offset: i32,
    },
    Tbnz {
        bit: u8,
        rt: Reg,
        offset: i32,
    },
    Svc {
        imm16: u16,
    },
    Hvc {
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
    Dmb {
        domain: u8,
    },
    Dsb {
        domain: u8,
    },
    Isb,
    Sb,
    Csdb,
    Nop,
    Yield,
    Wfi,
    Wfe,
    Sev,
    Sevl,
    // PAC / BTI hint-space — decoded explicitly so AT-5 doesn't see them as Unknown.
    PacHint {
        opc: u8,
    },
    BtiHint {
        target: u8,
    },
    Mrs {
        rt: Reg,
        sysreg: u16, // packed (op0|op1|CRn|CRm|op2) — resolved against sysreg::SysReg in lift
    },
    Msr {
        rt: Reg,
        sysreg: u16,
    },
    MsrImm {
        op1: u8,
        crm: u8,
        op2: u8,
    },
    SysIc {
        op1: u8,
        crm: u8,
        op2: u8,
        rt: Reg,
    },
    SysDc {
        op1: u8,
        crm: u8,
        op2: u8,
        rt: Reg,
    },
    SysAt {
        op1: u8,
        crm: u8,
        op2: u8,
        rt: Reg,
    },
    SysTlbi {
        op1: u8,
        crm: u8,
        op2: u8,
        rt: Reg,
    },
    // LL/SC and acquire/release
    Ldxr {
        size: AccessSize,
        rt: Reg,
        rn: Reg,
        acquire: bool,
        pair: bool,
        rt2: Reg,
    },
    Stxr {
        size: AccessSize,
        rs: Reg,
        rt: Reg,
        rn: Reg,
        release: bool,
        pair: bool,
        rt2: Reg,
    },
    Ldar {
        size: AccessSize,
        rt: Reg,
        rn: Reg,
    },
    Stlr {
        size: AccessSize,
        rt: Reg,
        rn: Reg,
    },
    Ldapr {
        size: AccessSize,
        rt: Reg,
        rn: Reg,
    },
    // LSE atomics (ARMv8.1)
    Cas {
        size: AccessSize,
        rs: Reg,
        rt: Reg,
        rn: Reg,
        acquire: bool,
        release: bool,
    },
    /// CASP/CASPA/CASPL/CASPAL — compare-and-swap PAIR. Operates on the register
    /// pairs (Rs,Rs+1) = expected, (Rt,Rt+1) = new, at [Rn] (2×elem bytes).
    /// Rs/Rt are even. `size` is per-element (Word=4 for the 32-bit pair,
    /// DoubleWord=8 for the 64-bit pair). Used by the SLUB `cmpxchg_double`
    /// fast path (`this_cpu_cmpxchg_double`).
    Casp {
        size: AccessSize,
        rs: Reg,
        rt: Reg,
        rn: Reg,
        acquire: bool,
        release: bool,
    },
    LdAtomicRmw {
        size: AccessSize,
        op: u8, // 0=ADD 1=CLR 2=EOR 3=SET 4=SMAX 5=SMIN 6=UMAX 7=UMIN
        rs: Reg,
        rt: Reg,
        rn: Reg,
        acquire: bool,
        release: bool,
    },
    Swp {
        size: AccessSize,
        rs: Reg,
        rt: Reg,
        rn: Reg,
        acquire: bool,
        release: bool,
    },

    // ----- AT-3: NEON / FP / SIMD / Crypto (huge family; placeholders for now) -----
    /// M4b-6: typed NEON 3-same (integer + FP). Fields per ARM ARM C4.1.6:
    /// `q`=bit30, `u`=bit29, `size`=bits[23:22], `opcode`=bits[15:11]. Lift
    /// classifies `(u, opcode[, size])` into the VecBin/VecCmp/VecPair/VecFp IR
    /// ops; unrecognized sub-forms fall back to a Hint (fail-loud at lower).
    SimdThreeSame {
        q: bool,
        u: bool,
        size: u8,
        opcode: u8,
        rm: VReg,
        rn: VReg,
        rd: VReg,
    },
    /// Catch-all for advanced-SIMD encodings until per-family decoding lands.
    AdvSimd {
        raw: u32,
    },
    /// Catch-all for scalar FP encodings until per-family decoding lands.
    FpScalar {
        raw: u32,
    },
    /// Crypto AES round.
    CryptoAes {
        op: u8,
        rd: VReg,
        rn: VReg,
    },
    /// Crypto SHA1/SHA256.
    CryptoSha {
        op: u8,
        raw: u32,
    },

    // ----- Permanently undefined -----
    /// `UDF #imm16` — bits[31:16] = 0x0000 (ARM ARM C6.2.401). A genuine
    /// architectural instruction whose semantics are "raise an Undefined
    /// Instruction exception". Encoders use it as a trap-on-execute marker
    /// (compilers emit it for unreachable code, alignment padding, etc.).
    Udf {
        imm16: u16,
    },

    // ----- Sentinel -----
    Unknown(u32),
}

/// Decoder error categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeErr {
    /// Reserved encoding per ARM ARM (e.g., op0=0b0000 currently reserved).
    Reserved,
    /// Encoding belongs to an extension AETHER explicitly excludes (SVE/SME/MTE).
    UnsupportedExtension,
    /// Family decoder not yet implemented (Phase A in-progress sentinel).
    Unimplemented,
}

/// Top-level entry point.
///
/// Decodes a single A64 instruction word into [`DecodedInsn`]. A64 words are
/// always little-endian per ARM ARM §B1.6.1; callers should provide the word
/// already in native u32 form (use `u32::from_le_bytes` on bytes).
pub fn decode_instruction(word: u32) -> Result<DecodedInsn, DecodeErr> {
    match top_level::dispatch(word) {
        // A valid Advanced SIMD encoding the typed decoder does not route yet but
        // the runtime helper implements exactly: accept it as AdvSimd (the lifter
        // turns it into a simd_rt call). `supports` rejects reserved encodings.
        Err(_) if crate::runtime::simd_rt::supports(word) => Ok(DecodedInsn::AdvSimd { raw: word }),
        r => r,
    }
}
