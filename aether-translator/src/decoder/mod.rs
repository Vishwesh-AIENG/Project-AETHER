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
    },
    Str {
        rt: Reg,
        size: AccessSize,
        addr: AddrMode,
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
    top_level::dispatch(word)
}
