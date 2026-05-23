//! System register catalog (MSR/MRS encoding).
//!
//! Sysreg encoding is `(op0:2, op1:3, CRn:4, CRm:4, op2:3)` = 16 bits packed
//! into [`SysRegId`]. The decoder produces `DecodedInsn::Mrs/Msr` with the
//! packed id; this module resolves it to a named [`SysReg`].
//!
//! Phase A AT-4 fill: ~180 named sysregs covering the registers Linux kernel
//! ARM64 entry points + Android bionic actually touch. Any unrecognised
//! valid encoding becomes `SysReg::OtherKnown(SysRegId)` — preserved for
//! lift but not given a name.
//!
//! The full ~600-entry ARM-architectural catalog is auto-generated from
//! Linux's `arch/arm64/tools/sysreg` table in production builds; that
//! generator lives outside this repo. The hand-curated subset below is
//! sufficient for Phase A decode coverage.

/// Packed 16-bit sysreg id: `(op0 << 14) | (op1 << 11) | (CRn << 7) | (CRm << 3) | op2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SysRegId(pub u16);

impl SysRegId {
    pub const fn new(op0: u8, op1: u8, crn: u8, crm: u8, op2: u8) -> Self {
        Self(
            ((op0 as u16 & 0b11) << 14)
                | ((op1 as u16 & 0b111) << 11)
                | ((crn as u16 & 0b1111) << 7)
                | ((crm as u16 & 0b1111) << 3)
                | (op2 as u16 & 0b111),
        )
    }
    pub const fn op0(self) -> u8 { ((self.0 >> 14) & 0b11) as u8 }
    pub const fn op1(self) -> u8 { ((self.0 >> 11) & 0b111) as u8 }
    pub const fn crn(self) -> u8 { ((self.0 >> 7) & 0b1111) as u8 }
    pub const fn crm(self) -> u8 { ((self.0 >> 3) & 0b1111) as u8 }
    pub const fn op2(self) -> u8 { (self.0 & 0b111) as u8 }
}

/// Named sysregs. ~180 entries covering Linux ARM64 + Android bionic actual
/// usage. Encodings cross-checked against `arch/arm64/include/asm/sysreg.h`
/// in the Linux kernel.
#[allow(non_camel_case_types)] // SysReg variant names preserve underscore separators between the
                               // ARM ARM mnemonic and the EL suffix where it improves readability
                               // (e.g. `Mdcr_El2`, `Hpfar_El2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysReg {
    // ----- Identification (op0=3, op1=0, CRn=0) -----
    MidrEl1,        // 3, 0, 0, 0, 0
    MpidrEl1,       // 3, 0, 0, 0, 5
    RevidrEl1,      // 3, 0, 0, 0, 6
    AidrEl1,        // 3, 1, 0, 0, 7
    CcsidrEl1,      // 3, 1, 0, 0, 0
    ClidrEl1,       // 3, 1, 0, 0, 1
    CsselrEl1,      // 3, 2, 0, 0, 0
    CtrEl0,         // 3, 3, 0, 0, 1
    DczidEl0,       // 3, 3, 0, 0, 7

    // Feature identification (op0=3, op1=0, CRn=0, CRm=4-7)
    IdAa64Pfr0El1,  // 3, 0, 0, 4, 0
    IdAa64Pfr1El1,  // 3, 0, 0, 4, 1
    IdAa64Zfr0El1,  // 3, 0, 0, 4, 4
    IdAa64Smfr0El1, // 3, 0, 0, 4, 5
    IdAa64Dfr0El1,  // 3, 0, 0, 5, 0
    IdAa64Dfr1El1,  // 3, 0, 0, 5, 1
    IdAa64Afr0El1,  // 3, 0, 0, 5, 4
    IdAa64Afr1El1,  // 3, 0, 0, 5, 5
    IdAa64Isar0El1, // 3, 0, 0, 6, 0
    IdAa64Isar1El1, // 3, 0, 0, 6, 1
    IdAa64Isar2El1, // 3, 0, 0, 6, 2
    IdAa64Mmfr0El1, // 3, 0, 0, 7, 0
    IdAa64Mmfr1El1, // 3, 0, 0, 7, 1
    IdAa64Mmfr2El1, // 3, 0, 0, 7, 2

    // ----- System control (op0=3, op1=0, CRn=1) -----
    SctlrEl1,       // 3, 0, 1, 0, 0
    ActlrEl1,       // 3, 0, 1, 0, 1
    CpacrEl1,       // 3, 0, 1, 0, 2
    SctlrEl2,       // 3, 4, 1, 0, 0
    ActlrEl2,       // 3, 4, 1, 0, 1
    HcrEl2,         // 3, 4, 1, 1, 0
    Mdcr_El2,       // 3, 4, 1, 1, 1
    CptrEl2,        // 3, 4, 1, 1, 2
    HstrEl2,        // 3, 4, 1, 1, 3
    HacrEl2,        // 3, 4, 1, 1, 7
    SctlrEl3,       // 3, 6, 1, 0, 0
    ActlrEl3,       // 3, 6, 1, 0, 1
    ScrEl3,         // 3, 6, 1, 1, 0

    // ----- Translation table base / TCR (op0=3, op1=0, CRn=2) -----
    TtbrEl1_0,      // 3, 0, 2, 0, 0
    TtbrEl1_1,      // 3, 0, 2, 0, 1
    TcrEl1,         // 3, 0, 2, 0, 2
    TtbrEl2_0,      // 3, 4, 2, 0, 0
    TcrEl2,         // 3, 4, 2, 0, 2
    VttbrEl2,       // 3, 4, 2, 1, 0
    VtcrEl2,        // 3, 4, 2, 1, 2
    TtbrEl3_0,      // 3, 6, 2, 0, 0
    TcrEl3,         // 3, 6, 2, 0, 2

    // ----- Exception state (op0=3, op1=0, CRn=4) -----
    SpsrEl1,        // 3, 0, 4, 0, 0
    ElrEl1,         // 3, 0, 4, 0, 1
    SpEl0,          // 3, 0, 4, 1, 0
    SpselEl1,       // 3, 0, 4, 2, 0
    CurrentEl,      // 3, 0, 4, 2, 2
    NzcvEl0,        // 3, 3, 4, 2, 0
    DaifEl0,        // 3, 3, 4, 2, 1
    FpcrEl0,        // 3, 3, 4, 4, 0
    FpsrEl0,        // 3, 3, 4, 4, 1
    SpsrEl2,        // 3, 4, 4, 0, 0
    ElrEl2,         // 3, 4, 4, 0, 1
    SpEl1,          // 3, 4, 4, 1, 0
    SpsrEl3,        // 3, 6, 4, 0, 0
    ElrEl3,         // 3, 6, 4, 0, 1
    SpEl2,          // 3, 6, 4, 1, 0

    // ----- Fault / Address syndrome (op0=3, op1=0, CRn=5/6) -----
    Afsr0El1,       // 3, 0, 5, 1, 0
    Afsr1El1,       // 3, 0, 5, 1, 1
    EsrEl1,         // 3, 0, 5, 2, 0
    FarEl1,         // 3, 0, 6, 0, 0
    Afsr0El2,       // 3, 4, 5, 1, 0
    Afsr1El2,       // 3, 4, 5, 1, 1
    EsrEl2,         // 3, 4, 5, 2, 0
    Hpfar_El2,      // 3, 4, 6, 0, 4
    FarEl2,         // 3, 4, 6, 0, 0
    EsrEl3,         // 3, 6, 5, 2, 0
    FarEl3,         // 3, 6, 6, 0, 0

    // ----- Vector base (op0=3, op1=0, CRn=12) -----
    VbarEl1,        // 3, 0, 12, 0, 0
    IsrEl1,         // 3, 0, 12, 1, 0
    VbarEl2,        // 3, 4, 12, 0, 0
    VbarEl3,        // 3, 6, 12, 0, 0

    // ----- Memory attributes / MAIR (op0=3, op1=0, CRn=10) -----
    MairEl1,        // 3, 0, 10, 2, 0
    AmairEl1,       // 3, 0, 10, 3, 0
    MairEl2,        // 3, 4, 10, 2, 0
    AmairEl2,       // 3, 4, 10, 3, 0
    MairEl3,        // 3, 6, 10, 2, 0
    AmairEl3,       // 3, 6, 10, 3, 0

    // ----- ContextIDR (op0=3, op1=0/4, CRn=13) -----
    ContextidrEl1,  // 3, 0, 13, 0, 1
    ContextidrEl2,  // 3, 4, 13, 0, 1
    TpidrEl0,       // 3, 3, 13, 0, 2
    TpidrroEl0,     // 3, 3, 13, 0, 3
    TpidrEl1,       // 3, 0, 13, 0, 4
    TpidrEl2,       // 3, 4, 13, 0, 2
    TpidrEl3,       // 3, 6, 13, 0, 2

    // ----- Generic timer (op0=3, op1=3, CRn=14) -----
    CntfrqEl0,      // 3, 3, 14, 0, 0
    CntpctEl0,      // 3, 3, 14, 0, 1
    CntvctEl0,      // 3, 3, 14, 0, 2
    CntpCtlEl0,     // 3, 3, 14, 2, 1
    CntpCvalEl0,    // 3, 3, 14, 2, 2
    CntpTvalEl0,    // 3, 3, 14, 2, 0
    CntvCtlEl0,     // 3, 3, 14, 3, 1
    CntvCvalEl0,    // 3, 3, 14, 3, 2
    CntvTvalEl0,    // 3, 3, 14, 3, 0
    CntkctlEl1,     // 3, 0, 14, 1, 0
    CnthctlEl2,     // 3, 4, 14, 1, 0
    CnthpCtlEl2,    // 3, 4, 14, 2, 1
    CnthpCvalEl2,   // 3, 4, 14, 2, 2
    CnthpTvalEl2,   // 3, 4, 14, 2, 0
    CnthvCtlEl2,    // 3, 4, 14, 3, 1
    CnthvCvalEl2,   // 3, 4, 14, 3, 2
    CntvoffEl2,     // 3, 4, 14, 0, 3
    CntpsCtlEl1,    // 3, 7, 14, 2, 1
    CntpsCvalEl1,   // 3, 7, 14, 2, 2

    // ----- GIC v3 CPU interface (op0=3, op1=0/4, CRn=12) -----
    IccPmrEl1,      // 3, 0, 4, 6, 0
    IccIar0El1,     // 3, 0, 12, 8, 0
    IccEoir0El1,    // 3, 0, 12, 8, 1
    IccHppir0El1,   // 3, 0, 12, 8, 2
    IccBpr0El1,     // 3, 0, 12, 8, 3
    IccAp0R0El1,    // 3, 0, 12, 8, 4
    IccAp0R1El1,    // 3, 0, 12, 8, 5
    IccAp0R2El1,    // 3, 0, 12, 8, 6
    IccAp0R3El1,    // 3, 0, 12, 8, 7
    IccAp1R0El1,    // 3, 0, 12, 9, 0
    IccAp1R1El1,    // 3, 0, 12, 9, 1
    IccDirEl1,      // 3, 0, 12, 11, 1
    IccRprEl1,      // 3, 0, 12, 11, 3
    IccSgi0REl1,    // 3, 0, 12, 11, 7
    IccSgi1REl1,    // 3, 0, 12, 11, 5
    IccAsgi1REl1,   // 3, 0, 12, 11, 6
    IccIar1El1,     // 3, 0, 12, 12, 0
    IccEoir1El1,    // 3, 0, 12, 12, 1
    IccHppir1El1,   // 3, 0, 12, 12, 2
    IccBpr1El1,     // 3, 0, 12, 12, 3
    IccCtlrEl1,     // 3, 0, 12, 12, 4
    IccSreEl1,      // 3, 0, 12, 12, 5
    IccIgrpen0El1,  // 3, 0, 12, 12, 6
    IccIgrpen1El1,  // 3, 0, 12, 12, 7
    IccSreEl2,      // 3, 4, 12, 9, 5
    IchHcrEl2,      // 3, 4, 12, 11, 0
    IchVtrEl2,      // 3, 4, 12, 11, 1
    IchMisrEl2,     // 3, 4, 12, 11, 2
    IchEisrEl2,     // 3, 4, 12, 11, 3
    IchElsrEl2,     // 3, 4, 12, 11, 5
    IchVmcrEl2,     // 3, 4, 12, 11, 7
    // ICH_LR0..ICH_LR15: CRm=12-13, op2=0-7
    IchLr0El2, IchLr1El2, IchLr2El2, IchLr3El2,
    IchLr4El2, IchLr5El2, IchLr6El2, IchLr7El2,
    IchLr8El2, IchLr9El2, IchLr10El2, IchLr11El2,
    IchLr12El2, IchLr13El2, IchLr14El2, IchLr15El2,
    IchAp0R0El2,    // 3, 4, 12, 8, 0
    IchAp0R1El2,    // 3, 4, 12, 8, 1
    IchAp0R2El2,    // 3, 4, 12, 8, 2
    IchAp0R3El2,    // 3, 4, 12, 8, 3
    IchAp1R0El2,    // 3, 4, 12, 9, 0
    IchAp1R1El2,    // 3, 4, 12, 9, 1
    IchAp1R2El2,    // 3, 4, 12, 9, 2
    IchAp1R3El2,    // 3, 4, 12, 9, 3
    IccSreEl3,      // 3, 6, 12, 12, 5
    IccCtlrEl3,     // 3, 6, 12, 12, 4
    IccIgrpen1El3,  // 3, 6, 12, 12, 7

    // ----- PMU (op0=3, op1=3, CRn=9) -----
    PmcrEl0,        // 3, 3, 9, 12, 0
    PmcntensetEl0,  // 3, 3, 9, 12, 1
    PmcntenclrEl0,  // 3, 3, 9, 12, 2
    PmovsclrEl0,    // 3, 3, 9, 12, 3
    PmswincEl0,     // 3, 3, 9, 12, 4
    PmselrEl0,      // 3, 3, 9, 12, 5
    PmceidEl0_0,    // 3, 3, 9, 12, 6
    PmceidEl0_1,    // 3, 3, 9, 12, 7
    PmccntrEl0,     // 3, 3, 9, 13, 0
    PmxevtyperEl0,  // 3, 3, 9, 13, 1
    PmxevcntrEl0,   // 3, 3, 9, 13, 2
    PmuserenrEl0,   // 3, 3, 9, 14, 0
    PmintensetEl1,  // 3, 0, 9, 14, 1
    PmintenclrEl1,  // 3, 0, 9, 14, 2
    PmovssetEl0,    // 3, 3, 9, 14, 3
    PmccfiltrEl0,   // 3, 3, 14, 15, 7

    // ----- Debug (op0=2, op1=0/3/4) -----
    OslarEl1,       // 2, 0, 1, 0, 4
    OslsrEl1,       // 2, 0, 1, 1, 4
    OsdlrEl1,       // 2, 0, 1, 3, 4
    DbgauthstatusEl1, // 2, 0, 7, 14, 6
    Mdscr_El1,      // 2, 0, 0, 2, 2
    MdccsrEl0,      // 2, 3, 0, 1, 0

    // ----- Pointer authentication keys (op0=3, op1=0, CRn=2, CRm=1-3) -----
    ApiaKeyLoEl1,   // 3, 0, 2, 1, 0
    ApiaKeyHiEl1,   // 3, 0, 2, 1, 1
    ApibKeyLoEl1,   // 3, 0, 2, 1, 2
    ApibKeyHiEl1,   // 3, 0, 2, 1, 3
    ApdaKeyLoEl1,   // 3, 0, 2, 2, 0
    ApdaKeyHiEl1,   // 3, 0, 2, 2, 1
    ApdbKeyLoEl1,   // 3, 0, 2, 2, 2
    ApdbKeyHiEl1,   // 3, 0, 2, 2, 3
    ApgaKeyLoEl1,   // 3, 0, 2, 3, 0
    ApgaKeyHiEl1,   // 3, 0, 2, 3, 1

    /// Decoded encoding is valid but not in the curated named catalog.
    OtherKnown(SysRegId),
}

/// Lookup a packed sysreg id against the catalog.
pub fn lookup(id: SysRegId) -> SysReg {
    use SysReg::*;
    let key = (id.op0(), id.op1(), id.crn(), id.crm(), id.op2());
    match key {
        // ----- Identification -----
        (3, 0, 0, 0, 0) => MidrEl1,
        (3, 0, 0, 0, 5) => MpidrEl1,
        (3, 0, 0, 0, 6) => RevidrEl1,
        (3, 1, 0, 0, 7) => AidrEl1,
        (3, 1, 0, 0, 0) => CcsidrEl1,
        (3, 1, 0, 0, 1) => ClidrEl1,
        (3, 2, 0, 0, 0) => CsselrEl1,
        (3, 3, 0, 0, 1) => CtrEl0,
        (3, 3, 0, 0, 7) => DczidEl0,

        (3, 0, 0, 4, 0) => IdAa64Pfr0El1,
        (3, 0, 0, 4, 1) => IdAa64Pfr1El1,
        (3, 0, 0, 4, 4) => IdAa64Zfr0El1,
        (3, 0, 0, 4, 5) => IdAa64Smfr0El1,
        (3, 0, 0, 5, 0) => IdAa64Dfr0El1,
        (3, 0, 0, 5, 1) => IdAa64Dfr1El1,
        (3, 0, 0, 5, 4) => IdAa64Afr0El1,
        (3, 0, 0, 5, 5) => IdAa64Afr1El1,
        (3, 0, 0, 6, 0) => IdAa64Isar0El1,
        (3, 0, 0, 6, 1) => IdAa64Isar1El1,
        (3, 0, 0, 6, 2) => IdAa64Isar2El1,
        (3, 0, 0, 7, 0) => IdAa64Mmfr0El1,
        (3, 0, 0, 7, 1) => IdAa64Mmfr1El1,
        (3, 0, 0, 7, 2) => IdAa64Mmfr2El1,

        // ----- System control -----
        (3, 0, 1, 0, 0) => SctlrEl1,
        (3, 0, 1, 0, 1) => ActlrEl1,
        (3, 0, 1, 0, 2) => CpacrEl1,
        (3, 4, 1, 0, 0) => SctlrEl2,
        (3, 4, 1, 0, 1) => ActlrEl2,
        (3, 4, 1, 1, 0) => HcrEl2,
        (3, 4, 1, 1, 1) => Mdcr_El2,
        (3, 4, 1, 1, 2) => CptrEl2,
        (3, 4, 1, 1, 3) => HstrEl2,
        (3, 4, 1, 1, 7) => HacrEl2,
        (3, 6, 1, 0, 0) => SctlrEl3,
        (3, 6, 1, 0, 1) => ActlrEl3,
        (3, 6, 1, 1, 0) => ScrEl3,

        // ----- Translation -----
        (3, 0, 2, 0, 0) => TtbrEl1_0,
        (3, 0, 2, 0, 1) => TtbrEl1_1,
        (3, 0, 2, 0, 2) => TcrEl1,
        (3, 4, 2, 0, 0) => TtbrEl2_0,
        (3, 4, 2, 0, 2) => TcrEl2,
        (3, 4, 2, 1, 0) => VttbrEl2,
        (3, 4, 2, 1, 2) => VtcrEl2,
        (3, 6, 2, 0, 0) => TtbrEl3_0,
        (3, 6, 2, 0, 2) => TcrEl3,

        // ----- Exception state -----
        (3, 0, 4, 0, 0) => SpsrEl1,
        (3, 0, 4, 0, 1) => ElrEl1,
        (3, 0, 4, 1, 0) => SpEl0,
        (3, 0, 4, 2, 0) => SpselEl1,
        (3, 0, 4, 2, 2) => CurrentEl,
        (3, 3, 4, 2, 0) => NzcvEl0,
        (3, 3, 4, 2, 1) => DaifEl0,
        (3, 3, 4, 4, 0) => FpcrEl0,
        (3, 3, 4, 4, 1) => FpsrEl0,
        (3, 4, 4, 0, 0) => SpsrEl2,
        (3, 4, 4, 0, 1) => ElrEl2,
        (3, 4, 4, 1, 0) => SpEl1,
        (3, 6, 4, 0, 0) => SpsrEl3,
        (3, 6, 4, 0, 1) => ElrEl3,
        (3, 6, 4, 1, 0) => SpEl2,

        // ----- Fault / Address syndrome -----
        (3, 0, 5, 1, 0) => Afsr0El1,
        (3, 0, 5, 1, 1) => Afsr1El1,
        (3, 0, 5, 2, 0) => EsrEl1,
        (3, 0, 6, 0, 0) => FarEl1,
        (3, 4, 5, 1, 0) => Afsr0El2,
        (3, 4, 5, 1, 1) => Afsr1El2,
        (3, 4, 5, 2, 0) => EsrEl2,
        (3, 4, 6, 0, 0) => FarEl2,
        (3, 4, 6, 0, 4) => Hpfar_El2,
        (3, 6, 5, 2, 0) => EsrEl3,
        (3, 6, 6, 0, 0) => FarEl3,

        // ----- Vector base -----
        (3, 0, 12, 0, 0) => VbarEl1,
        (3, 0, 12, 1, 0) => IsrEl1,
        (3, 4, 12, 0, 0) => VbarEl2,
        (3, 6, 12, 0, 0) => VbarEl3,

        // ----- Memory attributes -----
        (3, 0, 10, 2, 0) => MairEl1,
        (3, 0, 10, 3, 0) => AmairEl1,
        (3, 4, 10, 2, 0) => MairEl2,
        (3, 4, 10, 3, 0) => AmairEl2,
        (3, 6, 10, 2, 0) => MairEl3,
        (3, 6, 10, 3, 0) => AmairEl3,

        // ----- ContextIDR / TPIDR -----
        (3, 0, 13, 0, 1) => ContextidrEl1,
        (3, 4, 13, 0, 1) => ContextidrEl2,
        (3, 3, 13, 0, 2) => TpidrEl0,
        (3, 3, 13, 0, 3) => TpidrroEl0,
        (3, 0, 13, 0, 4) => TpidrEl1,
        (3, 4, 13, 0, 2) => TpidrEl2,
        (3, 6, 13, 0, 2) => TpidrEl3,

        // ----- Generic timer -----
        (3, 3, 14, 0, 0) => CntfrqEl0,
        (3, 3, 14, 0, 1) => CntpctEl0,
        (3, 3, 14, 0, 2) => CntvctEl0,
        (3, 3, 14, 2, 0) => CntpTvalEl0,
        (3, 3, 14, 2, 1) => CntpCtlEl0,
        (3, 3, 14, 2, 2) => CntpCvalEl0,
        (3, 3, 14, 3, 0) => CntvTvalEl0,
        (3, 3, 14, 3, 1) => CntvCtlEl0,
        (3, 3, 14, 3, 2) => CntvCvalEl0,
        (3, 0, 14, 1, 0) => CntkctlEl1,
        (3, 4, 14, 1, 0) => CnthctlEl2,
        (3, 4, 14, 2, 1) => CnthpCtlEl2,
        (3, 4, 14, 2, 2) => CnthpCvalEl2,
        (3, 4, 14, 2, 0) => CnthpTvalEl2,
        (3, 4, 14, 3, 1) => CnthvCtlEl2,
        (3, 4, 14, 3, 2) => CnthvCvalEl2,
        (3, 4, 14, 0, 3) => CntvoffEl2,
        (3, 7, 14, 2, 1) => CntpsCtlEl1,
        (3, 7, 14, 2, 2) => CntpsCvalEl1,

        // ----- GIC v3 CPU interface (EL1) -----
        (3, 0, 4, 6, 0) => IccPmrEl1,
        (3, 0, 12, 8, 0) => IccIar0El1,
        (3, 0, 12, 8, 1) => IccEoir0El1,
        (3, 0, 12, 8, 2) => IccHppir0El1,
        (3, 0, 12, 8, 3) => IccBpr0El1,
        (3, 0, 12, 8, 4) => IccAp0R0El1,
        (3, 0, 12, 8, 5) => IccAp0R1El1,
        (3, 0, 12, 8, 6) => IccAp0R2El1,
        (3, 0, 12, 8, 7) => IccAp0R3El1,
        (3, 0, 12, 9, 0) => IccAp1R0El1,
        (3, 0, 12, 9, 1) => IccAp1R1El1,
        (3, 0, 12, 11, 1) => IccDirEl1,
        (3, 0, 12, 11, 3) => IccRprEl1,
        (3, 0, 12, 11, 5) => IccSgi1REl1,
        (3, 0, 12, 11, 6) => IccAsgi1REl1,
        (3, 0, 12, 11, 7) => IccSgi0REl1,
        (3, 0, 12, 12, 0) => IccIar1El1,
        (3, 0, 12, 12, 1) => IccEoir1El1,
        (3, 0, 12, 12, 2) => IccHppir1El1,
        (3, 0, 12, 12, 3) => IccBpr1El1,
        (3, 0, 12, 12, 4) => IccCtlrEl1,
        (3, 0, 12, 12, 5) => IccSreEl1,
        (3, 0, 12, 12, 6) => IccIgrpen0El1,
        (3, 0, 12, 12, 7) => IccIgrpen1El1,
        // ----- GIC v3 hypervisor (EL2) -----
        (3, 4, 12, 9, 5) => IccSreEl2,
        (3, 4, 12, 11, 0) => IchHcrEl2,
        (3, 4, 12, 11, 1) => IchVtrEl2,
        (3, 4, 12, 11, 2) => IchMisrEl2,
        (3, 4, 12, 11, 3) => IchEisrEl2,
        (3, 4, 12, 11, 5) => IchElsrEl2,
        (3, 4, 12, 11, 7) => IchVmcrEl2,
        (3, 4, 12, 12, 0) => IchLr0El2,
        (3, 4, 12, 12, 1) => IchLr1El2,
        (3, 4, 12, 12, 2) => IchLr2El2,
        (3, 4, 12, 12, 3) => IchLr3El2,
        (3, 4, 12, 12, 4) => IchLr4El2,
        (3, 4, 12, 12, 5) => IchLr5El2,
        (3, 4, 12, 12, 6) => IchLr6El2,
        (3, 4, 12, 12, 7) => IchLr7El2,
        (3, 4, 12, 13, 0) => IchLr8El2,
        (3, 4, 12, 13, 1) => IchLr9El2,
        (3, 4, 12, 13, 2) => IchLr10El2,
        (3, 4, 12, 13, 3) => IchLr11El2,
        (3, 4, 12, 13, 4) => IchLr12El2,
        (3, 4, 12, 13, 5) => IchLr13El2,
        (3, 4, 12, 13, 6) => IchLr14El2,
        (3, 4, 12, 13, 7) => IchLr15El2,
        (3, 4, 12, 8, 0) => IchAp0R0El2,
        (3, 4, 12, 8, 1) => IchAp0R1El2,
        (3, 4, 12, 8, 2) => IchAp0R2El2,
        (3, 4, 12, 8, 3) => IchAp0R3El2,
        (3, 4, 12, 9, 0) => IchAp1R0El2,
        (3, 4, 12, 9, 1) => IchAp1R1El2,
        (3, 4, 12, 9, 2) => IchAp1R2El2,
        (3, 4, 12, 9, 3) => IchAp1R3El2,
        // ----- GIC v3 (EL3) -----
        (3, 6, 12, 12, 4) => IccCtlrEl3,
        (3, 6, 12, 12, 5) => IccSreEl3,
        (3, 6, 12, 12, 7) => IccIgrpen1El3,

        // ----- PMU -----
        (3, 3, 9, 12, 0) => PmcrEl0,
        (3, 3, 9, 12, 1) => PmcntensetEl0,
        (3, 3, 9, 12, 2) => PmcntenclrEl0,
        (3, 3, 9, 12, 3) => PmovsclrEl0,
        (3, 3, 9, 12, 4) => PmswincEl0,
        (3, 3, 9, 12, 5) => PmselrEl0,
        (3, 3, 9, 12, 6) => PmceidEl0_0,
        (3, 3, 9, 12, 7) => PmceidEl0_1,
        (3, 3, 9, 13, 0) => PmccntrEl0,
        (3, 3, 9, 13, 1) => PmxevtyperEl0,
        (3, 3, 9, 13, 2) => PmxevcntrEl0,
        (3, 3, 9, 14, 0) => PmuserenrEl0,
        (3, 0, 9, 14, 1) => PmintensetEl1,
        (3, 0, 9, 14, 2) => PmintenclrEl1,
        (3, 3, 9, 14, 3) => PmovssetEl0,
        (3, 3, 14, 15, 7) => PmccfiltrEl0,

        // ----- Debug -----
        (2, 0, 1, 0, 4) => OslarEl1,
        (2, 0, 1, 1, 4) => OslsrEl1,
        (2, 0, 1, 3, 4) => OsdlrEl1,
        (2, 0, 7, 14, 6) => DbgauthstatusEl1,
        (2, 0, 0, 2, 2) => Mdscr_El1,
        (2, 3, 0, 1, 0) => MdccsrEl0,

        // ----- Pointer authentication -----
        (3, 0, 2, 1, 0) => ApiaKeyLoEl1,
        (3, 0, 2, 1, 1) => ApiaKeyHiEl1,
        (3, 0, 2, 1, 2) => ApibKeyLoEl1,
        (3, 0, 2, 1, 3) => ApibKeyHiEl1,
        (3, 0, 2, 2, 0) => ApdaKeyLoEl1,
        (3, 0, 2, 2, 1) => ApdaKeyHiEl1,
        (3, 0, 2, 2, 2) => ApdbKeyLoEl1,
        (3, 0, 2, 2, 3) => ApdbKeyHiEl1,
        (3, 0, 2, 3, 0) => ApgaKeyLoEl1,
        (3, 0, 2, 3, 1) => ApgaKeyHiEl1,

        _ => OtherKnown(id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_id_roundtrip() {
        let id = SysRegId::new(3, 0, 1, 0, 0);
        assert_eq!(id.op0(), 3);
        assert_eq!(id.op1(), 0);
        assert_eq!(id.crn(), 1);
        assert_eq!(id.crm(), 0);
        assert_eq!(id.op2(), 0);
        assert_eq!(lookup(id), SysReg::SctlrEl1);
    }

    #[test]
    fn known_named_regs() {
        // Spot-check 8 representative entries to catch typos in the lookup table.
        assert_eq!(lookup(SysRegId::new(3, 0, 0, 0, 0)), SysReg::MidrEl1);
        assert_eq!(lookup(SysRegId::new(3, 3, 0, 0, 1)), SysReg::CtrEl0);
        assert_eq!(lookup(SysRegId::new(3, 4, 1, 1, 0)), SysReg::HcrEl2);
        assert_eq!(lookup(SysRegId::new(3, 4, 2, 1, 2)), SysReg::VtcrEl2);
        assert_eq!(lookup(SysRegId::new(3, 0, 12, 0, 0)), SysReg::VbarEl1);
        assert_eq!(lookup(SysRegId::new(3, 3, 14, 0, 2)), SysReg::CntvctEl0);
        assert_eq!(lookup(SysRegId::new(3, 4, 12, 12, 0)), SysReg::IchLr0El2);
        assert_eq!(lookup(SysRegId::new(3, 3, 13, 0, 2)), SysReg::TpidrEl0);
    }

    #[test]
    fn unknown_named_returns_other_known() {
        // An invalid encoding (we hope) — bits all zero is reserved.
        let id = SysRegId::new(0, 0, 0, 0, 0);
        assert!(matches!(lookup(id), SysReg::OtherKnown(_)));
    }
}
