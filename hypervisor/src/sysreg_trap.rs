// sysreg_trap.rs — decode + policy for EC 0x18 (trapped MSR/MRS/SYS) exits.
//
// Target-agnostic on purpose: the arm64 exception handler (aarch64-only) does
// the actual MRS/MSR/DC work, while this pure decode/classify logic is unit-
// tested on the host. See arm64/exception.rs handle_sysreg_trap.

/// Decoded system-register access from an EC 0x18 ISS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SysRegAccess {
    pub op0: u8,
    pub op1: u8,
    pub crn: u8,
    pub crm: u8,
    pub op2: u8,
    pub rt: usize,
    pub is_read: bool,
}

impl SysRegAccess {
    pub fn decode(esr: u64) -> Self {
        let iss = esr & 0x01FF_FFFF;
        Self {
            op0: ((iss >> 20) & 0x3) as u8,
            op2: ((iss >> 17) & 0x7) as u8,
            op1: ((iss >> 14) & 0x7) as u8,
            crn: ((iss >> 10) & 0xF) as u8,
            rt: ((iss >> 5) & 0x1F) as usize,
            crm: ((iss >> 1) & 0xF) as u8,
            is_read: iss & 1 != 0,
        }
    }

    /// ID register group 3 (TID3): Op0=3, Op1=0, CRn=0, CRm=1..7.
    pub fn is_id_group3(&self) -> bool {
        self.op0 == 3 && self.op1 == 0 && self.crn == 0 && (1..=7).contains(&self.crm)
    }
}

/// What the EC 0x18 handler does with an access (pure; unit-tested).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysRegAction {
    /// Read the real register at EL2 and return it in Rt.
    ReadHardwareId,
    /// Read as zero / write ignored.
    RazWi,
    /// Data-cache maintenance by set/way: perform DC CISW with Rt's value.
    SetWayClean,
    /// Guest SGI generation (ICC_SGI1R_EL1 / ICC_ASGI1R_EL1 write). Always
    /// traps under HCR_EL2.IMO=1; EL2 re-issues it physically (vCPUs are
    /// pinned 1:1 to cores with identity MPIDR) and the target core's EL2
    /// injects it as a virtual SGI.
    ForwardSgi { alias: bool },
    /// Not emulated: inject an UNDEFINED exception into the guest.
    InjectUndef,
}

pub fn classify_sysreg(a: &SysRegAccess) -> SysRegAction {
    match (a.op0, a.op1, a.crn, a.crm, a.op2) {
        _ if a.is_id_group3() && a.is_read => SysRegAction::ReadHardwareId,
        // TID1: REVIDR_EL1 (3,0,0,0,6) and AIDR_EL1 (3,1,0,0,7).
        (3, 0, 0, 0, 6) | (3, 1, 0, 0, 7) if a.is_read => SysRegAction::ReadHardwareId,
        // TACR: ACTLR_EL1 (3,0,1,0,1).
        (3, 0, 1, 0, 1) => SysRegAction::RazWi,
        // TSW: DC ISW (1,0,7,6,2), DC CSW (1,0,7,10,2), DC CISW (1,0,7,14,2).
        (1, 0, 7, 6, 2) | (1, 0, 7, 10, 2) | (1, 0, 7, 14, 2) => SysRegAction::SetWayClean,
        // ICC_SGI1R_EL1 (3,0,12,11,5) / ICC_ASGI1R_EL1 (3,0,12,11,6) writes.
        // ICC_SGI0R_EL1 (Group 0 / FIQ) is not offered to the guest -> UNDEF.
        (3, 0, 12, 11, 5) if !a.is_read => SysRegAction::ForwardSgi { alias: false },
        (3, 0, 12, 11, 6) if !a.is_read => SysRegAction::ForwardSgi { alias: true },
        _ => SysRegAction::InjectUndef,
    }
}

/// Mask out ID-register fields for features AETHER's EL2 does not host.
///
/// The guest sees the REAL hardware value (identity, revision, every feature
/// EL2 passes through untouched) — only features whose EL1 state EL2 neither
/// context-switches nor configures are reported as "not implemented", exactly
/// like KVM's sanitised view. Advertising them makes the guest touch state
/// that traps or is unmanaged (observed: ID_AA64PFR1.SME → sme_kernel_enable
/// UNDEF at boot). The target Snapdragon X implements none of these anyway.
///
/// `crm`/`op2` select the register within ID group 3 (Op0=3, Op1=0, CRn=0).
pub fn sanitize_id(crm: u8, op2: u8, value: u64) -> u64 {
    const fn field(lsb: u32) -> u64 { 0xF << lsb }
    let hide = match (crm, op2) {
        // ID_AA64PFR0_EL1: SVE[35:32], MPAM[43:40], AMU[47:44], RME[55:52].
        (4, 0) => field(32) | field(40) | field(44) | field(52),
        // ID_AA64PFR1_EL1: MTE[11:8], MPAM_frac[19:16], SME[27:24], MTE_frac[43:40].
        (4, 1) => field(8) | field(16) | field(24) | field(40),
        // ID_AA64ZFR0_EL1 (SVE features), ID_AA64SMFR0_EL1 (SME features).
        (4, 4) | (4, 5) => u64::MAX,
        // ID_AA64DFR0_EL1: PMSVer/SPE[35:32], TraceBuffer[47:44], BRBE[55:52].
        (5, 0) => field(32) | field(44) | field(52),
        _ => 0,
    };
    value & !hide
}
#[cfg(test)]
mod tests {
    use super::*;

    /// Build an EC 0x18 ESR from fields (inverse of SysRegAccess::decode).
    fn esr(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64, rt: u64, read: bool) -> u64 {
        (0x18 << 26) | (1 << 25) | (op0 << 20) | (op2 << 17) | (op1 << 14)
            | (crn << 10) | (rt << 5) | (crm << 1) | read as u64
    }

    #[test]
    fn decodes_the_observed_kernel_trap() {
        // ESR 0x6230002b from the QEMU boot: MRS x1, ID_AA64DFR0_EL1.
        let a = SysRegAccess::decode(0x6230_002B);
        assert_eq!((a.op0, a.op1, a.crn, a.crm, a.op2, a.rt, a.is_read), (3, 0, 0, 5, 0, 1, true));
        assert_eq!(classify_sysreg(&a), SysRegAction::ReadHardwareId);
    }

    #[test]
    fn decode_roundtrips() {
        let a = SysRegAccess::decode(esr(3, 0, 0, 4, 1, 17, true));
        assert_eq!((a.op0, a.op1, a.crn, a.crm, a.op2, a.rt, a.is_read), (3, 0, 0, 4, 1, 17, true));
    }

    #[test]
    fn classifies_trap_groups() {
        let c = |e| classify_sysreg(&SysRegAccess::decode(e));
        assert_eq!(c(esr(3, 0, 0, 7, 2, 0, true)), SysRegAction::ReadHardwareId); // ID_AA64MMFR2
        assert_eq!(c(esr(3, 0, 0, 0, 6, 0, true)), SysRegAction::ReadHardwareId); // REVIDR
        assert_eq!(c(esr(3, 1, 0, 0, 7, 0, true)), SysRegAction::ReadHardwareId); // AIDR
        assert_eq!(c(esr(3, 0, 0, 4, 0, 0, false)), SysRegAction::InjectUndef);   // write to RO ID reg
        assert_eq!(c(esr(3, 0, 1, 0, 1, 0, true)), SysRegAction::RazWi);          // ACTLR_EL1 read
        assert_eq!(c(esr(3, 0, 1, 0, 1, 0, false)), SysRegAction::RazWi);         // ACTLR_EL1 write
        assert_eq!(c(esr(1, 0, 7, 14, 2, 3, false)), SysRegAction::SetWayClean);  // DC CISW
        assert_eq!(c(esr(1, 0, 7, 6, 2, 3, false)), SysRegAction::SetWayClean);   // DC ISW
        assert_eq!(c(esr(3, 1, 15, 2, 0, 0, true)), SysRegAction::InjectUndef);   // TIDCP impl-def
        // The observed IPI trap: d518cba0 = MSR ICC_SGI1R_EL1, x0.
        assert_eq!(c(esr(3, 0, 12, 11, 5, 0, false)), SysRegAction::ForwardSgi { alias: false });
        assert_eq!(c(esr(3, 0, 12, 11, 6, 0, false)), SysRegAction::ForwardSgi { alias: true });
        assert_eq!(c(esr(3, 0, 12, 11, 7, 0, false)), SysRegAction::InjectUndef); // SGI0R
        // MIDR (3,0,0,0,0) is never trapped (VPIDR_EL2 path) and must not be emulated here.
        assert_eq!(c(esr(3, 0, 0, 0, 0, 0, true)), SysRegAction::InjectUndef);
    }

    #[test]
    fn sanitize_hides_only_unhosted_features() {
        // SME + MTE advertised in PFR1 → hidden; other PFR1 fields (BT, SSBS) kept.
        let pfr1 = (2u64 << 24) | (2 << 8) | (1 << 4) | 1;
        assert_eq!(sanitize_id(4, 1, pfr1), (1 << 4) | 1);
        // PFR0: SVE hidden, EL0..EL3 + FP/AdvSIMD + GIC fields untouched.
        let pfr0 = (1u64 << 32) | 0x0100_1111; // SVE + GIC[27:24]=1 + EL0..EL3
        assert_eq!(sanitize_id(4, 0, pfr0), 0x0100_1111);
        // ZFR0/SMFR0 fully hidden; MMFR registers (CRm=7) pass through.
        assert_eq!(sanitize_id(4, 4, u64::MAX), 0);
        assert_eq!(sanitize_id(4, 5, u64::MAX), 0);
        assert_eq!(sanitize_id(7, 0, 0x1234_5678), 0x1234_5678);
        // DFR0: SPE/TRBE/BRBE hidden, DebugVer[3:0] + PMUVer[11:8] kept.
        let dfr0 = (1u64 << 52) | (1 << 44) | (1 << 32) | (6 << 8) | 6;
        assert_eq!(sanitize_id(5, 0, dfr0), (6 << 8) | 6);
    }
}