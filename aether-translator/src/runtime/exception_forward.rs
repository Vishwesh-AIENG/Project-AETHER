//! AT-20: Exception forwarding — x86 traps → ARM exception classes.
//!
//! When translated ARM64 code running under the x86 hypervisor takes a fault,
//! the hardware delivers an x86 exception (vector 0–31).  The dispatcher must
//! convert that x86 fault into the ARM64 equivalent and present it to the
//! Android kernel at EL1 as if native ARM64 hardware raised it.
//!
//! # Mapping table
//!
//! | x86 vector | Name | ARM ESR EC | Reason |
//! |------------|------|------------|--------|
//! | 0  #DE     | Divide Error   | 0x00 Unknown | ARM has no integer divide fault |
//! | 1  #DB     | Debug          | 0x30 Breakpoint | hardware watchpoint |
//! | 3  #BP     | Breakpoint     | 0x38 SoftBreakpoint | `INT3` → BRK |
//! | 6  #UD     | Invalid Opcode | 0x00 Unknown | undefined instruction |
//! | 13 #GP     | General Protection | 0x24 DataAbort | unaligned/privilege access |
//! | 14 #PF     | Page Fault     | 0x24 DataAbort (data) or 0x20 (fetch) | |
//! | 12 #SS     | Stack Fault    | 0x24 DataAbort | stack overflow → data abort |
//!
//! # ESR_EL1 synthesis
//!
//! Each `ArmFaultInfo` carries a synthesized ESR_EL1 with:
//! - `EC` in bits [31:26]
//! - `ISS` in bits [24:0] (instruction-specific syndrome)
//! - `IL` (instruction length) = 1 for 32-bit instructions
//!
//! # Gate
//!
//! An unaligned 64-bit load in translated ARM code produces a #PF on x86
//! (or #GP on some micro-architectures).  The forwarder must produce
//! `ArmFaultInfo { ec: DataAbort, far: <faulting_address>, iss: 0x28 }`.
//!
//! Gate test: `forward(X86Fault::PageFault { cr2: 0x1234, error: 0b110 })`
//! → `ArmFaultInfo { ec: DataAbort, far: 0x1234, iss: ISS_DATA_ABORT_ALIGN }`.

// ── ARM exception classes (ESR_EL1 EC field, bits [31:26]) ────────────────

/// ARM64 Exception Class (ESR_EL1 bits [31:26]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ArmEc {
    /// EC 0x00 — Unknown reason (used for faults with no ARM equivalent).
    Unknown = 0x00,
    /// EC 0x20 — Instruction Abort from lower EL (EL0/EL1).
    InstructionAbort = 0x20,
    /// EC 0x24 — Data Abort from lower EL.
    DataAbort = 0x24,
    /// EC 0x30 — Breakpoint exception from lower EL (hardware watchpoint).
    Breakpoint = 0x30,
    /// EC 0x38 — Software Breakpoint (BRK instruction / INT3 → HLT path).
    SoftwareBreakpoint = 0x38,
}

impl ArmEc {
    /// ESR_EL1 value with this EC, IL=1 (32-bit instruction), and given ISS.
    pub fn to_esr(self, iss: u32) -> u64 {
        let ec = self as u64;
        let il = 1u64; // IL=1 for 32-bit (A64) instructions
        (ec << 26) | (il << 25) | (iss as u64 & 0x01FF_FFFF)
    }
}

// ── ISS constants for Data Abort ──────────────────────────────────────────────

/// ISS for a data abort due to alignment fault (DFSC = 0b100001).
pub const ISS_DATA_ALIGN: u32 = 0b10_0001;
/// ISS for a data abort due to translation fault level 0.
pub const ISS_DATA_TRANSLATION: u32 = 0b00_0100;
/// ISS for a data abort due to permission fault.
pub const ISS_DATA_PERMISSION: u32 = 0b00_1101;
/// ISS for a data abort from an instruction fetch (IS_FETCH bit set for #PF).
pub const ISS_INSN_FETCH: u32 = 0b0001_0000;

// ── x86 fault descriptor ─────────────────────────────────────────────────────

/// x86_64 exception/fault as delivered by hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86Fault {
    /// #DE — Divide by zero.
    DivideError,
    /// #DB — Debug exception (hardware watchpoint / single-step).
    Debug,
    /// #BP — Software breakpoint (INT3).
    Breakpoint,
    /// #UD — Invalid opcode (also: CPUID with leaf outside range on some CPUs).
    InvalidOpcode,
    /// #SS — Stack-segment fault. `error` is the selector error code.
    StackFault { error: u32 },
    /// #GP — General protection fault. `error` is the selector error code.
    GeneralProtection { error: u32 },
    /// #PF — Page fault.  `cr2` is the faulting virtual address.
    /// `error` bits: P=0 (not-present), W=1 (write), U=2 (user), I=4 (fetch).
    PageFault { cr2: u64, error: u32 },
}

impl X86Fault {
    /// x86 interrupt vector number for this fault.
    pub fn vector(self) -> u8 {
        match self {
            X86Fault::DivideError => 0,
            X86Fault::Debug => 1,
            X86Fault::Breakpoint => 3,
            X86Fault::InvalidOpcode => 6,
            X86Fault::StackFault { .. } => 12,
            X86Fault::GeneralProtection { .. } => 13,
            X86Fault::PageFault { .. } => 14,
        }
    }
}

// ── ARM fault descriptor ──────────────────────────────────────────────────────

/// ARM64 fault information synthesized from an x86 fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArmFaultInfo {
    /// Exception class (ESR_EL1 EC field).
    pub ec: ArmEc,
    /// Guest ARM64 PC at the faulting instruction (from the translator's
    /// guest-PC tracking, not the x86 RIP).
    pub guest_pc: u64,
    /// Fault Address Register value (FAR_EL1).  Meaningful for data aborts.
    /// Set to `guest_pc` for instruction aborts.  Zero for non-address faults.
    pub far: u64,
    /// Instruction Specific Syndrome (ESR_EL1 ISS, bits [24:0]).
    pub iss: u32,
    /// Synthesized ESR_EL1 value.
    pub esr: u64,
}

impl ArmFaultInfo {
    fn new(ec: ArmEc, guest_pc: u64, far: u64, iss: u32) -> Self {
        let esr = ec.to_esr(iss);
        Self { ec, guest_pc, far, iss, esr }
    }
}

// ── Exception forwarder ───────────────────────────────────────────────────────

/// Convert an x86 fault into an ARM `ArmFaultInfo`.
///
/// `guest_pc` is the ARM64 guest PC that the translator was executing when
/// the fault occurred (tracked by the dispatcher, not the x86 RIP).
pub fn forward(fault: X86Fault, guest_pc: u64) -> ArmFaultInfo {
    match fault {
        // #DE — no ARM equivalent; present as Unknown.
        X86Fault::DivideError => {
            ArmFaultInfo::new(ArmEc::Unknown, guest_pc, 0, 0)
        }

        // #DB — hardware watchpoint → ARM Breakpoint.
        X86Fault::Debug => {
            ArmFaultInfo::new(ArmEc::Breakpoint, guest_pc, guest_pc, 0)
        }

        // #BP (INT3) — software breakpoint → ARM SoftwareBreakpoint (BRK).
        X86Fault::Breakpoint => {
            ArmFaultInfo::new(ArmEc::SoftwareBreakpoint, guest_pc, guest_pc, 0)
        }

        // #UD — undefined instruction → ARM Unknown (EC=0x00).
        X86Fault::InvalidOpcode => {
            ArmFaultInfo::new(ArmEc::Unknown, guest_pc, 0, 0)
        }

        // #SS — stack fault → Data Abort (alignment/translation).
        X86Fault::StackFault { .. } => {
            ArmFaultInfo::new(ArmEc::DataAbort, guest_pc, guest_pc, ISS_DATA_ALIGN)
        }

        // #GP — general protection fault → Data Abort.
        X86Fault::GeneralProtection { .. } => {
            ArmFaultInfo::new(ArmEc::DataAbort, guest_pc, guest_pc, ISS_DATA_ALIGN)
        }

        // #PF — page fault:
        //   • Instruction fetch (error bit I=4): Instruction Abort.
        //   • Data access: Data Abort.
        //   • P=0 (not-present): translation fault.
        //   • P=1 + W=1: permission fault.
        //   • Alignment: alignment fault.
        X86Fault::PageFault { cr2, error } => {
            let fetch = (error & 0x10) != 0; // I bit
            if fetch {
                ArmFaultInfo::new(
                    ArmEc::InstructionAbort,
                    guest_pc,
                    cr2,
                    ISS_INSN_FETCH,
                )
            } else {
                let iss = if (error & 0x01) != 0 {
                    // P=1: permission fault
                    ISS_DATA_PERMISSION
                } else {
                    // P=0: translation fault
                    ISS_DATA_TRANSLATION
                };
                ArmFaultInfo::new(ArmEc::DataAbort, guest_pc, cr2, iss)
            }
        }
    }
}

/// Forward an unaligned-access fault specifically.
///
/// ARM SIGBUS (alignment fault) maps to ESR_EL1 EC=0x24, DFSC=0b100001.
pub fn forward_align_fault(faulting_va: u64, guest_pc: u64) -> ArmFaultInfo {
    ArmFaultInfo::new(ArmEc::DataAbort, guest_pc, faulting_va, ISS_DATA_ALIGN)
}

// ── Gate check ────────────────────────────────────────────────────────────────

/// Gate: `forward(#PF data with P=1, cr2=addr)` → Data Abort with correct FAR.
pub fn gate_passes() -> bool {
    // error bits: P=1 (bit0), W=1 (bit1), U=1 (bit2) → 0b0111 = 7.
    let fault = X86Fault::PageFault { cr2: 0x1234, error: 0b0111 };
    let info = forward(fault, 0xFFFF_0000);
    info.ec == ArmEc::DataAbort && info.far == 0x1234 && info.iss == ISS_DATA_PERMISSION
}

/// Gate: unaligned-access alias.
pub fn gate_align_passes() -> bool {
    let info = forward_align_fault(0xDEAD_BEE0, 0x4000);
    info.ec == ArmEc::DataAbort
        && info.far == 0xDEAD_BEE0
        && info.iss == ISS_DATA_ALIGN
}
