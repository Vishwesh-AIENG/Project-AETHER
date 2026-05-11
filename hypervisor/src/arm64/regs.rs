// ch04: ARM64 system register access
//
// ARM64 system registers are accessed exclusively through two instructions:
//   MRS  Xd, <register>   — read system register into Xd
//   MSR  <register>, Xn   — write Xn into system register
//
// There is no memory-mapped access. Every register has a name that encodes
// both its function and the exception level at which it is accessible
// (e.g. SCTLR_EL1 vs SCTLR_EL2 are different registers).
//
// All register names and bit field positions in this file are verified
// against: linux-ref/arch/arm64/tools/sysreg
// Cross-checked with: ARM ARM DDI0487 Appendix G
//
// The skill guide (aether-skills/part-02-silicon/ch04-arm64-substrate.md)
// explicitly warns that Claude confuses EL suffixes. Every suffix here has
// been checked against the sysreg source before being written.

use core::arch::asm;

// ─────────────────────────────────────────────────────────────────────────────
// Read/write macros
//
// These expand to a single MRS or MSR instruction. The register name is a
// string literal consumed directly by the assembler — it is never a Rust
// identifier. This means the assembler (not the Rust compiler) validates the
// name against its own register table, giving us a second verification layer.
// ─────────────────────────────────────────────────────────────────────────────

/// Read a system register into a u64.
///
/// # Safety
/// Caller must be executing at an exception level that has read access to
/// the named register. Reading a register at the wrong EL causes an
/// Undefined Instruction exception.
///
/// # Example
/// ```rust
/// let val: u64 = unsafe { read_sysreg!("currentel") };
/// ```
#[macro_export]
macro_rules! read_sysreg {
    ($reg:literal) => {{
        let val: u64;
        unsafe {
            core::arch::asm!(
                concat!("mrs {}, ", $reg),
                out(reg) val,
                options(nomem, nostack, preserves_flags)
            );
        }
        val
    }};
}

/// Write a u64 into a system register.
///
/// # Safety
/// Caller must be executing at an exception level that has write access to
/// the named register. Writing a register at the wrong EL causes an
/// Undefined Instruction exception. Many registers require an ISB after
/// writing for the change to take effect — the caller is responsible for
/// issuing the appropriate barrier (see `barriers` module).
#[macro_export]
macro_rules! write_sysreg {
    ($reg:literal, $val:expr) => {{
        let val: u64 = $val;
        unsafe {
            core::arch::asm!(
                concat!("msr ", $reg, ", {}"),
                in(reg) val,
                options(nomem, nostack, preserves_flags)
            );
        }
    }};
}

// ─────────────────────────────────────────────────────────────────────────────
// CurrentEL — read the current exception level
//
// Bits [3:2] of CurrentEL encode the EL:
//   0b00 → EL0,  0b01 → EL1,  0b10 → EL2,  0b11 → EL3
//
// Source: ARM ARM DDI0487 Section D1.2.1
// Verified: linux-ref/arch/arm64/tools/sysreg line "Sysreg CurrentEL"
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the exception level from a `CurrentEL` register value.
#[inline]
pub fn current_el_from_reg(val: u64) -> u8 {
    ((val >> 2) & 0b11) as u8
}

/// Read the processor's current exception level (0–3).
///
/// AETHER should always read 2 (EL2) when this executes. If it returns
/// anything else the boot sequence has gone wrong.
///
/// # Safety
/// `CurrentEL` is always readable at any exception level.
#[inline]
pub unsafe fn current_el() -> u8 {
    let raw: u64;
    unsafe {
        asm!(
            "mrs {}, CurrentEL",
            out(reg) raw,
            options(nomem, nostack, preserves_flags)
        );
    }
    current_el_from_reg(raw)
}

// ─────────────────────────────────────────────────────────────────────────────
// SCTLR_EL2 — System Control Register (EL2)
//
// Controls the MMU, instruction cache, data cache, and stack alignment
// checking for EL2. AETHER configures this early in boot.
//
// Bit positions verified against linux-ref/arch/arm64/include/asm/sysreg.h
// macros SCTLR_ELx_M, SCTLR_ELx_C, SCTLR_ELx_I, SCTLR_ELx_SA, SCTLR_ELx_WXN
// ─────────────────────────────────────────────────────────────────────────────

pub mod sctlr_el2 {
    /// Bit 0 — M: MMU enable for EL2 stage 1 translation.
    pub const M:   u64 = 1 << 0;
    /// Bit 2 — C: Data cache enable.
    pub const C:   u64 = 1 << 2;
    /// Bit 3 — SA: Stack alignment check enable.
    pub const SA:  u64 = 1 << 3;
    /// Bit 12 — I: Instruction cache enable.
    pub const I:   u64 = 1 << 12;
    /// Bit 19 — WXN: Write permission implies XN (write-no-execute).
    pub const WXN: u64 = 1 << 19;
}

/// Read SCTLR_EL2.
///
/// # Safety
/// Must be called from EL2.
#[inline]
pub unsafe fn read_sctlr_el2() -> u64 {
    let v: u64;
    unsafe {
        asm!("mrs {}, sctlr_el2", out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// Write SCTLR_EL2.
///
/// # Safety
/// Must be called from EL2. An ISB is required after this write before
/// the new settings take effect for instruction fetch.
#[inline]
pub unsafe fn write_sctlr_el2(val: u64) {
    unsafe {
        asm!("msr sctlr_el2, {}", in(reg) val,
             options(nomem, nostack, preserves_flags));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HCR_EL2 — Hypervisor Configuration Register
//
// The single most important register in the virtualization architecture.
// Controls which guest operations trap to EL2 and whether Stage 2
// translation is active.
//
// Bit positions from: linux-ref/arch/arm64/tools/sysreg
//   (Sysreg HCR_EL2  3 4 1 1 0, fields listed Bit → Name)
// Cross-checked with: ARM ARM DDI0487 Section G4, Table G4-1
//
// WARNING (from skill guide): Claude frequently gets HCR_EL2 bit positions
// wrong. Every constant below is from the sysreg tool, not from Claude's
// training data.
// ─────────────────────────────────────────────────────────────────────────────

pub mod hcr_el2 {
    /// Bit 0 — VM: Enable Stage 2 address translation.
    /// Must be 1 for any guest that uses memory.
    pub const VM:   u64 = 1 << 0;
    /// Bit 1 — SWIO: Set/Way Invalidate Override.
    /// Forces DC ISW/CSW operations to include clean.
    pub const SWIO: u64 = 1 << 1;
    /// Bit 2 — PTW: Protected Table Walk.
    /// Faults stage 1 page table walks through device memory.
    pub const PTW:  u64 = 1 << 2;
    /// Bit 3 — FMO: Physical FIQ routing override.
    /// Routes physical FIQs to EL2. Required for AETHER to receive FIQs.
    pub const FMO:  u64 = 1 << 3;
    /// Bit 4 — IMO: Physical IRQ routing override.
    /// Routes physical IRQs to EL2. Required for AETHER to receive IRQs.
    pub const IMO:  u64 = 1 << 4;
    /// Bit 5 — AMO: Physical SError routing override.
    /// Routes physical SError to EL2.
    pub const AMO:  u64 = 1 << 5;
    /// Bit 13 — TWI: Trap WFI.
    /// Guest WFI instructions trap to EL2. AETHER intercepts idle.
    pub const TWI:  u64 = 1 << 13;
    /// Bit 14 — TWE: Trap WFE.
    /// Guest WFE instructions trap to EL2.
    pub const TWE:  u64 = 1 << 14;
    /// Bit 19 — TSC: Trap SMC.
    /// Guest SMC instructions trap to EL2 instead of reaching EL3.
    pub const TSC:  u64 = 1 << 19;
    /// Bit 26 — TVM: Trap Virtual Memory controls.
    /// Traps guest writes to EL1 virtual memory control registers.
    pub const TVM:  u64 = 1 << 26;
    /// Bit 31 — RW: Lower exception level is AArch64.
    /// Must be 1 for 64-bit guests (both Windows-on-ARM and Android Linux).
    pub const RW:   u64 = 1 << 31;
    /// Bit 34 — E2H: EL2 Host (VHE mode).
    /// AETHER uses nVHE (this bit stays 0) for stronger isolation.
    pub const E2H:  u64 = 1 << 34;
}

/// Read HCR_EL2.
///
/// # Safety
/// Must be called from EL2.
#[inline]
pub unsafe fn read_hcr_el2() -> u64 {
    let v: u64;
    unsafe {
        asm!("mrs {}, hcr_el2", out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// Write HCR_EL2.
///
/// # Safety
/// Must be called from EL2. Changes take effect immediately — no ISB needed
/// for most bits, but Stage 2 translation (VM bit) activation requires all
/// Stage 2 page tables to be populated and barriers issued first.
#[inline]
pub unsafe fn write_hcr_el2(val: u64) {
    unsafe {
        asm!("msr hcr_el2, {}", in(reg) val,
             options(nomem, nostack, preserves_flags));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VBAR_EL2 — Vector Base Address Register (EL2)
//
// Points to AETHER's exception vector table. Must be 2048-byte aligned.
// The vector table layout is implemented in the exception handler module
// (Chapter 5). This register just holds the base address.
//
// Source: ARM ARM DDI0487 Section D1.10
// Verified: linux-ref/arch/arm64/tools/sysreg "Sysreg VBAR_EL2  3 4 12 0 0"
// ─────────────────────────────────────────────────────────────────────────────

/// Write VBAR_EL2.
///
/// # Safety
/// - Must be called from EL2.
/// - `addr` must be 2048-byte aligned (bits [10:0] must be zero).
/// - An ISB must be issued after this write.
#[inline]
pub unsafe fn write_vbar_el2(addr: u64) {
    debug_assert_eq!(addr & 0x7FF, 0, "VBAR_EL2 must be 2KiB aligned");
    unsafe {
        asm!("msr vbar_el2, {}", in(reg) addr,
             options(nomem, nostack, preserves_flags));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ESR_EL2 — Exception Syndrome Register (EL2)
//
// When an exception is taken to EL2, ESR_EL2 describes the cause.
// Bits [31:26] are the EC (Exception Class) field — the primary dispatcher.
//
// EC values (from ARM ARM DDI0487 Table D1-6):
//   0x16 → HVC instruction in AArch64 state
//   0x17 → SMC instruction in AArch64 state (when trapped by HCR_EL2.TSC)
//   0x20 → Instruction Abort from lower EL (stage 2 instruction fault)
//   0x24 → Data Abort from lower EL       (stage 2 data fault)
//
// Source: ARM ARM DDI0487 Table D1-6
// Verified: linux-ref/arch/arm64/include/asm/esr.h ESR_ELx_EC_*
// ─────────────────────────────────────────────────────────────────────────────

pub mod esr_el2 {
    /// Bits [31:26] — EC: Exception Class.
    pub const EC_SHIFT: u32 = 26;
    pub const EC_MASK:  u64 = 0x3F << EC_SHIFT;

    /// EC = 0x16: HVC instruction executed from AArch64 EL1.
    pub const EC_HVC64: u64 = 0x16;
    /// EC = 0x17: SMC instruction executed from AArch64 EL1 (trapped).
    pub const EC_SMC64: u64 = 0x17;
    /// EC = 0x20: Instruction Abort from a lower Exception Level.
    pub const EC_IABT_LOW: u64 = 0x20;
    /// EC = 0x24: Data Abort from a lower Exception Level.
    pub const EC_DABT_LOW: u64 = 0x24;

    /// Extract the Exception Class from an ESR value.
    #[inline]
    pub const fn exception_class(esr: u64) -> u64 {
        (esr & EC_MASK) >> EC_SHIFT
    }
}

/// Read FAR_EL2 — Fault Address Register (EL2).
///
/// On a Stage 2 data or instruction abort, FAR_EL2 holds the faulting
/// virtual address (VA) as seen by EL1. Bits [11:0] are the byte offset
/// within the faulting page and are valid for computing the IPA offset.
///
/// Source: ARM ARM DDI0487 Section D1.10.6
#[inline]
pub unsafe fn read_far_el2() -> u64 {
    let v: u64;
    unsafe {
        asm!("mrs {}, far_el2", out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// Read HPFAR_EL2 — Hypervisor IPA Fault Address Register (EL2).
///
/// On a Stage 2 abort, HPFAR_EL2[43:4] holds IPA[47:12] of the faulting
/// guest physical address (the 4KB page number). To reconstruct the full IPA:
///
///   `ipa = (hpfar_el2 & 0x0000_00FF_FFFF_FFF0) << 8 | (far_el2 & 0xFFF)`
///
/// The lower 12 bits of the IPA are the page offset from FAR_EL2[11:0].
/// Verified against Linux kernel arch/arm64/kvm/fault.c `get_fault_ipa()`.
///
/// Source: ARM ARM DDI0487 Section D1.10.7
#[inline]
pub unsafe fn read_hpfar_el2() -> u64 {
    let v: u64;
    unsafe {
        asm!("mrs {}, hpfar_el2", out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// Read ESR_EL2.
///
/// # Safety
/// Must be called from EL2, typically inside an exception handler.
#[inline]
pub unsafe fn read_esr_el2() -> u64 {
    let v: u64;
    unsafe {
        asm!("mrs {}, esr_el2", out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

// ─────────────────────────────────────────────────────────────────────────────
// ELR_EL2 — Exception Link Register (EL2)
//
// On exception entry to EL2: holds the return address (faulting or next
// instruction, depending on exception type).
// On ERET from EL2: the processor jumps to the address stored here.
//
// AETHER uses this to set a guest's initial entry point during boot
// (Chapter 7) by writing the guest's entry address then executing ERET.
//
// Source: ARM ARM DDI0487 Section D1.15
// Verified: linux-ref/arch/arm64/tools/sysreg "Sysreg ELR_EL2  3 4 4 0 1"
// ─────────────────────────────────────────────────────────────────────────────

/// Read ELR_EL2.
///
/// # Safety
/// Must be called from EL2.
#[inline]
pub unsafe fn read_elr_el2() -> u64 {
    let v: u64;
    unsafe {
        asm!("mrs {}, elr_el2", out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// Write ELR_EL2.
///
/// # Safety
/// Must be called from EL2. The written value will be used as the return
/// address of the next ERET instruction.
#[inline]
pub unsafe fn write_elr_el2(addr: u64) {
    unsafe {
        asm!("msr elr_el2, {}", in(reg) addr,
             options(nomem, nostack, preserves_flags));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SPSR_EL2 — Saved Program Status Register (EL2)
//
// On exception entry to EL2: holds the PSTATE of the interrupted context.
// On ERET from EL2: PSTATE is restored from this register.
//
// When constructing a new guest context (Chapter 7), AETHER writes a
// synthesized SPSR_EL2 value representing a valid EL1h state, then ERETs
// to transfer execution to the guest entry point.
//
// Key SPSR fields for constructing EL1 guest entry:
//   Bits [4:0] = 0b00101 → EL1h (EL1 with dedicated SP_EL1)
//   Bit  [6]   = 1       → FIQ masked
//   Bit  [7]   = 1       → IRQ masked   (AETHER unmasks after full init)
//   Bit  [8]   = 1       → SError masked
//   Bit  [9]   = 1       → Debug masked
//
// Source: ARM ARM DDI0487 Section D1.12, Table D1-3
// ─────────────────────────────────────────────────────────────────────────────

pub mod spsr_el2 {
    /// M[4:0] = 0b00101 — AArch64 EL1 with dedicated SP_EL1 (EL1h).
    /// Used when constructing the initial guest context.
    pub const M_EL1H: u64 = 0b00101;
    /// Bit 6 — F: FIQ mask bit.
    pub const F:      u64 = 1 << 6;
    /// Bit 7 — I: IRQ mask bit.
    pub const I:      u64 = 1 << 7;
    /// Bit 8 — A: SError mask bit.
    pub const A:      u64 = 1 << 8;
    /// Bit 9 — D: Debug mask bit.
    pub const D:      u64 = 1 << 9;

    /// A SPSR_EL2 value representing an EL1h context with all interrupts
    /// masked. Written before the first ERET into a guest to give the guest
    /// kernel a clean, fully-masked starting state.
    pub const GUEST_ENTRY_EL1H: u64 = M_EL1H | F | I | A | D;
}

/// Write SPSR_EL2.
///
/// # Safety
/// Must be called from EL2. Used during guest construction to set the
/// processor state the guest will start in after ERET.
#[inline]
pub unsafe fn write_spsr_el2(val: u64) {
    unsafe {
        asm!("msr spsr_el2, {}", in(reg) val,
             options(nomem, nostack, preserves_flags));
    }
}
