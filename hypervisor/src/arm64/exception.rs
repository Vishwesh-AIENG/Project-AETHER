// ch05: Exception classification and dispatch
//
// When an exception is taken to EL2, the first task is to determine what
// caused it. ESR_EL2 (Exception Syndrome Register) contains a 6-bit
// Exception Class (EC) field in bits [31:26] that identifies the cause.
//
// This module defines:
//   - ExceptionType: which of the four ARM64 exception types arrived
//   - ExceptionClass: the EC field decoded into a Rust enum
//   - ExitReason: what AETHER should do in response
//
// All EC values are verified against:
//   linux-ref/arch/arm64/include/asm/esr.h
//   ARM ARM DDI0487 Table D1-6
//
// Skill guide warning (ch05): Claude frequently gets EC values wrong.
// Every variant below is from esr.h, not from training data.

use super::context::GuestContext;
use super::regs::{read_far_el2, read_hpfar_el2};
use crate::uart::Uart;

// ─────────────────────────────────────────────────────────────────────────────
// ExceptionType — the four hardware exception categories
//
// ARM64 has four exception types. Each has a dedicated vector table slot.
// Source: ARM ARM DDI0487 Section D1.7
// ────────────────────────────────────────────────────────────────────────────��

/// The four ARM64 exception types that can be taken to EL2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionType {
    /// Synchronous exception: caused by the currently executing instruction.
    /// Includes page faults, undefined instructions, SVC, HVC, SMC.
    /// ESR_EL2 is valid and contains the Exception Class.
    Synchronous,

    /// IRQ: normal hardware interrupt. Routed to EL2 when HCR_EL2.IMO = 1.
    /// ESR_EL2 is NOT valid for IRQ; GIC registers describe the interrupt.
    Irq,

    /// FIQ: fast interrupt request. Routed to EL2 when HCR_EL2.FMO = 1.
    /// ESR_EL2 is NOT valid for FIQ.
    Fiq,

    /// SError: asynchronous system error (bus error, memory abort).
    /// Routed to EL2 when HCR_EL2.AMO = 1.
    SError,
}

// ─────────────────────────────────────────────────────────────────────────────
// ExceptionClass — decoded EC field from ESR_EL2
//
// Only the EC values that AETHER will actually handle are listed.
// Unknown EC values are represented by `ExceptionClass::Unknown(u8)`.
//
// All values verified against:
//   linux-ref/arch/arm64/include/asm/esr.h ESR_ELx_EC_* constants
//   ARM ARM DDI0487 Table D1-6
// ─────────────────────────────────────────────────────────────────────────────

/// Decoded Exception Class from ESR_EL2 bits [31:26].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionClass {
    /// EC = 0x01: WFI or WFE instruction trapped.
    /// Occurs when HCR_EL2.TWI=1 (WFI) or HCR_EL2.TWE=1 (WFE).
    /// AETHER intercepts WFI to implement guest idle.
    WfxTrap,

    /// EC = 0x0E: Illegal execution state.
    /// Guest attempted to execute an instruction that is UNDEFINED at its
    /// current exception level.
    IllegalState,

    /// EC = 0x15: SVC instruction from AArch64.
    /// Guest made a system call into its own kernel (EL0 → EL1).
    /// Should not normally reach EL2; if it does, it is a configuration error.
    Svc64,

    /// EC = 0x16: HVC instruction from AArch64.
    /// Guest explicitly invoked the hypervisor. AETHER's hypercall interface
    /// is the only intentional cross-EL communication (Chapter 7).
    Hvc64,

    /// EC = 0x17: SMC instruction from AArch64.
    /// Guest attempted to call secure firmware. Trapped because HCR_EL2.TSC=1.
    /// AETHER filters SMC calls; most are forwarded to EL3.
    Smc64,

    /// EC = 0x18: MSR/MRS to a system register that is trapped.
    /// Guest tried to read/write a system register AETHER intercepts.
    SystemRegister,

    /// EC = 0x20: Instruction Abort from a lower Exception Level.
    /// Stage 2 instruction fault — guest tried to fetch from an unmapped IPA.
    InstructionAbortLow,

    /// EC = 0x24: Data Abort from a lower Exception Level.
    /// Stage 2 data fault — guest tried to read/write an unmapped or
    /// protected IPA. The most common fault AETHER handles (Chapter 8).
    DataAbortLow,

    /// Any other EC value not explicitly handled above.
    /// AETHER logs and halts on unknown EC values during development.
    Unknown(u8),
}

impl ExceptionClass {
    /// Decode the EC field from a raw ESR_EL2 register value.
    ///
    /// Extracts bits [31:26] and maps them to an `ExceptionClass` variant.
    #[inline]
    pub fn from_esr(esr: u64) -> Self {
        // EC field: bits [31:26], 6 bits wide.
        // Verified: linux-ref/arch/arm64/include/asm/esr.h ESR_ELx_EC_SHIFT=26
        let ec = ((esr >> 26) & 0x3F) as u8;
        match ec {
            0x01 => Self::WfxTrap,
            0x0E => Self::IllegalState,
            0x15 => Self::Svc64,
            0x16 => Self::Hvc64,
            0x17 => Self::Smc64,
            0x18 => Self::SystemRegister,
            0x20 => Self::InstructionAbortLow,
            0x24 => Self::DataAbortLow,
            other => Self::Unknown(other),
        }
    }

    /// Return the raw 6-bit EC value.
    #[inline]
    pub fn raw(self) -> u8 {
        match self {
            Self::WfxTrap             => 0x01,
            Self::IllegalState        => 0x0E,
            Self::Svc64               => 0x15,
            Self::Hvc64               => 0x16,
            Self::Smc64               => 0x17,
            Self::SystemRegister      => 0x18,
            Self::InstructionAbortLow => 0x20,
            Self::DataAbortLow        => 0x24,
            Self::Unknown(v)          => v,
        }
    }

    /// Return true if this EC is a guest memory fault (Stage 2 violation).
    #[inline]
    pub fn is_memory_fault(self) -> bool {
        matches!(self, Self::InstructionAbortLow | Self::DataAbortLow)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ISS field helpers for DataAbortLow (EC = 0x24)
//
// When a Data Abort is taken to EL2, bits [24:0] of ESR_EL2 are the
// Instruction-Specific Syndrome (ISS). Key subfields:
//
//   ISS[5:0]  — DFSC: Data Fault Status Code
//   ISS[6]    — WnR: 0=read fault, 1=write fault
//   ISS[24]   — ISV: Instruction Syndrome Valid
//
// Source: ARM ARM DDI0487 Section D1.13.5 (Data Abort ISS encoding)
// Verified: linux-ref/arch/arm64/include/asm/esr.h ESR_ELx_WNR, ESR_ELx_DFSC_*
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the Data Fault Status Code from ESR_EL2 for a Data Abort.
/// Bits [5:0] of ESR_EL2.
#[inline]
pub const fn dfsc(esr: u64) -> u8 {
    (esr & 0x3F) as u8
}

/// Return true if the faulting access was a write (ESR_EL2 bit 6 = WnR).
#[inline]
pub const fn is_write_fault(esr: u64) -> bool {
    (esr >> 6) & 1 == 1
}

// ─────────────────────────────────────────────────────────────────────────────
// ExitReason — what AETHER should do after classifying the exception
//
// The Rust exception handlers (called from the vector table) return an
// ExitReason that tells the assembly epilogue how to return to the guest.
// ─────────────────────────────────────────────────────────────────────────────

/// What AETHER should do after handling an EL2 exception.
///
/// `#[repr(u8)]` makes this FFI-safe so the enum can be returned from
/// `extern "C"` handler functions called by the vector table assembly.
/// The integer values are arbitrary; only `ReturnToGuest` / `Halt` matter
/// to the current assembly epilogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitReason {
    /// Return to the same guest at the instruction after the trap.
    /// The vector epilogue executes ERET with restored context.
    ReturnToGuest,

    /// Return to the same guest but at the *current* PC
    /// (re-execute the faulting instruction after AETHER resolved the fault).
    RetryInstruction,

    /// A fatal condition was encountered. The hypervisor halts.
    /// Used during bring-up when unhandled exceptions must not silently corrupt state.
    Halt,
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level synchronous exception dispatcher
//
// Called by the EL2 vector table after saving the GuestContext.
// Reads ESR_EL2, decodes the EC, and calls the appropriate handler.
// Returns an ExitReason that drives the assembly epilogue.
// ─────────────────────────────────────────────────────────────────────────────

/// Dispatch a synchronous EL1→EL2 exception.
///
/// Called from assembly (vectors.rs) with a mutable pointer to the guest
/// context on the EL2 stack. Reads ESR_EL2 directly from hardware since
/// the exception just fired.
///
/// # Safety
/// - Must be called from EL2 with interrupts masked.
/// - `ctx` must point to a valid, fully-populated `GuestContext` on the stack.
///   The pointer is valid for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aether_handle_sync(ctx: *mut GuestContext) -> ExitReason {
    let esr: u64;
    unsafe {
        core::arch::asm!("mrs {}, esr_el2", out(reg) esr,
                         options(nomem, nostack, preserves_flags));
    }

    let ec = ExceptionClass::from_esr(esr);
    let ctx = unsafe { &mut *ctx };

    match ec {
        ExceptionClass::Hvc64 => handle_hvc(ctx, esr),
        ExceptionClass::Smc64 => handle_smc(ctx, esr),
        ExceptionClass::WfxTrap => handle_wfx(ctx, esr),
        ExceptionClass::DataAbortLow => handle_data_abort(ctx, esr),
        ExceptionClass::InstructionAbortLow => handle_inst_abort(ctx, esr),
        ExceptionClass::SystemRegister => handle_sysreg_trap(ctx, esr),
        _ => ExitReason::Halt, // unhandled EC — halt during bring-up
    }
}

/// Handle a physical IRQ taken to EL2.
///
/// HCR_EL2.IMO=1 routes all Group 1 NS physical IRQs to EL2. This handler
/// acknowledges the physical interrupt and forwards it to the Android guest
/// via a hardware-backed List Register (ICH_LRn_EL2.HW=1). The GIC then
/// delivers it to the virtual CPU Interface automatically.
///
/// Maintenance interrupts (ICH_MISR_EL2) arrive on the same path and are
/// distinguished by their INTID matching `VGicState::maint_intid()`.
///
/// # Safety
/// Must be called from EL2 with interrupts masked (guaranteed by exception
/// entry). The global VGIC state must have been initialized via
/// `gic::aether_vgic_init()` before this is called.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aether_handle_irq(_ctx: *mut GuestContext) -> ExitReason {
    // SAFETY: called from EL2 exception handler (non-reentrant — PSTATE.I
    // is set on EL2 exception entry, preventing nested IRQ exceptions).
    let vgic = unsafe { crate::gic::aether_vgic_mut() };
    unsafe { crate::gic::handle_physical_irq(vgic) };
    ExitReason::ReturnToGuest
}

/// Handle a System Error (SError) taken to EL2.
///
/// # Safety
/// Must be called from EL2.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aether_handle_serror(_ctx: *mut GuestContext) -> ExitReason {
    // Unrecoverable at this stage.
    ExitReason::Halt
}

// ─────────────────────────────────────────────────────────────────────────────
// Individual exception handlers (stubs — fleshed out in later chapters)
// ─────────────────────────────────────────────────────────────────────────────

/// EC = 0x16: HVC — hypervisor call.
///
/// Dispatches PSCI calls (CPU_ON / CPU_OFF / AFFINITY_INFO etc.) to
/// `cpu::handle_psci_call`.  The SMCCC convention places the function
/// identifier in x0 and arguments in x1–x3; the return value goes back
/// into x0.  ELR_EL2 already points past the HVC instruction so no PC
/// adjustment is needed here.
#[inline]
fn handle_hvc(ctx: &mut GuestContext, _esr: u64) -> ExitReason {
    let func_id = ctx.regs[0];
    let arg1    = ctx.regs[1];
    let arg2    = ctx.regs[2];
    let arg3    = ctx.regs[3];

    // SAFETY: mrs mpidr_el1 is always valid at EL2; aether_partition_mut
    // returns the single mutable reference to the static partition table,
    // which is only accessed from exception context (single-threaded per
    // core, serialised by EL2 entry).
    let caller_mpidr = unsafe { crate::cpu::Mpidr::read_current() };
    let partition    = unsafe { crate::cpu::aether_partition_mut() };
    let result = crate::cpu::handle_psci_call(
        func_id, arg1, arg2, arg3, caller_mpidr, partition,
    );
    ctx.regs[0] = result as u64;
    ExitReason::ReturnToGuest
}

/// EC = 0x17: SMC trapped from EL1.
///
/// Guests running at EL1 must not issue SMC directly (that would bypass
/// AETHER).  We forward PSCI-shaped SMC calls through the same dispatch
/// path as HVC so that guests compiled with either convention work
/// transparently.  Non-PSCI SMC calls return NOT_SUPPORTED.
#[inline]
fn handle_smc(ctx: &mut GuestContext, _esr: u64) -> ExitReason {
    let func_id = ctx.regs[0];
    let arg1    = ctx.regs[1];
    let arg2    = ctx.regs[2];
    let arg3    = ctx.regs[3];

    // SAFETY: same as handle_hvc above.
    let caller_mpidr = unsafe { crate::cpu::Mpidr::read_current() };
    let partition    = unsafe { crate::cpu::aether_partition_mut() };
    let result = crate::cpu::handle_psci_call(
        func_id, arg1, arg2, arg3, caller_mpidr, partition,
    );
    ctx.regs[0] = result as u64;
    ExitReason::ReturnToGuest
}

/// EC = 0x01: WFI/WFE trapped from EL1.
///
/// Guest is idle. AETHER can park the CPU or schedule other work.
/// Static partitioning (Chapter 9) means the CPU stays with this guest.
#[inline]
fn handle_wfx(_ctx: &mut GuestContext, _esr: u64) -> ExitReason {
    // Chapter 9: CPU partitioning — for now just return to let guest re-execute.
    ExitReason::ReturnToGuest
}

/// EC = 0x24: Stage 2 Data Abort.
///
/// Guest accessed an IPA that has no Stage 2 mapping or that is protected.
///
/// Prints the faulting IPA (from HPFAR_EL2) and ESR to the UART for
/// Test 3 isolation verification, then halts the guest.
#[inline]
fn handle_data_abort(_ctx: &mut GuestContext, esr: u64) -> ExitReason {
    // SAFETY: UART_PA is the QEMU virt PL011 address, always identity-mapped
    // by UEFI and never reclaimed. We are at EL2 in an exception handler;
    // the UART is accessible unconditionally.
    let uart = unsafe { Uart::new(0x0900_0000) };

    // FAR_EL2: faulting virtual address (EL1 view).
    // HPFAR_EL2[43:4]: IPA[47:8]. Reconstruct page-aligned IPA then OR in
    // the byte offset from FAR_EL2[11:0].
    // Source: ARM ARM DDI0487 Section D1.10.6 / D1.10.7.
    let far  = unsafe { read_far_el2() };
    let hpfar = unsafe { read_hpfar_el2() };
    // HPFAR_EL2[43:4] = IPA[47:12] (page number, not byte address).
    // Each HPFAR bit n maps to IPA bit n+8, so shift left 8. FAR[11:0] is
    // the byte offset within the page (same in VA and IPA for 4KB granule).
    // Source: ARM ARM DDI0487 D1.10.7; verified against Linux kvm/fault.c.
    let ipa = ((hpfar & 0x0000_00FF_FFFF_FFF0) << 8) | (far & 0xFFF);

    unsafe {
        uart.puts("\r\n[EL2] Stage 2 fault caught!\r\n");
        uart.puts("  IPA =");
        uart.puthex64(ipa);
        uart.puts("\r\n  ESR =");
        uart.puthex64(esr);
        uart.puts("\r\n  FAR =");
        uart.puthex64(far);
        uart.puts("\r\n[EL2] Isolation confirmed — guest halted.\r\n");
    }

    ExitReason::Halt
}

/// EC = 0x20: Stage 2 Instruction Abort.
///
/// Guest tried to fetch an instruction from an IPA with no Stage 2 mapping.
/// This is almost always a bug — valid code should always be mapped.
#[inline]
fn handle_inst_abort(_ctx: &mut GuestContext, _esr: u64) -> ExitReason {
    // Chapter 8: map the missing page if it belongs to the guest.
    ExitReason::Halt
}

/// EC = 0x18: System register access trapped.
///
/// Guest tried to read/write a system register that AETHER intercepts.
/// Chapter 6 configures which registers trap; Chapter 7 implements
/// the emulation.
#[inline]
fn handle_sysreg_trap(_ctx: &mut GuestContext, _esr: u64) -> ExitReason {
    // Chapter 6/7: emulate the trapped system register access.
    ExitReason::Halt
}
