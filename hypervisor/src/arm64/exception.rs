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

    /// The trapped instruction was fully emulated by EL2: resume at the
    /// NEXT instruction (ELR_EL2 += 4). Required for every trap whose
    /// preferred return address is the trapped instruction itself — MSR/MRS
    /// (EC 0x18), WFI/WFE (EC 0x01), SMC under HCR_EL2.TSC (EC 0x17), and
    /// emulated MMIO data aborts (EC 0x24). Returning without advancing
    /// re-executes the instruction forever (ARM ARM D1.10.1).
    Emulated,

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

    let reason = match ec {
        ExceptionClass::Hvc64 => handle_hvc(ctx, esr),
        ExceptionClass::Smc64 => handle_smc(ctx, esr),
        ExceptionClass::WfxTrap => handle_wfx(ctx, esr),
        ExceptionClass::DataAbortLow => handle_data_abort(ctx, esr),
        ExceptionClass::InstructionAbortLow => handle_inst_abort(ctx, esr),
        ExceptionClass::SystemRegister => handle_sysreg_trap(ctx, esr),
        _ => ExitReason::Halt, // unhandled EC — halt during bring-up
    };
    // The vector epilogue unconditionally restores the context and ERETs to
    // ctx.elr_el2, so every ExitReason must be realised HERE.
    finish_exit(ctx, reason, esr)
}

/// Apply an `ExitReason` to the saved context before the vector epilogue
/// ERETs. `Halt` never returns: it reports and parks this core, instead of
/// silently re-entering the guest at the faulting PC (which turns any
/// unhandled trap into an invisible infinite trap loop).
fn finish_exit(ctx: &mut GuestContext, reason: ExitReason, esr: u64) -> ExitReason {
    match reason {
        ExitReason::ReturnToGuest | ExitReason::RetryInstruction => {}
        ExitReason::Emulated => ctx.elr_el2 = ctx.elr_el2.wrapping_add(4),
        ExitReason::Halt => halt_with_report(ctx, esr),
    }
    reason
}

/// Report an exception taken AT EL2 (a hypervisor fault) and park this core.
/// Called from the EL2h sync vector on a dedicated fault stack.
#[unsafe(no_mangle)]
pub extern "C" fn aether_el2_fault_report(esr: u64, elr: u64, spsr: u64, far: u64) -> ! {
    // SAFETY: QEMU virt PL011 identity-mapped by UEFI; core is parked after.
    let uart = unsafe { Uart::new(0x0900_0000) };
    unsafe {
        uart.puts("\r\n[EL2] FAULT AT EL2  ESR=");
        uart.puthex64(esr);
        uart.puts(" EC=");
        uart.puthex64((esr >> 26) & 0x3F);
        uart.puts(" ELR=");
        uart.puthex64(elr);
        uart.puts(" SPSR=");
        uart.puthex64(spsr);
        uart.puts(" FAR=");
        uart.puthex64(far);
        uart.puts("\r\n");
    }
    loop {
        // SAFETY: parking the core.
        unsafe { core::arch::asm!("wfe", options(nomem, nostack)) };
    }
}

/// Report an unrecoverable guest exit on the UART and park this core forever.
fn halt_with_report(ctx: &GuestContext, esr: u64) -> ! {
    // SAFETY: QEMU virt PL011 identity-mapped by UEFI; EL2 exception context.
    let uart = unsafe { Uart::new(0x0900_0000) };
    unsafe {
        uart.puts("\r\n[EL2] HALT: unhandled guest exit  ESR=");
        uart.puthex64(esr);
        uart.puts(" EC=");
        uart.puthex64((esr >> 26) & 0x3F);
        uart.puts(" ELR=");
        uart.puthex64(ctx.elr_el2);
        uart.puts(" SPSR=");
        uart.puthex64(ctx.spsr_el2);
        uart.puts("\r\n");
    }
    loop {
        // SAFETY: parking the core; interrupts are masked on EL2 entry.
        unsafe { core::arch::asm!("wfe", options(nomem, nostack)) };
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
pub unsafe extern "C" fn aether_handle_serror(ctx: *mut GuestContext) -> ExitReason {
    // Unrecoverable at this stage.
    let esr: u64;
    unsafe {
        core::arch::asm!("mrs {}, esr_el2", out(reg) esr,
                         options(nomem, nostack, preserves_flags));
    }
    halt_with_report(unsafe { &*ctx }, esr)
}

// ─────────────────────────────────────────────────────────────────────────────
// Individual exception handlers (stubs — fleshed out in later chapters)
// ─────────────────────────────────────────────────────────────────────────────

/// EC = 0x16: HVC — hypervisor call.
///
/// Dispatch order:
///   1. AETHER vendor range (0x8600_0001–0x8600_0006) → ch47 sensor/modem HVCs.
///   2. All other function IDs → PSCI dispatch (CPU_ON / CPU_OFF / etc.).
///
/// The SMCCC convention places the function identifier in x0 and arguments
/// in x1–x3; results go back into x0 (status) and optionally x1–x3 (data).
/// ELR_EL2 already points past the HVC instruction so no PC adjustment is needed.
#[inline]
fn handle_hvc(ctx: &mut GuestContext, _esr: u64) -> ExitReason {
    let func_id = ctx.regs[0];
    let arg1    = ctx.regs[1];
    let arg2    = ctx.regs[2];
    let arg3    = ctx.regs[3];

    // Route AETHER vendor HVCs (ch47) before PSCI so they are never
    // misinterpreted as PSCI calls (different OEN in bits[29:24]).
    if crate::virtual_sensors_modem::is_aether_hvc(func_id) {
        // SAFETY: called from EL2 exception handler (IRQs masked, single core).
        // AETHER_PARAVIRT_STATE is initialised before any guest runs.
        unsafe { crate::virtual_sensors_modem::dispatch_aether_hvc(&mut ctx.regs) };
        return ExitReason::ReturnToGuest;
    }

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
    // A TSC-trapped SMC's preferred return address is the SMC itself.
    ExitReason::Emulated
}

/// EC = 0x01: WFI/WFE trapped from EL1.
///
/// Guest is idle. Poll the paravirt modem shared page (ch47) on every WFI
/// exit so that AT commands from Android's RIL are processed with
/// sub-millisecond latency. Static CPU partitioning (ch09) means this CPU
/// stays with this guest; there is no scheduler to call.
#[inline]
fn handle_wfx(_ctx: &mut GuestContext, _esr: u64) -> ExitReason {
    // SAFETY: called from EL2 exception handler (IRQs masked). The paravirt
    // state was initialised by init_virtual_sensors_and_modem() before this
    // guest's first ERET; poll_modem_on_wfi() is a no-op until then.
    unsafe { crate::virtual_sensors_modem::poll_modem_on_wfi() };
    // Preferred return address of a trapped WFx is the WFx itself; step past
    // it so the guest's idle loop re-evaluates (pending vIRQs are taken on ERET).
    ExitReason::Emulated
}

/// EC = 0x24: Stage 2 Data Abort.
///
/// Guest accessed an IPA that has no Stage 2 mapping or that is protected.
///
/// Prints the faulting IPA (from HPFAR_EL2) and ESR to the UART for
/// Test 3 isolation verification, then halts the guest.
#[inline]
fn handle_data_abort(ctx: &mut GuestContext, esr: u64) -> ExitReason {
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

    // Phase 3: dispatch virtio-blk MMIO accesses inside the device window
    // before treating the fault as fatal.
    if crate::virtio_blk::ipa_in_device_window(ipa) {
        if let Some(ret) = handle_virtio_mmio_fault(ctx, esr, ipa) {
            return ret;
        }
        // Fault inside the window but undecodable — fall through to halt.
    }

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

// ─────────────────────────────────────────────────────────────────────────────
// Phase 3: virtio-mmio fault decoder
//
// Decodes ESR_EL2.ISS for an ISV=1 data abort, dispatches the access to the
// global virtio_blk backend, writes the result back into the destination
// register on reads, and returns `RetryInstruction` so the guest advances
// past the faulting instruction once the trap completes.
//
// On ISV=0 (unsupported decode) we return None so the caller treats it as
// fatal — a real driver doing word-sized accesses always gets ISV=1.
// ─────────────────────────────────────────────────────────────────────────────

#[inline]
fn handle_virtio_mmio_fault(ctx: &mut GuestContext, esr: u64, ipa: u64) -> Option<ExitReason> {
    // ISS layout for a synchronous data abort with ISV=1:
    //   bit 24: ISV
    //   bits 23:22: SAS — 00=byte, 01=halfword, 10=word, 11=doubleword
    //   bits 21: SSE (sign-extend) — ignored
    //   bits 20:16: SRT — destination register index (0..30, 31 = XZR/discard)
    //   bit  6: WnR — 1 = write, 0 = read
    let iss = esr & 0x01FF_FFFF;
    let isv = (iss >> 24) & 1 != 0;
    if !isv { return None; }
    let sas  = ((iss >> 22) & 0x3) as u8;
    let srt  = ((iss >> 16) & 0x1F) as usize;
    let is_write = (iss >> 6) & 1 != 0;

    let offset = ipa - crate::virtio::VIRTIO_MMIO_BASE_IPA;

    // We only handle word-sized accesses. virtio-mmio drivers always use 32-bit
    // accesses except for descriptor ring memory (which goes through Stage 2
    // mappings, not MMIO).
    if sas != 0b10 { return None; }

    if is_write {
        // Source register value. Note: SRT=31 is XZR (writes-zero, ignored).
        let val = if srt == 31 { 0u32 } else { ctx.regs[srt] as u32 };
        let r = crate::virtio_blk::with_backend_mut(|be| be.handle_mmio_write(offset, val));
        match r {
            Some(Ok(())) => Some(ExitReason::Emulated),
            _ => None,
        }
    } else {
        let r = crate::virtio_blk::with_backend_mut(|be| be.handle_mmio_read(offset));
        match r {
            Some(Ok(v)) => {
                if srt != 31 {
                    // The load is emulated here; `Emulated` steps ELR past it
                    // (a data abort's preferred return is the faulting insn).
                    ctx.regs[srt] = v as u64;
                }
                Some(ExitReason::Emulated)
            }
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EC = 0x18: trapped MSR/MRS/SYS (ESR ISS layout, ARM ARM D17.2.37)
//
//   [21:20] Op0  [19:17] Op2  [16:14] Op1  [13:10] CRn  [9:5] Rt
//   [4:1]   CRm  [0]     Direction (1 = read / MRS, 0 = write / MSR)
//
// What traps under HCR_EL2 GUEST_FLAGS, and how it is handled:
//   TID3/TID1  ID registers           → emulate: return the REAL hardware value
//                                        (hardware authenticity: Android must
//                                        see the true CPU, never a sanitised one)
//   TACR       ACTLR_EL1              → RAZ/WI (IMPLEMENTATION DEFINED register)
//   TSW        DC ISW/CSW/CISW        → perform DC CISW at EL2 (safe superset)
//   TIDCP/TLOR/anything else          → inject UNDEF into the guest, as KVM does
// ─────────────────────────────────────────────────────────────────────────────

use crate::sysreg_trap::{classify_sysreg, SysRegAccess, SysRegAction};

/// Read a TID1/TID3 ID register at EL2 (the real hardware value).
/// MRS needs a static encoding, so expand every (CRm, Op2) of group 3.
fn read_hardware_id(a: &SysRegAccess) -> u64 {
    macro_rules! mrs {
        ($name:literal) => {{
            let v: u64;
            // SAFETY: reading an ID register at EL2 has no side effects; the
            // ID space Op0=3,Op1=0,CRn=0,CRm=1..7 reads as zero where unallocated.
            unsafe { core::arch::asm!(concat!("mrs {}, ", $name), out(reg) v,
                                      options(nomem, nostack, preserves_flags)) };
            v
        }};
    }
    macro_rules! group3 {
        ($crm:expr, $op2:expr; $($c:literal => [$($o:literal),*]),*) => {
            match ($crm, $op2) {
                $($( ($c, $o) => {
                    let v: u64;
                    // SAFETY: as in mrs! above — side-effect-free ID read.
                    unsafe { core::arch::asm!(concat!("mrs {}, S3_0_C0_C", $c, "_", $o),
                                              out(reg) v, options(nomem, nostack, preserves_flags)) };
                    v
                } )*)*
                _ => 0,
            }
        };
    }
    match (a.op1, a.crm, a.op2) {
        (0, 0, 6) => mrs!("revidr_el1"),
        (1, 0, 7) => mrs!("aidr_el1"),
        (0, crm, op2) => group3!(crm, op2;
            1 => [0, 1, 2, 3, 4, 5, 6, 7], 2 => [0, 1, 2, 3, 4, 5, 6, 7],
            3 => [0, 1, 2, 3, 4, 5, 6, 7], 4 => [0, 1, 2, 3, 4, 5, 6, 7],
            5 => [0, 1, 2, 3, 4, 5, 6, 7], 6 => [0, 1, 2, 3, 4, 5, 6, 7],
            7 => [0, 1, 2, 3, 4, 5, 6, 7]),
        _ => 0,
    }
}

/// Inject an UNDEFINED exception into the guest at EL1, as if the trapped
/// instruction had been UNDEFINED (mirrors KVM `inject_undef64`).
///
/// ESR_EL1 = EC 0 (Unknown) with IL=1; ELR_EL1/SPSR_EL1 = the trapped context;
/// the guest resumes at its own vector table with DAIF masked in EL1h.
fn inject_undef(ctx: &mut GuestContext) {
    const PSR_MODE_MASK: u64 = 0xF;
    const PSR_MODE_EL1T: u64 = 0b0100;
    const PSR_MODE_EL1H: u64 = 0b0101;
    let vbar: u64;
    // SAFETY: EL2 with HCR_EL2.E2H=0, so *_EL1 accesses reach the guest's
    // EL1 registers; this is exactly the exception-entry the CPU would do.
    unsafe {
        core::arch::asm!("mrs {}, vbar_el1", out(reg) vbar, options(nomem, nostack));
        core::arch::asm!("msr esr_el1, {}", in(reg) 1u64 << 25, options(nomem, nostack));
        core::arch::asm!("msr elr_el1, {}", in(reg) ctx.elr_el2, options(nomem, nostack));
        core::arch::asm!("msr spsr_el1, {}", in(reg) ctx.spsr_el2, options(nomem, nostack));
    }
    let offset = match ctx.spsr_el2 & PSR_MODE_MASK {
        PSR_MODE_EL1T => 0x000, // current EL with SP_EL0
        PSR_MODE_EL1H => 0x200, // current EL with SP_ELx
        _ => 0x400,             // lower EL (EL0) using AArch64
    };
    ctx.elr_el2 = vbar + offset;
    // EL1h, D/A/I/F masked (0x3C5).
    ctx.spsr_el2 = 0x3C0 | PSR_MODE_EL1H;
}

/// EC = 0x18: System register access trapped.
#[inline]
fn handle_sysreg_trap(ctx: &mut GuestContext, esr: u64) -> ExitReason {
    let a = SysRegAccess::decode(esr);
    let rt_val = if a.rt == 31 { 0 } else { ctx.regs[a.rt] };
    match classify_sysreg(&a) {
        SysRegAction::ReadHardwareId => {
            let v = read_hardware_id(&a);
            // Real value, minus features EL2 does not host (sysreg_trap::sanitize_id).
            let v = if a.is_id_group3() { crate::sysreg_trap::sanitize_id(a.crm, a.op2, v) } else { v };
            if a.rt != 31 { ctx.regs[a.rt] = v; }
            ExitReason::Emulated
        }
        SysRegAction::RazWi => {
            if a.is_read && a.rt != 31 { ctx.regs[a.rt] = 0; }
            ExitReason::Emulated
        }
        SysRegAction::SetWayClean => {
            // SAFETY: set/way clean+invalidate is a superset of ISW/CSW and
            // never loses dirty data; same operand the guest supplied.
            unsafe { core::arch::asm!("dc cisw, {}", in(reg) rt_val, options(nostack)) };
            ExitReason::Emulated
        }
        SysRegAction::ForwardSgi { alias } => {
            // SAFETY: EL2 with SRE enabled; re-issues exactly the guest's SGI
            // (same INTID, IRM, target list, affinity) — vCPU affinity ==
            // physical affinity under AETHER's 1:1 core partitioning.
            unsafe {
                if alias {
                    core::arch::asm!("msr icc_asgi1r_el1, {}", "isb", in(reg) rt_val, options(nostack));
                } else {
                    core::arch::asm!("msr icc_sgi1r_el1, {}", "isb", in(reg) rt_val, options(nostack));
                }
            }
            ExitReason::Emulated
        }
        SysRegAction::InjectUndef => {
            inject_undef(ctx);
            ExitReason::ReturnToGuest
        }
    }
}
