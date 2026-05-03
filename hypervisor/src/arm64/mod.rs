// ch04: ARM64 As The Substrate
//
// The ARM64 architecture (AArch64) is the only thing AETHER assumes exists.
// This module exposes every primitive the ARM64 hardware provides that
// AETHER builds on top of — system register access, memory barriers, and
// address-translation constants.
//
// Nothing in this module is AETHER-specific. These are raw hardware
// abstractions that would exist in any bare-metal ARM64 program. Higher
// modules (partition, boot, memory) import from here rather than touching
// the hardware directly.
//
// Primary reference: ARM Architecture Reference Manual for Armv8-A (DDI0487)
// Secondary: linux-ref/arch/arm64/include/asm/sysreg.h
//            linux-ref/arch/arm64/tools/sysreg  (authoritative bit positions)
//
// Register definitions in this file have been verified against the Linux
// kernel's sysreg generator tool at arch/arm64/tools/sysreg, which is the
// same source the kernel's own headers are generated from.

pub mod barriers; // DSB, ISB, DMB — memory and instruction ordering
pub mod paging;   // page granule constants and address-space sizing
pub mod regs;     // system register read/write via MRS/MSR

// ch05: Exception Levels — vector table, context save frame, ESR dispatch
pub mod context;   // GuestContext: 272-byte CPU state save frame
pub mod exception; // ExceptionClass / ExitReason; aether_handle_* C entry points
pub mod vectors;   // EL2 vector table (global_asm!); install_vectors()

// ch06: The Virtualization Extensions — HCR_EL2, Stage 2, GIC virt
pub mod virt;      // configure_el2_virt(); hcr_el2/vtcr_el2/vttbr_el2/stage2/cptr_el2/gic_virt
