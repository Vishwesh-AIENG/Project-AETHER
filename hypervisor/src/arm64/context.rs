// ch05: Guest CPU context — register save and restore frame
//
// When an exception is taken to EL2, AETHER must save the complete CPU
// state of the interrupted guest so that the guest can resume exactly
// where it left off. This module defines that save frame.
//
// Layout is designed to match the ARM64 `user_pt_regs` structure from
// linux-ref/arch/arm64/include/uapi/asm/ptrace.h:
//   struct user_pt_regs { u64 regs[31]; u64 sp; u64 pc; u64 pstate; }
// Extended with EL2-specific fields (elr_el2, spsr_el2, sp_el1).
//
// The frame is `repr(C)` so that the assembly save/restore macros can
// access fields at fixed, predictable offsets. The `#[repr(C, align(16))]`
// alignment requirement comes from the STP/LDP instructions used to save
// pairs of registers — STP requires the destination address to be 16-byte
// aligned when the pair spans a 16-byte boundary.
//
// Primary reference: ARM ARM DDI0487 Section D1.11 (exception entry)
// Verified against: linux-ref/arch/arm64/kvm/hyp/hyp-entry.S save macros
//                   linux-ref/arch/arm64/include/uapi/asm/ptrace.h

use core::mem;

// ─────────────────────────────────────────────────────────────────────────────
// GuestContext — complete CPU state for one guest vCPU
//
// Field order must not change: assembly code accesses fields by numeric
// offset. If you add or reorder fields, update OFFSET_ constants below
// and the save/restore macros in vectors.rs.
// ─────────────────────────────────────────────────────────────────────────────

/// Complete CPU register state of a guest at the moment it trapped to EL2.
///
/// Saved on the EL2 stack by the vector table entry code (vectors.rs).
/// Passed by pointer to Rust exception handlers.
///
/// The assembly prologue saves registers in this exact order:
///   1. x0, x1  (saved first in the vector entry, before SP is adjusted)
///   2. x2–x29  (saved in pairs with STP)
///   3. x30, xzr (x30=link register; xzr pads the pair to 16 bytes)
///   4. sp_el1   (guest's stack pointer)
///   5. elr_el2  (guest's PC at time of exception)
///   6. spsr_el2 (guest's PSTATE at time of exception)
#[derive(Debug, Default)]
#[repr(C, align(16))]
pub struct GuestContext {
    /// General-purpose registers x0–x30 (indices 0–30).
    /// x30 is the link register. x31 (XZR/SP) is handled separately.
    pub regs: [u64; 31],

    /// SP_EL1: the guest's stack pointer.
    ///
    /// Not accessible as a general register; read via `mrs x, sp_el1`.
    /// Must be saved before switching to EL2-owned stack operations.
    pub sp_el1: u64,

    /// ELR_EL2: the address of the instruction that caused the exception
    /// (or the next instruction, depending on exception type).
    ///
    /// Restored into ELR_EL2 before ERET so the guest resumes at the
    /// correct instruction.
    pub elr_el2: u64,

    /// SPSR_EL2: the saved PSTATE of the guest at exception entry.
    ///
    /// Restored into SPSR_EL2 before ERET so the guest's flags,
    /// exception level, and interrupt mask state are restored.
    pub spsr_el2: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Field offsets — used by assembly to access fields by byte offset
//
// These are const, computed from mem::offset_of!, so if the struct layout
// changes the assembly that references them must be updated.
//
// All offsets are verified at compile time by the assertions below.
// ─────────────────────────────────────────────────────────────────────────────

/// Byte offset of `regs[0]` (x0) in `GuestContext`.
pub const OFFSET_X0: usize    = mem::offset_of!(GuestContext, regs);

/// Byte offset of `sp_el1` in `GuestContext`.
pub const OFFSET_SP_EL1: usize  = mem::offset_of!(GuestContext, sp_el1);

/// Byte offset of `elr_el2` in `GuestContext`.
pub const OFFSET_ELR_EL2: usize = mem::offset_of!(GuestContext, elr_el2);

/// Byte offset of `spsr_el2` in `GuestContext`.
pub const OFFSET_SPSR_EL2: usize = mem::offset_of!(GuestContext, spsr_el2);

/// Total size of the `GuestContext` frame in bytes.
/// The vector entry assembly adjusts SP by exactly this amount.
pub const GUEST_CONTEXT_SIZE: usize = mem::size_of::<GuestContext>();

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time layout assertions
// ─────────────────────────────────────────────────────────────────────────────

const _: () = {
    // x0 must be the very first field — assembly saves it at offset 0.
    assert!(OFFSET_X0 == 0,
        "regs[0] (x0) must be at offset 0 in GuestContext");

    // regs array covers x0–x30: 31 × 8 = 248 bytes.
    assert!(OFFSET_SP_EL1 == 248,
        "sp_el1 must immediately follow regs[30] at offset 248");

    // sp_el1, elr_el2, spsr_el2 are packed at 8-byte offsets after regs.
    assert!(OFFSET_ELR_EL2 == 256,
        "elr_el2 must be at offset 256");
    assert!(OFFSET_SPSR_EL2 == 264,
        "spsr_el2 must be at offset 264");

    // Total size must be 16-byte aligned (for STP alignment requirements).
    assert!(GUEST_CONTEXT_SIZE == 272,
        "GuestContext must be 272 bytes (31+3 registers at 8 bytes each)");
    assert!(GUEST_CONTEXT_SIZE % 16 == 0,
        "GuestContext size must be 16-byte aligned for STP");
};

impl GuestContext {
    /// Construct a zeroed context. Used when synthesizing a fresh guest
    /// entry (Chapter 7 boot sequence).
    #[inline]
    pub const fn new() -> Self {
        Self {
            regs: [0u64; 31],
            sp_el1: 0,
            elr_el2: 0,
            spsr_el2: 0,
        }
    }

    /// Return the guest's program counter at the time of exception.
    #[inline]
    pub fn pc(&self) -> u64 {
        self.elr_el2
    }

    /// Set the guest's program counter (used during guest construction).
    #[inline]
    pub fn set_pc(&mut self, addr: u64) {
        self.elr_el2 = addr;
    }

    /// Return the guest's first argument register (x0).
    /// Useful for reading HVC call numbers from the handler.
    #[inline]
    pub fn x0(&self) -> u64 {
        self.regs[0]
    }

    /// Set a return value in x0 (used after handling a hypercall).
    #[inline]
    pub fn set_x0(&mut self, val: u64) {
        self.regs[0] = val;
    }

    /// Return the exception level the guest was running at.
    /// Extracted from bits [4:0] of SPSR_EL2 (the M field).
    #[inline]
    pub fn guest_el(&self) -> u8 {
        // M[3:2]: 00=EL0, 01=EL1, 10=EL2 (should never be EL2 for our guests)
        ((self.spsr_el2 >> 2) & 0b11) as u8
    }
}
