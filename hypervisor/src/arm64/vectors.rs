// ch05: EL2 exception vector table
//
// ARM64 exception handling requires a vector table stored at a 2KiB-aligned
// address pointed to by VBAR_EL2. The table has 16 entries × 128 bytes each.
//
// Table structure (four groups of four entries):
//
//   Offset  | Group                          | Entries
//   --------|--------------------------------|------------------------------------
//   +0x000  | EL2 with SP_EL0 (EL2t)        | Sync, IRQ, FIQ, SError  — INVALID
//   +0x200  | EL2 with SP_ELx (EL2h)        | Sync, IRQ, FIQ, SError  — EL2 self
//   +0x400  | Lower EL AArch64 (guests)      | Sync, IRQ, FIQ, SError  — VM exits
//   +0x600  | Lower EL AArch32 (legacy)      | Sync, IRQ, FIQ, SError  — INVALID
//
// AETHER only supports 64-bit guests (both Windows-on-ARM and Android Linux
// are AArch64-only). The AArch32 group and EL2t group are therefore invalid
// entries that halt the system if somehow reached.
//
// The EL2h group handles exceptions taken while AETHER itself is running.
// The lower EL AArch64 group handles guest VM exits — this is where all the
// work happens.
//
// Implementation approach:
//   - The vector table itself is in global_asm! so the assembler can enforce
//     the 128-byte-per-entry constraint with `.org` checks.
//   - Each entry saves x0/x1 on the EL2 stack, branches to a common save
//     routine that saves all remaining registers into a GuestContext, then
//     calls a Rust handler.
//   - The Rust handlers are `extern "C"` functions in exception.rs.
//   - After the Rust handler returns, a common restore/ERET epilogue restores
//     the GuestContext and returns to the guest.
//
// Reference: linux-ref/arch/arm64/kvm/hyp/hyp-entry.S (closest reference)
//            ARM ARM DDI0487 Section D1.10-D1.12
//
// Skill guide warnings observed:
//   - Vector table base alignment MUST be 2048 bytes (.align 11)
//   - Each entry MUST be exactly 128 bytes (.align 7, verified with .org)
//   - SP selection at entry: we use SP_ELx (EL2h), so SP is SP_EL2 on entry
//   - Callee-saved registers (x19–x30) must be saved before any BL

use core::arch::global_asm;

use super::context::GUEST_CONTEXT_SIZE; // passed to global_asm! as a const operand

/// Install AETHER's vector table into VBAR_EL2.
///
/// Must be called early in EL2 initialization, before enabling interrupts
/// or entering any guest. Requires a valid EL2 stack to be set up first
/// (the EL2 stack is used to save guest register state on exception entry).
///
/// # Safety
/// - Must be called from EL2.
/// - The EL2 stack pointer (SP_EL2) must be valid and point to sufficient
///   stack space (at least `GUEST_CONTEXT_SIZE` bytes per nested exception,
///   which should not occur, but safe stack headroom is required).
pub unsafe fn install_vectors() {
    unsafe extern "C" {
        /// Symbol defined at the start of the vector table in the assembly below.
        static aether_vectors: u8;
    }

    let vbar = unsafe { &aether_vectors as *const u8 as u64 };

    // Verify the table is 2KiB aligned before installing.
    debug_assert_eq!(vbar & 0x7FF, 0, "aether_vectors must be 2KiB aligned");

    unsafe {
        core::arch::asm!(
            "msr vbar_el2, {0}",
            "isb",
            in(reg) vbar,
            options(nomem, nostack, preserves_flags)
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Vector table — assembly
//
// Each .align 7 produces a 128-byte-aligned entry.
// The .org at the end of each entry asserts it did not overflow 128 bytes.
//
// Save sequence (matches GuestContext layout in context.rs):
//   1. x0, x1 saved in the vector entry before branching (16 bytes)
//   2. save_guest_context macro saves x2–x30, sp_el1, elr_el2, spsr_el2
//
// Total frame = GUEST_CONTEXT_SIZE = 272 bytes.
//
// Note: We allocate GUEST_CONTEXT_SIZE bytes on entry for the full frame,
// but save x0/x1 last (after adjusting SP) to keep the frame contiguous.
// ─────────────────────────────────────────────────────────────────────────────

global_asm!(
    // Bring GUEST_CONTEXT_SIZE into the assembly as a numeric constant.
    // Rust's global_asm! allows const expressions via {ctx_size} syntax.
    // NOTE: ctx_size operand declaration MUST appear at the end of this
    // global_asm! invocation (after all string literals). The Rust macro
    // parser does not allow string literals after named operand declarations.
    ".equ GUEST_CTX_SIZE, {ctx_size}",

    // ─── Common save macro ──────────────────────────────────────────────────
    // Called from each valid vector entry after x0/x1 are on the stack.
    // On entry: SP points to saved x0/x1 (lowest address = x0).
    //           x0 = scratch (caller's x0 already saved at [sp+0])
    //           x1 = scratch (caller's x1 already saved at [sp+8])
    //
    // This macro saves x2–x30, then the three EL2 system registers,
    // giving a complete GuestContext at the current SP.
    //
    // GuestContext layout (from context.rs):
    //   [sp+ 0]: x0  (already saved by vector entry)
    //   [sp+ 8]: x1  (already saved by vector entry)
    //   [sp+16]: x2
    //   ...
    //   [sp+240]: x30
    //   [sp+248]: sp_el1
    //   [sp+256]: elr_el2
    //   [sp+264]: spsr_el2
    ".macro save_guest_context",
    "    stp  x2,  x3,  [sp, #16]",
    "    stp  x4,  x5,  [sp, #32]",
    "    stp  x6,  x7,  [sp, #48]",
    "    stp  x8,  x9,  [sp, #64]",
    "    stp  x10, x11, [sp, #80]",
    "    stp  x12, x13, [sp, #96]",
    "    stp  x14, x15, [sp, #112]",
    "    stp  x16, x17, [sp, #128]",
    "    stp  x18, x19, [sp, #144]",
    "    stp  x20, x21, [sp, #160]",
    "    stp  x22, x23, [sp, #176]",
    "    stp  x24, x25, [sp, #192]",
    "    stp  x26, x27, [sp, #208]",
    "    stp  x28, x29, [sp, #224]",
    "    str  x30,      [sp, #240]",  // x30 alone (sp_el1 follows at #248)
    "    mrs  x9,  sp_el1",
    "    mrs  x10, elr_el2",
    "    mrs  x11, spsr_el2",
    "    stp  x9,  x10, [sp, #248]", // sp_el1 @ 248, elr_el2 @ 256
    "    str  x11,      [sp, #264]", // spsr_el2 @ 264
    ".endm",

    // ─── Common restore macro ───────────────────────────────────────────────
    // Mirror of save_guest_context; restores state and issues ERET.
    ".macro restore_guest_context_and_eret",
    "    ldp  x9,  x10, [sp, #248]",
    "    ldr  x11,      [sp, #264]",
    "    msr  sp_el1,   x9",
    "    msr  elr_el2,  x10",
    "    msr  spsr_el2, x11",
    "    ldp  x2,  x3,  [sp, #16]",
    "    ldp  x4,  x5,  [sp, #32]",
    "    ldp  x6,  x7,  [sp, #48]",
    "    ldp  x8,  x9,  [sp, #64]",
    "    ldp  x10, x11, [sp, #80]",
    "    ldp  x12, x13, [sp, #96]",
    "    ldp  x14, x15, [sp, #112]",
    "    ldp  x16, x17, [sp, #128]",
    "    ldp  x18, x19, [sp, #144]",
    "    ldp  x20, x21, [sp, #160]",
    "    ldp  x22, x23, [sp, #176]",
    "    ldp  x24, x25, [sp, #192]",
    "    ldp  x26, x27, [sp, #208]",
    "    ldp  x28, x29, [sp, #224]",
    "    ldr  x30,      [sp, #240]",
    "    ldp  x0,  x1,  [sp], #GUEST_CTX_SIZE", // restore x0/x1 and pop frame
    "    eret",
    ".endm",

    // ─────────────────────────────────────────────────────────────────────────
    // The vector table
    // .align 11 = 2048 bytes: required base alignment for VBAR_EL2
    // Each .align 7 = 128 bytes: required entry spacing
    // The .org check at the end of each entry asserts no overflow.
    // ─────────────────────────────────────────────────────────────────────────
    ".section .text.vectors, \"ax\"",
    ".align 11",                      // 2KiB alignment — MANDATORY for VBAR_EL2
    "aether_vectors:",

    // ── Group 1: EL2 with SP_EL0 (EL2t) — should never happen in AETHER ────
    // AETHER always uses SP_ELx (EL2h). If we somehow land here, halt.

    ".align 7",                       // entry 0: Sync EL2t
    "0: b 0b",                        // infinite loop = halt
    ".org aether_vectors + 0x080",    // assert: exactly 128 bytes used

    ".align 7",                       // entry 1: IRQ EL2t
    "0: b 0b",
    ".org aether_vectors + 0x100",

    ".align 7",                       // entry 2: FIQ EL2t
    "0: b 0b",
    ".org aether_vectors + 0x180",

    ".align 7",                       // entry 3: SError EL2t
    "0: b 0b",
    ".org aether_vectors + 0x200",

    // ── Group 2: EL2 with SP_ELx (EL2h) — AETHER itself ────────────────────
    // Exceptions while AETHER code is running. Sync is possible (e.g., if
    // AETHER has a bug). IRQ/FIQ during EL2 should not occur with our
    // interrupt routing. SError is fatal.

    ".align 7",                       // entry 4: Sync EL2h — AETHER bug
    "sub  sp, sp, #GUEST_CTX_SIZE",
    "stp  x0, x1, [sp, #0]",
    "save_guest_context",
    "mov  x0, sp",
    "bl   aether_handle_sync",        // returns ExitReason; for EL2h bugs, always Halt
    "restore_guest_context_and_eret", // included for structure; Halt won't return here
    ".org aether_vectors + 0x280",

    ".align 7",                       // entry 5: IRQ EL2h — unexpected
    "0: b 0b",
    ".org aether_vectors + 0x300",

    ".align 7",                       // entry 6: FIQ EL2h — unexpected
    "0: b 0b",
    ".org aether_vectors + 0x380",

    ".align 7",                       // entry 7: SError EL2h — fatal bus error
    "0: b 0b",
    ".org aether_vectors + 0x400",

    // ── Group 3: Lower EL AArch64 — guest VM exits ───────────────────────────
    // This is where all the work happens. Every guest exception that reaches
    // EL2 lands in one of these four entries.

    ".align 7",                       // entry 8: Sync from AArch64 EL1
    "sub  sp, sp, #GUEST_CTX_SIZE",
    "stp  x0, x1, [sp, #0]",
    "save_guest_context",
    "mov  x0, sp",                    // first arg = *GuestContext
    "bl   aether_handle_sync",
    "restore_guest_context_and_eret",
    ".org aether_vectors + 0x480",

    ".align 7",                       // entry 9: IRQ from AArch64 EL1
    "sub  sp, sp, #GUEST_CTX_SIZE",
    "stp  x0, x1, [sp, #0]",
    "save_guest_context",
    "mov  x0, sp",
    "bl   aether_handle_irq",
    "restore_guest_context_and_eret",
    ".org aether_vectors + 0x500",

    ".align 7",                       // entry 10: FIQ from AArch64 EL1
    "sub  sp, sp, #GUEST_CTX_SIZE",
    "stp  x0, x1, [sp, #0]",
    "save_guest_context",
    "mov  x0, sp",
    "bl   aether_handle_irq",         // FIQ uses same handler as IRQ at this stage
    "restore_guest_context_and_eret",
    ".org aether_vectors + 0x580",

    ".align 7",                       // entry 11: SError from AArch64 EL1
    "sub  sp, sp, #GUEST_CTX_SIZE",
    "stp  x0, x1, [sp, #0]",
    "save_guest_context",
    "mov  x0, sp",
    "bl   aether_handle_serror",
    "restore_guest_context_and_eret",
    ".org aether_vectors + 0x600",

    // ── Group 4: Lower EL AArch32 — AETHER does not support 32-bit guests ───
    // AETHER supports only 64-bit operating systems (Windows-on-ARM and
    // Android both run AArch64). HCR_EL2.RW = 1 configures this.
    // These entries are unreachable in a correct configuration.

    ".align 7",                       // entry 12: Sync AArch32 EL1
    "0: b 0b",
    ".org aether_vectors + 0x680",

    ".align 7",                       // entry 13: IRQ AArch32 EL1
    "0: b 0b",
    ".org aether_vectors + 0x700",

    ".align 7",                       // entry 14: FIQ AArch32 EL1
    "0: b 0b",
    ".org aether_vectors + 0x780",

    ".align 7",                       // entry 15: SError AArch32 EL1
    "0: b 0b",
    ".org aether_vectors + 0x800",

    // End of vector table — exactly 2KiB from aether_vectors.

    // Named const operand — must be declared after all string literals.
    ctx_size = const GUEST_CONTEXT_SIZE,
);
