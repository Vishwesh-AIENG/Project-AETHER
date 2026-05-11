// AETHER — minimal bare-metal ARM64 guest stub (Tests 2 + 3)
//
// Phase 1 — Test 2: print "Guest EL1 OK\r\n" to PL011 UART to confirm EL1
//   execution and Stage 2 address translation are working.
//
// Phase 2 — Test 3: load from IPA 0x20000000 (deliberately unmapped in Stage 2)
//   to trigger a Stage 2 Data Abort. AETHER's exception handler at EL2 catches
//   the fault and prints "Stage 2 fault caught!" — proving memory isolation works.
//
// Design constraints:
//   - Position-independent: copied to an arbitrary PA and entered via ERET.
//     Absolute MMIO addresses use movz/movk; string data is PC-relative (adr).
//   - No stack at entry: all work in registers.
//   - UART 0x09000000 and unmapped IPA 0x20000000 are both in the EL1 IPA
//     address space; the UART is Stage 2 mapped DeviceRw, 0x20000000 is not
//     mapped at all — any access to it produces EC=0x24 DataAbortLow.

use core::arch::global_asm;

global_asm!(
    ".section .text.guest_stub, \"ax\"",
    ".global guest_stub_start",
    ".global guest_stub_end",
    ".balign 4",
    "guest_stub_start:",

    // ── Phase 1: print "Guest EL1 OK\r\n" via PL011 UART ──────────────────────
    // x1 = PL011 UART DR (data register) = 0x09000000
    "movz x1, #0x0900, lsl #16",

    // x2 = PC-relative pointer to the message string (forward reference to str_msg)
    "adr  x2, 3f",

    // x3 = 14 (length of "Guest EL1 OK\r\n")
    "mov  x3, #14",

    // Byte-by-byte transmit loop
    "0:",
    "ldrb w4, [x2], #1",   // load byte, post-increment
    "str  w4, [x1]",       // write to PL011 DR
    "subs x3, x3, #1",
    "b.ne 0b",

    // ── Phase 2: access unmapped IPA → Stage 2 Data Abort ────────────────────
    // 0x20000000 is between the GIC (ends ~0x0A000000) and DRAM (starts 0x40000000).
    // It is not mapped in Stage 2 — any load or store here triggers EC=0x24 in EL2.
    "movz x5, #0x2000, lsl #16",
    "ldr  x6, [x5]",       // Stage 2 Data Abort → AETHER exception handler

    // Should never reach here (fault is unrecoverable in bring-up).
    "1:",
    "wfe",
    "b 1b",

    // String data placed AFTER the halt loop so it is never executed as code.
    ".balign 4",
    "3:",
    ".ascii \"Guest EL1 OK\\r\\n\"",

    "guest_stub_end:",
);

unsafe extern "C" {
    static guest_stub_start: u8;
    static guest_stub_end: u8;
}

/// Pointer to the first byte of the guest stub code.
#[allow(unused_unsafe)]
#[inline(always)]
pub fn stub_start() -> *const u8 {
    unsafe { core::ptr::addr_of!(guest_stub_start) }
}

/// Byte length of the guest stub.
#[allow(unused_unsafe)]
#[inline(always)]
pub fn stub_len() -> usize {
    let start = stub_start() as usize;
    let end = unsafe { core::ptr::addr_of!(guest_stub_end) } as usize;
    end - start
}
