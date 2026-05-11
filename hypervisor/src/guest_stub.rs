// AETHER — minimal bare-metal ARM64 guest stub (Test 2)
//
// This stub runs at EL1 under Stage 2 address translation. It prints
// "Guest EL1 OK\r\n" to the PL011 UART at 0x09000000, then halts with WFE.
//
// Design constraints:
//   - Must be position-independent: the stub is copied to an arbitrary PA
//     and entered via ERET from EL2. We use absolute MMIO addresses via movz/movk
//     and PC-relative data via adr.
//   - No stack assumed at entry: all work done in registers.
//   - UART PA 0x09000000 is mapped Stage 2 DeviceRw (main.rs map_range).
//   - The stub is linked at 0 but runs wherever it's copied — adr is safe
//     because the PC-relative offset to the string is fixed regardless of load PA.

use core::arch::global_asm;

global_asm!(
    ".section .text.guest_stub, \"ax\"",
    ".global guest_stub_start",
    ".global guest_stub_end",
    ".balign 4",
    "guest_stub_start:",

    // x1 = PL011 UART DR (data register) = 0x09000000
    "movz x1, #0x0900, lsl #16",

    // Load address of the message string (PC-relative)
    "adr  x2, 1f",

    // x3 = length of string (13 bytes: "Guest EL1 OK\r\n")
    "mov  x3, #14",

    // Loop: write one byte at a time to UART DR
    "0:",
    "ldrb w4, [x2], #1",   // load byte, post-increment pointer
    "str  w4, [x1]",       // write to PL011 DR (offset 0 = transmit)
    "subs x3, x3, #1",
    "b.ne 0b",

    // Halt
    "1:",                   // string is here (reuse label — GNU assembler allows this
                            // only as a numeric local; branch above uses "0b" not "1b")
    ".ascii \"Guest EL1 OK\\r\\n\"",

    // The WFE loop must come AFTER the string data to avoid executing data.
    // Place it at a known offset by aligning.
    ".balign 4",
    "2:",
    "wfe",
    "b 2b",

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
