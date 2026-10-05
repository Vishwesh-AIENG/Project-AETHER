//! Minimal x86_64 long-mode host IDT for AETHER's SVM host mode.
//!
//! Installed in `boot_amd` immediately before the first host-mode CALL into
//! translated JIT bytes (the M2 execution proof). Its ONLY job: turn a CPU
//! exception during that CALL — most likely a #PF from an NX (no-execute)
//! page if the firmware marked the BSS heap non-executable, or #UD/#GP from a
//! malformed block — into a readable on-screen post-mortem instead of a silent
//! triple-fault that resets the machine. We never resume.
//!
//! `no_std`, no heap, Win64 ABI. Diagnostics via `crate::boot_x86::dual_puts`
//! / `dual_puthex64` (the framebuffer text painter, confirmed working on the
//! real Ryzen). All output ports / beep are self-contained (boot_x86's beep is
//! private to that module).
//!
//! Rust `global_asm!` / `asm!` default to **Intel** operand syntax — the stubs
//! below are written accordingly (`push 0`, not `push $0`).

#![cfg(target_arch = "x86_64")]

use core::arch::{asm, global_asm};
use core::ptr::addr_of_mut;

// ─────────────────────────────────────────────────────────────────────────────
// 16-byte x86_64 IDT gate descriptor (Intel SDM Vol.3 §6.14.1 / AMD APM Vol.2):
//   [0..2]   offset_low   handler VA [15:0]
//   [2..4]   selector     code segment selector (the LIVE long-mode CS)
//   [4]      ist          bits[2:0] IST index (0 = use current/legacy stack)
//   [5]      type_attr    0x8E: P=1, DPL=0, type=0xE (64-bit interrupt gate)
//   [6..8]   offset_mid   handler VA [31:16]
//   [8..12]  offset_high  handler VA [63:32]
//   [12..16] reserved     0
// ─────────────────────────────────────────────────────────────────────────────
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct GateDescriptor {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl GateDescriptor {
    const fn zero() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    /// `handler` = stub VA; `cs` = the live code selector read at install time.
    fn set(&mut self, handler: u64, cs: u16) {
        self.offset_low = (handler & 0xFFFF) as u16;
        self.selector = cs;
        self.ist = 0; // current (UEFI) stack — valid in host mode
        self.type_attr = 0x8E; // present, DPL0, 64-bit interrupt gate (masks IF)
        self.offset_mid = ((handler >> 16) & 0xFFFF) as u16;
        self.offset_high = ((handler >> 32) & 0xFFFF_FFFF) as u32;
        self.reserved = 0;
    }
}

#[repr(C, packed)]
struct Idtr {
    limit: u16,
    base: u64,
}

static mut IDT: [GateDescriptor; 32] = [GateDescriptor::zero(); 32];

// ─────────────────────────────────────────────────────────────────────────────
// ISR stubs (Intel syntax). Goal: hand the Rust handler a UNIFORM frame whether
// or not the CPU pushed an error code. The CPU pushes an error code for vectors
// 8, 10–14, 17, 21, 29, 30 but NOT for 6 (#UD) or the generic catch-all.
//
// No-error-code stubs push a dummy 0 first so every path reaches host_isr_common
// with the SAME layout:
//   [rsp+0]  = vector       (we pushed)
//   [rsp+8]  = error code   (CPU's real one, or our dummy 0)
//   [rsp+16] = faulting RIP  (CPU)
//   [rsp+24] = CS, [rsp+32] = RFLAGS, ...
//
// Win64 arg registers: RCX, RDX, R8, R9. We pass:
//   RCX = vector, RDX = error_code, R8 = RIP, R9 = CR2.
// We never return, so callee-saved registers need not be preserved.
//
// Stubs are written explicitly (no GAS .macro) to avoid any assembler-dialect
// ambiguity — a wrong stub triple-faults the box, so clarity beats brevity.
// ─────────────────────────────────────────────────────────────────────────────
global_asm!(
    r#"
.global host_isr_ud
host_isr_ud:
    push 0
    push 6
    jmp host_isr_common

.global host_isr_df
host_isr_df:
    push 8
    jmp host_isr_common

.global host_isr_gp
host_isr_gp:
    push 13
    jmp host_isr_common

.global host_isr_pf
host_isr_pf:
    push 14
    jmp host_isr_common

.global host_isr_generic
host_isr_generic:
    push 0
    push 255
    jmp host_isr_common

.global host_isr_generic_err
host_isr_generic_err:
    push 254
    jmp host_isr_common

host_isr_common:
    mov rcx, [rsp]
    mov rdx, [rsp + 8]
    mov r8,  [rsp + 16]
    mov r9,  cr2
    and rsp, -16
    sub rsp, 32
    call host_exception_handler
host_isr_wedge:
    cli
    hlt
    jmp host_isr_wedge
"#
);

unsafe extern "C" {
    fn host_isr_ud();
    fn host_isr_df();
    fn host_isr_gp();
    fn host_isr_pf();
    fn host_isr_generic();
    fn host_isr_generic_err();
}

// ─────────────────────────────────────────────────────────────────────────────
// Rust handler — no_std, no heap, never returns.
// ─────────────────────────────────────────────────────────────────────────────
#[unsafe(no_mangle)]
pub extern "C" fn host_exception_handler(
    vector: u64,
    error_code: u64,
    rip: u64,
    cr2: u64,
) -> ! {
    use crate::boot_x86::{dual_puthex64, dual_puts};
    // SAFETY: dual_puts/dual_puthex64 are the established post-EBS diagnostic
    // path; we are single-threaded with interrupts masked (interrupt gate).
    unsafe {
        dual_puts(b"\n[idt] HOST EXCEPTION vec=");
        dual_puthex64(vector);
        dual_puts(b" err=");
        dual_puthex64(error_code);
        dual_puts(b" rip=");
        dual_puthex64(rip);

        match vector {
            14 => {
                // #PF: CR2 = faulting linear address; decode the error code.
                dual_puts(b" cr2=");
                dual_puthex64(cr2);
                dual_puts(b"\n[idt] #PF");
                if error_code & 0x01 != 0 {
                    dual_puts(b" P=1(prot-viol)");
                } else {
                    dual_puts(b" P=0(not-present)");
                }
                if error_code & 0x02 != 0 {
                    dual_puts(b" W=1(write)");
                }
                if error_code & 0x04 != 0 {
                    dual_puts(b" U=1(user)");
                }
                if error_code & 0x08 != 0 {
                    dual_puts(b" RSVD=1(reserved-bit)");
                }
                // bit 4 = instruction-fetch: the smoking gun for NX/no-exec on
                // the JIT page — the expected failure mode if BSS is NX.
                if error_code & 0x10 != 0 {
                    dual_puts(b" I=1(instr-fetch => NX/no-exec page)");
                }
                dual_puts(b"\n");
            }
            6 => dual_puts(b"\n[idt] #UD (invalid opcode - bad/garbled JIT bytes)\n"),
            13 => dual_puts(b"\n[idt] #GP (general protection - bad selector/canonical)\n"),
            8 => dual_puts(b"\n[idt] #DF (double fault - nested exception)\n"),
            _ => dual_puts(b"\n[idt] (other vector)\n"),
        }

        // Dump the recent guest-PC ring (oldest→newest). The LAST entry is the
        // ARM64 block whose translated x86 just faulted; the prior entries are
        // the branch/call chain into it. This is the culprit-block locator for
        // a host fault in translated code.
        {
            let idx = *core::ptr::addr_of!(crate::boot_x86::DBG_GUEST_PC_IDX);
            dual_puts(b"[idt] recent guest block PCs (oldest->newest):\n");
            let mut k: usize = 0;
            while k < 16 {
                let slot = (idx + k) % 16;
                let p = *core::ptr::addr_of!(crate::boot_x86::DBG_GUEST_PC_RING[slot]);
                if p != 0 {
                    dual_puts(b"[idt]   guest_pc=");
                    dual_puthex64(p);
                    dual_puts(b"\n");
                }
                k += 1;
            }
        }

        // Dump the live guest GPR file (x0..x30). On a host #PF from a translated
        // block's guest-memory access, these say WHAT the guest was computing —
        // e.g. a garbage PFN in a sparsemem mem_section lookup vs a sane one.
        {
            let g = &*core::ptr::addr_of!(crate::boot_x86::NPF_GUEST_CTX);
            dual_puts(b"[idt] guest GPRs x0..x30:\n");
            let mut r: usize = 0;
            while r < 31 {
                dual_puts(b"[idt]   x");
                dual_puthex64(r as u64);
                dual_puts(b"=");
                dual_puthex64(g[r]);
                dual_puts(b"\n");
                r += 1;
            }
            dual_puts(b"[idt]   sp=");
            dual_puthex64(g[0xF8 / 8]);
            dual_puts(b"\n");
        }

        // Distinctive cue: 5 high beeps (vs halt()'s 3x440 Hz).
        beep_n(5, 1200);
    }
    loop {
        // SAFETY: terminal park; no memory or stack operands.
        unsafe { asm!("cli; hlt", options(nomem, nostack)); }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Self-contained PC-speaker beep (boot_x86::beep_n is private to that module).
// ─────────────────────────────────────────────────────────────────────────────
#[inline]
unsafe fn outb(port: u16, val: u8) {
    // SAFETY: caller passes a valid port; `out` has no memory effects.
    unsafe { asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack)); }
}
#[inline]
unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: caller passes a valid port; `in` has no memory effects.
    unsafe { asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack)); }
    v
}
unsafe fn beep_n(n: u32, freq_hz: u32) {
    // SAFETY: standard PIT-channel-2 + port-0x61 speaker sequence.
    unsafe {
        let div: u16 = (1_193_182u32 / freq_hz.max(1)).min(0xFFFF) as u16;
        for _ in 0..n {
            outb(0x43, 0xB6);
            outb(0x42, (div & 0xFF) as u8);
            outb(0x42, ((div >> 8) & 0xFF) as u8);
            let prev = inb(0x61);
            outb(0x61, prev | 0x03);
            for _ in 0..150_000_000u32 {
                asm!("pause", options(nomem, nostack));
            }
            outb(0x61, prev & !0x03);
            for _ in 0..40_000_000u32 {
                asm!("pause", options(nomem, nostack));
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
/// Build and load the host IDT. Call once in `boot_amd` before the host-mode
/// CALL into translated JIT bytes.
///
/// # Safety
/// Must run in long mode on the UEFI page tables (IDT VA is in low BSS,
/// identity-mapped). Interrupts are effectively off; we only take exceptions.
// ─────────────────────────────────────────────────────────────────────────────
pub unsafe fn install_host_idt() {
    // SAFETY: we are CPL0 in SVM host mode; the IDT static is identity-mapped.
    unsafe {
        // Read the LIVE code selector — never assume 0x38. The gate selector
        // MUST equal the CS the stub runs under, or the first exception #GPs
        // recursively into a triple fault.
        let cs: u16;
        asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack));

        let idt = &mut *addr_of_mut!(IDT);
        // Default every vector to the no-error-code generic stub (pushes a
        // dummy 0 so the handler frame is uniform), then specialise.
        let g = host_isr_generic as *const () as u64;
        for slot in idt.iter_mut() {
            slot.set(g, cs);
        }
        // Error-code-pushing vectors (Intel SDM Vol.3 Table 6-1): 8,10,11,12,
        // 13,14,17,21,29,30. These must NOT push a dummy 0 (the CPU already
        // pushed an error code) or the handler frame skews. 8/13/14 have
        // dedicated decoders below; route the rest to host_isr_generic_err.
        let ge = host_isr_generic_err as *const () as u64;
        for &v in &[10usize, 11, 12, 17, 21, 29, 30] {
            idt[v].set(ge, cs);
        }
        idt[6].set(host_isr_ud as *const () as u64, cs);
        idt[8].set(host_isr_df as *const () as u64, cs);
        idt[13].set(host_isr_gp as *const () as u64, cs);
        idt[14].set(host_isr_pf as *const () as u64, cs);

        let idtr = Idtr {
            limit: (core::mem::size_of::<[GateDescriptor; 32]>() - 1) as u16,
            base: addr_of_mut!(IDT) as u64,
        };
        asm!("lidt [{}]", in(reg) &idtr, options(readonly, nostack));

        crate::boot_x86::dual_puts(b"[idt] host IDT installed, CS=");
        crate::boot_x86::dual_puthex64(cs as u64);
        crate::boot_x86::dual_puts(b"\n");
    }
}
